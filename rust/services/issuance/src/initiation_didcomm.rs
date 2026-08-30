use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io::{Read, Take},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_didcomm::{
    encrypt_for_recipient, encrypt_for_recipient_authenticated, pack_credential_for_holder,
    unpack_didcomm_message, DidDocument, DidResolver,
};
use reqwest::{redirect::Policy, Certificate, Client, Url};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::json;
use thiserror::Error;

use crate::network_policy::is_public_ip;

const MAX_ENDPOINT_LENGTH: usize = 2_048;
const MAX_POLICY_BYTES: u64 = 64 * 1_024;
const MAX_POLICY_ISSUERS: usize = 1_000;
const DEFAULT_DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);
const DIDCOMM_CONTENT_TYPE: &str = "application/didcomm-encrypted+json";

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NativeDidcommError {
    #[error("DID resolution is unavailable")]
    ResolutionUnavailable,
    #[error("DID resolution returned a mismatched document")]
    MismatchedDocument,
    #[error("holder DID has no DIDComm service endpoint")]
    MissingEndpoint,
    #[error("DIDComm service endpoint is invalid")]
    InvalidEndpoint,
    #[error("DIDComm service endpoint must use HTTPS")]
    HttpsRequired,
    #[error("DIDComm service endpoint could not be resolved")]
    EndpointUnresolvable,
    #[error("DIDComm service endpoint is not publicly routable")]
    EndpointNotPublic,
    #[error("DIDComm encryption policy is unavailable")]
    EncryptionPolicyUnavailable,
    #[error("DIDComm sender authentication is unavailable")]
    SenderAuthenticationUnavailable,
    #[error("holder DID has no compatible DIDComm key agreement")]
    IncompatibleKeyAgreement,
    #[error("DIDComm message packing failed")]
    PackUnavailable,
    #[error("DIDComm TLS trust configuration is unavailable")]
    TlsUnavailable,
    #[error("DIDComm transport is unavailable")]
    TransportUnavailable,
}

#[derive(Clone)]
pub struct NativeDidcommEnvelope {
    resolver: Arc<DidResolver>,
    policy_file: Option<Arc<PathBuf>>,
}

impl fmt::Debug for NativeDidcommEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeDidcommEnvelope")
            .field("policy_configured", &self.policy_file.is_some())
            .finish_non_exhaustive()
    }
}

impl NativeDidcommEnvelope {
    #[must_use]
    pub fn new(
        universal_resolver_url: Option<&str>,
        did_web_internal_base_url: Option<&str>,
        policy_file: Option<&str>,
    ) -> Self {
        let mut resolver = universal_resolver_url.map_or_else(DidResolver::new, |url| {
            DidResolver::with_universal_resolver(url.to_owned())
        });
        if let Some(base_url) = did_web_internal_base_url {
            resolver = resolver.with_did_web_internal_base_urls([base_url]);
        }
        Self {
            resolver: Arc::new(resolver),
            policy_file: policy_file.map(PathBuf::from).map(Arc::new),
        }
    }

    pub async fn resolve_recipient(
        &self,
        holder_did: &str,
    ) -> Result<ResolvedDidcommRecipient, NativeDidcommError> {
        let result = self
            .resolver
            .resolve_with_metadata(holder_did)
            .await
            .map_err(|_| NativeDidcommError::ResolutionUnavailable)?;
        if result.document.id != holder_did {
            return Err(NativeDidcommError::MismatchedDocument);
        }
        let endpoint = result
            .document
            .didcomm_endpoint()
            .filter(|value| !value.is_empty())
            .ok_or(NativeDidcommError::MissingEndpoint)?
            .to_owned();
        Ok(ResolvedDidcommRecipient {
            document: result.document,
            endpoint,
        })
    }

    pub async fn prepare_encryption(
        &self,
        issuer_did: &str,
        recipient_document: DidDocument,
    ) -> Result<PreparedDidcommEncryption, NativeDidcommError> {
        let mode = load_active_policy(
            self.policy_file.as_deref().map(PathBuf::as_path),
            issuer_did,
        )?;
        let plaintext = preflight_plaintext(issuer_did, &recipient_document)?;
        let mode = match mode {
            ActiveEncryptionPolicy::Anoncrypt => {
                encrypt_for_recipient(&plaintext, &recipient_document)
                    .map_err(|_| NativeDidcommError::IncompatibleKeyAgreement)?;
                PreparedEncryptionMode::Anoncrypt
            }
            ActiveEncryptionPolicy::Authcrypt(sender_private_key) => {
                let sender_document = self
                    .resolver
                    .resolve(issuer_did)
                    .await
                    .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?;
                if sender_document.id != issuer_did {
                    return Err(NativeDidcommError::SenderAuthenticationUnavailable);
                }
                encrypt_for_recipient_authenticated(
                    &plaintext,
                    &sender_document,
                    sender_private_key.expose(),
                    &recipient_document,
                )
                .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?;
                PreparedEncryptionMode::Authcrypt {
                    sender_document: Box::new(sender_document),
                    sender_private_key,
                }
            }
        };
        Ok(PreparedDidcommEncryption {
            issuer_did: issuer_did.to_owned(),
            recipient_document,
            mode,
        })
    }

    pub fn pack_credential(
        &self,
        credential: &str,
        credential_format: &str,
        issuer_did: &str,
        holder_did: &str,
        transaction_id: &str,
        credential_id: &str,
    ) -> Result<PackedDidcommCredential, NativeDidcommError> {
        let plaintext = pack_credential_for_holder(
            credential,
            credential_format,
            issuer_did,
            holder_did,
            Some(transaction_id),
            Some(credential_id),
        )
        .map_err(|_| NativeDidcommError::PackUnavailable)?;
        let message =
            unpack_didcomm_message(&plaintext).map_err(|_| NativeDidcommError::PackUnavailable)?;
        if message.id.is_empty() {
            return Err(NativeDidcommError::PackUnavailable);
        }
        Ok(PackedDidcommCredential {
            plaintext,
            message_id: message.id,
        })
    }

    pub fn encrypt_prepared(
        &self,
        plaintext: &str,
        prepared: &PreparedDidcommEncryption,
    ) -> Result<String, NativeDidcommError> {
        match &prepared.mode {
            PreparedEncryptionMode::Anoncrypt => {
                encrypt_for_recipient(plaintext, &prepared.recipient_document)
                    .map_err(|_| NativeDidcommError::IncompatibleKeyAgreement)
            }
            PreparedEncryptionMode::Authcrypt {
                sender_document,
                sender_private_key,
            } => encrypt_for_recipient_authenticated(
                plaintext,
                sender_document,
                sender_private_key.expose(),
                &prepared.recipient_document,
            )
            .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable),
        }
    }
}

pub struct ResolvedDidcommRecipient {
    pub document: DidDocument,
    pub endpoint: String,
}

impl fmt::Debug for ResolvedDidcommRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedDidcommRecipient")
            .field("document_id_matches_endpoint_owner", &true)
            .finish_non_exhaustive()
    }
}

pub struct PreparedDidcommEncryption {
    issuer_did: String,
    recipient_document: DidDocument,
    mode: PreparedEncryptionMode,
}

impl fmt::Debug for PreparedDidcommEncryption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDidcommEncryption")
            .field("issuer_configured", &!self.issuer_did.is_empty())
            .field("mode", &self.mode.name())
            .finish_non_exhaustive()
    }
}

enum PreparedEncryptionMode {
    Anoncrypt,
    Authcrypt {
        sender_document: Box<DidDocument>,
        sender_private_key: SenderPrivateKey,
    },
}

impl PreparedEncryptionMode {
    fn name(&self) -> &'static str {
        match self {
            Self::Anoncrypt => "anoncrypt",
            Self::Authcrypt { .. } => "authcrypt",
        }
    }
}

pub struct PackedDidcommCredential {
    pub plaintext: String,
    pub message_id: String,
}

impl fmt::Debug for PackedDidcommCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackedDidcommCredential")
            .field("message_id_configured", &!self.message_id.is_empty())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct DidcommEndpointValidator {
    allow_private_ips: bool,
}

impl DidcommEndpointValidator {
    #[must_use]
    pub fn new(allow_private_ips: bool) -> Self {
        Self { allow_private_ips }
    }

    pub async fn validate(
        &self,
        endpoint: &str,
    ) -> Result<ValidatedDidcommEndpoint, NativeDidcommError> {
        if endpoint.len() > MAX_ENDPOINT_LENGTH {
            return Err(NativeDidcommError::InvalidEndpoint);
        }
        let url = Url::parse(endpoint).map_err(|_| NativeDidcommError::InvalidEndpoint)?;
        if url.scheme() != "https" {
            return Err(NativeDidcommError::HttpsRequired);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(NativeDidcommError::InvalidEndpoint);
        }
        let hostname = url
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or(NativeDidcommError::InvalidEndpoint)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !self.allow_private_ips && (hostname == "localhost" || hostname.ends_with(".localhost"))
        {
            return Err(NativeDidcommError::EndpointNotPublic);
        }
        let port = url.port().unwrap_or(443);
        let addresses = tokio::net::lookup_host((hostname.as_str(), port))
            .await
            .map_err(|_| NativeDidcommError::EndpointUnresolvable)?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(NativeDidcommError::EndpointUnresolvable);
        }
        if !self.allow_private_ips && addresses.iter().any(|address| !is_public_ip(address.ip())) {
            return Err(NativeDidcommError::EndpointNotPublic);
        }
        Ok(ValidatedDidcommEndpoint {
            original: endpoint.to_owned(),
            url,
            hostname,
            addresses,
        })
    }
}

pub struct ValidatedDidcommEndpoint {
    original: String,
    url: Url,
    hostname: String,
    addresses: Vec<SocketAddr>,
}

impl ValidatedDidcommEndpoint {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }
}

impl fmt::Debug for ValidatedDidcommEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedDidcommEndpoint")
            .field("address_count", &self.addresses.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct DidcommTransport {
    tls_ca: Option<Certificate>,
    timeout: Duration,
}

impl fmt::Debug for DidcommTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DidcommTransport")
            .field("operator_ca_configured", &self.tls_ca.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl DidcommTransport {
    pub fn new(tls_ca_file: Option<&str>) -> Result<Self, NativeDidcommError> {
        Self::with_timeout(tls_ca_file, DEFAULT_DELIVERY_TIMEOUT)
    }

    pub fn with_timeout(
        tls_ca_file: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, NativeDidcommError> {
        if timeout.is_zero() {
            return Err(NativeDidcommError::TransportUnavailable);
        }
        let tls_ca = tls_ca_file
            .map(|path| {
                let pem = std::fs::read(path).map_err(|_| NativeDidcommError::TlsUnavailable)?;
                Certificate::from_pem(&pem).map_err(|_| NativeDidcommError::TlsUnavailable)
            })
            .transpose()?;
        Ok(Self { tls_ca, timeout })
    }

    pub async fn deliver(
        &self,
        endpoint: &ValidatedDidcommEndpoint,
        encrypted_message: String,
    ) -> DidcommTransportOutcome {
        let mut builder = Client::builder()
            .timeout(self.timeout)
            .redirect(Policy::none())
            .resolve_to_addrs(&endpoint.hostname, &endpoint.addresses);
        if let Some(certificate) = self.tls_ca.clone() {
            builder = builder.add_root_certificate(certificate);
        }
        let Ok(client) = builder.build() else {
            return DidcommTransportOutcome::Failed;
        };
        match client
            .post(endpoint.url.clone())
            .header(reqwest::header::CONTENT_TYPE, DIDCOMM_CONTENT_TYPE)
            .body(encrypted_message)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => DidcommTransportOutcome::Delivered,
            Ok(_) | Err(_) => DidcommTransportOutcome::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidcommTransportOutcome {
    Delivered,
    Failed,
}

enum ActiveEncryptionPolicy {
    Anoncrypt,
    Authcrypt(SenderPrivateKey),
}

struct SenderPrivateKey([u8; 32]);

impl SenderPrivateKey {
    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SenderPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SenderPrivateKey([REDACTED])")
    }
}

impl Drop for SenderPrivateKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptionPolicyFile {
    version: u64,
    issuers: UniqueStringMap<ConfiguredIssuerPolicy>,
}

enum ConfiguredIssuerPolicy {
    Anoncrypt,
    Authcrypt { sender_x25519_private_key: String },
}

impl<'de> Deserialize<'de> for ConfiguredIssuerPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssuerPolicyVisitor;

        impl<'de> Visitor<'de> for IssuerPolicyVisitor {
            type Value = ConfiguredIssuerPolicy;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an exact DIDComm issuer encryption policy")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(de::Error::custom(format!("duplicate member {key}")));
                    }
                }
                let mode = values.get("mode").and_then(serde_json::Value::as_str);
                match mode {
                    Some("anoncrypt") if values.len() == 1 => Ok(Self::Value::Anoncrypt),
                    Some("authcrypt")
                        if values.len() == 2
                            && values.contains_key("sender_x25519_private_key") =>
                    {
                        let sender_x25519_private_key = values
                            .remove("sender_x25519_private_key")
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .ok_or_else(|| {
                                de::Error::custom("authcrypt sender key must be a base64url string")
                            })?;
                        Ok(Self::Value::Authcrypt {
                            sender_x25519_private_key,
                        })
                    }
                    _ => Err(de::Error::custom(
                        "DIDComm encryption policy entry has invalid fields or mode",
                    )),
                }
            }
        }

        deserializer.deserialize_map(IssuerPolicyVisitor)
    }
}

struct UniqueStringMap<T>(BTreeMap<String, T>);

impl<'de, T> Deserialize<'de> for UniqueStringMap<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueMapVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> Visitor<'de> for UniqueMapVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = UniqueStringMap<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object without duplicate members")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, T>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(de::Error::custom(format!("duplicate member {key}")));
                    }
                }
                Ok(UniqueStringMap(values))
            }
        }

        deserializer.deserialize_map(UniqueMapVisitor(std::marker::PhantomData))
    }
}

fn load_active_policy(
    policy_file: Option<&Path>,
    issuer_did: &str,
) -> Result<ActiveEncryptionPolicy, NativeDidcommError> {
    let Some(policy_file) = policy_file else {
        return Ok(ActiveEncryptionPolicy::Anoncrypt);
    };
    let file =
        File::open(policy_file).map_err(|_| NativeDidcommError::EncryptionPolicyUnavailable)?;
    let mut encoded = Vec::new();
    let mut bounded: Take<File> = file.take(MAX_POLICY_BYTES + 1);
    bounded
        .read_to_end(&mut encoded)
        .map_err(|_| NativeDidcommError::EncryptionPolicyUnavailable)?;
    if encoded.len() as u64 > MAX_POLICY_BYTES {
        return Err(NativeDidcommError::EncryptionPolicyUnavailable);
    }
    let mut policy: EncryptionPolicyFile = serde_json::from_slice(&encoded)
        .map_err(|_| NativeDidcommError::EncryptionPolicyUnavailable)?;
    if policy.version != 1 || policy.issuers.0.len() > MAX_POLICY_ISSUERS {
        return Err(NativeDidcommError::EncryptionPolicyUnavailable);
    }
    if policy
        .issuers
        .0
        .keys()
        .any(|did| !did.starts_with("did:") || did.len() > MAX_ENDPOINT_LENGTH)
    {
        return Err(NativeDidcommError::EncryptionPolicyUnavailable);
    }
    let mut used_authcrypt_keys = BTreeSet::new();
    let mut active = None;
    for (did, configured) in std::mem::take(&mut policy.issuers.0) {
        let resolved = match configured {
            ConfiguredIssuerPolicy::Anoncrypt => ActiveEncryptionPolicy::Anoncrypt,
            ConfiguredIssuerPolicy::Authcrypt {
                sender_x25519_private_key,
            } => {
                let key = decode_sender_private_key(&sender_x25519_private_key)?;
                if !used_authcrypt_keys.insert(key.0) {
                    return Err(NativeDidcommError::EncryptionPolicyUnavailable);
                }
                ActiveEncryptionPolicy::Authcrypt(key)
            }
        };
        if did == issuer_did {
            active = Some(resolved);
        }
    }
    active.ok_or(NativeDidcommError::EncryptionPolicyUnavailable)
}

fn decode_sender_private_key(value: &str) -> Result<SenderPrivateKey, NativeDidcommError> {
    if value.is_empty() || value.contains('=') {
        return Err(NativeDidcommError::EncryptionPolicyUnavailable);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| NativeDidcommError::EncryptionPolicyUnavailable)?;
    let decoded: [u8; 32] = decoded
        .try_into()
        .map_err(|_| NativeDidcommError::EncryptionPolicyUnavailable)?;
    if URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(NativeDidcommError::EncryptionPolicyUnavailable);
    }
    Ok(SenderPrivateKey(decoded))
}

fn preflight_plaintext(
    issuer_did: &str,
    recipient_document: &DidDocument,
) -> Result<String, NativeDidcommError> {
    if !recipient_document.id.starts_with("did:") {
        return Err(NativeDidcommError::IncompatibleKeyAgreement);
    }
    serde_json::to_string(&json!({
        "id": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "from": issuer_did,
        "to": [recipient_document.id.as_str()],
        "body": {"preflight": true},
    }))
    .map_err(|_| NativeDidcommError::IncompatibleKeyAgreement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_didcomm::types::{Jwk, VerificationMethod};

    fn recipient_document() -> DidDocument {
        let did = "did:example:holder";
        let key_id = format!("{did}#key-1");
        DidDocument {
            id: did.to_owned(),
            context: serde_json::Value::Null,
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: vec![json!(key_id)],
            verification_method: vec![VerificationMethod {
                id: key_id,
                r#type: "JsonWebKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_jwk: Some(Jwk {
                    kty: "OKP".to_owned(),
                    crv: Some("X25519".to_owned()),
                    x: Some(URL_SAFE_NO_PAD.encode([7_u8; 32])),
                    y: None,
                    d: None,
                    kid: None,
                    additional_properties: serde_json::Map::new(),
                }),
                public_key_multibase: None,
                public_key_base58: None,
                additional_properties: serde_json::Map::new(),
            }],
            service: Vec::new(),
            additional_properties: serde_json::Map::new(),
        }
    }

    fn policy_file(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "marty-didcomm-policy-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[tokio::test]
    async fn anoncrypt_preflight_is_frozen_and_reused_for_delivery() {
        let envelope = NativeDidcommEnvelope::new(None, None, None);
        let prepared = envelope
            .prepare_encryption("did:example:issuer", recipient_document())
            .await
            .unwrap();
        assert_eq!(prepared.mode.name(), "anoncrypt");

        let packed = envelope
            .pack_credential(
                "signed-credential",
                "w3c_vcdm_v2_sd_jwt",
                "did:example:issuer",
                "did:example:holder",
                "transaction-1",
                "credential-1",
            )
            .unwrap();
        let encrypted = envelope
            .encrypt_prepared(&packed.plaintext, &prepared)
            .unwrap();
        let jwe: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        assert!(jwe.get("protected").is_some());
        assert!(!packed.message_id.is_empty());
        assert!(!format!("{prepared:?}").contains("did:example:holder"));
        assert!(!format!("{packed:?}").contains("signed-credential"));
    }

    #[test]
    fn policy_requires_exact_canonical_entries_without_key_reuse() {
        let key = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let valid = policy_file(&format!(
            r#"{{"version":1,"issuers":{{"did:example:issuer":{{"mode":"authcrypt","sender_x25519_private_key":"{key}"}}}}}}"#
        ));
        assert!(matches!(
            load_active_policy(Some(&valid), "did:example:issuer").unwrap(),
            ActiveEncryptionPolicy::Authcrypt(_)
        ));
        std::fs::remove_file(valid).unwrap();

        for invalid in [
            r#"{"version":1,"issuers":{"did:example:issuer":{"mode":"anoncrypt","mode":"authcrypt"}}}"#.to_owned(),
            r#"{"version":true,"issuers":{"did:example:issuer":{"mode":"anoncrypt"}}}"#.to_owned(),
            r#"{"version":1,"issuers":{"did:example:issuer":{"mode":"authcrypt","sender_x25519_private_key":"AA=="}}}"#.to_owned(),
            r#"{"version":1,"issuers":{"did:example:issuer":{"mode":"anoncrypt","unexpected":true}}}"#.to_owned(),
            format!(r#"{{"version":1,"issuers":{{"did:example:a":{{"mode":"authcrypt","sender_x25519_private_key":"{key}"}},"did:example:b":{{"mode":"authcrypt","sender_x25519_private_key":"{key}"}}}}}}"#),
        ] {
            let path = policy_file(&invalid);
            assert_eq!(
                load_active_policy(Some(&path), "did:example:issuer").err(),
                Some(NativeDidcommError::EncryptionPolicyUnavailable)
            );
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn configured_policy_requires_the_active_issuer() {
        let path =
            policy_file(r#"{"version":1,"issuers":{"did:example:other":{"mode":"anoncrypt"}}}"#);
        assert_eq!(
            load_active_policy(Some(&path), "did:example:issuer").err(),
            Some(NativeDidcommError::EncryptionPolicyUnavailable)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn endpoint_validation_requires_https_and_public_dns_by_default() {
        let public_only = DidcommEndpointValidator::new(false);
        assert_eq!(
            public_only.validate("http://127.0.0.1/inbox").await.err(),
            Some(NativeDidcommError::HttpsRequired)
        );
        assert_eq!(
            public_only
                .validate("https://user:secret@wallet.example/inbox")
                .await
                .err(),
            Some(NativeDidcommError::InvalidEndpoint)
        );
        assert_eq!(
            public_only.validate("https://127.0.0.1/inbox").await.err(),
            Some(NativeDidcommError::EndpointNotPublic)
        );

        let private_allowed = DidcommEndpointValidator::new(true);
        let endpoint = private_allowed
            .validate("https://127.0.0.1:18444/inbox")
            .await
            .unwrap();
        assert_eq!(endpoint.as_str(), "https://127.0.0.1:18444/inbox");
        assert!(!format!("{endpoint:?}").contains("127.0.0.1"));
    }

    #[test]
    fn transport_uses_system_roots_unless_an_operator_ca_is_valid() {
        assert!(DidcommTransport::new(None).is_ok());
        assert_eq!(
            DidcommTransport::new(Some("missing-didcomm-ca.pem")).err(),
            Some(NativeDidcommError::TlsUnavailable)
        );
    }
}
