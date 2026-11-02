//! OpenBao DIDComm authcrypt client. The issuer receives only public key
//! metadata and complete JWEs; sender private keys remain in the plugin.

use std::{fmt, fs::File, io::Read, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
#[cfg(test)]
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Client, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

const MAX_TOKEN_BYTES: u64 = 4_096;
const MAX_JWE_BYTES: usize = 2 * 1024 * 1024;
const MAX_METADATA_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_PACK_RESPONSE_BYTES: usize = MAX_JWE_BYTES + 1024;

pub use marty_signing_grant::didcomm::{DidcommKeyReference, RemoteRecipientPublic};
use marty_signing_grant::{didcomm::DidcommPackRequest, replay::ConsumedGrant};

#[derive(Clone)]
pub struct RemoteDidcommKms {
    base_url: Url,
    token: DidcommToken,
    namespace: Option<String>,
    service_id: String,
    service_config_sha256: String,
    client: Client,
}

#[derive(Clone)]
enum DidcommToken {
    ManagedFile(PathBuf),
    Registered(String),
}

impl fmt::Debug for RemoteDidcommKms {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteDidcommKms")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum RemoteDidcommKmsError {
    #[error("DIDComm authcrypt capability is not configured")]
    CapabilityUnavailable,
    #[error("DIDComm authcrypt authorization is invalid")]
    Unauthorized,
    #[error("invalid DIDComm KMS reference")]
    InvalidReference,
    #[error("invalid DIDComm KMS configuration")]
    InvalidConfiguration,
    #[error("DIDComm KMS token is unavailable")]
    TokenUnavailable,
    #[error("DIDComm KMS operation failed")]
    OperationFailed,
    #[error("DIDComm KMS returned mismatched key metadata")]
    BindingMismatch,
}

#[derive(Deserialize)]
struct BaoResponse<T> {
    data: T,
}

#[derive(Deserialize)]
struct PublicMetadata {
    tenant: String,
    name: String,
    version: String,
    sender_did: String,
    sender_key_id: String,
    public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteSenderPublic {
    pub sender_key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Serialize)]
struct PackRequest<'a> {
    recipient_did: &'a str,
    recipients: String,
    plaintext_base64: String,
}

#[derive(Deserialize)]
struct PackResponse {
    jwe: String,
    version: String,
    sender_key_id: String,
}

async fn bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<T, RemoteDidcommKmsError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RemoteDidcommKmsError::OperationFailed)?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(RemoteDidcommKmsError::OperationFailed);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| RemoteDidcommKmsError::OperationFailed)
}

impl RemoteDidcommKms {
    pub(crate) fn from_registered_service(
        service: &serde_json::Value,
    ) -> Result<Self, RemoteDidcommKmsError> {
        if service
            .get("service_type")
            .and_then(serde_json::Value::as_str)
            != Some("openbao-transit")
        {
            return Err(RemoteDidcommKmsError::CapabilityUnavailable);
        }
        crate::kms::validate_transit_auth_config(service)
            .map_err(|_| RemoteDidcommKmsError::InvalidConfiguration)?;
        let string = |field| {
            service
                .get(field)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
        };
        let token = match string("auth_mode") {
            // validate_transit_auth_config pins this mode to the managed ID and
            // exact BAO_ADDR origin. No UI field may select a mounted token.
            "service_token" => {
                let file = std::env::var_os("DIDCOMM_KMS_TOKEN_FILE")
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .ok_or(RemoteDidcommKmsError::CapabilityUnavailable)?;
                DidcommToken::ManagedFile(file)
            }
            "token" => DidcommToken::Registered(string("auth_reference").to_owned()),
            _ => return Err(RemoteDidcommKmsError::InvalidConfiguration),
        };
        Ok(Self {
            base_url: Url::parse(string("endpoint"))
                .map_err(|_| RemoteDidcommKmsError::InvalidConfiguration)?,
            token,
            namespace: (!string("namespace").is_empty()).then(|| string("namespace").to_owned()),
            service_id: string("id").to_owned(),
            service_config_sha256: crate::registry::didcomm_service_config_sha256(service),
            client: crate::kms::transit_http_client(service)
                .map_err(|_| RemoteDidcommKmsError::InvalidConfiguration)?,
        })
    }

    #[cfg(test)]
    fn new(
        base_url: &str,
        token_file: PathBuf,
        ca_file: Option<PathBuf>,
    ) -> Result<Self, RemoteDidcommKmsError> {
        let transport = OpenBaoHttp::connect(
            base_url,
            ca_file.as_deref(),
            std::time::Duration::from_secs(10),
        )
        .map_err(|_| RemoteDidcommKmsError::InvalidConfiguration)?;
        let url = Url::parse(transport.origin())
            .map_err(|_| RemoteDidcommKmsError::InvalidConfiguration)?;
        Ok(Self {
            base_url: url,
            token: DidcommToken::ManagedFile(token_file),
            namespace: None,
            service_id: String::new(),
            service_config_sha256: String::new(),
            client: transport.client().clone(),
        })
    }

    fn token(&self) -> Result<String, RemoteDidcommKmsError> {
        let DidcommToken::ManagedFile(path) = &self.token else {
            let DidcommToken::Registered(token) = &self.token else {
                unreachable!()
            };
            return Ok(token.clone());
        };
        let file = File::open(path).map_err(|_| RemoteDidcommKmsError::TokenUnavailable)?;
        let mut data = Vec::new();
        file.take(MAX_TOKEN_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|_| RemoteDidcommKmsError::TokenUnavailable)?;
        if data.is_empty() || data.len() as u64 > MAX_TOKEN_BYTES {
            return Err(RemoteDidcommKmsError::TokenUnavailable);
        }
        let token = String::from_utf8(data).map_err(|_| RemoteDidcommKmsError::TokenUnavailable)?;
        let token = token.trim_end_matches(['\r', '\n']);
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(RemoteDidcommKmsError::TokenUnavailable);
        }
        Ok(token.to_owned())
    }

    fn authorized(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, RemoteDidcommKmsError> {
        let mut request = request.header("X-Vault-Token", self.token()?);
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        Ok(request)
    }

    pub async fn public_key(
        &self,
        reference: &DidcommKeyReference,
        expected_sender_did: &str,
    ) -> Result<RemoteSenderPublic, RemoteDidcommKmsError> {
        let url = self
            .base_url
            .join(&reference.public_path())
            .map_err(|_| RemoteDidcommKmsError::InvalidReference)?;
        let response = self
            .authorized(self.client.get(url))?
            .send()
            .await
            .map_err(|_| RemoteDidcommKmsError::OperationFailed)?;
        if !response.status().is_success() {
            return Err(RemoteDidcommKmsError::OperationFailed);
        }
        let metadata: BaoResponse<PublicMetadata> =
            bounded_json(response, MAX_METADATA_RESPONSE_BYTES).await?;
        let data = metadata.data;
        let public = URL_SAFE_NO_PAD
            .decode(&data.public_key)
            .map_err(|_| RemoteDidcommKmsError::BindingMismatch)?;
        let public_key: [u8; 32] = public
            .try_into()
            .map_err(|_| RemoteDidcommKmsError::BindingMismatch)?;
        if data.tenant != reference.tenant()
            || data.name != reference.name()
            || data.version != reference.version()
            || data.sender_did != expected_sender_did
            || !data
                .sender_key_id
                .starts_with(&format!("{expected_sender_did}#"))
        {
            return Err(RemoteDidcommKmsError::BindingMismatch);
        }
        Ok(RemoteSenderPublic {
            sender_key_id: data.sender_key_id,
            public_key,
        })
    }

    pub(crate) async fn pack_authorized(
        &self,
        request: &DidcommPackRequest,
        consumed: ConsumedGrant,
    ) -> Result<String, RemoteDidcommKmsError> {
        let payload = request
            .bound_payload()
            .map_err(|_| RemoteDidcommKmsError::Unauthorized)?;
        if self.service_id != request.binding.service_id
            || self.service_config_sha256 != request.binding.service_config_sha256
            || !consumed.authorizes(&request.grant_binding(&payload))
        {
            return Err(RemoteDidcommKmsError::Unauthorized);
        }
        let reference = request
            .binding
            .validate(&request.organization_id, &request.issuer_did)
            .map_err(|_| RemoteDidcommKmsError::BindingMismatch)?;
        self.pack(
            &reference,
            &request.binding.sender_key_id,
            &request.recipient_did,
            &request.recipients,
            &request.plaintext,
        )
        .await
    }

    async fn pack(
        &self,
        reference: &DidcommKeyReference,
        sender_key_id: &str,
        recipient_did: &str,
        recipients: &[RemoteRecipientPublic],
        plaintext: &str,
    ) -> Result<String, RemoteDidcommKmsError> {
        if recipients.is_empty() || recipients.len() > 32 || plaintext.len() > 1 << 20 {
            return Err(RemoteDidcommKmsError::OperationFailed);
        }
        let url = self
            .base_url
            .join(&reference.pack_path())
            .map_err(|_| RemoteDidcommKmsError::InvalidReference)?;
        let request = PackRequest {
            recipient_did,
            recipients: serde_json::to_string(recipients)
                .map_err(|_| RemoteDidcommKmsError::OperationFailed)?,
            plaintext_base64: base64::engine::general_purpose::STANDARD.encode(plaintext),
        };
        let response = self
            .authorized(self.client.post(url))?
            .json(&request)
            .send()
            .await
            .map_err(|_| RemoteDidcommKmsError::OperationFailed)?;
        if !response.status().is_success() {
            return Err(RemoteDidcommKmsError::OperationFailed);
        }
        let body: BaoResponse<PackResponse> =
            bounded_json(response, MAX_PACK_RESPONSE_BYTES).await?;
        if body.data.version != reference.version()
            || body.data.sender_key_id != sender_key_id
            || body.data.jwe.is_empty()
            || body.data.jwe.len() > MAX_JWE_BYTES
        {
            return Err(RemoteDidcommKmsError::BindingMismatch);
        }
        let jwe: serde_json::Value = serde_json::from_str(&body.data.jwe)
            .map_err(|_| RemoteDidcommKmsError::BindingMismatch)?;
        let protected = jwe
            .get("protected")
            .and_then(serde_json::Value::as_str)
            .filter(|value| value.len() <= 8192)
            .ok_or(RemoteDidcommKmsError::BindingMismatch)?;
        let protected = URL_SAFE_NO_PAD
            .decode(protected)
            .map_err(|_| RemoteDidcommKmsError::BindingMismatch)?;
        let protected: serde_json::Value = serde_json::from_slice(&protected)
            .map_err(|_| RemoteDidcommKmsError::BindingMismatch)?;
        if protected["alg"] != marty_signing_grant::didcomm::ALGORITHM
            || protected["skid"] != sender_key_id
        {
            return Err(RemoteDidcommKmsError::BindingMismatch);
        }
        Ok(body.data.jwe)
    }
}

#[cfg(test)]
mod tests {
    use super::{DidcommKeyReference, RemoteDidcommKms};

    #[test]
    fn reference_requires_exact_tenant_name_and_opaque_version() {
        let valid = "didcomm/keys/organization-1/sender/versions/0123456789abcdef0123456789abcdef";
        let reference = DidcommKeyReference::parse(valid).unwrap();
        assert_eq!(reference.tenant(), "organization-1");
        assert_eq!(reference.version(), "0123456789abcdef0123456789abcdef");
        for invalid in [
            "didcomm/keys/../sender/versions/0123456789abcdef0123456789abcdef",
            "didcomm/keys/org/sender/versions/1",
            "didcomm/keys/org/sender/versions/0123456789ABCDEF0123456789ABCDEF",
            "didcomm/keys/org/sender/versions/0123456789abcdef0123456789abcdef/extra",
            "transit/keys/org/sender/versions/0123456789abcdef0123456789abcdef",
        ] {
            assert!(DidcommKeyReference::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn kms_url_requires_https_origin_and_rejects_invalid_ca() {
        let token_file = std::path::PathBuf::from("/not-read-in-constructor");
        for url in [
            "http://openbao:8200",
            "http://user:password@localhost:8200",
            "https://example.org/other/path",
            "https://example.org/?query=1",
            "file:///tmp/openbao",
        ] {
            assert!(RemoteDidcommKms::new(url, token_file.clone(), None).is_err());
        }
        assert!(RemoteDidcommKms::new("https://openbao:8200", token_file.clone(), None).is_ok());
        assert!(RemoteDidcommKms::new(
            "https://openbao:8200",
            token_file,
            Some(std::path::PathBuf::from("/missing-openbao-ca")),
        )
        .is_err());
    }
}
