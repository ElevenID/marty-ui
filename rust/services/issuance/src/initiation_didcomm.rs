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

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_didcomm::{
    encrypt_for_recipient, encrypt_for_recipient_authenticated, pack_credential_for_holder,
    unpack_didcomm_message, DidDocument, DidResolver,
};
use reqwest::{redirect::Policy, Certificate, Client, Url};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::json;
use thiserror::Error;

use crate::{
    credential::{
        apply_issuer_context, didcomm_format_policy, materialize_credential,
        reserved_credential_id, CredentialBuilder, CredentialIssuanceError, CredentialLifecycle,
        CredentialMaterializationContext, CredentialTransaction, CredentialTransactionStatus,
        IssuedCredential, IssuerContextResolver, VerifiedCredentialProof,
    },
    initiation_response::{
        InitiationDidcommDelivery, InitiationDidcommDeliveryError, InitiationDidcommDeliveryReceipt,
    },
    network_policy::is_public_ip,
};

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

#[derive(Clone, Debug)]
pub struct InitiationDidcommClaim {
    pub transaction: CredentialTransaction,
    pub previous_status: CredentialTransactionStatus,
}

#[derive(Clone, Eq, PartialEq)]
pub struct StagedInitiationDidcommDelivery {
    pub holder_did: String,
    pub service_endpoint: String,
    pub message_id: String,
    pub encrypted_message: String,
}

impl fmt::Debug for StagedInitiationDidcommDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedInitiationDidcommDelivery")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq)]
pub struct PendingInitiationDidcommDelivery {
    pub transaction: CredentialTransaction,
    pub credential: IssuedCredential,
    pub delivery: StagedInitiationDidcommDelivery,
    pub transported: bool,
}

impl fmt::Debug for PendingInitiationDidcommDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingInitiationDidcommDelivery")
            .field("transported", &self.transported)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeliveredInitiationDidcommDelivery {
    pub transaction_id: String,
    pub organization_id: String,
    pub credential_id: String,
    pub holder_did: String,
    pub service_endpoint: String,
    pub message_id: String,
}

impl fmt::Debug for DeliveredInitiationDidcommDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveredInitiationDidcommDelivery")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq)]
pub enum InitiationDidcommDeliveryState {
    Pending(Box<PendingInitiationDidcommDelivery>),
    Delivered(DeliveredInitiationDidcommDelivery),
}

impl fmt::Debug for InitiationDidcommDeliveryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending(_) => formatter.write_str("InitiationDidcommDeliveryState::Pending(..)"),
            Self::Delivered(_) => {
                formatter.write_str("InitiationDidcommDeliveryState::Delivered(..)")
            }
        }
    }
}

#[async_trait]
pub trait InitiationDidcommRepository: Send + Sync {
    async fn pending_delivery(
        &self,
        organization_id: &str,
        transaction_id: &str,
    ) -> Result<Option<PendingInitiationDidcommDelivery>, CredentialIssuanceError>;

    async fn delivery_state(
        &self,
        organization_id: &str,
        transaction_id: &str,
    ) -> Result<Option<InitiationDidcommDeliveryState>, CredentialIssuanceError> {
        self.pending_delivery(organization_id, transaction_id)
            .await
            .map(|pending| {
                pending.map(|pending| InitiationDidcommDeliveryState::Pending(Box::new(pending)))
            })
    }

    async fn transaction_for_delivery(
        &self,
        organization_id: &str,
        transaction_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError>;

    async fn claim_retryably(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
    ) -> Result<Option<InitiationDidcommClaim>, CredentialIssuanceError>;

    async fn release_retryably(
        &self,
        claim: &InitiationDidcommClaim,
    ) -> Result<(), CredentialIssuanceError>;

    async fn finalize_delivered(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError>;

    async fn stage_delivery(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        delivery: &StagedInitiationDidcommDelivery,
    ) -> Result<(), CredentialIssuanceError>;

    async fn mark_transport_delivered(
        &self,
        transaction_id: &str,
        message_id: &str,
    ) -> Result<(), CredentialIssuanceError>;

    async fn mark_transport_failed(
        &self,
        transaction_id: &str,
        message_id: &str,
    ) -> Result<(), CredentialIssuanceError>;
}

#[async_trait]
pub trait DidcommEnvelopePort: Send + Sync {
    async fn resolve_recipient(
        &self,
        holder_did: &str,
    ) -> Result<ResolvedDidcommRecipient, NativeDidcommError>;

    async fn prepare_encryption(
        &self,
        issuer_did: &str,
        recipient_document: DidDocument,
    ) -> Result<PreparedDidcommEncryption, NativeDidcommError>;

    fn pack_credential(
        &self,
        credential: &str,
        credential_format: &str,
        issuer_did: &str,
        holder_did: &str,
        transaction_id: &str,
        credential_id: &str,
    ) -> Result<PackedDidcommCredential, NativeDidcommError>;

    fn encrypt_prepared(
        &self,
        plaintext: &str,
        prepared: &PreparedDidcommEncryption,
    ) -> Result<String, NativeDidcommError>;
}

#[async_trait]
pub trait DidcommEndpointPort: Send + Sync {
    async fn validate(
        &self,
        endpoint: &str,
    ) -> Result<ValidatedDidcommEndpoint, NativeDidcommError>;
}

#[async_trait]
pub trait DidcommTransportPort: Send + Sync {
    async fn deliver(
        &self,
        endpoint: &ValidatedDidcommEndpoint,
        encrypted_message: String,
    ) -> DidcommTransportOutcome;
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

#[async_trait]
impl DidcommEnvelopePort for NativeDidcommEnvelope {
    async fn resolve_recipient(
        &self,
        holder_did: &str,
    ) -> Result<ResolvedDidcommRecipient, NativeDidcommError> {
        NativeDidcommEnvelope::resolve_recipient(self, holder_did).await
    }

    async fn prepare_encryption(
        &self,
        issuer_did: &str,
        recipient_document: DidDocument,
    ) -> Result<PreparedDidcommEncryption, NativeDidcommError> {
        NativeDidcommEnvelope::prepare_encryption(self, issuer_did, recipient_document).await
    }

    fn pack_credential(
        &self,
        credential: &str,
        credential_format: &str,
        issuer_did: &str,
        holder_did: &str,
        transaction_id: &str,
        credential_id: &str,
    ) -> Result<PackedDidcommCredential, NativeDidcommError> {
        NativeDidcommEnvelope::pack_credential(
            self,
            credential,
            credential_format,
            issuer_did,
            holder_did,
            transaction_id,
            credential_id,
        )
    }

    fn encrypt_prepared(
        &self,
        plaintext: &str,
        prepared: &PreparedDidcommEncryption,
    ) -> Result<String, NativeDidcommError> {
        NativeDidcommEnvelope::encrypt_prepared(self, plaintext, prepared)
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

#[async_trait]
impl DidcommEndpointPort for DidcommEndpointValidator {
    async fn validate(
        &self,
        endpoint: &str,
    ) -> Result<ValidatedDidcommEndpoint, NativeDidcommError> {
        DidcommEndpointValidator::validate(self, endpoint).await
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

#[async_trait]
impl DidcommTransportPort for DidcommTransport {
    async fn deliver(
        &self,
        endpoint: &ValidatedDidcommEndpoint,
        encrypted_message: String,
    ) -> DidcommTransportOutcome {
        DidcommTransport::deliver(self, endpoint, encrypted_message).await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidcommTransportOutcome {
    Delivered,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NativeInitiationDidcommDeliveryError {
    #[error("DIDComm delivery is misconfigured")]
    InvalidConfiguration,
    #[error("DIDComm delivery request is invalid")]
    InvalidRequest,
    #[error("issuance transaction was not found")]
    TransactionNotFound,
    #[error("issuance transaction is not retryable for DIDComm delivery")]
    InvalidTransactionState,
    #[error("DIDComm delivery prerequisites are unavailable")]
    DidcommUnavailable,
    #[error("credential materialization is unavailable")]
    CredentialUnavailable,
    #[error("another delivery attempt owns the issuance transaction")]
    ConcurrentDelivery,
    #[error("DIDComm transport failed")]
    TransportFailed,
    #[error("DIDComm post-issuance projection is unavailable")]
    PostIssuanceUnavailable,
    #[error("DIDComm retry state could not be restored")]
    RetryStateUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeDidcommDeliveryStatus {
    Delivered,
    DeliveryFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeInitiationDidcommDeliveryReceipt {
    pub transaction_id: String,
    pub credential_id: String,
    pub holder_did: String,
    pub service_endpoint: String,
    pub didcomm_message_id: String,
    pub status: NativeDidcommDeliveryStatus,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct NativeInitiationDidcommPorts {
    pub repository: Arc<dyn InitiationDidcommRepository>,
    pub issuer_resolver: Arc<dyn IssuerContextResolver>,
    pub builder: Arc<dyn CredentialBuilder>,
    pub lifecycle: Arc<dyn CredentialLifecycle>,
    pub envelope: Arc<dyn DidcommEnvelopePort>,
    pub endpoints: Arc<dyn DidcommEndpointPort>,
    pub transport: Arc<dyn DidcommTransportPort>,
}

impl fmt::Debug for NativeInitiationDidcommPorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeInitiationDidcommPorts")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct NativeInitiationDidcommDelivery {
    ports: NativeInitiationDidcommPorts,
    issuer_base_url: Arc<str>,
}

impl fmt::Debug for NativeInitiationDidcommDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeInitiationDidcommDelivery")
            .field("issuer_base_url", &self.issuer_base_url)
            .finish_non_exhaustive()
    }
}

impl NativeInitiationDidcommDelivery {
    pub fn new(
        ports: NativeInitiationDidcommPorts,
        issuer_base_url: &str,
    ) -> Result<Self, NativeInitiationDidcommDeliveryError> {
        let issuer_base_url = issuer_base_url.trim_end_matches('/');
        if issuer_base_url.is_empty() {
            return Err(NativeInitiationDidcommDeliveryError::InvalidConfiguration);
        }
        Ok(Self {
            ports,
            issuer_base_url: Arc::from(issuer_base_url),
        })
    }

    pub async fn deliver_for_organization(
        &self,
        organization_id: &str,
        transaction_id: &str,
        holder_did: &str,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, NativeInitiationDidcommDeliveryError> {
        let organization_id = organization_id.trim();
        let transaction_id = transaction_id.trim();
        let holder_did = holder_did.trim();
        if organization_id.is_empty()
            || transaction_id.is_empty()
            || !holder_did.starts_with("did:")
            || holder_did.len() <= "did:".len()
        {
            return Err(NativeInitiationDidcommDeliveryError::InvalidRequest);
        }
        let transaction = self
            .ports
            .repository
            .transaction_for_delivery(organization_id, transaction_id)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::CredentialUnavailable)?
            .ok_or(NativeInitiationDidcommDeliveryError::TransactionNotFound)?;
        self.deliver_native(&transaction, holder_did).await
    }

    pub async fn deliver_native(
        &self,
        transaction: &CredentialTransaction,
        holder_did: &str,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, NativeInitiationDidcommDeliveryError> {
        if let Some(delivery_state) = self
            .ports
            .repository
            .delivery_state(&transaction.organization_id, &transaction.id)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::CredentialUnavailable)?
        {
            match delivery_state {
                InitiationDidcommDeliveryState::Delivered(delivered) => {
                    Self::validate_terminal_delivery(transaction, holder_did, &delivered)?;
                    return Ok(Self::terminal_receipt(delivered));
                }
                InitiationDidcommDeliveryState::Pending(pending) => {
                    if pending.delivery.holder_did != holder_did {
                        return Err(NativeInitiationDidcommDeliveryError::InvalidRequest);
                    }
                    let endpoint = self
                        .ports
                        .endpoints
                        .validate(&pending.delivery.service_endpoint)
                        .await
                        .map_err(|_| NativeInitiationDidcommDeliveryError::DidcommUnavailable)?;
                    return self.deliver_staged(*pending, endpoint).await;
                }
            }
        }
        if !matches!(
            transaction.status,
            CredentialTransactionStatus::Pending | CredentialTransactionStatus::Authorized
        ) {
            return Err(NativeInitiationDidcommDeliveryError::InvalidTransactionState);
        }
        let policy = didcomm_format_policy(transaction)
            .map_err(|_| NativeInitiationDidcommDeliveryError::CredentialUnavailable)?;
        let recipient = self
            .ports
            .envelope
            .resolve_recipient(holder_did)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::DidcommUnavailable)?;
        let endpoint = self
            .ports
            .endpoints
            .validate(&recipient.endpoint)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::DidcommUnavailable)?;

        let mut prepared_transaction = transaction.clone();
        let initial_issuer = self
            .ports
            .issuer_resolver
            .resolve(&prepared_transaction, &policy.remote_format, false)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::CredentialUnavailable)?;
        apply_issuer_context(&mut prepared_transaction, &initial_issuer);
        let issuer = self
            .ports
            .issuer_resolver
            .resolve(&prepared_transaction, &policy.remote_format, true)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::CredentialUnavailable)?;
        apply_issuer_context(&mut prepared_transaction, &issuer);
        self.ports
            .lifecycle
            .ensure_ready(&prepared_transaction, &issuer)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::CredentialUnavailable)?;
        let prepared_encryption = self
            .ports
            .envelope
            .prepare_encryption(&issuer.issuer_did, recipient.document)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::DidcommUnavailable)?;

        let credential_id = reserved_credential_id(&prepared_transaction);
        let claim = self
            .ports
            .repository
            .claim_retryably(&prepared_transaction, &credential_id)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::CredentialUnavailable)?
            .ok_or(NativeInitiationDidcommDeliveryError::ConcurrentDelivery)?;
        let issued = match materialize_credential(
            CredentialMaterializationContext {
                builder: self.ports.builder.as_ref(),
                lifecycle: self.ports.lifecycle.as_ref(),
                issuer_base_url: &self.issuer_base_url,
            },
            &claim.transaction,
            &credential_id,
            &policy,
            issuer,
            VerifiedCredentialProof {
                holder_did: holder_did.to_owned(),
                holder_jwk: None,
            },
        )
        .await
        {
            Ok(issued) => issued,
            Err(_) => {
                return self
                    .release_failure(
                        &claim,
                        NativeInitiationDidcommDeliveryError::CredentialUnavailable,
                    )
                    .await
            }
        };
        let packed = match self.ports.envelope.pack_credential(
            &issued.credential,
            &claim.transaction.credential_payload_format,
            &issued.issuer_did,
            holder_did,
            &claim.transaction.id,
            &credential_id,
        ) {
            Ok(packed) => packed,
            Err(_) => {
                return self
                    .release_failure(
                        &claim,
                        NativeInitiationDidcommDeliveryError::DidcommUnavailable,
                    )
                    .await
            }
        };
        let encrypted = match self
            .ports
            .envelope
            .encrypt_prepared(&packed.plaintext, &prepared_encryption)
        {
            Ok(encrypted) => encrypted,
            Err(_) => {
                return self
                    .release_failure(
                        &claim,
                        NativeInitiationDidcommDeliveryError::DidcommUnavailable,
                    )
                    .await
            }
        };
        let delivery = StagedInitiationDidcommDelivery {
            holder_did: holder_did.to_owned(),
            service_endpoint: endpoint.as_str().to_owned(),
            message_id: packed.message_id,
            encrypted_message: encrypted,
        };
        if self
            .ports
            .repository
            .stage_delivery(&claim.transaction, &issued, &delivery)
            .await
            .is_err()
        {
            return self
                .release_failure(
                    &claim,
                    NativeInitiationDidcommDeliveryError::CredentialUnavailable,
                )
                .await;
        }
        self.deliver_staged(
            PendingInitiationDidcommDelivery {
                transaction: claim.transaction,
                credential: issued,
                delivery,
                transported: false,
            },
            endpoint,
        )
        .await
    }

    async fn deliver_staged(
        &self,
        pending: PendingInitiationDidcommDelivery,
        endpoint: ValidatedDidcommEndpoint,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, NativeInitiationDidcommDeliveryError> {
        if !pending.transported {
            if self
                .ports
                .transport
                .deliver(&endpoint, pending.delivery.encrypted_message.clone())
                .await
                != DidcommTransportOutcome::Delivered
            {
                self.ports
                    .repository
                    .mark_transport_failed(&pending.transaction.id, &pending.delivery.message_id)
                    .await
                    .map_err(|_| NativeInitiationDidcommDeliveryError::RetryStateUnavailable)?;
                return Ok(NativeInitiationDidcommDeliveryReceipt {
                    transaction_id: pending.transaction.id,
                    credential_id: pending.credential.id,
                    holder_did: pending.delivery.holder_did,
                    service_endpoint: pending.delivery.service_endpoint,
                    didcomm_message_id: pending.delivery.message_id,
                    status: NativeDidcommDeliveryStatus::DeliveryFailed,
                    error: Some("didcomm_delivery_failed".to_owned()),
                });
            }
            self.ports
                .repository
                .mark_transport_delivered(&pending.transaction.id, &pending.delivery.message_id)
                .await
                .map_err(|_| NativeInitiationDidcommDeliveryError::RetryStateUnavailable)?;
        }
        self.ports
            .lifecycle
            .after_didcomm_issued(
                &pending.transaction,
                &pending.credential,
                &pending.delivery.service_endpoint,
                &pending.delivery.message_id,
            )
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::PostIssuanceUnavailable)?;
        Ok(Self::delivered_receipt(pending))
    }

    fn delivered_receipt(
        pending: PendingInitiationDidcommDelivery,
    ) -> NativeInitiationDidcommDeliveryReceipt {
        NativeInitiationDidcommDeliveryReceipt {
            transaction_id: pending.transaction.id,
            credential_id: pending.credential.id,
            holder_did: pending.delivery.holder_did,
            service_endpoint: pending.delivery.service_endpoint,
            didcomm_message_id: pending.delivery.message_id,
            status: NativeDidcommDeliveryStatus::Delivered,
            error: None,
        }
    }

    fn terminal_receipt(
        delivered: DeliveredInitiationDidcommDelivery,
    ) -> NativeInitiationDidcommDeliveryReceipt {
        NativeInitiationDidcommDeliveryReceipt {
            transaction_id: delivered.transaction_id,
            credential_id: delivered.credential_id,
            holder_did: delivered.holder_did,
            service_endpoint: delivered.service_endpoint,
            didcomm_message_id: delivered.message_id,
            status: NativeDidcommDeliveryStatus::Delivered,
            error: None,
        }
    }

    fn validate_terminal_delivery(
        transaction: &CredentialTransaction,
        holder_did: &str,
        delivered: &DeliveredInitiationDidcommDelivery,
    ) -> Result<(), NativeInitiationDidcommDeliveryError> {
        let required = [
            delivered.credential_id.as_str(),
            delivered.holder_did.as_str(),
            delivered.service_endpoint.as_str(),
            delivered.message_id.as_str(),
        ];
        if required.iter().any(|value| value.trim().is_empty())
            || delivered.transaction_id != transaction.id
            || delivered.organization_id != transaction.organization_id
            || delivered.credential_id != reserved_credential_id(transaction)
            || delivered.holder_did != holder_did
        {
            return Err(NativeInitiationDidcommDeliveryError::InvalidRequest);
        }
        Ok(())
    }

    async fn release_failure<T>(
        &self,
        claim: &InitiationDidcommClaim,
        error: NativeInitiationDidcommDeliveryError,
    ) -> Result<T, NativeInitiationDidcommDeliveryError> {
        self.ports
            .repository
            .release_retryably(claim)
            .await
            .map_err(|_| NativeInitiationDidcommDeliveryError::RetryStateUnavailable)?;
        Err(error)
    }
}

#[async_trait]
impl InitiationDidcommDelivery for NativeInitiationDidcommDelivery {
    async fn deliver(
        &self,
        transaction: &CredentialTransaction,
        holder_did: &str,
    ) -> Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError> {
        match self.deliver_native(transaction, holder_did).await {
            Ok(receipt) if receipt.status == NativeDidcommDeliveryStatus::Delivered => {
                Ok(InitiationDidcommDeliveryReceipt {
                    service_endpoint: receipt.service_endpoint,
                })
            }
            Ok(_) | Err(_) => Err(InitiationDidcommDeliveryError),
        }
    }
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
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    use crate::credential::{
        AllocatedCredentialStatus, BuiltCredential, CredentialBuildRequest, CredentialBuilder,
        CredentialLifecycle, IssuerContext,
    };
    use chrono::{TimeZone, Utc};
    use marty_didcomm::types::{Jwk, VerificationMethod};
    use serde_json::Map;

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

    type Order = Arc<Mutex<Vec<&'static str>>>;

    fn record(order: &Order, stage: &'static str) {
        order.lock().unwrap().push(stage);
    }

    fn transaction() -> CredentialTransaction {
        CredentialTransaction {
            id: "transaction-1".to_owned(),
            organization_id: "org-a".to_owned(),
            credential_template_id: "template-a".to_owned(),
            revocation_profile_id: Some("profile-a".to_owned()),
            renewal_of_credential_id: None,
            applicant_id: None,
            application_id: None,
            subject_did: None,
            idempotency_key_hash: None,
            idempotency_request_hash: None,
            status: CredentialTransactionStatus::Pending,
            pre_authorized_code: "pre-auth".to_owned(),
            nonce: None,
            claims: Map::from_iter([("given_name".to_owned(), json!("Alice"))]),
            credential_type: Some("EmployeeCredential".to_owned()),
            selective_disclosure_claims: Vec::new(),
            zk_predicate_claims: Vec::new(),
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
            wallet_configs: Vec::new(),
            validity_days: 365,
            renewable: false,
            renewal_window_days: 30,
            delivery_mode: "wallet_only".to_owned(),
            issuer_profile_id: Some("issuer-profile-a".to_owned()),
            issuer_mode: "org_managed".to_owned(),
            issuer_did: Some("did:example:issuer".to_owned()),
            issuer_algorithm: Some("ES256".to_owned()),
            signing_service_id: None,
            reserved_credential_id: None,
            oid4vci_client_id: None,
            created_at: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
            expires_at: Utc.timestamp_opt(1_700_003_600, 0).single().unwrap(),
        }
    }

    fn issuer() -> IssuerContext {
        IssuerContext {
            issuer_profile_id: "issuer-profile-a".to_owned(),
            issuer_did: "did:example:issuer".to_owned(),
            signing_service_id: "signing-service-a".to_owned(),
            algorithm: "ES256".to_owned(),
            verification_method_id: Some("did:example:issuer#key-1".to_owned()),
            public_jwk: None,
            certificate_chain: Vec::new(),
            raw_context: json!({}),
        }
    }

    fn issued_credential(
        transaction: &CredentialTransaction,
        credential: &str,
    ) -> IssuedCredential {
        IssuedCredential {
            id: reserved_credential_id(transaction),
            transaction_id: transaction.id.clone(),
            organization_id: transaction.organization_id.clone(),
            credential_template_id: transaction.credential_template_id.clone(),
            applicant_id: transaction.applicant_id.clone(),
            subject_did: transaction.subject_did.clone(),
            issuer_did: "did:example:issuer".to_owned(),
            revocation_profile_id: transaction.revocation_profile_id.clone(),
            renewed_from_credential_id: None,
            status_list_entries: Vec::new(),
            credential: credential.to_owned(),
            credential_hash: "credential-hash".to_owned(),
            issued_at: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
            expires_at: Utc.timestamp_opt(1_731_536_000, 0).single().unwrap(),
        }
    }

    struct HarnessRepository {
        order: Order,
        lookups: AtomicUsize,
        releases: AtomicUsize,
        finalizations: AtomicUsize,
        delivery: Arc<Mutex<Option<InitiationDidcommDeliveryState>>>,
    }

    impl HarnessRepository {
        fn new(order: Order) -> Self {
            Self {
                order,
                lookups: AtomicUsize::new(0),
                releases: AtomicUsize::new(0),
                finalizations: AtomicUsize::new(0),
                delivery: Arc::new(Mutex::new(None)),
            }
        }
    }

    #[async_trait]
    impl InitiationDidcommRepository for HarnessRepository {
        async fn pending_delivery(
            &self,
            organization_id: &str,
            transaction_id: &str,
        ) -> Result<Option<PendingInitiationDidcommDelivery>, CredentialIssuanceError> {
            self.delivery_state(organization_id, transaction_id)
                .await
                .map(|state| match state {
                    Some(InitiationDidcommDeliveryState::Pending(pending)) => Some(*pending),
                    Some(InitiationDidcommDeliveryState::Delivered(_)) | None => None,
                })
        }

        async fn delivery_state(
            &self,
            _organization_id: &str,
            _transaction_id: &str,
        ) -> Result<Option<InitiationDidcommDeliveryState>, CredentialIssuanceError> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            Ok(self.delivery.lock().unwrap().clone())
        }

        async fn transaction_for_delivery(
            &self,
            organization_id: &str,
            transaction_id: &str,
        ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
            record(&self.order, "load-transaction");
            let transaction = transaction();
            Ok(
                (transaction.organization_id == organization_id
                    && transaction.id == transaction_id)
                    .then_some(transaction),
            )
        }

        async fn claim_retryably(
            &self,
            transaction: &CredentialTransaction,
            credential_id: &str,
        ) -> Result<Option<InitiationDidcommClaim>, CredentialIssuanceError> {
            record(&self.order, "claim");
            let mut claimed = transaction.clone();
            claimed.status = CredentialTransactionStatus::Signing;
            claimed.reserved_credential_id = Some(credential_id.to_owned());
            Ok(Some(InitiationDidcommClaim {
                transaction: claimed,
                previous_status: transaction.status,
            }))
        }

        async fn release_retryably(
            &self,
            claim: &InitiationDidcommClaim,
        ) -> Result<(), CredentialIssuanceError> {
            record(&self.order, "release");
            assert_eq!(
                claim.transaction.status,
                CredentialTransactionStatus::Signing
            );
            assert!(matches!(
                claim.previous_status,
                CredentialTransactionStatus::Pending | CredentialTransactionStatus::Authorized
            ));
            self.releases.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn finalize_delivered(
            &self,
            transaction: &CredentialTransaction,
            credential: &IssuedCredential,
        ) -> Result<(), CredentialIssuanceError> {
            record(&self.order, "finalize");
            assert_eq!(transaction.status, CredentialTransactionStatus::Signing);
            assert_eq!(
                transaction.reserved_credential_id.as_deref(),
                Some(credential.id.as_str())
            );
            self.finalizations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn stage_delivery(
            &self,
            transaction: &CredentialTransaction,
            credential: &IssuedCredential,
            delivery: &StagedInitiationDidcommDelivery,
        ) -> Result<(), CredentialIssuanceError> {
            self.finalize_delivered(transaction, credential).await?;
            let mut finalized = transaction.clone();
            finalized.status = CredentialTransactionStatus::Issued;
            *self.delivery.lock().unwrap() = Some(InitiationDidcommDeliveryState::Pending(
                Box::new(PendingInitiationDidcommDelivery {
                    transaction: finalized,
                    credential: credential.clone(),
                    delivery: delivery.clone(),
                    transported: false,
                }),
            ));
            Ok(())
        }

        async fn mark_transport_delivered(
            &self,
            transaction_id: &str,
            message_id: &str,
        ) -> Result<(), CredentialIssuanceError> {
            record(&self.order, "mark-transported");
            let mut delivery = self.delivery.lock().unwrap();
            let Some(InitiationDidcommDeliveryState::Pending(pending)) = delivery.as_mut() else {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
            };
            if pending.transaction.id != transaction_id || pending.delivery.message_id != message_id
            {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
            }
            pending.transported = true;
            Ok(())
        }

        async fn mark_transport_failed(
            &self,
            transaction_id: &str,
            message_id: &str,
        ) -> Result<(), CredentialIssuanceError> {
            record(&self.order, "mark-transport-failed");
            let delivery = self.delivery.lock().unwrap();
            let Some(InitiationDidcommDeliveryState::Pending(pending)) = delivery.as_ref() else {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
            };
            if pending.transaction.id != transaction_id || pending.delivery.message_id != message_id
            {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
            }
            Ok(())
        }
    }

    struct HarnessIssuerResolver {
        order: Order,
    }

    #[async_trait]
    impl IssuerContextResolver for HarnessIssuerResolver {
        async fn resolve(
            &self,
            _transaction: &CredentialTransaction,
            _credential_format: &str,
            _force: bool,
        ) -> Result<IssuerContext, CredentialIssuanceError> {
            record(&self.order, "resolve-issuer");
            Ok(issuer())
        }
    }

    struct HarnessBuilder {
        order: Order,
        fail: bool,
    }

    #[async_trait]
    impl CredentialBuilder for HarnessBuilder {
        async fn build(
            &self,
            request: &CredentialBuildRequest,
        ) -> Result<BuiltCredential, CredentialIssuanceError> {
            record(&self.order, "build");
            if self.fail {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
            }
            Ok(BuiltCredential {
                credential_id: request.credential_id.clone(),
                credential: "signed-credential".to_owned(),
            })
        }
    }

    struct HarnessLifecycle {
        order: Order,
        post_issuance_fail: bool,
        delivery: Arc<Mutex<Option<InitiationDidcommDeliveryState>>>,
    }

    #[async_trait]
    impl CredentialLifecycle for HarnessLifecycle {
        async fn ensure_ready(
            &self,
            _transaction: &CredentialTransaction,
            _issuer: &IssuerContext,
        ) -> Result<(), CredentialIssuanceError> {
            record(&self.order, "ensure-ready");
            Ok(())
        }

        async fn allocate_status(
            &self,
            _transaction: &CredentialTransaction,
            _credential_id: &str,
            _credential_format: &str,
        ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
            record(&self.order, "allocate-status");
            Ok(AllocatedCredentialStatus::default())
        }

        async fn after_issued(
            &self,
            _transaction: &CredentialTransaction,
            _credential: &IssuedCredential,
            _response_format: &str,
        ) -> Result<(), CredentialIssuanceError> {
            panic!("OID4VCI lifecycle must not project a DIDComm delivery")
        }

        async fn after_didcomm_issued(
            &self,
            _transaction: &CredentialTransaction,
            _credential: &IssuedCredential,
            service_endpoint: &str,
            message_id: &str,
        ) -> Result<(), CredentialIssuanceError> {
            record(&self.order, "after-didcomm");
            assert_eq!(service_endpoint, "https://wallet.example/inbox");
            assert_eq!(message_id, "message-1");
            if self.post_issuance_fail {
                Err(CredentialIssuanceError::RepositoryUnavailable)
            } else {
                let mut delivery = self.delivery.lock().unwrap();
                let Some(InitiationDidcommDeliveryState::Pending(pending)) = delivery.as_ref()
                else {
                    return Err(CredentialIssuanceError::RepositoryUnavailable);
                };
                *delivery = Some(InitiationDidcommDeliveryState::Delivered(
                    DeliveredInitiationDidcommDelivery {
                        transaction_id: pending.transaction.id.clone(),
                        organization_id: pending.transaction.organization_id.clone(),
                        credential_id: pending.credential.id.clone(),
                        holder_did: pending.delivery.holder_did.clone(),
                        service_endpoint: service_endpoint.to_owned(),
                        message_id: message_id.to_owned(),
                    },
                ));
                Ok(())
            }
        }
    }

    struct HarnessEnvelope {
        order: Order,
    }

    #[async_trait]
    impl DidcommEnvelopePort for HarnessEnvelope {
        async fn resolve_recipient(
            &self,
            _holder_did: &str,
        ) -> Result<ResolvedDidcommRecipient, NativeDidcommError> {
            record(&self.order, "resolve-recipient");
            Ok(ResolvedDidcommRecipient {
                document: recipient_document(),
                endpoint: "https://wallet.example/inbox".to_owned(),
            })
        }

        async fn prepare_encryption(
            &self,
            _issuer_did: &str,
            recipient_document: DidDocument,
        ) -> Result<PreparedDidcommEncryption, NativeDidcommError> {
            record(&self.order, "prepare-encryption");
            Ok(PreparedDidcommEncryption {
                issuer_did: "did:example:issuer".to_owned(),
                recipient_document,
                mode: PreparedEncryptionMode::Anoncrypt,
            })
        }

        fn pack_credential(
            &self,
            credential: &str,
            _credential_format: &str,
            _issuer_did: &str,
            _holder_did: &str,
            _transaction_id: &str,
            _credential_id: &str,
        ) -> Result<PackedDidcommCredential, NativeDidcommError> {
            record(&self.order, "pack");
            assert_eq!(credential, "signed-credential");
            Ok(PackedDidcommCredential {
                plaintext: "packed-credential".to_owned(),
                message_id: "message-1".to_owned(),
            })
        }

        fn encrypt_prepared(
            &self,
            plaintext: &str,
            _prepared: &PreparedDidcommEncryption,
        ) -> Result<String, NativeDidcommError> {
            record(&self.order, "encrypt");
            assert_eq!(plaintext, "packed-credential");
            Ok("encrypted-credential".to_owned())
        }
    }

    struct HarnessEndpoint {
        order: Order,
        fail: bool,
    }

    #[async_trait]
    impl DidcommEndpointPort for HarnessEndpoint {
        async fn validate(
            &self,
            endpoint: &str,
        ) -> Result<ValidatedDidcommEndpoint, NativeDidcommError> {
            record(&self.order, "validate-endpoint");
            if self.fail {
                return Err(NativeDidcommError::EndpointNotPublic);
            }
            Ok(ValidatedDidcommEndpoint {
                original: endpoint.to_owned(),
                url: Url::parse(endpoint).unwrap(),
                hostname: "wallet.example".to_owned(),
                addresses: vec!["1.1.1.1:443".parse().unwrap()],
            })
        }
    }

    struct HarnessTransport {
        order: Order,
        outcome: DidcommTransportOutcome,
    }

    #[async_trait]
    impl DidcommTransportPort for HarnessTransport {
        async fn deliver(
            &self,
            _endpoint: &ValidatedDidcommEndpoint,
            encrypted_message: String,
        ) -> DidcommTransportOutcome {
            record(&self.order, "transport");
            assert_eq!(encrypted_message, "encrypted-credential");
            self.outcome
        }
    }

    struct HarnessOptions {
        endpoint_fail: bool,
        builder_fail: bool,
        transport_outcome: DidcommTransportOutcome,
        post_issuance_fail: bool,
    }

    fn delivery_harness(
        options: HarnessOptions,
    ) -> (
        NativeInitiationDidcommDelivery,
        Arc<HarnessRepository>,
        Order,
    ) {
        let order = Arc::new(Mutex::new(Vec::new()));
        let repository = Arc::new(HarnessRepository::new(order.clone()));
        let delivery = NativeInitiationDidcommDelivery::new(
            NativeInitiationDidcommPorts {
                repository: repository.clone(),
                issuer_resolver: Arc::new(HarnessIssuerResolver {
                    order: order.clone(),
                }),
                builder: Arc::new(HarnessBuilder {
                    order: order.clone(),
                    fail: options.builder_fail,
                }),
                lifecycle: Arc::new(HarnessLifecycle {
                    order: order.clone(),
                    post_issuance_fail: options.post_issuance_fail,
                    delivery: repository.delivery.clone(),
                }),
                envelope: Arc::new(HarnessEnvelope {
                    order: order.clone(),
                }),
                endpoints: Arc::new(HarnessEndpoint {
                    order: order.clone(),
                    fail: options.endpoint_fail,
                }),
                transport: Arc::new(HarnessTransport {
                    order: order.clone(),
                    outcome: options.transport_outcome,
                }),
            },
            "https://issuer.example",
        )
        .unwrap();
        (delivery, repository, order)
    }

    #[tokio::test]
    async fn delivery_orders_irreversible_work_after_security_preflight() {
        let (delivery, repository, order) = delivery_harness(HarnessOptions {
            endpoint_fail: false,
            builder_fail: false,
            transport_outcome: DidcommTransportOutcome::Delivered,
            post_issuance_fail: false,
        });
        let receipt = delivery
            .deliver_native(&transaction(), "did:example:holder")
            .await
            .unwrap();

        assert_eq!(receipt.transaction_id, "transaction-1");
        assert_eq!(
            receipt.credential_id,
            reserved_credential_id(&transaction())
        );
        assert_eq!(receipt.holder_did, "did:example:holder");
        assert_eq!(receipt.service_endpoint, "https://wallet.example/inbox");
        assert_eq!(receipt.didcomm_message_id, "message-1");
        assert_eq!(receipt.status, NativeDidcommDeliveryStatus::Delivered);
        assert_eq!(receipt.error, None);
        assert_eq!(repository.releases.load(Ordering::SeqCst), 0);
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);
        assert_eq!(
            *order.lock().unwrap(),
            [
                "resolve-recipient",
                "validate-endpoint",
                "resolve-issuer",
                "resolve-issuer",
                "ensure-ready",
                "prepare-encryption",
                "claim",
                "allocate-status",
                "build",
                "pack",
                "encrypt",
                "finalize",
                "transport",
                "mark-transported",
                "after-didcomm",
            ]
        );
    }

    #[tokio::test]
    async fn delivered_retry_returns_the_same_receipt_without_repeating_side_effects() {
        let (delivery, repository, order) = delivery_harness(HarnessOptions {
            endpoint_fail: false,
            builder_fail: false,
            transport_outcome: DidcommTransportOutcome::Delivered,
            post_issuance_fail: false,
        });
        let first = delivery
            .deliver_native(&transaction(), "did:example:holder")
            .await
            .unwrap();
        let first_order = order.lock().unwrap().clone();
        assert_eq!(first.status, NativeDidcommDeliveryStatus::Delivered);
        assert_eq!(
            first_order
                .iter()
                .filter(|stage| **stage == "transport")
                .count(),
            1
        );
        assert_eq!(
            first_order
                .iter()
                .filter(|stage| **stage == "after-didcomm")
                .count(),
            1
        );
        assert_eq!(
            first_order
                .iter()
                .filter(|stage| **stage == "build")
                .count(),
            1
        );
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);

        order.lock().unwrap().clear();
        let lookups_before_retry = repository.lookups.load(Ordering::SeqCst);
        let second = delivery
            .deliver_native(&transaction(), "did:example:holder")
            .await
            .unwrap();
        assert_eq!(second, first);
        assert_eq!(
            repository.lookups.load(Ordering::SeqCst),
            lookups_before_retry + 1
        );
        assert!(
            order.lock().unwrap().is_empty(),
            "a terminal retry must perform only the unrecorded repository lookup"
        );
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);

        let terminal = repository.delivery.lock().unwrap().clone().unwrap();
        let InitiationDidcommDeliveryState::Delivered(terminal) = terminal else {
            panic!("the first delivery must leave terminal state")
        };
        let invalid_terminal_states = [
            (
                "transaction",
                DeliveredInitiationDidcommDelivery {
                    transaction_id: "another-transaction".to_owned(),
                    ..terminal.clone()
                },
            ),
            (
                "organization",
                DeliveredInitiationDidcommDelivery {
                    organization_id: "another-organization".to_owned(),
                    ..terminal.clone()
                },
            ),
            (
                "credential",
                DeliveredInitiationDidcommDelivery {
                    credential_id: "another-credential".to_owned(),
                    ..terminal.clone()
                },
            ),
            (
                "blank credential",
                DeliveredInitiationDidcommDelivery {
                    credential_id: "  ".to_owned(),
                    ..terminal.clone()
                },
            ),
            (
                "blank holder",
                DeliveredInitiationDidcommDelivery {
                    holder_did: "  ".to_owned(),
                    ..terminal.clone()
                },
            ),
            (
                "blank endpoint",
                DeliveredInitiationDidcommDelivery {
                    service_endpoint: "  ".to_owned(),
                    ..terminal.clone()
                },
            ),
            (
                "blank message",
                DeliveredInitiationDidcommDelivery {
                    message_id: "  ".to_owned(),
                    ..terminal.clone()
                },
            ),
        ];
        for (case, invalid) in invalid_terminal_states {
            *repository.delivery.lock().unwrap() =
                Some(InitiationDidcommDeliveryState::Delivered(invalid));
            let lookups_before_mismatch = repository.lookups.load(Ordering::SeqCst);
            assert_eq!(
                delivery
                    .deliver_native(&transaction(), "did:example:holder")
                    .await,
                Err(NativeInitiationDidcommDeliveryError::InvalidRequest),
                "terminal {case} mismatch must fail closed"
            );
            assert_eq!(
                repository.lookups.load(Ordering::SeqCst),
                lookups_before_mismatch + 1
            );
            assert!(order.lock().unwrap().is_empty());
            assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);
        }
        *repository.delivery.lock().unwrap() =
            Some(InitiationDidcommDeliveryState::Delivered(terminal));
        assert_eq!(
            delivery
                .deliver_native(&transaction(), "did:example:other-holder")
                .await,
            Err(NativeInitiationDidcommDeliveryError::InvalidRequest)
        );
        assert!(order.lock().unwrap().is_empty());
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn didcomm_delivery_state_debug_output_is_stable_and_redacted() {
        let secrets = [
            "did:example:holder-debug-sentinel",
            "https://wallet.example/debug-endpoint-sentinel",
            "message-debug-sentinel",
            "ciphertext-debug-sentinel",
            "signed-credential-debug-sentinel",
            "transaction-debug-sentinel",
            "claim-debug-sentinel",
            "organization-debug-sentinel",
            "pre-authorized-code-debug-sentinel",
        ];
        let mut transaction = transaction();
        transaction.id = secrets[5].to_owned();
        transaction.organization_id = secrets[7].to_owned();
        transaction.pre_authorized_code = secrets[8].to_owned();
        transaction.claims = Map::from_iter([("secret_claim".to_owned(), json!(secrets[6]))]);
        let staged = StagedInitiationDidcommDelivery {
            holder_did: secrets[0].to_owned(),
            service_endpoint: secrets[1].to_owned(),
            message_id: secrets[2].to_owned(),
            encrypted_message: secrets[3].to_owned(),
        };
        let delivered = DeliveredInitiationDidcommDelivery {
            transaction_id: secrets[5].to_owned(),
            organization_id: secrets[7].to_owned(),
            credential_id: "credential-debug-sentinel".to_owned(),
            holder_did: secrets[0].to_owned(),
            service_endpoint: secrets[1].to_owned(),
            message_id: secrets[2].to_owned(),
        };
        let pending = PendingInitiationDidcommDelivery {
            credential: issued_credential(&transaction, secrets[4]),
            transaction,
            delivery: staged.clone(),
            transported: true,
        };

        let staged_debug = format!("{staged:?}");
        let pending_debug = format!("{pending:?}");
        let delivered_debug = format!("{delivered:?}");
        let pending_state_debug = format!(
            "{:?}",
            InitiationDidcommDeliveryState::Pending(Box::new(pending.clone()))
        );
        let delivered_state_debug =
            format!("{:?}", InitiationDidcommDeliveryState::Delivered(delivered));
        assert_eq!(staged_debug, "StagedInitiationDidcommDelivery { .. }");
        assert_eq!(
            pending_debug,
            "PendingInitiationDidcommDelivery { transported: true, .. }"
        );
        assert_eq!(delivered_debug, "DeliveredInitiationDidcommDelivery { .. }");
        assert_eq!(
            pending_state_debug,
            "InitiationDidcommDeliveryState::Pending(..)"
        );
        assert_eq!(
            delivered_state_debug,
            "InitiationDidcommDeliveryState::Delivered(..)"
        );
        for secret in secrets {
            assert!(!staged_debug.contains(secret));
            assert!(!pending_debug.contains(secret));
            assert!(!delivered_debug.contains(secret));
            assert!(!pending_state_debug.contains(secret));
            assert!(!delivered_state_debug.contains(secret));
        }
        assert!(!delivered_debug.contains("credential-debug-sentinel"));
        assert!(!pending_state_debug.contains("credential-debug-sentinel"));
        assert!(!delivered_state_debug.contains("credential-debug-sentinel"));
    }

    #[tokio::test]
    async fn direct_delivery_is_exactly_tenant_bound_before_prerequisite_work() {
        let (delivery, repository, order) = delivery_harness(HarnessOptions {
            endpoint_fail: false,
            builder_fail: false,
            transport_outcome: DidcommTransportOutcome::Delivered,
            post_issuance_fail: false,
        });
        assert_eq!(
            delivery
                .deliver_for_organization("org-other", "transaction-1", "did:example:holder")
                .await,
            Err(NativeInitiationDidcommDeliveryError::TransactionNotFound)
        );
        assert_eq!(*order.lock().unwrap(), ["load-transaction"]);
        assert_eq!(repository.releases.load(Ordering::SeqCst), 0);
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 0);

        order.lock().unwrap().clear();
        assert_eq!(
            delivery
                .deliver_for_organization("org-1", "transaction-1", "https://holder.example")
                .await,
            Err(NativeInitiationDidcommDeliveryError::InvalidRequest)
        );
        assert!(order.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn endpoint_rejection_precedes_issuer_status_and_claim_work() {
        let (delivery, repository, order) = delivery_harness(HarnessOptions {
            endpoint_fail: true,
            builder_fail: false,
            transport_outcome: DidcommTransportOutcome::Delivered,
            post_issuance_fail: false,
        });
        assert_eq!(
            delivery
                .deliver_native(&transaction(), "did:example:holder")
                .await,
            Err(NativeInitiationDidcommDeliveryError::DidcommUnavailable)
        );
        assert_eq!(
            *order.lock().unwrap(),
            ["resolve-recipient", "validate-endpoint"]
        );
        assert_eq!(repository.releases.load(Ordering::SeqCst), 0);
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn materialization_failure_restores_the_retryable_claim() {
        let (delivery, repository, order) = delivery_harness(HarnessOptions {
            endpoint_fail: false,
            builder_fail: true,
            transport_outcome: DidcommTransportOutcome::Delivered,
            post_issuance_fail: false,
        });
        assert_eq!(
            delivery
                .deliver_native(&transaction(), "did:example:holder")
                .await,
            Err(NativeInitiationDidcommDeliveryError::CredentialUnavailable)
        );
        assert_eq!(repository.releases.load(Ordering::SeqCst), 1);
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 0);
        let order = order.lock().unwrap();
        assert!(order.contains(&"build"));
        assert_eq!(order.last(), Some(&"release"));
    }

    #[tokio::test]
    async fn transport_failure_preserves_staged_delivery_and_returns_a_sanitized_receipt() {
        let (delivery, repository, order) = delivery_harness(HarnessOptions {
            endpoint_fail: false,
            builder_fail: false,
            transport_outcome: DidcommTransportOutcome::Failed,
            post_issuance_fail: false,
        });
        let receipt = delivery
            .deliver_native(&transaction(), "did:example:holder")
            .await
            .unwrap();
        assert_eq!(receipt.transaction_id, "transaction-1");
        assert_eq!(
            receipt.credential_id,
            reserved_credential_id(&transaction())
        );
        assert_eq!(receipt.holder_did, "did:example:holder");
        assert_eq!(receipt.service_endpoint, "https://wallet.example/inbox");
        assert_eq!(receipt.didcomm_message_id, "message-1");
        assert_eq!(receipt.status, NativeDidcommDeliveryStatus::DeliveryFailed);
        assert_eq!(receipt.error.as_deref(), Some("didcomm_delivery_failed"));
        assert_eq!(repository.releases.load(Ordering::SeqCst), 0);
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);
        {
            let recorded = order.lock().unwrap();
            assert!(recorded.contains(&"transport"));
            assert_eq!(recorded.last(), Some(&"mark-transport-failed"));
        }

        order.lock().unwrap().clear();
        let retry = delivery
            .deliver_native(&transaction(), "did:example:holder")
            .await
            .unwrap();
        assert_eq!(retry.status, NativeDidcommDeliveryStatus::DeliveryFailed);
        assert_eq!(
            *order.lock().unwrap(),
            ["validate-endpoint", "transport", "mark-transport-failed"]
        );
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn post_issuance_failure_never_reopens_a_finalized_transaction() {
        let (delivery, repository, order) = delivery_harness(HarnessOptions {
            endpoint_fail: false,
            builder_fail: false,
            transport_outcome: DidcommTransportOutcome::Delivered,
            post_issuance_fail: true,
        });
        assert_eq!(
            delivery
                .deliver_native(&transaction(), "did:example:holder")
                .await,
            Err(NativeInitiationDidcommDeliveryError::PostIssuanceUnavailable)
        );
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);
        assert_eq!(repository.releases.load(Ordering::SeqCst), 0);
        assert_eq!(order.lock().unwrap().last(), Some(&"after-didcomm"));

        order.lock().unwrap().clear();
        assert_eq!(
            delivery
                .deliver_native(&transaction(), "did:example:holder")
                .await,
            Err(NativeInitiationDidcommDeliveryError::PostIssuanceUnavailable)
        );
        assert_eq!(
            *order.lock().unwrap(),
            ["validate-endpoint", "after-didcomm"],
            "a durable transport marker must prevent a second external send while projection retries"
        );
        assert_eq!(repository.finalizations.load(Ordering::SeqCst), 1);
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
