use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{TimeZone, Utc};
use marty_didcomm::{
    types::{Jwk, VerificationMethod},
    DidDocument,
};
use marty_issuance_service::{
    credential::{
        AllocatedCredentialStatus, BuiltCredential, CredentialBuildRequest, CredentialBuilder,
        CredentialIssuanceError, CredentialLifecycle, CredentialTransaction,
        CredentialTransactionStatus, IssuedCredential, IssuerContext, IssuerContextResolver,
    },
    initiation_didcomm::{
        DidcommEndpointValidator, DidcommEnvelopePort, DidcommTransportOutcome,
        DidcommTransportPort, InitiationDidcommClaim, InitiationDidcommRepository,
        NativeDidcommEnvelope, NativeDidcommError, NativeInitiationDidcommDelivery,
        NativeInitiationDidcommDeliveryError, NativeInitiationDidcommPorts,
        PackedDidcommCredential, PendingInitiationDidcommDelivery, PreparedDidcommEncryption,
        ResolvedDidcommRecipient, StagedInitiationDidcommDelivery, ValidatedDidcommEndpoint,
    },
};
use serde_json::{json, Map};

fn transaction() -> CredentialTransaction {
    CredentialTransaction {
        id: "transaction-atomicity".to_owned(),
        organization_id: "organization-atomicity".to_owned(),
        credential_template_id: "template-atomicity".to_owned(),
        revocation_profile_id: Some("profile-atomicity".to_owned()),
        renewal_of_credential_id: None,
        applicant_id: None,
        application_id: None,
        subject_did: None,
        idempotency_key_hash: None,
        idempotency_request_hash: None,
        status: CredentialTransactionStatus::Pending,
        pre_authorized_code: "pre-authorized-code".to_owned(),
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
        issuer_profile_id: Some("issuer-profile-atomicity".to_owned()),
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
        issuer_profile_id: "issuer-profile-atomicity".to_owned(),
        issuer_did: "did:example:issuer".to_owned(),
        signing_service_id: "signing-service-atomicity".to_owned(),
        algorithm: "ES256".to_owned(),
        verification_method_id: Some("did:example:issuer#key-1".to_owned()),
        public_jwk: None,
        certificate_chain: Vec::new(),
        raw_context: json!({}),
    }
}

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
                additional_properties: Map::new(),
            }),
            public_key_multibase: None,
            public_key_base58: None,
            additional_properties: Map::new(),
        }],
        service: Vec::new(),
        additional_properties: Map::new(),
    }
}

struct RepositoryState {
    transaction: CredentialTransaction,
}

struct FailingOnceRepository {
    state: Mutex<RepositoryState>,
    finalization_attempts: AtomicUsize,
}

impl FailingOnceRepository {
    fn new() -> Self {
        Self {
            state: Mutex::new(RepositoryState {
                transaction: transaction(),
            }),
            finalization_attempts: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl InitiationDidcommRepository for FailingOnceRepository {
    async fn pending_delivery(
        &self,
        _organization_id: &str,
        _transaction_id: &str,
    ) -> Result<Option<PendingInitiationDidcommDelivery>, CredentialIssuanceError> {
        Ok(None)
    }

    async fn transaction_for_delivery(
        &self,
        organization_id: &str,
        transaction_id: &str,
    ) -> Result<Option<CredentialTransaction>, CredentialIssuanceError> {
        let state = self.state.lock().unwrap();
        Ok((state.transaction.organization_id == organization_id
            && state.transaction.id == transaction_id)
            .then(|| state.transaction.clone()))
    }

    async fn claim_retryably(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
    ) -> Result<Option<InitiationDidcommClaim>, CredentialIssuanceError> {
        let mut state = self.state.lock().unwrap();
        if state.transaction.id != transaction.id
            || !matches!(
                state.transaction.status,
                CredentialTransactionStatus::Pending | CredentialTransactionStatus::Authorized
            )
        {
            return Ok(None);
        }
        let previous_status = state.transaction.status;
        state.transaction.status = CredentialTransactionStatus::Signing;
        state.transaction.reserved_credential_id = Some(credential_id.to_owned());
        Ok(Some(InitiationDidcommClaim {
            transaction: state.transaction.clone(),
            previous_status,
        }))
    }

    async fn release_retryably(
        &self,
        claim: &InitiationDidcommClaim,
    ) -> Result<(), CredentialIssuanceError> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.transaction.id, claim.transaction.id);
        assert_eq!(
            state.transaction.status,
            CredentialTransactionStatus::Signing
        );
        state.transaction.status = claim.previous_status;
        state.transaction.reserved_credential_id = None;
        Ok(())
    }

    async fn finalize_delivered(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError> {
        assert_eq!(transaction.id, credential.transaction_id);
        if self.finalization_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(CredentialIssuanceError::RepositoryUnavailable);
        }
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.transaction.id, transaction.id);
        assert_eq!(
            state.transaction.status,
            CredentialTransactionStatus::Signing
        );
        state.transaction.status = CredentialTransactionStatus::Issued;
        Ok(())
    }

    async fn stage_delivery(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        _delivery: &StagedInitiationDidcommDelivery,
    ) -> Result<(), CredentialIssuanceError> {
        self.finalize_delivered(transaction, credential).await
    }
}

struct FixedIssuerResolver;

#[async_trait]
impl IssuerContextResolver for FixedIssuerResolver {
    async fn resolve(
        &self,
        _transaction: &CredentialTransaction,
        _credential_format: &str,
        _force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        Ok(issuer())
    }
}

struct FixedCredentialBuilder;

#[async_trait]
impl CredentialBuilder for FixedCredentialBuilder {
    async fn build(
        &self,
        request: &CredentialBuildRequest,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        Ok(BuiltCredential {
            credential_id: request.credential_id.clone(),
            credential: "signed-credential".to_owned(),
        })
    }
}

struct NoopLifecycle;

#[async_trait]
impl CredentialLifecycle for NoopLifecycle {
    async fn ensure_ready(
        &self,
        _transaction: &CredentialTransaction,
        _issuer: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError> {
        Ok(())
    }

    async fn allocate_status(
        &self,
        _transaction: &CredentialTransaction,
        _credential_id: &str,
        _credential_format: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        Ok(AllocatedCredentialStatus::default())
    }

    async fn after_issued(
        &self,
        _transaction: &CredentialTransaction,
        _credential: &IssuedCredential,
        _response_format: &str,
    ) -> Result<(), CredentialIssuanceError> {
        panic!("OID4VCI projection must not handle a DIDComm delivery")
    }

    async fn after_didcomm_issued(
        &self,
        _transaction: &CredentialTransaction,
        _credential: &IssuedCredential,
        _service_endpoint: &str,
        _message_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        Ok(())
    }
}

struct LocalEnvelope {
    native: NativeDidcommEnvelope,
}

#[async_trait]
impl DidcommEnvelopePort for LocalEnvelope {
    async fn resolve_recipient(
        &self,
        holder_did: &str,
    ) -> Result<ResolvedDidcommRecipient, NativeDidcommError> {
        assert_eq!(holder_did, "did:example:holder");
        Ok(ResolvedDidcommRecipient {
            document: recipient_document(),
            endpoint: "https://127.0.0.1/didcomm".to_owned(),
        })
    }

    async fn prepare_encryption(
        &self,
        issuer_did: &str,
        recipient_document: DidDocument,
    ) -> Result<PreparedDidcommEncryption, NativeDidcommError> {
        self.native
            .prepare_encryption(issuer_did, recipient_document)
            .await
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
        self.native.pack_credential(
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
        self.native.encrypt_prepared(plaintext, prepared)
    }
}

struct CountingTransport {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl DidcommTransportPort for CountingTransport {
    async fn deliver(
        &self,
        endpoint: &ValidatedDidcommEndpoint,
        encrypted_message: String,
    ) -> DidcommTransportOutcome {
        assert_eq!(endpoint.as_str(), "https://127.0.0.1/didcomm");
        assert!(!encrypted_message.is_empty());
        self.calls.fetch_add(1, Ordering::SeqCst);
        DidcommTransportOutcome::Delivered
    }
}

#[tokio::test]
async fn legacy_repository_without_transport_claims_fails_closed_before_post() {
    let repository = Arc::new(FailingOnceRepository::new());
    let transport_calls = Arc::new(AtomicUsize::new(0));
    let delivery = NativeInitiationDidcommDelivery::new(
        NativeInitiationDidcommPorts {
            repository,
            issuer_resolver: Arc::new(FixedIssuerResolver),
            builder: Arc::new(FixedCredentialBuilder),
            lifecycle: Arc::new(NoopLifecycle),
            envelope: Arc::new(LocalEnvelope {
                native: NativeDidcommEnvelope::new(None, None, None),
            }),
            endpoints: Arc::new(DidcommEndpointValidator::new(true)),
            transport: Arc::new(CountingTransport {
                calls: transport_calls.clone(),
            }),
        },
        "https://issuer.example",
    )
    .unwrap();

    let first = delivery
        .deliver_for_organization(
            "organization-atomicity",
            "transaction-atomicity",
            "did:example:holder",
        )
        .await;
    assert_eq!(
        first,
        Err(NativeInitiationDidcommDeliveryError::CredentialUnavailable)
    );
    let calls_after_failed_finalization = transport_calls.load(Ordering::SeqCst);

    let second = delivery
        .deliver_for_organization(
            "organization-atomicity",
            "transaction-atomicity",
            "did:example:holder",
        )
        .await;
    assert_eq!(
        second,
        Err(NativeInitiationDidcommDeliveryError::CredentialUnavailable)
    );
    let calls_after_retry = transport_calls.load(Ordering::SeqCst);

    assert_eq!(
        (calls_after_failed_finalization, calls_after_retry),
        (0, 0),
        "database finalization and a durable claim must both precede external delivery"
    );
}
