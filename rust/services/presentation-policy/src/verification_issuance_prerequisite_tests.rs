// Included only in the ignored, disposable native owner qualification fixture.
// Policy and Flow acquisitions, holder proof, persistence and SD-JWT assembly
// use product implementations. Metadata/lifecycle providers isolate the W05
// handoff; the output signature uses a separate non-exportable OpenBao key.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use marty_issuance_service::{
    credential::{
        AllocatedCredentialStatus, CredentialIssuanceError, CredentialIssuanceService,
        CredentialLifecycle, CredentialPorts, CredentialRepository, CredentialRequest,
        CredentialTransaction, CredentialTransactionStatus, IssuedCredential, IssuerContext,
        IssuerContextResolver, UuidNotificationIdGenerator,
    },
    credential_builder::HttpCredentialBuilder,
    credential_issuer::NativeCredentialProofVerifier,
    credential_postgres::PostgresCredentialRepository,
    dpop::MartyDpopProofVerifier,
    ephemeral_postgres::PostgresProofNonceRepository,
    initiation::{
        InitiationApplicationClaimsResolver, InitiationClientRepository, InitiationDependencyError,
        InitiationOrganizationValidator, InitiationPorts, InitiationRegisteredClient,
        InitiationRelatedResourceValidator, InitiationRequest,
        InitiationRevocationProfileValidator, InitiationService, InitiationTemplate,
        InitiationTemplateResolver, OrganizationValidation, SecureInitiationSeedGenerator,
        SystemInitiationClock,
    },
    initiation_http::InitiationHttpService,
    initiation_response::{
        InitiationDidcommDelivery, InitiationDidcommDeliveryError,
        InitiationDidcommDeliveryReceipt, InitiationOfferProjector, InitiationOfferResponse,
    },
    proof_nonce::{ProofNonceService, SecureProofNonceGenerator},
    token_exchange::TokenExchangeRepository,
    token_postgres::PostgresTokenExchangeRepository,
    verification_prerequisite_client::FlowPrerequisiteClient,
};
use marty_oid4vp_contract::issuance_prerequisite::{
    IssuancePrerequisitePolicyV1, IssuancePrerequisiteProfileV1,
};
use marty_service_runtime::{
    https::{BoundKeylessHttpsServer, ManagedAuthorityHttpsConfig},
    RemoteTlsIdentityFiles, TlsIdentityNames,
};
use sqlx::{PgPool, Row};
use std::{collections::BTreeMap, sync::atomic::AtomicUsize, time::Duration};

const PREREQUISITE_OWNER_TOKEN: &str = "separate-flow-issuance-prerequisite-owner-token-32-bytes";
const MANAGEMENT_KEY: &str = "separate-issuance-management-fixture-key-32-bytes";
const SIGNING_API_KEY: &str = "separate-issuance-signer-fixture-key-32-bytes";
const TOKEN_HMAC_KEY: &str = "separate-issuance-bearer-fixture-hmac-32-bytes";
const OUTPUT_TEMPLATE: &str = "00000000-0000-4000-8000-000000000051";
const OUTPUT_TYPE: &str = "VerifiedEmailMembershipCredential";
const ISSUER_BASE: &str = "https://issuance-prerequisite.example";

struct HandoffCatalog;

#[async_trait]
impl mmf_security::TenantMembershipProvider for HandoffCatalog {
    async fn membership(
        &self,
        principal: &str,
        tenant: &str,
    ) -> Result<Option<mmf_security::TenantMembership>, mmf_security::SecurityError> {
        Ok(
            (principal == LIVE_FLOW_PRINCIPAL && tenant == ORGANIZATION_ID.to_string()).then(
                || mmf_security::TenantMembership {
                    principal_id: principal.into(),
                    tenant_id: tenant.into(),
                    status: "active".into(),
                    role_names: ["member".into()].into(),
                    permissions: ["flow-instance:start".into()].into(),
                    is_owner: false,
                },
            ),
        )
    }
}

#[async_trait]
impl marty_flow::FlowReferenceProvider for HandoffCatalog {
    async fn resolve(
        &self,
        kind: marty_flow::FlowReferenceKind,
        id: &str,
        principal: &str,
        organization: &str,
    ) -> Result<marty_flow::FlowReference, marty_flow::FlowProviderError> {
        assert_eq!(principal, LIVE_FLOW_PRINCIPAL);
        assert_eq!(organization, ORGANIZATION_ID.to_string());
        assert_eq!(id, POLICY_PROFILE_ID.to_string());
        Ok(marty_flow::FlowReference {
            kind,
            id: id.into(),
            organization_id: Some(organization.into()),
            status: "active".into(),
            system_owned: false,
        })
    }
}

#[async_trait]
impl marty_flow::SigningIdentityProvider for HandoffCatalog {
    async fn resolve(
        &self,
        organization: &str,
        did: &str,
        purpose: &str,
        format: &str,
        algorithm: Option<&str>,
    ) -> Result<marty_flow::SigningIdentity, marty_flow::FlowProviderError> {
        if did == ISSUER {
            assert_eq!(algorithm, Some("EdDSA"));
            return Ok(marty_flow::SigningIdentity {
                organization_id: organization.into(),
                issuer_did: did.into(),
                verification_method_id: ISSUER_KEY_ID.into(),
                signing_key_reference: "fixture-input-credential-identity".into(),
                public_jwk: serde_json::from_value(public_key(&issuer_key())).unwrap(),
                key_purpose: purpose.into(),
                credential_format: format.into(),
                algorithm: "EdDSA".into(),
            });
        }
        marty_flow::SigningIdentityProvider::resolve(
            &LiveFlowCatalog,
            organization,
            did,
            purpose,
            format,
            algorithm,
        )
        .await
    }
    async fn sign(
        &self,
        request: &marty_flow::SigningRequest,
    ) -> Result<marty_flow::SigningResult, marty_flow::FlowProviderError> {
        use p256::ecdsa::signature::Signer as _;
        assert_eq!(request.organization_id, ORGANIZATION_ID.to_string());
        assert_eq!(request.issuer_did, AUDIENCE);
        assert_eq!(request.algorithm, "ES256");
        assert_eq!(
            request.verification_method_id,
            format!("{AUDIENCE}#request")
        );
        assert_eq!(
            request.signing_key_reference,
            "synthetic-public-request-identity"
        );
        let key = p256::ecdsa::SigningKey::from_slice(&[72; 32]).unwrap();
        let signature: p256::ecdsa::Signature =
            key.sign(&URL_SAFE_NO_PAD.decode(&request.payload_b64url).unwrap());
        Ok(marty_flow::SigningResult {
            issuer_did: request.issuer_did.clone(),
            verification_method_id: request.verification_method_id.clone(),
            algorithm: request.algorithm.clone(),
            signature_raw_b64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

struct HandoffPorts {
    template: marty_credential_template::CredentialTemplate,
    issuer: IssuerContext,
}

#[async_trait]
impl InitiationOrganizationValidator for HandoffPorts {
    async fn validate(&self, id: &str) -> OrganizationValidation {
        if id == ORGANIZATION_ID.to_string() {
            OrganizationValidation::Found
        } else {
            OrganizationValidation::NotFound
        }
    }
}
#[async_trait]
impl InitiationClientRepository for HandoffPorts {
    async fn get(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
        panic!("the accepted route has no OAuth client")
    }
}
#[async_trait]
impl InitiationTemplateResolver for HandoffPorts {
    async fn resolve(&self, id: &str) -> Result<InitiationTemplate, InitiationDependencyError> {
        assert_eq!(id, self.template.id);
        Ok(InitiationTemplate {
            credential_type: self.template.credential_type.clone(),
            vct: Some(self.template.vct.clone()),
            credential_payload_format: self.template.credential_payload_format.clone(),
            verification_prerequisite: self.template.verification_prerequisite.clone(),
            template_version: self.template.version,
            issuance_protocol: self.template.issuance_protocol.clone(),
            issuer_did: self.template.issuer_did.clone(),
            issuer_algorithm: self.template.issuer_algorithm.clone(),
            selective_disclosure_claims: self.template.selective_disclosure_fields.clone(),
            validity_days: i64::from(self.template.validity_rules.default_validity_days),
            renewable: false,
            ..InitiationTemplate::default()
        })
    }
}
#[async_trait]
impl InitiationRevocationProfileValidator for HandoffPorts {
    async fn validate_active(
        &self,
        organization: &str,
        profile: Option<&str>,
    ) -> Result<(), InitiationDependencyError> {
        assert_eq!(organization, ORGANIZATION_ID.to_string());
        assert_eq!(profile, None);
        Ok(())
    }
}
#[async_trait]
impl InitiationApplicationClaimsResolver for HandoffPorts {
    async fn resolve(&self, _: &str) -> Result<Option<serde_json::Map<String, Value>>, ()> {
        panic!("application approval cannot enter this prerequisite route")
    }
}
#[async_trait]
impl InitiationRelatedResourceValidator for HandoffPorts {
    async fn validate(&self, _: &Value) -> Result<(), InitiationDependencyError> {
        panic!("this SD-JWT route has no VC document")
    }
}
#[async_trait]
impl IssuerContextResolver for HandoffPorts {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        format: &str,
        _: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        assert_eq!(transaction.organization_id, ORGANIZATION_ID.to_string());
        assert_eq!(transaction.issuer_did.as_deref(), Some(ISSUER));
        assert_eq!(format, "dc+sd-jwt");
        Ok(self.issuer.clone())
    }
}
#[async_trait]
impl InitiationDidcommDelivery for HandoffPorts {
    async fn deliver(
        &self,
        _: &CredentialTransaction,
        _: &str,
    ) -> Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError> {
        panic!("DIDComm cannot enter this prerequisite route")
    }
}
#[async_trait]
impl CredentialLifecycle for HandoffPorts {
    async fn ensure_ready(
        &self,
        transaction: &CredentialTransaction,
        issuer: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError> {
        assert!(transaction.issuance_intent.is_some());
        assert_eq!(issuer.issuer_did, ISSUER);
        Ok(())
    }
    async fn allocate_status(
        &self,
        _: &CredentialTransaction,
        _: &str,
        _: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        Ok(AllocatedCredentialStatus::default())
    }
    async fn after_issued(
        &self,
        _: &CredentialTransaction,
        _: &IssuedCredential,
        _: &str,
    ) -> Result<(), CredentialIssuanceError> {
        Ok(())
    }
}

#[derive(Clone)]
struct HandoffSigner {
    pool: PgPool,
    calls: Arc<AtomicUsize>,
    client: reqwest::Client,
    kms_url: String,
    kms_token: String,
    kms_key: String,
    public_jwk: Value,
}

async fn sign_after_claim(
    State(signer): State<HandoffSigner>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    use base64::engine::general_purpose::STANDARD;
    assert_eq!(headers.get("x-api-key").unwrap(), SIGNING_API_KEY);
    assert_eq!(
        query.get("organization_id"),
        Some(&ORGANIZATION_ID.to_string())
    );
    let grant = marty_signing_grant::GrantEnvelope::from_header_value(
        headers
            .get(marty_signing_grant::HEADER_NAME)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        grant.claims.origin,
        marty_signing_grant::SigningOrigin::IssuanceCredential
    );
    assert_eq!(grant.claims.organization_id, ORGANIZATION_ID.to_string());
    assert_eq!(grant.claims.issuer_did.as_deref(), Some(ISSUER));
    assert_eq!(body["issuer_did"], ISSUER);
    assert_eq!(body["algorithm"], "EdDSA");
    assert_eq!(body["credential_format"], "dc+sd-jwt");
    assert_eq!(body["expected_public_jwk"], signer.public_jwk);
    let payload = URL_SAFE_NO_PAD
        .decode(body["payload_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        grant.claims.payload_sha256_b64,
        marty_signing_grant::payload_digest(&payload)
    );
    let consumed: bool = sqlx::query_scalar("SELECT EXISTS (
        SELECT 1 FROM issuance_service.issuance_transactions tx
        JOIN issuance_service.issuance_prerequisite_continuations continuation ON continuation.transaction_id=tx.id
        WHERE tx.organization_id=$1 AND tx.status='signing' AND tx.reserved_credential_id=$2
        AND continuation.credential_id=$2 AND continuation.intent_digest=tx.issuance_intent->>'intent_digest'
        AND continuation.consumed_at IS NOT NULL)")
        .bind(ORGANIZATION_ID.to_string()).bind(&grant.claims.operation_id).fetch_one(&signer.pool).await.unwrap();
    assert!(
        consumed,
        "no issuer signature before the actual durable continuation claim"
    );
    signer.calls.fetch_add(1, Ordering::SeqCst);
    let result: Value = signer
        .client
        .post(format!(
            "{}/v1/transit/sign/{}",
            signer.kms_url.trim_end_matches('/'),
            signer.kms_key
        ))
        .header("x-vault-token", &signer.kms_token)
        .json(&json!({"input":STANDARD.encode(&payload),"key_version":1}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let signature = result["data"]["signature"]
        .as_str()
        .unwrap()
        .strip_prefix("vault:v1:")
        .unwrap();
    let signature = STANDARD.decode(signature).unwrap();
    Json(json!({"ok":true,"issuer_did":ISSUER,"algorithm":"EdDSA",
        "verification_method_id":format!("{ISSUER}#prerequisite-output"),"signature_raw_b64":URL_SAFE_NO_PAD.encode(signature)}))
}

fn proof_request(nonce: &str, key: &SigningKey) -> CredentialRequest {
    let proof = sign_jwt(
        key,
        json!({"typ":"openid4vci-proof+jwt","alg":"EdDSA","jwk":public_key(key)}),
        &json!({"aud":format!("{ISSUER_BASE}/org/{ORGANIZATION_ID}"),"nonce":nonce,"iat":chrono::Utc::now().timestamp()}),
    );
    serde_json::from_value(json!({"credential_configuration_id":format!("{OUTPUT_TYPE}#sd-jwt"),"proofs":{"jwt":[proof]},
        "evidence":{"approved":true,"holder":"caller-claimed"}})).unwrap()
}

async fn complete_prerequisite(
    fixture: &Fixture,
    providers: &marty_flow::FlowProviderRegistry,
    repository: &marty_flow::PostgresFlowRepository,
    offer: &InitiationOfferResponse,
) -> marty_oid4vp_contract::ManagedOid4vpEvidenceProjectionV2 {
    let instance = repository
        .instance(
            &offer
                .verification_prerequisite
                .as_ref()
                .unwrap()
                .flow_instance_id,
        )
        .await
        .unwrap()
        .unwrap();
    let expected_status = instance.status;
    let expected_updated_at = instance.updated_at;
    let ready = marty_flow::prepare_verification_request(
        providers,
        instance,
        "https://managed-flow.example.test",
        &marty_flow::VerificationRequestRetrievalOptions::default(),
        chrono::Utc::now().max(expected_updated_at + chrono::Duration::microseconds(1)),
    )
    .await
    .unwrap();
    let marty_flow::PreparedVerificationRequest::Ready(ready) = ready else {
        panic!("the live prerequisite must emit a signed request before wallet submission")
    };
    {
        use p256::ecdsa::signature::Verifier as _;
        let parts = ready.compact_jwt.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        let signature =
            p256::ecdsa::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        p256::ecdsa::SigningKey::from_slice(&[72; 32])
            .unwrap()
            .verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }
    assert!(repository
        .compare_and_swap_instance(&ready.instance, expected_status, expected_updated_at)
        .await
        .unwrap());
    let instance = repository
        .instance(&ready.instance.id)
        .await
        .unwrap()
        .unwrap();
    let nonce = instance.context["nonce"].as_str().unwrap();
    let audience = instance.context["oid4vp_client_id"].as_str().unwrap();
    let token = presentation(&fixture.claims, nonce, audience, fixture.now);
    let input = marty_flow::VerificationSubmissionInput {
        vp_token: json!({(fixture.query_id.clone()):[token]}).to_string(),
        presentation_submission: None,
        state: Some(instance.id.clone()),
        audience_override: None,
    };
    let options = marty_flow::VerificationSubmissionOptions {
        callback_destinations: Default::default(),
        callback_secret: None,
        verifier_sender_id: AUDIENCE.into(),
        nonce_ttl_seconds: 900,
        callback_retention_seconds: marty_flow::CALLBACK_RETENTION_SECONDS,
        callback_max_attempts: marty_flow::CALLBACK_MAX_ATTEMPTS,
    };
    let prepared = marty_flow::prepare_verification_submission(
        providers,
        instance,
        input,
        &options,
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    let marty_flow::PreparedVerificationSubmission::Final(finalization) = prepared else {
        panic!("native managed verification must commit a final result")
    };
    repository
        .finalize_verification_with_receipt(&finalization)
        .await
        .unwrap()
        .unwrap()
        .managed_evidence()
        .unwrap()
        .projection()
        .clone()
}

async fn authorize_offer(
    tokens: &PostgresTokenExchangeRepository,
    offer: &InitiationOfferResponse,
    access_token: &str,
) {
    let transaction = tokens
        .transaction_by_pre_authorized_code(&offer.pre_auth_code)
        .await
        .unwrap()
        .unwrap();
    assert!(tokens
        .claim_transaction(&transaction, access_token, None)
        .await
        .unwrap());
}

async fn wait_for_issuance_lock(pool: &PgPool, blocker_pid: i32, minimum: i64) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // Follow the exact held transaction's blocker chain. The second
            // claimant may wait on the first claimant's tuple lock, and query
            // text is neither an identity nor guaranteed to be untruncated.
            let count: i64 = sqlx::query_scalar("WITH RECURSIVE activity AS MATERIALIZED (
                    SELECT pid,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE datname=current_database()
                ), waiting(pid) AS (
                    SELECT pid FROM activity WHERE $1=ANY(blockers)
                    UNION SELECT activity.pid FROM activity JOIN waiting ON waiting.pid=ANY(activity.blockers)
                ) SELECT count(*) FROM waiting")
                .bind(blocker_pid)
                .fetch_one(pool).await.unwrap();
            if count >= minimum { break; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.is_ok()
}

pub(super) async fn qualify(
    fixture: &Fixture,
    original_providers: &marty_flow::FlowProviderRegistry,
    pool: &PgPool,
    external_deadline_epoch_micros: i64,
    values: &BTreeMap<String, String>,
) {
    use marty_credential_template::{
        catalog::marty_login_badge, migration::migrate_credential_template_schema,
        CredentialFormat, PostgresCredentialTemplateStore, TemplateStatus,
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter("marty_issuance_service::verification_prerequisite=debug,marty_flow::postgres_issuance_prerequisite=debug")
        .with_test_writer()
        .try_init();
    let now = chrono::Utc::now();
    // The fresh Issuance owner seeds application metadata from the Organization
    // and Template catalogs. Install the real owner SQL under the enclosing
    // qualification's schema lock, before running Issuance's owned migration.
    for source in [
        include_str!("../../organization/migrations/0001_organization_schema.sql"),
        include_str!("../../organization/migrations/0002_offline_audit_receipts.sql"),
    ] {
        sqlx::raw_sql(source).execute(pool).await.unwrap();
    }
    sqlx::query("INSERT INTO organization_service.organizations (id,name,status,created_at,updated_at) VALUES ($1,'Native handoff fixture','active',$2,$2)")
        .bind(ORGANIZATION_ID).bind(now).execute(pool).await.unwrap();
    migrate_credential_template_schema(pool).await.unwrap();
    marty_issuance_service::migration::migrate_owned_schema(pool, ORGANIZATION_ID)
        .await
        .unwrap();
    let flow_repository = marty_flow::PostgresFlowRepository::new(pool.clone());
    let mut definition = marty_flow::create_definition_record(marty_flow::parse_request(json!({
        "organization_id":ORGANIZATION_ID,"name":"Native prerequisite issuance handoff","flow_type":"oid4vp_presentation",
        "presentation_policy_id":fixture.policy.id,"trust_profile_id":POLICY_PROFILE_ID,
    })).unwrap(), now).unwrap();
    definition.status = marty_flow::DefinitionStatus::Active;
    definition.default_timeout_seconds = 300;
    flow_repository.save_definition(&definition).await.unwrap();
    let prerequisite = IssuancePrerequisitePolicyV1 {
        profile: IssuancePrerequisiteProfileV1::ManagedSdJwtDcqlSameHolderV1,
        flow_definition_id: definition.id.clone(),
        flow_definition_version: definition.version,
        policy: policy_revision(&fixture.policy).unwrap(),
        verifier_issuer_did: AUDIENCE.into(),
        ttl_seconds: 300,
    };
    let mut template = marty_login_badge(now, &ORGANIZATION_ID.to_string(), ISSUER_BASE, ISSUER);
    template.id = OUTPUT_TEMPLATE.into();
    template.name = "Verified email membership".into();
    template.credential_type = OUTPUT_TYPE.into();
    template.vct = "urn:example:verified-email-membership".into();
    template.credential_payload_format = "SD_JWT_VC".into();
    template.supported_formats = vec![CredentialFormat::SdJwtVc];
    template.issuer_algorithm = Some("EdDSA".into());
    template.issuance_protocol = "OID4VCI_PRE_AUTH".into();
    template.status = TemplateStatus::Active;
    template.wallet_configs.clear();
    template.validity_rules.renewable = false;
    template.jwt_vc_profile = None;
    template.verification_prerequisite = Some(prerequisite);
    template.application_template_id = None;
    template.revocation_profile_id = None;
    template.selective_disclosure_fields = vec!["email".into()];
    template.zk_predicate_claims.clear();
    let store = PostgresCredentialTemplateStore::new(pool.clone());
    store.save_template(&template).await.unwrap();
    let template = store
        .template_by_id(OUTPUT_TEMPLATE)
        .await
        .unwrap()
        .unwrap();
    let public_jwk: Value = serde_json::from_slice(
        &std::fs::read(
            values
                .get("MARTY_TEST_ISSUANCE_SIGNING_PUBLIC_JWK_FILE")
                .expect("disposable issuance public key"),
        )
        .unwrap(),
    )
    .unwrap();
    let issuer = IssuerContext {
        issuer_profile_id: "fixture-prerequisite-output-profile".into(),
        issuer_did: ISSUER.into(),
        signing_service_id: "fixture-openbao-issuance-owner".into(),
        algorithm: "EdDSA".into(),
        verification_method_id: Some(format!("{ISSUER}#prerequisite-output")),
        public_jwk: Some(public_jwk.clone()),
        certificate_chain: vec![],
        raw_context: json!({"signing_key_reference":"fixture-prerequisite-output-key"}),
    };
    let ports = Arc::new(HandoffPorts { template, issuer });
    let mut providers = original_providers.clone();
    providers.tenant_membership = Some(Arc::new(HandoffCatalog));
    providers.reference_catalog = Some(Arc::new(HandoffCatalog));
    providers.signing_identity = Some(Arc::new(HandoffCatalog));
    let identity = RemoteTlsIdentityFiles::from_values(
        |name| values.get(name).map(String::as_str),
        TlsIdentityNames::files("MARTY_TEST_POLICY_OWNER_TLS"),
        Duration::from_secs(5),
        16,
    )
    .unwrap()
    .unwrap();
    let owner_state = marty_flow::FlowHttpState {
        service_authenticator: None,
        issuance_prerequisite_authenticator: Some(Arc::new(
            mmf_security::ServiceTokenAuthenticator::new(
                Some(PREREQUISITE_OWNER_TOKEN.into()),
                true,
            )
            .unwrap(),
        )),
        repository: flow_repository.clone(),
        providers: Arc::new(providers.clone()),
        public_base_url: "https://managed-flow.example.test".into(),
        verification: marty_flow::FlowHttpVerificationOptions::default(),
        application_approval: Default::default(),
    };
    let owner_server = BoundKeylessHttpsServer::bind(
        &ManagedAuthorityHttpsConfig {
            address: "127.0.0.1:0".parse().unwrap(),
            identity,
        },
        marty_flow::flow_wallet_authority_router(owner_state),
    )
    .await
    .unwrap();
    let origin = format!("https://{}", owner_server.local_addr().unwrap());
    let (owner_shutdown, receiver) = tokio::sync::watch::channel(false);
    let owner_task = tokio::spawn(async move { owner_server.serve(receiver).await.unwrap() });
    let ca = std::fs::read(values.get("MARTY_TEST_POLICY_OWNER_CA_CERT").unwrap()).unwrap();
    let client =
        Arc::new(FlowPrerequisiteClient::new(&origin, PREREQUISITE_OWNER_TOKEN, &ca).unwrap());
    let repository = Arc::new(PostgresCredentialRepository::new(
        pool.clone(),
        TOKEN_HMAC_KEY,
    ));
    let initiation = InitiationService::new(
        InitiationPorts {
            repository: repository.clone(),
            organizations: ports.clone(),
            clients: ports.clone(),
            templates: ports.clone(),
            revocation_profiles: ports.clone(),
            applications: ports.clone(),
            related_resources: ports.clone(),
            issuer_resolver: ports.clone(),
            seeds: Arc::new(SecureInitiationSeedGenerator),
            clock: Arc::new(SystemInitiationClock),
        },
        ISSUER_BASE,
    )
    .unwrap();
    let projector = InitiationOfferProjector::new(ISSUER_BASE, ports.clone())
        .unwrap()
        .with_prerequisites(Some(client.clone()));
    let initiation = InitiationHttpService::new(initiation, projector, Some(MANAGEMENT_KEY));
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", MANAGEMENT_KEY.parse().unwrap());
    headers.insert("x-user-id", LIVE_FLOW_PRINCIPAL.parse().unwrap());
    headers.insert(
        "x-organization-id",
        ORGANIZATION_ID.to_string().parse().unwrap(),
    );
    let request:InitiationRequest=serde_json::from_value(json!({"organization_id":ORGANIZATION_ID,"credential_template_id":OUTPUT_TEMPLATE,"issuer_did":ISSUER,
        "applicant_id":"issuance-applicant-not-authority","delivery_mode":"wallet_only","claims":{"email":EMAIL,"role":"verified-member"}})).unwrap();
    let first = initiation.initiate(&headers, &request).await.unwrap();
    let second = initiation.initiate(&headers, &request).await.unwrap();
    assert_ne!(first.id, second.id);
    let tokens = PostgresTokenExchangeRepository::new(pool.clone(), TOKEN_HMAC_KEY);
    authorize_offer(&tokens, &first, "first-native-handoff-token").await;
    authorize_offer(&tokens, &second, "second-native-handoff-token").await;
    let nonces = Arc::new(PostgresProofNonceRepository::new(pool.clone()));
    let nonce_service = ProofNonceService::new(nonces.clone(), Arc::new(SecureProofNonceGenerator));
    let before_completion_nonce = nonce_service.issue().await.unwrap().c_nonce;
    let wrong_holder_nonce = nonce_service.issue().await.unwrap().c_nonce;
    let first_a_nonce = nonce_service.issue().await.unwrap().c_nonce;
    let first_b_nonce = nonce_service.issue().await.unwrap().c_nonce;
    let second_expired_nonce = nonce_service.issue().await.unwrap().c_nonce;
    assert_ne!(first_a_nonce, first_b_nonce);
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let kms_ca = reqwest::Certificate::from_pem(
        &std::fs::read(
            values
                .get("MARTY_TEST_ISSUANCE_SIGNING_KMS_CA_CERT_FILE")
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let output_public_key = public_jwk.clone();
    let signer = HandoffSigner {
        pool: pool.clone(),
        calls: signer_calls.clone(),
        client: reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_certs_only([kms_ca])
            .build()
            .unwrap(),
        kms_url: values
            .get("MARTY_TEST_ISSUANCE_SIGNING_KMS_URL")
            .unwrap()
            .clone(),
        kms_token: std::fs::read_to_string(
            values
                .get("MARTY_TEST_ISSUANCE_SIGNING_KMS_TOKEN_FILE")
                .unwrap(),
        )
        .unwrap()
        .trim()
        .into(),
        kms_key: values
            .get("MARTY_TEST_ISSUANCE_SIGNING_KEY_NAME")
            .unwrap()
            .clone(),
        public_jwk,
    };
    let signing_router = Router::new()
        .route("/issuer-dids/sign", post(sign_after_claim))
        .with_state(signer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signing_origin = format!("http://{}", listener.local_addr().unwrap());
    let signing_task =
        tokio::spawn(async move { axum::serve(listener, signing_router).await.unwrap() });
    let builder = HttpCredentialBuilder::new_with_grant(
        signing_origin.parse().unwrap(),
        Some(SIGNING_API_KEY),
        Duration::from_secs(5),
        marty_signing_grant_test_support::ContractGrantMinter(
            marty_signing_grant::SigningOrigin::IssuanceCredential,
        ),
    )
    .unwrap();
    let credential = CredentialIssuanceService::new(
        CredentialPorts {
            repository: repository.clone(),
            nonce_repository: nonces,
            dpop_verifier: Arc::new(MartyDpopProofVerifier),
            proof_verifier: Arc::new(NativeCredentialProofVerifier),
            issuer_resolver: ports.clone(),
            builder: Arc::new(builder),
            lifecycle: ports,
            notification_ids: Arc::new(UuidNotificationIdGenerator),
        },
        ISSUER_BASE,
    )
    .with_prerequisites(Some(client));
    let endpoint = format!("{ISSUER_BASE}/oid4vci/credential");
    let before = credential
        .issue(
            &proof_request(&before_completion_nonce, &holder_key()),
            Some("Bearer first-native-handoff-token"),
            None,
            &endpoint,
        )
        .await;
    assert!(matches!(
        before,
        Err(CredentialIssuanceError::ApplicationEligibilityDenied)
    ));
    assert_eq!(signer_calls.load(Ordering::SeqCst), 0);
    let first_evidence = complete_prerequisite(fixture, &providers, &flow_repository, &first).await;
    let second_evidence =
        complete_prerequisite(fixture, &providers, &flow_repository, &second).await;
    for (offer, evidence) in [(&first, &first_evidence), (&second, &second_evidence)] {
        assert_eq!(
            evidence.policy_evidence.validity.valid_until_epoch_micros,
            external_deadline_epoch_micros,
            "the signed external lease must survive Policy and durable Flow finalization",
        );
        assert!(
            evidence.policy_evidence.trust.valid_until_epoch_seconds * 1_000_000
                > external_deadline_epoch_micros
        );
        assert!(
            evidence.policy_evidence.status.valid_until_epoch_seconds * 1_000_000
                > external_deadline_epoch_micros
        );
        let intent = repository
            .transaction_by_id(&offer.id)
            .await
            .unwrap()
            .unwrap()
            .issuance_intent
            .unwrap();
        assert!(
            evidence.policy_evidence.validity.evaluated_at_epoch_micros
                >= intent.created_at_epoch_micros,
            "the actual Policy observation must follow the reserved intent: evaluated={}, intent_created={}",
            evidence.policy_evidence.validity.evaluated_at_epoch_micros,
            intent.created_at_epoch_micros,
        );
    }
    let wrong = credential
        .issue(
            &proof_request(&wrong_holder_nonce, &SigningKey::from_bytes(&[83; 32])),
            Some("Bearer first-native-handoff-token"),
            None,
            &endpoint,
        )
        .await;
    assert!(matches!(
        wrong,
        Err(CredentialIssuanceError::ApplicationEligibilityDenied)
    ));
    assert_eq!(signer_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_prerequisite_continuations"
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        0
    );

    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM issuance_service.issuance_transactions WHERE id=$1 FOR UPDATE")
        .bind(&first.id)
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let mut attempts = Vec::new();
    for nonce in [first_a_nonce, first_b_nonce] {
        let service = credential.clone();
        let request = proof_request(&nonce, &holder_key());
        let endpoint = endpoint.clone();
        attempts.push(tokio::spawn(async move {
            service
                .issue(
                    &request,
                    Some("Bearer first-native-handoff-token"),
                    None,
                    &endpoint,
                )
                .await
        }));
    }
    if !wait_for_issuance_lock(pool, blocker_pid, 2).await {
        let mut completed = Vec::new();
        for attempt in &mut attempts {
            if attempt.is_finished() {
                completed.push(attempt.await.map(|outcome| outcome.map(|_| ())));
            }
        }
        panic!("concurrent signing claims did not reach held parent; completed={completed:?}; policy remaining={}us; pool size={},idle={}",
            first_evidence.policy_evidence.validity.valid_until_epoch_micros-chrono::Utc::now().timestamp_micros(),pool.size(),pool.num_idle());
    }
    lock.commit().await.unwrap();
    let mut issued = None;
    for attempt in attempts {
        match attempt.await.unwrap() {
            Ok(response) => {
                if let Some(original) = &issued {
                    assert_eq!(original, &response)
                } else {
                    issued = Some(response)
                }
            }
            Err(CredentialIssuanceError::IssuanceInProgress) => {}
            Err(error) => panic!("unexpected concurrent handoff failure: {error:?}"),
        }
    }
    let issued = issued.expect("one native same-holder signing claim succeeds");
    assert_eq!(signer_calls.load(Ordering::SeqCst), 1);
    let compact = issued.credentials[0]["credential"].as_str().unwrap();
    let jwt = compact.split('~').next().unwrap();
    let parts = jwt.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let public_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(output_public_key["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let verification_key = ed25519_dalek::VerifyingKey::from_bytes(&public_bytes).unwrap();
    let signature =
        ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    verification_key
        .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
    let issued_claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(issued_claims["iss"], ISSUER);
    assert_eq!(
        issuer_public_key_thumbprint(&issued_claims["cnf"]["jwk"]).unwrap(),
        issuer_public_key_thumbprint(&public_key(&holder_key())).unwrap()
    );
    let row=sqlx::query("SELECT tx.status,tx.issuance_intent,continuation.evidence_digest,continuation.holder_key_thumbprint,continuation.credential_id,(extract(epoch FROM continuation.expires_at)*1000000)::bigint AS valid_until_epoch_micros,tx.reserved_credential_id
        FROM issuance_service.issuance_transactions tx JOIN issuance_service.issuance_prerequisite_continuations continuation ON continuation.transaction_id=tx.id WHERE tx.id=$1")
        .bind(&first.id).fetch_one(pool).await.unwrap();
    assert_eq!(row.get::<String, _>("status"), "issued");
    assert_eq!(
        row.get::<i64, _>("valid_until_epoch_micros"),
        external_deadline_epoch_micros,
        "the consumed issuance continuation must retain the exact external bound",
    );
    assert_eq!(
        row.get::<String, _>("evidence_digest"),
        first_evidence.evidence_digest
    );
    assert_eq!(
        row.get::<String, _>("holder_key_thumbprint"),
        issuer_public_key_thumbprint(&public_key(&holder_key())).unwrap()
    );
    assert_eq!(
        row.get::<String, _>("credential_id"),
        row.get::<String, _>("reserved_credential_id")
    );
    assert_eq!(
        row.get::<Value, _>("issuance_intent")["initiating_principal_id"],
        LIVE_FLOW_PRINCIPAL
    );
    assert!(repository
        .credential_by_transaction(&first.id)
        .await
        .unwrap()
        .is_some());

    // The second real owner acquisition is live before it waits for the signing
    // lock. The signed external list expires first; both managed owners remain
    // live. The signing claim must check that external bound using the DB clock.
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM issuance_service.issuance_transactions WHERE id=$1 FOR UPDATE")
        .bind(&second.id)
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let service = credential.clone();
    let request = proof_request(&second_expired_nonce, &holder_key());
    let endpoint_copy = endpoint.clone();
    let mut late = tokio::spawn(async move {
        service
            .issue(
                &request,
                Some("Bearer second-native-handoff-token"),
                None,
                &endpoint_copy,
            )
            .await
    });
    if !wait_for_issuance_lock(pool, blocker_pid, 1).await {
        let completed = if late.is_finished() {
            Some((&mut late).await.map(|outcome| outcome.map(|_| ())))
        } else {
            None
        };
        panic!("expiry claim did not reach held parent; completed={completed:?}; policy remaining={}us; pool size={},idle={}",
            second_evidence.policy_evidence.validity.valid_until_epoch_micros-chrono::Utc::now().timestamp_micros(),pool.size(),pool.num_idle());
    }
    let remaining = second_evidence
        .policy_evidence
        .validity
        .valid_until_epoch_micros
        - chrono::Utc::now().timestamp_micros();
    if remaining > 0 {
        assert!(remaining < 21_000_000);
        tokio::time::sleep(Duration::from_micros(remaining as u64) + Duration::from_millis(2))
            .await;
    }
    lock.commit().await.unwrap();
    assert!(matches!(
        late.await.unwrap(),
        Err(CredentialIssuanceError::ApplicationEligibilityDenied)
    ));
    let denied_at: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(denied_at >= external_deadline_epoch_micros);
    assert!(
        denied_at < second_evidence.policy_evidence.trust.valid_until_epoch_seconds * 1_000_000,
        "the external lease, not the managed trust lease, expired at consumption",
    );
    assert!(
        denied_at < second_evidence.policy_evidence.status.valid_until_epoch_seconds * 1_000_000,
        "the external lease, not the managed status lease, expired at consumption",
    );
    assert_eq!(signer_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        repository
            .transaction_by_id(&second.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        CredentialTransactionStatus::Authorized
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM issuance_service.issuance_prerequisite_continuations WHERE transaction_id=$1").bind(&second.id).fetch_one(pool).await.unwrap(),0);
    let replay_request: CredentialRequest = serde_json::from_value(
        json!({"credential_configuration_id":format!("{OUTPUT_TYPE}#sd-jwt")}),
    )
    .unwrap();
    let replay = credential
        .issue(
            &replay_request,
            Some("Bearer first-native-handoff-token"),
            None,
            &endpoint,
        )
        .await
        .unwrap();
    assert_eq!(issued, replay);
    assert_eq!(signer_calls.load(Ordering::SeqCst), 1);
    owner_shutdown.send(true).unwrap();
    owner_task.await.unwrap();
    signing_task.abort();
}
