use super::*;
use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use chrono::Duration;
use marty_delegated_authority::{
    ApprovalEvidence, Authority, AuthorityMode, Binding, BindingMethod, ConsentEvidenceVerifier,
    ConsentVerificationError, ConsentVerificationRequest, ConstraintMode, Constraints,
    DelegationAuthorityService, DelegationChallengeIssuer, DelegationChallengeRequest,
    DelegationClock, DelegationGrant, DelegationOid4vpChallengeStore, GrantTerms,
    InMemoryDelegationGrantRepository, Principal, VerifiedConsent,
};
use marty_verification::flow::FlowInstanceStatus;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};

use crate::{
    create_definition_record, migrate_flow_schema, parse_request, CredentialClaimReference,
    CredentialTemplateProvider, CredentialTemplateReference, DefinitionStatus,
    FlowDelegationOid4vpChallengeStore, FlowProviderError, FlowReference, FlowReferenceKind,
    FlowReferenceProvider, PresentationEvaluationRequest, PresentationEvaluationResult,
    PresentationPolicyProvider, PresentationPolicyReference, SigningIdentity,
    SigningIdentityProvider, SigningRequest, SigningResult,
};

#[path = "../tests/support/flow_schema.rs"]
mod flow_schema;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct Clock(Mutex<DateTime<Utc>>);
impl Clock {
    fn set(&self, now: DateTime<Utc>) {
        *self.0.lock().unwrap() = now;
    }
}
impl DelegationClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

struct Consent(Arc<Mutex<DateTime<Utc>>>);
#[async_trait]
impl ConsentEvidenceVerifier for Consent {
    async fn verify_approval(
        &self,
        _: ConsentVerificationRequest<'_>,
    ) -> Result<VerifiedConsent, ConsentVerificationError> {
        Ok(VerifiedConsent {
            valid_until: *self.0.lock().unwrap(),
        })
    }
}

struct Fixture {
    lifecycle: Arc<DelegationAuthorityService>,
    issuer: DelegationChallengeIssuer,
    clock: Arc<Clock>,
    consent_until: Arc<Mutex<DateTime<Utc>>>,
    grant: DelegationGrant,
    definition: FlowDefinitionRecord,
    configuration: DelegatedVerificationStartConfiguration,
    providers: FlowProviderRegistry,
}

impl Fixture {
    async fn new(now: DateTime<Utc>) -> Self {
        let clock = Arc::new(Clock(Mutex::new(now)));
        let consent_until = Arc::new(Mutex::new(now + Duration::seconds(60)));
        let lifecycle = Arc::new(
            DelegationAuthorityService::with_clock(
                Arc::new(InMemoryDelegationGrantRepository::default()),
                Arc::new(Consent(consent_until.clone())),
                Authority {
                    mode: AuthorityMode::Managed,
                    issuer: Principal {
                        principal_type: PrincipalType::ServiceAccount,
                        id: "urn:example:grant-authority".into(),
                    },
                    status_ref: "https://authority.example/delegation-status".into(),
                    source_profile: None,
                    source_evidence_ref: None,
                    source_evidence_digest: None,
                    source_expires_at: None,
                },
                clock.clone(),
            )
            .unwrap(),
        );
        let grant = lifecycle
            .propose(
                Uuid::new_v4(),
                GrantTerms {
                    grantor: Principal {
                        principal_type: PrincipalType::User,
                        id: "urn:example:grantor".into(),
                    },
                    subject: Principal {
                        principal_type: PrincipalType::Organization,
                        id: "urn:example:represented-organization".into(),
                    },
                    delegate: Principal {
                        principal_type: PrincipalType::ServiceAccount,
                        id: "urn:example:actual-delegate".into(),
                    },
                    binding: Binding {
                        method: BindingMethod::Key,
                        key_thumbprint: Some(format!("sha256:{}", "a".repeat(64))),
                        session_ref: None,
                        establishment_evidence_ref: None,
                    },
                    actions: vec!["urn:example:read".into()],
                    audiences: vec!["https://consuming-domain.example".into()],
                    resources: vec!["urn:example:dataset".into()],
                    valid_from: now - Duration::seconds(1),
                    valid_until: now + Duration::hours(1),
                    subdelegation_allowed: false,
                    constraints: Constraints {
                        mode: ConstraintMode::ExactOperation,
                        request_profile: Some("urn:example:operation:v1".into()),
                        request_digest: Some(format!("sha256:{}", "b".repeat(64))),
                        profile: None,
                        document_ref: None,
                        document_digest: None,
                        evaluator: None,
                    },
                },
            )
            .await
            .unwrap();
        clock.set(now + Duration::microseconds(1));
        let grant = lifecycle
            .approve(
                grant.organization_id,
                grant.id,
                grant.revision,
                &grant.terms.grantor,
                ApprovalEvidence {
                    profile: "urn:example:approval:v1".into(),
                    evidence_ref: "urn:example:consent:1".into(),
                    authority_evidence_ref: "urn:example:representation:1".into(),
                },
            )
            .await
            .unwrap();
        let issuer =
            DelegationChallengeIssuer::with_clock(lifecycle.clone(), None, 120, clock.clone())
                .unwrap();
        let mut definition = create_definition_record(
            parse_request(json!({
                "organization_id": grant.organization_id, "name":"Delegated verification",
                "flow_type":"oid4vp_presentation", "presentation_policy_id":"policy-1",
            }))
            .unwrap(),
            now,
        )
        .unwrap();
        definition.status = DefinitionStatus::Active;
        let configuration = DelegatedVerificationStartConfiguration {
            definition: VerificationDefinitionBinding {
                organization_id: grant.organization_id.to_string(),
                definition_id: definition.id.clone(),
                version: definition.version,
            },
            issuer_did: "did:web:verifier.example".into(),
            public_base_url: "https://verifier.example".into(),
            allow_http_loopback: false,
            options: VerificationStartOptions::default(),
        };
        let ports = Arc::new(Ports {
            organization_id: grant.organization_id.to_string(),
        });
        let providers = FlowProviderRegistry {
            presentation_policy: Some(ports.clone()),
            credential_template: Some(ports.clone()),
            signing_identity: Some(ports.clone()),
            reference_catalog: Some(ports),
            ..Default::default()
        };
        Self {
            lifecycle,
            issuer,
            clock,
            consent_until,
            grant,
            definition,
            configuration,
            providers,
        }
    }

    async fn admission(&self) -> DelegationChallengeAdmission {
        self.issuer
            .admit(
                self.grant.organization_id,
                &self.grant.terms.delegate,
                DelegationChallengeRequest {
                    grant_id: self.grant.id,
                    expected_revision: self.grant.revision,
                    action: self.grant.terms.actions[0].clone(),
                    audience: self.grant.terms.audiences[0].clone(),
                    resource: self.grant.terms.resources[0].clone(),
                    operation_profile: self
                        .grant
                        .terms
                        .constraints
                        .request_profile
                        .clone()
                        .unwrap(),
                    operation_digest: self.grant.terms.constraints.request_digest.clone().unwrap(),
                },
            )
            .await
            .unwrap()
    }

    fn starter(&self, repository: PostgresFlowRepository) -> FlowDelegatedVerificationStarter {
        FlowDelegatedVerificationStarter::new(
            repository,
            self.providers.clone(),
            self.configuration.clone(),
        )
    }
}

struct Ports {
    organization_id: String,
}
#[async_trait]
impl PresentationPolicyProvider for Ports {
    async fn configuration_digest(&self, _: &str) -> Result<String, FlowProviderError> {
        Ok(format!("sha256:{}", "a".repeat(64)))
    }
    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            id: id.into(),
            organization_id: self.organization_id.clone(),
            status: "active".into(),
            holder_binding_required: false,
            prerequisite_evidence_profile: None,
            credential_authority: None,
            policy_revision: marty_oid4vp_contract::FrozenPolicyIdentity {
                id: id.into(),
                version: 1,
                content_digest: format!("sha256:{}", "a".repeat(64)),
            },
            credential_requirements: vec![
                json!({"id":"member","credential_template_id":"template-1","requested_claims":[{"claim_name":"member","required":true}]}),
            ],
        })
    }
    async fn evaluate(
        &self,
        _: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        unreachable!("challenge admission cannot authorize a presentation or operation")
    }
}
#[async_trait]
impl CredentialTemplateProvider for Ports {
    async fn get_template(
        &self,
        id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        Ok(CredentialTemplateReference {
            jwt_vc_profile: None,
            id: id.into(),
            organization_id: self.organization_id.clone(),
            status: "active".into(),
            credential_type: "MemberCredential".into(),
            vct: "https://credentials.example/member".into(),
            doctype: String::new(),
            supported_formats: vec!["dc+sd-jwt".into()],
            claims: vec![CredentialClaimReference {
                name: "member".into(),
                display_name: "Member".into(),
                description: String::new(),
                required: true,
                mdoc_namespace: String::new(),
                mdoc_element_identifier: String::new(),
            }],
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "dc+sd-jwt".into(),
            issuance_protocol: "OID4VCI_PRE_AUTH".into(),
            wallet_configurations: Vec::new(),
            issuer_algorithm: Some("ES256".into()),
        })
    }
    async fn wallet_formats(
        &self,
        organization_id: &str,
    ) -> Result<Vec<String>, FlowProviderError> {
        assert_eq!(organization_id, self.organization_id);
        Ok(vec!["dc+sd-jwt".into()])
    }
}
#[async_trait]
impl SigningIdentityProvider for Ports {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
        purpose: &str,
        format: &str,
        _: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        // P-256 generator coordinates are public data. This start path resolves
        // identity only; it does not manufacture or use a private fixture key.
        Ok(SigningIdentity {
            organization_id: organization_id.into(),
            issuer_did: issuer_did.into(),
            verification_method_id: format!("{issuer_did}#request"),
            signing_key_reference: "managed-request-key".into(),
            public_jwk: BTreeMap::from([
                ("kty".into(), json!("EC")),
                ("crv".into(), json!("P-256")),
                (
                    "x".into(),
                    json!("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"),
                ),
                (
                    "y".into(),
                    json!("T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"),
                ),
            ]),
            key_purpose: purpose.into(),
            credential_format: format.into(),
            algorithm: "ES256".into(),
        })
    }
    async fn sign(&self, _: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        unreachable!("request_uri is signed only on later canonical retrieval")
    }
}
#[async_trait]
impl FlowReferenceProvider for Ports {
    async fn resolve(
        &self,
        kind: FlowReferenceKind,
        id: &str,
        principal_id: &str,
        organization_id: &str,
    ) -> Result<FlowReference, FlowProviderError> {
        assert_eq!(principal_id, "urn:example:actual-delegate");
        assert_eq!(organization_id, self.organization_id);
        Ok(FlowReference {
            kind,
            id: id.into(),
            organization_id: Some(organization_id.into()),
            status: "active".into(),
            system_owned: false,
        })
    }
}

fn fixed_now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_794_934_801, 0).unwrap()
}

#[tokio::test]
async fn prepares_real_defined_flow_with_separate_audiences_and_delegate_role() {
    let fixture = Fixture::new(fixed_now()).await;
    let admission = fixture.admission().await;
    let id = admission.binding().challenge_id;
    let deadline = admission.valid_until();
    let prepared = prepare_delegated_verification_start(
        &fixture.providers,
        &fixture.configuration,
        fixture.definition.clone(),
        admission,
    )
    .await
    .unwrap();
    assert_eq!(prepared.instance.id, id.to_string());
    assert_eq!(prepared.instance.flow_definition_id, fixture.definition.id);
    assert_eq!(prepared.response.flow_definition_id, fixture.definition.id);
    assert_eq!(
        prepared.instance.subject_id.as_deref(),
        Some(fixture.grant.terms.delegate.id.as_str())
    );
    assert_eq!(prepared.instance.subject_type, "service_account");
    assert_ne!(
        prepared.instance.subject_id.as_deref(),
        Some(fixture.grant.terms.subject.id.as_str())
    );
    assert_eq!(
        prepared.instance.context["_marty_verification_principal_id"],
        fixture.grant.terms.delegate.id
    );
    assert_eq!(prepared.instance.expires_at, Some(deadline));
    let challenge = validate_delegation_snapshot(&prepared.instance).unwrap();
    assert_eq!(
        challenge.binding.audience,
        "https://consuming-domain.example"
    );
    assert_eq!(
        challenge.verifier_client_id,
        prepared.instance.context["oid4vp_client_id"]
            .as_str()
            .unwrap()
    );
    assert_ne!(challenge.verifier_client_id, challenge.binding.audience);
    assert!(challenge
        .verifier_client_id
        .starts_with("decentralized_identifier:did:"));
    assert_eq!(challenge.nonce.len(), 43);
    assert!(prepared
        .response
        .request_uri
        .starts_with("openid4vp://authorize?"));
    assert_eq!(challenge.expires_at, deadline);
}

#[tokio::test]
async fn revalidation_caps_both_deadlines_and_rejects_revoked_grant() {
    let fixture = Fixture::new(fixed_now()).await;
    let admission = fixture.admission().await;
    let mut prepared = prepare_delegated_verification_start(
        &fixture.providers,
        &fixture.configuration,
        fixture.definition.clone(),
        admission,
    )
    .await
    .unwrap();
    let shortened = fixture.clock.now() + Duration::seconds(10);
    *fixture.consent_until.lock().unwrap() = shortened;
    prepared.revalidate().await.unwrap();
    assert_eq!(prepared.instance.expires_at, Some(shortened));
    assert_eq!(
        prepared.response.expires_at,
        shortened.to_rfc3339_opts(SecondsFormat::AutoSi, true)
    );
    *fixture.consent_until.lock().unwrap() = shortened + Duration::minutes(1);
    prepared.revalidate().await.unwrap();
    assert_eq!(prepared.instance.expires_at, Some(shortened));
    fixture
        .clock
        .set(fixture.clock.now() + Duration::microseconds(1));
    fixture
        .lifecycle
        .revoke(
            fixture.grant.organization_id,
            fixture.grant.id,
            fixture.grant.revision,
        )
        .await
        .unwrap();
    assert!(prepared.revalidate().await.is_err());
}

#[tokio::test]
async fn preparation_rejects_foreign_changed_or_custom_definition_and_expired_admission() {
    let mutations: &[fn(&mut Fixture)] = &[
        |f| f.configuration.definition.organization_id = Uuid::new_v4().to_string(),
        |f| f.definition.organization_id = Uuid::new_v4().to_string(),
        |f| f.definition.version += 1,
        |f| f.definition.status = DefinitionStatus::Paused,
        |f| {
            f.definition
                .hooks
                .insert("on_start".into(), vec![json!({"kind":"custom"})]);
        },
    ];
    for mutate in mutations {
        let mut fixture = Fixture::new(fixed_now()).await;
        let admission = fixture.admission().await;
        mutate(&mut fixture);
        assert!(prepare_delegated_verification_start(
            &fixture.providers,
            &fixture.configuration,
            fixture.definition,
            admission
        )
        .await
        .is_err());
    }
    let fixture = Fixture::new(fixed_now()).await;
    let admission = fixture.admission().await;
    fixture.clock.set(admission.valid_until());
    assert!(prepare_delegated_verification_start(
        &fixture.providers,
        &fixture.configuration,
        fixture.definition,
        admission
    )
    .await
    .is_err());
}

struct PendingPolicy(Arc<AtomicBool>);
#[async_trait]
impl PresentationPolicyProvider for PendingPolicy {
    async fn get_policy(&self, _: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        self.0.store(true, Ordering::SeqCst);
        std::future::pending().await
    }
    async fn evaluate(
        &self,
        _: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        unreachable!()
    }
}

async fn reset_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql("DROP SCHEMA IF EXISTS flow_service CASCADE; DROP SCHEMA IF EXISTS deployment_profile_service CASCADE;
        CREATE SCHEMA deployment_profile_service;
        CREATE TABLE deployment_profile_service.deployment_profiles (
          id text PRIMARY KEY, organization_id text NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001', enabled_flow_ids jsonb NOT NULL DEFAULT '[]'::jsonb
        );").execute(pool).await?;
    Ok(())
}

#[tokio::test]
async fn postgres_guarded_start_roundtrip_preserves_bindings_and_blocks_legacy_finalization(
) -> TestResult {
    let Ok(database_url) = std::env::var("FLOW_POSTGRES_TEST_URL") else {
        eprintln!(
            "FLOW_POSTGRES_TEST_URL is not configured; delegated Flow PostgreSQL contract skipped"
        );
        return Ok(());
    };
    let options = PgConnectOptions::from_str(&database_url)?;
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(options.get_database(), Some("marty_atomic_test"));
    let _schema_lock = flow_schema::lock_shared_test_schemas(&options).await?;
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect_with(options)
        .await?;
    reset_schema(&pool).await?;
    migrate_flow_schema(&pool).await?;
    let repository = PostgresFlowRepository::new(pool.clone());
    let fixture = Fixture::new(Utc::now() - Duration::milliseconds(1)).await;
    repository.save_definition(&fixture.definition).await?;
    let admission = fixture.admission().await;
    let challenge_id = admission.binding().challenge_id;
    let response = fixture.starter(repository.clone()).start(admission).await?;
    assert_eq!(response.instance_id, challenge_id.to_string());
    let instance = repository.instance(&response.instance_id).await?.unwrap();
    let challenge = FlowDelegationOid4vpChallengeStore::new(repository.clone())
        .load_active(
            fixture.grant.organization_id,
            fixture.grant.id,
            challenge_id,
        )
        .await?;
    assert_eq!(challenge.binding.actor, fixture.grant.terms.delegate);
    assert_eq!(
        challenge.binding.operation_digest,
        fixture
            .grant
            .terms
            .constraints
            .request_digest
            .clone()
            .unwrap()
    );
    assert_ne!(challenge.binding.audience, challenge.verifier_client_id);
    assert_eq!(instance.flow_definition_id, fixture.definition.id);
    assert_eq!(challenge.nonce, instance.context["nonce"].as_str().unwrap());

    assert!(repository.save_instance(&instance).await.is_err());
    assert!(repository
        .save_started_instance(&instance, None)
        .await
        .is_err());
    let mut stripped = instance.clone();
    stripped
        .context
        .as_object_mut()
        .unwrap()
        .remove(DELEGATION_FLOW_CONTEXT_KEY);
    stripped
        .context
        .as_object_mut()
        .unwrap()
        .remove(DELEGATION_VERIFIER_CLIENT_ID_KEY);
    assert!(!repository.save_instance(&stripped).await?);
    stripped.updated_at += Duration::microseconds(1);
    assert!(
        !repository
            .compare_and_swap_instance(&stripped, instance.status, instance.updated_at)
            .await?
    );

    let mutations: &[fn(&mut FlowInstanceRecord)] = &[
        |i| {
            i.context[DELEGATION_FLOW_CONTEXT_KEY]["operation_digest"] =
                json!(format!("sha256:{}", "c".repeat(64)))
        },
        |i| {
            i.context[DELEGATION_VERIFIER_CLIENT_ID_KEY] = json!("https://attacker.example");
            i.context["oid4vp_client_id"] = json!("https://attacker.example");
        },
        |i| {
            i.context["nonce"] = json!("changed-single-use-nonce-123456");
            i.context["_marty_presentation_request_v1"]["nonce"] = i.context["nonce"].clone();
        },
        |i| i.subject_id = Some("urn:example:represented-organization".into()),
        |i| i.subject_type = "organization".into(),
        |i| i.status = FlowInstanceStatus::Completed,
        |i| {
            i.status = FlowInstanceStatus::Completed;
            i.completed_at = Some(i.updated_at + Duration::microseconds(1));
            i.result = Some(json!({"decision":"allow"}));
        },
        |i| i.result = Some(json!({"decision":"allow"})),
        |i| i.expires_at = i.expires_at.map(|expiry| expiry + Duration::seconds(1)),
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut changed = instance.clone();
        mutate(&mut changed);
        changed.updated_at += Duration::microseconds(1);
        assert!(
            !matches!(
                repository
                    .compare_and_swap_instance(&changed, instance.status, instance.updated_at)
                    .await,
                Ok(true)
            ),
            "accepted change {index}"
        );
    }
    let mut completed = instance.clone();
    completed.status = FlowInstanceStatus::Completed;
    completed.result = Some(json!({"decision":"allow"}));
    completed.completed_at = Some(Utc::now());
    completed.updated_at += Duration::microseconds(1);
    assert!(repository
        .finalize_verification(
            &completed,
            &"a".repeat(64),
            u64::try_from(challenge.expires_at.timestamp_millis())?,
            &instance,
            None
        )
        .await
        .is_err());
    let consumed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM flow_service.flow_nonce_consumptions WHERE flow_instance_id=$1",
    )
    .bind(&instance.id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(consumed, 0);

    let mut retrieved = instance.clone();
    retrieved.context["request_retrieved"] = json!(true);
    retrieved.updated_at += Duration::microseconds(1);
    assert!(
        repository
            .compare_and_swap_instance(&retrieved, instance.status, instance.updated_at)
            .await?
    );
    let mut expired = retrieved.clone();
    expired.status = FlowInstanceStatus::Expired;
    expired.completed_at = Some(Utc::now());
    expired.updated_at = expired.completed_at.unwrap();
    assert!(
        repository
            .compare_and_swap_instance(&expired, retrieved.status, retrieved.updated_at)
            .await?
    );
    assert!(FlowDelegationOid4vpChallengeStore::new(repository.clone())
        .load_active(
            fixture.grant.organization_id,
            fixture.grant.id,
            challenge_id
        )
        .await
        .is_err());

    // A provider that never returns must time out before any instance is saved.
    let mut starter = fixture.starter(repository.clone());
    let policy_called = Arc::new(AtomicBool::new(false));
    starter.providers.presentation_policy = Some(Arc::new(PendingPolicy(policy_called.clone())));
    starter.preparation_timeout = std::time::Duration::from_millis(500);
    let admission = fixture.admission().await;
    let timed_out_id = admission.binding().challenge_id;
    assert!(
        matches!(starter.start(admission).await, Err(FlowDelegationStartError::Preparation { challenge_id }) if challenge_id == timed_out_id)
    );
    assert!(repository
        .instance(&timed_out_id.to_string())
        .await?
        .is_none());
    assert!(policy_called.load(Ordering::SeqCst));

    // A configuration race after preparation cannot persist a stale definition.
    let starter = fixture.starter(repository.clone());
    let mut prepared = starter.prepare(fixture.admission().await).await?;
    let changed_id = prepared.instance.id.clone();
    let mut changed_definition = repository
        .definition(&fixture.definition.id)
        .await?
        .unwrap();
    changed_definition.version += 1;
    repository.save_definition(&changed_definition).await?;
    assert!(repository
        .save_delegated_verification_start(&mut prepared)
        .await
        .is_err());
    assert!(repository.instance(&changed_id).await?.is_none());
    repository.save_definition(&fixture.definition).await?;

    // A database write that outlives evidence must roll back despite a frozen
    // application clock. The trigger is confined to this fresh test schema.
    *fixture.consent_until.lock().unwrap() = Utc::now() + Duration::milliseconds(500);
    let mut prepared = starter.prepare(fixture.admission().await).await?;
    let delayed_id = prepared.instance.id.clone();
    sqlx::raw_sql("CREATE FUNCTION flow_service.delay_delegation_test_insert() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_sleep(0.8); RETURN NEW; END $$;
        CREATE TRIGGER delay_delegation_test_insert BEFORE INSERT ON flow_service.flow_instances
        FOR EACH ROW EXECUTE FUNCTION flow_service.delay_delegation_test_insert();").execute(&pool).await?;
    assert!(repository
        .save_delegated_verification_start(&mut prepared)
        .await
        .is_err());
    assert!(repository.instance(&delayed_id).await?.is_none());
    sqlx::raw_sql(
        "DROP SCHEMA flow_service CASCADE; DROP SCHEMA deployment_profile_service CASCADE;",
    )
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}
