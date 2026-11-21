use super::*;
use crate::{
    approval::{organization_principal, user_principal},
    ApprovalAdapterPin, ApprovalDecision, Binding, BindingMethod,
    ConfiguredConsentEvidenceVerifier, ConsentEvidenceLookup, ConsentEvidenceVerifier,
    ConsentRecordProvider, ConsentRecordState, ConsentVerificationPurpose,
    ConsentVerificationRequest, DelegationAuthorityService, DelegationGrantRepository,
    PgConsentEvidenceProvider, PrincipalType, RepresentationAuthorityProvider,
    SystemDelegationClock,
};
use marty_organization::{
    domain::{JoinMechanism, Organization, OrganizationCreate, OrganizationType, Permission, Role},
    migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore,
};
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe};

struct Fixture {
    owner: PgPool,
    read: PgPool,
    consent: PgPool,
    authority_pool: PgPool,
    organization_read: PgPool,
    service: PgOrganizationApprovalService,
    authority: Arc<PgOrganizationAuthorityProducer>,
    configuration: OrganizationApprovalConfiguration,
    grant: DelegationGrant,
    user: Uuid,
    role: Uuid,
}

impl Fixture {
    async fn new() -> Option<Self> {
        let url = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL").ok()?;
        let owner = PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        PgDelegationGrantRepository::new(owner.clone())
            .migrate()
            .await
            .unwrap();
        migrate_organization_schema(&owner).await.unwrap();
        let organization_store = PostgresOrganizationStore::new(owner.clone());
        let user = Uuid::new_v4();
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Approval {}", Uuid::new_v4()),
            owner_id: user.to_string(),
            org_type: OrganizationType::Enterprise,
            display_name: None,
            description: None,
            join_mechanism: JoinMechanism::Invite,
            requires_approval: true,
            is_discoverable: false,
            now: Utc::now(),
        })
        .unwrap();
        organization_store
            .save_organization(&organization)
            .await
            .unwrap();
        organization_store.save_member(&member).await.unwrap();
        let mut permissions = Vec::new();
        for action in ["view", "approve"] {
            let permission = if let Some(p) = organization_store
                .permission_by_key("delegation-grant", action)
                .await
                .unwrap()
            {
                p
            } else {
                let p = Permission::new("delegation-grant", action);
                organization_store.save_permission(&p).await.unwrap();
                p
            };
            permissions.push(permission);
        }
        let role = Role {
            id: Uuid::new_v4(),
            organization_id: organization.id,
            name: "approval-test-permission-holder".into(),
            display_name: None,
            description: None,
            is_system: false,
            is_default_for_new_members: false,
            permissions,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        organization_store.save_role(&role).await.unwrap();
        organization_store
            .add_member_role(member.id, role.id)
            .await
            .unwrap();

        let mut template = crate::test_support::pending_grant();
        template.authority.issuer = organization_principal(organization.id);
        template.terms.grantor = user_principal(user);
        template.terms.subject = organization_principal(organization.id);
        template.terms.binding = Binding {
            method: BindingMethod::Key,
            key_thumbprint: Some(format!("sha256:{}", "3e".repeat(32))),
            session_ref: None,
            establishment_evidence_ref: None,
        };
        template.terms.valid_from = Utc::now() - Duration::seconds(1);
        template.terms.valid_until = Utc::now() + Duration::hours(1);
        let grant = DelegationGrant::pending(
            organization.id,
            template.authority,
            template.terms,
            Utc::now() - Duration::seconds(1),
        )
        .unwrap();
        PgDelegationGrantRepository::new(owner.clone())
            .insert(grant.clone())
            .await
            .unwrap();
        let configuration = OrganizationApprovalConfiguration::new(
            organization.id,
            organization_principal(organization.id),
            ApprovalAdapterPin {
                profile: "urn:example:organization-approval:v1".into(),
                version: "1.0.0".into(),
                artifact_digest: format!("sha256:{}", "a7".repeat(32)),
            },
            120,
            300,
            15,
        )
        .unwrap();
        let mut pools = Vec::new();
        for purpose in ["read", "consent", "authority", "organization"] {
            let role_name = format!("approval_{}_{}", purpose, Uuid::new_v4().simple());
            // Audited test-only identifiers: a fixed prefix plus a generated
            // UUID, not external SQL text. Values remain normal bind parameters.
            assert!(role_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role_name} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;")))
                .execute(&owner).await.unwrap();
            if purpose == "organization" {
                sqlx::raw_sql(AssertSqlSafe(format!("GRANT USAGE ON SCHEMA organization_service TO {role_name}; GRANT SELECT ON ALL TABLES IN SCHEMA organization_service TO {role_name};")))
                    .execute(&owner).await.unwrap();
            } else {
                sqlx::raw_sql(AssertSqlSafe(format!("GRANT USAGE ON SCHEMA delegated_authority_service TO {role_name}; GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(TEXT) TO {role_name};")))
                    .execute(&owner).await.unwrap();
                let read_tables = match purpose {
                    "consent" => &CONSENT_READ_TABLES[..],
                    "authority" => &[
                        "delegation_grants",
                        "representation_authority_sources",
                        "representation_authority_assertions",
                        "organization_authority_observations",
                        "approval_storage_identity",
                    ][..],
                    _ => &EVIDENCE_READ_TABLES[..],
                };
                for table in read_tables {
                    sqlx::raw_sql(AssertSqlSafe(format!(
                        "GRANT SELECT ON delegated_authority_service.{table} TO {role_name}"
                    )))
                    .execute(&owner)
                    .await
                    .unwrap();
                }
                let tables = match purpose {
                    "consent" => &CONSENT_WRITE_TABLES[..],
                    "authority" => &AUTHORITY_WRITE_TABLES[..],
                    _ => &[],
                };
                for table in tables {
                    sqlx::raw_sql(AssertSqlSafe(format!(
                        "GRANT INSERT ON delegated_authority_service.{table} TO {role_name}"
                    )))
                    .execute(&owner)
                    .await
                    .unwrap();
                }
            }
            let mut role_url = url::Url::parse(&url).unwrap();
            role_url.set_username(&role_name).unwrap();
            pools.push(
                PgPoolOptions::new()
                    .max_connections(4)
                    .connect(role_url.as_str())
                    .await
                    .unwrap(),
            );
        }
        let read = pools.remove(0);
        let consent = pools.remove(0);
        let authority_pool = pools.remove(0);
        let organization_read = pools.remove(0);
        let authority = Arc::new(PgOrganizationAuthorityProducer::new(
            PostgresOrganizationStore::new(organization_read.clone()),
            authority_pool.clone(),
            configuration.clone(),
            Arc::new(SystemDelegationClock),
        ));
        let service = PgOrganizationApprovalService::new(
            read.clone(),
            consent.clone(),
            authority.clone(),
            configuration.clone(),
            Arc::new(SystemDelegationClock),
        )
        .unwrap();
        Some(Self {
            owner,
            read,
            consent,
            authority_pool,
            organization_read,
            service,
            authority,
            configuration,
            grant,
            user,
            role: role.id,
        })
    }
    fn session(&self) -> AuthenticatedApprovalSession {
        let now = Utc::now();
        AuthenticatedApprovalSession::from_authenticated_gateway_context(
            self.grant.organization_id,
            self.user,
            format!("urn:marty:session:sha256:{}", "6b".repeat(32)),
            now,
            now + Duration::seconds(25),
        )
        .unwrap()
    }
    fn reference(&self) -> CommandGrantReference {
        CommandGrantReference {
            id: self.grant.id,
            revision: self.grant.revision,
            terms_digest: self.grant.terms_digest.clone(),
        }
    }
    fn request(&self) -> ExplicitApprovalConfirmation {
        ExplicitApprovalConfirmation {
            confirmation_id: Uuid::new_v4(),
            terms_digest: self.grant.terms_digest.clone(),
            decision: ApprovalDecision::Confirm,
        }
    }
    async fn confirmed(
        &self,
    ) -> (
        ApprovalReview,
        ExplicitApprovalConfirmation,
        ApprovalConfirmation,
    ) {
        let review = self
            .service
            .review(&self.session(), &self.reference())
            .await
            .unwrap();
        let request = self.request();
        let result = self
            .service
            .confirm(&self.session(), self.grant.id, review.review_id, &request)
            .await
            .unwrap();
        (review, request, result)
    }
    async fn remove_approve(&self) {
        sqlx::query("DELETE FROM organization_service.role_permissions WHERE role_id=$1 AND permission_id IN
            (SELECT id FROM organization_service.permissions WHERE resource='delegation-grant' AND action='approve')")
            .bind(self.role).execute(&self.owner).await.unwrap();
    }
    async fn evidence(&self, confirmation_id: Uuid) -> ApprovalEvidence {
        PgApprovalConfirmationSource::new(
            self.read.clone(),
            self.configuration.clone(),
            Arc::new(SystemDelegationClock),
        )
        .resolve_confirmation(
            &self.session().command_caller().unwrap(),
            &self.grant,
            confirmation_id,
            Utc::now(),
        )
        .await
        .unwrap()
    }
    async fn count(&self, table: &str) -> i64 {
        // Table names are checked fixed literals, never request text.
        assert!(EVIDENCE_READ_TABLES.contains(&table));
        sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT count(*) FROM delegated_authority_service.{table} WHERE organization_id=$1"
        )))
        .bind(self.grant.organization_id)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }
}

#[test]
fn caller_shape_never_deserializes_trust_or_accepts_aliases() {
    let org = Uuid::new_v4();
    let user = Uuid::new_v4();
    let now = Utc::now();
    for reference in [
        "session-cookie",
        "urn:marty:session:sha256:short",
        &format!("urn:marty:session:sha256:{}", "AB".repeat(32)),
    ] {
        assert!(
            AuthenticatedApprovalSession::from_authenticated_gateway_context(
                org,
                user,
                reference.into(),
                now,
                now + Duration::seconds(15)
            )
            .is_err()
        );
    }
    assert!(
        AuthenticatedApprovalSession::from_authenticated_gateway_context(
            org,
            user,
            format!("urn:marty:session:sha256:{}", "ab".repeat(32)),
            now,
            now + Duration::seconds(31)
        )
        .is_err()
    );
    assert!(crate::approval::canonical_user_id(&crate::Principal {
        principal_type: PrincipalType::User,
        id: user.to_string()
    })
    .is_none());
    assert!(crate::approval::canonical_user_id(&crate::Principal {
        principal_type: PrincipalType::External,
        id: format!("urn:marty:user:{user}")
    })
    .is_none());
    assert!(serde_json::from_value::<ExplicitApprovalConfirmation>(serde_json::json!({"confirmation_id":Uuid::new_v4(),"terms_digest":format!("sha256:{}","aa".repeat(32)),"decision":"CONFIRM","authenticated":true})).is_err());
    assert!(serde_json::from_value::<ExplicitApprovalConfirmation>(serde_json::json!({"confirmation_id":Uuid::new_v4(),"terms_digest":format!("sha256:{}","aa".repeat(32)),"decision":true})).is_err());
}

#[tokio::test]
async fn postgres_explicit_key_consent_is_durable_and_activates_only_through_existing_verifier() {
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.service.readiness().await.unwrap();
    let (review, request, result) = f.confirmed().await;
    assert_eq!(review.terms, f.grant.terms);
    assert_eq!(review.confirmation_max_age_seconds, 300);
    assert_eq!(
        result.valid_until,
        result.confirmed_at + Duration::seconds(300)
    );
    let pending = load_grant(&f.read, f.grant.organization_id, f.grant.id)
        .await
        .unwrap();
    assert_eq!(pending.status, crate::GrantStatus::Pending); // Login + confirmation did not activate.
    let evidence = f.evidence(request.confirmation_id).await;
    let verifier = Arc::new(
        ConfiguredConsentEvidenceVerifier::new(
            [f.configuration.consent_profile()],
            Arc::new(PgConsentEvidenceProvider::new(f.read.clone())),
            Arc::new(f.authority.read_provider(f.read.clone())),
        )
        .unwrap(),
    );
    let lifecycle = DelegationAuthorityService::new(
        Arc::new(PgDelegationGrantRepository::new(f.owner.clone())),
        verifier.clone(),
        f.grant.authority.clone(),
    )
    .unwrap();
    let active = lifecycle
        .approve(
            f.grant.organization_id,
            f.grant.id,
            f.grant.revision,
            &f.grant.terms.grantor,
            evidence,
        )
        .await
        .unwrap();
    assert_eq!(active.status, crate::GrantStatus::Active);
    verifier
        .verify_approval(ConsentVerificationRequest {
            grant: &active,
            approval: active.approval.as_ref().unwrap(),
            purpose: ConsentVerificationPurpose::Resolution,
            now: Utc::now(),
        })
        .await
        .unwrap();
    assert_eq!(f.count("approval_confirmation_bindings").await, 1);
    assert_eq!(f.count("organization_authority_observations").await, 1);
    let no_session = DelegationCommandCaller::from_authenticated_context(
        f.grant.organization_id,
        f.grant.terms.grantor.clone(),
    )
    .unwrap();
    assert!(PgApprovalConfirmationSource::new(
        f.read.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock)
    )
    .resolve_confirmation(&no_session, &f.grant, request.confirmation_id, Utc::now())
    .await
    .is_err());
}

#[tokio::test]
async fn postgres_concurrent_confirmation_replay_preserves_original_and_rejects_substitutions() {
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(f) = Fixture::new().await else {
        return;
    };
    let review = f
        .service
        .review(&f.session(), &f.reference())
        .await
        .unwrap();
    let request = f.request();
    let session = f.session();
    let (a, b) = tokio::join!(
        f.service
            .confirm(&session, f.grant.id, review.review_id, &request),
        f.service
            .confirm(&session, f.grant.id, review.review_id, &request)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a.recovered, b.recovered);
    assert_eq!(a.confirmed_at, b.confirmed_at);
    assert_eq!(a.valid_until, b.valid_until);
    assert_eq!(f.count("consent_confirmations").await, 1);
    assert_eq!(f.count("organization_authority_observations").await, 1);
    let mut altered = request.clone();
    altered.terms_digest = format!("sha256:{}", "99".repeat(32));
    assert_eq!(
        f.service
            .confirm(&f.session(), f.grant.id, review.review_id, &altered)
            .await
            .unwrap_err(),
        ApprovalProducerError::Conflict
    );
    let mut different_session = f.session();
    different_session.session_ref = format!("urn:marty:session:sha256:{}", "12".repeat(32));
    assert_eq!(
        f.service
            .confirm(&different_session, f.grant.id, review.review_id, &request)
            .await
            .unwrap_err(),
        ApprovalProducerError::Conflict
    );
    assert_eq!(
        f.service
            .confirm(&f.session(), Uuid::new_v4(), review.review_id, &request)
            .await
            .unwrap_err(),
        ApprovalProducerError::Conflict
    );
    let mut wrong_actor = f.session();
    wrong_actor.user_id = Uuid::new_v4();
    assert_eq!(
        f.service
            .confirm(&wrong_actor, f.grant.id, review.review_id, &request)
            .await
            .unwrap_err(),
        ApprovalProducerError::AccessDenied
    );
    f.remove_approve().await;
    let recovered = f
        .service
        .confirm(&f.session(), f.grant.id, review.review_id, &request)
        .await
        .unwrap();
    assert!(recovered.recovered);
    assert_eq!(recovered.confirmed_at, a.confirmed_at);
    assert_eq!(f.count("organization_authority_observations").await, 1);
}

#[tokio::test]
async fn postgres_current_authority_revocation_and_withdrawal_are_independent_of_historical_consent(
) {
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (review, request, original) = f.confirmed().await;
    let evidence = f.evidence(request.confirmation_id).await;
    let binding = ConsentEvidenceBinding {
        organization_id: f.grant.organization_id,
        grant_id: f.grant.id,
        terms_digest: f.grant.terms_digest.clone(),
        grantor: f.grant.terms.grantor.clone(),
        subject: f.grant.terms.subject.clone(),
        issuer: f.grant.authority.issuer.clone(),
        evidence_ref: evidence.evidence_ref.clone(),
        authority_evidence_ref: evidence.authority_evidence_ref.clone(),
    };
    let lookup = ConsentEvidenceLookup {
        pin: &f.configuration.pin,
        binding: &binding,
    };
    f.authority
        .read_provider(f.read.clone())
        .resolve_authority(lookup)
        .await
        .unwrap();
    f.remove_approve().await;
    assert!(f
        .authority
        .read_provider(f.read.clone())
        .resolve_authority(lookup)
        .await
        .is_err());
    assert_eq!(
        f.authority
            .refresh_authority(f.grant.organization_id, &binding.authority_evidence_ref)
            .await
            .unwrap_err(),
        ApprovalProducerError::AccessDenied
    );
    let state:String = sqlx::query_scalar("SELECT state FROM delegated_authority_service.representation_authority_assertions WHERE organization_id=$1 ORDER BY revision DESC LIMIT 1")
        .bind(f.grant.organization_id).fetch_one(&f.read).await.unwrap();
    assert_eq!(state, "REVOKED");
    let still_consent = PgConsentEvidenceProvider::new(f.read.clone())
        .resolve_consent(lookup)
        .await
        .unwrap();
    assert_eq!(still_consent.state, ConsentRecordState::Confirmed);
    let mut new_session = f.session();
    new_session.session_ref = format!("urn:marty:session:sha256:{}", "cd".repeat(32));
    let withdrawn = f
        .service
        .withdraw(&new_session, f.grant.id, request.confirmation_id)
        .await
        .unwrap();
    let duplicate = f
        .service
        .withdraw(&new_session, f.grant.id, request.confirmation_id)
        .await
        .unwrap();
    assert!(!withdrawn.recovered && duplicate.recovered);
    assert_eq!(withdrawn.withdrawn_at, duplicate.withdrawn_at);
    assert!(PgApprovalConfirmationSource::new(
        f.read.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock)
    )
    .resolve_confirmation(
        &f.session().command_caller().unwrap(),
        &f.grant,
        request.confirmation_id,
        Utc::now()
    )
    .await
    .is_err());
    let recovered = f
        .service
        .confirm(&f.session(), f.grant.id, review.review_id, &request)
        .await
        .unwrap();
    assert_eq!(recovered.confirmed_at, original.confirmed_at);
}

#[tokio::test]
async fn postgres_wrong_approver_digest_session_binding_and_missing_permission_do_not_record_consent(
) {
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut other = f.session();
    other.user_id = Uuid::new_v4();
    assert_eq!(
        f.service.review(&other, &f.reference()).await.unwrap_err(),
        ApprovalProducerError::AccessDenied
    );
    let mut bad = f.reference();
    bad.terms_digest = format!("sha256:{}", "91".repeat(32));
    assert_eq!(
        f.service.review(&f.session(), &bad).await.unwrap_err(),
        ApprovalProducerError::Conflict
    );
    let review = f
        .service
        .review(&f.session(), &f.reference())
        .await
        .unwrap();
    let mut bad_request = f.request();
    bad_request.terms_digest = bad.terms_digest;
    assert_eq!(
        f.service
            .confirm(&f.session(), f.grant.id, review.review_id, &bad_request)
            .await
            .unwrap_err(),
        ApprovalProducerError::Conflict
    );
    let mut other_session = f.session();
    other_session.session_ref = format!("urn:marty:session:sha256:{}", "a9".repeat(32));
    assert_eq!(
        f.service
            .confirm(&other_session, f.grant.id, review.review_id, &f.request())
            .await
            .unwrap_err(),
        ApprovalProducerError::AccessDenied
    );
    f.remove_approve().await;
    assert_eq!(
        f.service
            .confirm(&f.session(), f.grant.id, review.review_id, &f.request())
            .await
            .unwrap_err(),
        ApprovalProducerError::AccessDenied
    );
    // The member remains the organization's recorded owner; that cannot replace the permission.
    assert_eq!(
        f.service
            .review(&f.session(), &f.reference())
            .await
            .unwrap_err(),
        ApprovalProducerError::AccessDenied
    );
    assert_eq!(f.count("consent_confirmations").await, 0);
    let mut unsupported = f.grant.clone();
    unsupported.terms.binding = crate::test_support::pending_grant().terms.binding;
    unsupported.terms_digest = unsupported.calculate_terms_digest().unwrap();
    assert!(f.configuration.check_grant(&unsupported).is_err());
}

#[tokio::test]
async fn postgres_expired_source_is_not_renewed_by_reads_and_source_outage_denies() {
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    f.configuration.authority_validity_seconds = 1;
    f.authority = Arc::new(PgOrganizationAuthorityProducer::new(
        PostgresOrganizationStore::new(f.organization_read.clone()),
        f.authority_pool.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock),
    ));
    f.service = PgOrganizationApprovalService::new(
        f.read.clone(),
        f.consent.clone(),
        f.authority.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock),
    )
    .unwrap();
    let (_, request, _) = f.confirmed().await;
    let evidence = f.evidence(request.confirmation_id).await;
    let binding = ConsentEvidenceBinding {
        organization_id: f.grant.organization_id,
        grant_id: f.grant.id,
        terms_digest: f.grant.terms_digest.clone(),
        grantor: f.grant.terms.grantor.clone(),
        subject: f.grant.terms.subject.clone(),
        issuer: f.grant.authority.issuer.clone(),
        evidence_ref: evidence.evidence_ref,
        authority_evidence_ref: evidence.authority_evidence_ref,
    };
    let lookup = ConsentEvidenceLookup {
        pin: &f.configuration.pin,
        binding: &binding,
    };
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(f
        .authority
        .read_provider(f.read.clone())
        .resolve_authority(lookup)
        .await
        .is_err());
    assert_eq!(f.count("organization_authority_observations").await, 1);
    f.authority
        .refresh_authority(f.grant.organization_id, &binding.authority_evidence_ref)
        .await
        .unwrap();
    f.authority
        .read_provider(f.read.clone())
        .resolve_authority(lookup)
        .await
        .unwrap();
    assert_eq!(f.count("organization_authority_observations").await, 2);
    // A failed authoritative source is not replaced with old successful SQL evidence.
    f.organization_read.close().await;
    assert!(f
        .authority
        .read_provider(f.read.clone())
        .resolve_authority(lookup)
        .await
        .is_err());
}

#[tokio::test]
async fn postgres_role_separation_and_append_only_confirmation_guards_are_enforced() {
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.service.readiness().await.unwrap();
    f.confirmed().await;
    // Approval can operate with producer-owned evidence reads only. The
    // separate runtime reader supplies lifecycle snapshots; consent credentials
    // do not need access to command history or the authority producer's source.
    for table in ["command_results", "representation_authority_sources"] {
        let allowed: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user,format('delegated_authority_service.%I',$1::TEXT),'SELECT')",
        )
        .bind(table)
        .fetch_one(&f.consent)
        .await
        .unwrap();
        assert!(!allowed);
    }
    for pool in [&f.read, &f.consent, &f.authority_pool] {
        assert!(sqlx::query("DELETE FROM delegated_authority_service.approval_confirmation_bindings WHERE organization_id=$1")
            .bind(f.grant.organization_id).execute(pool).await.is_err());
    }
    assert!(sqlx::query("DELETE FROM delegated_authority_service.approval_confirmation_bindings WHERE organization_id=$1")
        .bind(f.grant.organization_id).execute(&f.owner).await.is_err());
    let consent_role = role_identity(&f.consent).await.unwrap();
    let authority_role = role_identity(&f.authority_pool).await.unwrap();
    for name in [&consent_role, &authority_role] {
        assert!(
            name.starts_with("approval_")
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
    }
    // NOINHERIT still allows SET ROLE: readiness must detect that escape.
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT {authority_role} TO {consent_role}"
    )))
    .execute(&f.owner)
    .await
    .unwrap();
    assert_eq!(
        f.service.readiness().await.unwrap_err(),
        ApprovalProducerError::NotReady
    );
    sqlx::raw_sql(AssertSqlSafe(format!(
        "REVOKE {authority_role} FROM {consent_role}"
    )))
    .execute(&f.owner)
    .await
    .unwrap();
    f.service.readiness().await.unwrap();
    // Column ACLs do not appear as whole-table UPDATE privileges.
    for (grant, revoke) in [
        (format!("GRANT UPDATE(terms_digest) ON delegated_authority_service.approval_reviews TO {consent_role}"),
         format!("REVOKE UPDATE(terms_digest) ON delegated_authority_service.approval_reviews FROM {consent_role}")),
        (format!("GRANT UPDATE(status) ON organization_service.members TO {consent_role}"),
         format!("REVOKE UPDATE(status) ON organization_service.members FROM {consent_role}")),
        (format!("GRANT INSERT ON organization_service.role_permissions TO {consent_role}"),
         format!("REVOKE INSERT ON organization_service.role_permissions FROM {consent_role}")),
        (format!("GRANT INSERT ON delegated_authority_service.consent_confirmations TO {consent_role} WITH GRANT OPTION"),
         format!("REVOKE GRANT OPTION FOR INSERT ON delegated_authority_service.consent_confirmations FROM {consent_role}")),
    ] {
        sqlx::raw_sql(AssertSqlSafe(grant)).execute(&f.owner).await.unwrap();
        assert_eq!(f.service.readiness().await.unwrap_err(), ApprovalProducerError::NotReady);
        sqlx::raw_sql(AssertSqlSafe(revoke)).execute(&f.owner).await.unwrap();
        f.service.readiness().await.unwrap();
    }
    // A familiar trigger name pointing to a different function is not the guard.
    sqlx::raw_sql("DROP TRIGGER approval_reviews_binding ON delegated_authority_service.approval_reviews;
        CREATE TRIGGER approval_reviews_binding BEFORE INSERT ON delegated_authority_service.approval_reviews
        FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();")
        .execute(&f.owner).await.unwrap();
    assert_eq!(
        f.service.readiness().await.unwrap_err(),
        ApprovalProducerError::NotReady
    );
    sqlx::raw_sql("DROP TRIGGER approval_reviews_binding ON delegated_authority_service.approval_reviews;
        CREATE TRIGGER approval_reviews_binding BEFORE INSERT ON delegated_authority_service.approval_reviews
        FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_approval_review();")
        .execute(&f.owner).await.unwrap();
    f.service.readiness().await.unwrap();
    let bad = PgOrganizationApprovalService::new(
        f.owner.clone(),
        f.consent.clone(),
        f.authority.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock),
    )
    .unwrap();
    assert_eq!(
        bad.readiness().await.unwrap_err(),
        ApprovalProducerError::NotReady
    );
}

#[tokio::test]
async fn postgres_expired_review_and_consent_cannot_be_renewed_by_retry() {
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    f.configuration.review_ttl_seconds = 1;
    f.configuration.confirmation_max_age_seconds = 1;
    f.service = PgOrganizationApprovalService::new(
        f.read.clone(),
        f.consent.clone(),
        f.authority.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock),
    )
    .unwrap();
    let expired = f
        .service
        .review(&f.session(), &f.reference())
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        f.service
            .confirm(&f.session(), f.grant.id, expired.review_id, &f.request())
            .await
            .unwrap_err(),
        ApprovalProducerError::Stale
    );
    assert_eq!(f.count("consent_confirmations").await, 0);
    assert_eq!(f.count("organization_authority_observations").await, 0);
    // A new deliberate review can confirm, but a committed consent lifetime is
    // immutable even when both the session and current authority remain valid.
    let (review, request, original) = f.confirmed().await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let recovered = f
        .service
        .confirm(&f.session(), f.grant.id, review.review_id, &request)
        .await
        .unwrap();
    assert!(recovered.recovered);
    assert_eq!(recovered.confirmed_at, original.confirmed_at);
    assert_eq!(recovered.valid_until, original.valid_until);
    assert!(recovered.valid_until < Utc::now());
    assert!(PgApprovalConfirmationSource::new(
        f.read.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock)
    )
    .resolve_confirmation(
        &f.session().command_caller().unwrap(),
        &f.grant,
        request.confirmation_id,
        Utc::now()
    )
    .await
    .is_err());
    assert_eq!(f.count("organization_authority_observations").await, 1);
}

#[tokio::test]
async fn postgres_authority_expiry_during_confirmation_rolls_back_consent_and_index_together() {
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    f.configuration.authority_validity_seconds = 1;
    f.authority = Arc::new(PgOrganizationAuthorityProducer::new(
        PostgresOrganizationStore::new(f.organization_read.clone()),
        f.authority_pool.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock),
    ));
    f.service = PgOrganizationApprovalService::new(
        f.read.clone(),
        f.consent.clone(),
        f.authority.clone(),
        f.configuration.clone(),
        Arc::new(SystemDelegationClock),
    )
    .unwrap();
    let review = f
        .service
        .review(&f.session(), &f.reference())
        .await
        .unwrap();
    let request = f.request();
    sqlx::raw_sql("CREATE FUNCTION public.approval_test_delay() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
        BEGIN PERFORM pg_sleep(1.1); RETURN NEW; END $$;
        CREATE TRIGGER approval_test_delay AFTER INSERT ON delegated_authority_service.approval_confirmation_bindings
        FOR EACH ROW EXECUTE FUNCTION public.approval_test_delay();")
        .execute(&f.owner).await.unwrap();
    let delayed = f
        .service
        .confirm(&f.session(), f.grant.id, review.review_id, &request)
        .await;
    sqlx::raw_sql("DROP TRIGGER approval_test_delay ON delegated_authority_service.approval_confirmation_bindings;
        DROP FUNCTION public.approval_test_delay();").execute(&f.owner).await.unwrap();
    assert_eq!(delayed.unwrap_err(), ApprovalProducerError::Stale);
    assert_eq!(f.count("consent_confirmations").await, 0);
    assert_eq!(f.count("approval_confirmation_bindings").await, 0);
    assert_eq!(f.count("organization_authority_observations").await, 1);
    assert_eq!(
        load_grant(&f.read, f.grant.organization_id, f.grant.id)
            .await
            .unwrap()
            .status,
        crate::GrantStatus::Pending
    );
    // The independently committed authority observation is not consent. A
    // deliberate retry uses the same review/request and performs a new current
    // source check before committing its first consent, without renewing review.
    let first_committed = f
        .service
        .confirm(&f.session(), f.grant.id, review.review_id, &request)
        .await
        .unwrap();
    assert!(!first_committed.recovered);
    assert_eq!(f.count("consent_confirmations").await, 1);
    assert_eq!(f.count("organization_authority_observations").await, 2);
}
