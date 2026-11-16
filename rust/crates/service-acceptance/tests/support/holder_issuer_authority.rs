//! Real PostgreSQL Trust Profile owner and production keyless HTTPS listener.
//! Only human membership/PDP decisions and issuer public metadata are fixtures.
use async_trait::async_trait;
use chrono::{Duration, Utc};
use marty_service_runtime::{
    https::{BoundKeylessHttpsServer, ManagedAuthorityHttpsConfig},
    RemoteTlsIdentityFiles, TlsIdentityNames,
};
use marty_trust_profile::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus,
    IssuerEntityType, PostgresTrustProfileRepository, TrustAuthorizationError, TrustProfile,
    TrustProfileApplication, TrustProfileControlPlane, TrustProfileHttpState, TrustProfileIssuer,
    TrustProfileRepository, TrustProfileStatus, TrustProfileType, TrustPurpose,
    TrustRegistrySyncError, TrustRegistrySynchronizer, TrustRelationshipStatus,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::watch;
use uuid::Uuid;

pub struct ControlledPdp {
    user: String,
    organization: String,
    pub allowed: AtomicBool,
}
#[async_trait]
impl TrustProfileControlPlane for ControlledPdp {
    async fn require_permission(
        &self,
        user: &str,
        organization: &str,
        _resource: &'static str,
        _action: &'static str,
    ) -> Result<(), TrustAuthorizationError> {
        if user == self.user
            && organization == self.organization
            && self.allowed.load(Ordering::SeqCst)
        {
            Ok(())
        } else {
            Err(TrustAuthorizationError::MembershipRequired)
        }
    }
}
struct NoRegistrySync;
#[async_trait]
impl TrustRegistrySynchronizer for NoRegistrySync {
    async fn synchronize(&self, _profile: TrustProfile) -> Result<Value, TrustRegistrySyncError> {
        panic!("issuer authority must not synchronize an external registry")
    }
}
pub struct Owner {
    pub origin: String,
    pub ca: Vec<u8>,
    pub repository: Arc<PostgresTrustProfileRepository>,
    pub relationship: TrustProfileIssuer,
    pub pdp: Arc<ControlledPdp>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Owner {
    pub async fn start(
        pool: &PgPool,
        profile_id: Uuid,
        user: &str,
        organization: &str,
        token: &str,
    ) -> Self {
        // The caller establishes fresh owned SQL before any migration.
        marty_trust_profile::run_migrations(pool).await.unwrap();
        let repository = Arc::new(PostgresTrustProfileRepository::new(pool.clone()));
        let now = Utc::now();
        let mut profile = TrustProfile {
            id: profile_id,
            organization_id: organization.into(),
            name: "Owned wallet issuer".into(),
            description: None,
            status: TrustProfileStatus::Active,
            profile_type: TrustProfileType::Custom,
            compliance_status: ComplianceStatus::Compliant,
            trust_purposes: Some(vec![TrustPurpose::CredentialIssuer]),
            trust_sources: vec![],
            validation_rules: Default::default(),
            allowed_issuers: None,
            denied_issuers: None,
            system_issuer_overrides: Default::default(),
            compatible_compliance_codes: vec![],
            verification_policy_set_id: None,
            auto_generated: false,
            revocation_policy: Default::default(),
            revocation_profile_id: None,
            time_policy: Default::default(),
            supported_formats: vec!["SD_JWT_VC".into()],
            trusted_assertion_formats: None,
            created_at: now,
            updated_at: now,
        };
        profile.revocation_policy.check_ocsp = false;
        profile.revocation_policy.check_crl = false;
        profile.revocation_policy.check_status_list = false;
        repository.save_profile(&profile, None).await.unwrap();
        // Public-only synthetic issuer identity. This acceptance test exercises
        // governance transport; credential signing is qualified by native tests.
        let issuer = IssuerEntity {
            id: Uuid::new_v4(),
            organization_id: Some(organization.into()),
            issuer_id: "did:web:issuer.example".into(),
            issuer_type: IssuerEntityType::Organization,
            display_name: "Owned issuer fixture".into(),
            description: None,
            is_system_issuer: false,
            compliance_status: IssuerEntityComplianceStatus::Compliant,
            accreditation_body: None,
            accreditations: vec![],
            accreditation_date: None,
            valid_from: now - Duration::minutes(1),
            valid_until: Some(now + Duration::hours(1)),
            trust_anchor_id: None,
            metadata: json!({"verification_keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"owned-issuer-public-key",
                "x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}]}),
            revoked_at: None,
            revocation_reason: None,
            revoked_by: None,
            created_at: now,
            updated_at: now,
        };
        repository.save_issuer_entity(&issuer).await.unwrap();
        let relationship = TrustProfileIssuer {
            id: Uuid::new_v4(),
            trust_profile_id: profile_id,
            issuer_id: issuer.id,
            trust_level: 100,
            relationship_status: TrustRelationshipStatus::Trusted,
            cascade_revocation_policy: CascadeRevocationPolicy::NotifyOnly,
            metadata: json!({"marty_credential_authorizations_v1":[{"format":"SD_JWT_VC","vct":"urn:elevenid:credential:identity"}],
                "marty_wallet_issuance_authorizations_v1":[{"credential_issuer":"https://credential-service.example/tenant",
                    "credential_configuration_id":"identity","format":"dc+sd-jwt","vct":"urn:elevenid:credential:identity",
                    "authorization_server":null,"token_endpoint":null}]}),
            created_at: now,
            updated_at: now,
        };
        repository.save_profile_issuer(&relationship).await.unwrap();
        let pdp = Arc::new(ControlledPdp {
            user: user.into(),
            organization: organization.into(),
            allowed: AtomicBool::new(true),
        });
        let app = marty_trust_profile::trust_credential_authority_router(TrustProfileHttpState {
            flow_owner: None,
            application: Arc::new(TrustProfileApplication::new(
                repository.clone(),
                pdp.clone(),
            )),
            repository: repository.clone(),
            service_authenticator: Arc::new(
                mmf_security::ServiceTokenAuthenticator::new(Some(token.into()), true).unwrap(),
            ),
            internal_api_key: None,
            registry_synchronizer: Arc::new(NoRegistrySync),
        })
        .layer(axum::middleware::from_fn(
            |request: axum::extract::Request, next: axum::middleware::Next| async move {
                // The production Device client must use its own service token and
                // pairing-derived user, never forward the mobile bearer.
                assert!(!request.headers().contains_key("authorization"));
                next.run(request).await
            },
        ));
        let values: BTreeMap<String, String> = std::env::vars().collect();
        let identity = RemoteTlsIdentityFiles::from_values(
            |name| values.get(name).map(String::as_str),
            TlsIdentityNames::files("MARTY_TEST_POLICY_OWNER_TLS"),
            std::time::Duration::from_secs(5),
            16,
        )
        .unwrap()
        .unwrap();
        let ca = std::fs::read(values.get("MARTY_TEST_POLICY_OWNER_CA_CERT").unwrap()).unwrap();
        let listener = BoundKeylessHttpsServer::bind(
            &ManagedAuthorityHttpsConfig {
                address: "127.0.0.1:0".parse().unwrap(),
                identity,
            },
            app,
        )
        .await
        .unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(listener.serve(receiver));
        Self {
            origin,
            ca,
            repository,
            relationship,
            pdp,
            shutdown,
            task,
        }
    }
    pub async fn stop(self) {
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
