//! Actual Credential Template and Presentation Policy read owners for the
//! opt-in network lifecycle gate. Provisioning uses each owner's validated
//! domain records and PostgreSQL repository under the disposable administrator.
//! Human administration, template activation dependencies, and presentation
//! evaluation are outside this gate: those unused application ports fail closed.
//! The served reads use the production applications, serializers, authentication,
//! generated gRPC services, and remotely held TLS keys, without wire responses.

use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use marty_credential_template::{
    application::{
        ControlPlaneError, CredentialTemplateApplication, CredentialTemplateControlPlane,
        IssuerIdentity,
    },
    credential_template_proto::{
        credential_template_service_client::CredentialTemplateServiceClient,
        credential_template_service_server::CredentialTemplateServiceServer, GetTemplateRequest,
        ListWalletsRequest,
    },
    grpc_service::CredentialTemplateGrpcService,
    registry_application::CredentialTemplateRegistryApplication,
    validate_protocol_requirements, ClaimDefinition, CredentialFormat, CredentialTemplate,
    DisplayStyle, IssuanceProtocol, IssuerRequirements, PostgresCredentialTemplateStore,
    PrivacyPosture, TemplateStatus, ValidityRules,
};
use marty_presentation_policy::{
    presentation_policy_proto::{
        presentation_policy_service_client::PresentationPolicyServiceClient,
        presentation_policy_service_server::PresentationPolicyServiceServer,
        EvaluatePresentationRequest as EvaluatePresentationMessage, GetPolicyRequest,
        PolicyIdRequest,
    },
    EvaluatePresentationRequest, PolicyApplication, PolicyAuthorization, PostgresPolicyStore,
    PresentationGrpcSecurity, PresentationPolicy, PresentationPolicyGrpcService,
    PresentationPolicyServiceConfig, PresentationVerificationError,
    PresentationVerificationOrchestrator, WorkloadServerTlsFiles,
};
use marty_service_runtime::{keyless_incoming, wait_for_shutdown};
use mmf_platform::KeylessGrpcTransportOptions;
use serde_json::{json, Value};
use sqlx::PgPool;
use tonic::{Code, Request};
use uuid::Uuid;

use super::live_support::{identity, setting, Server, SERVICE_TOKEN};
use crate::support::{owned::now, TestResult};

// Existing owner migration 0002 binds otherwise-unclassified nested VC-JWT
// templates to this OID4VC Core baseline. This is the explicit catalog reference
// required by template provisioning, not a compliance evaluation in this gate.
const OID4VC_CORE_PROFILE_ID: &str = "10000000-0000-0000-0000-000000000001";

pub struct LifecycleOwners {
    pub template: CredentialTemplate,
    pub policy: PresentationPolicy,
    pub template_server: Server,
    pub policy_server: Server,
}

impl LifecycleOwners {
    pub async fn start(
        admin: &PgPool,
        organization: Uuid,
        credential_issuer: &str,
    ) -> TestResult<Self> {
        marty_credential_template::migration::migrate_credential_template_schema(admin).await?;
        marty_presentation_policy::migrate_presentation_policy_schema(admin).await?;
        let template_store = Arc::new(PostgresCredentialTemplateStore::new(admin.clone()));
        let policy_store = Arc::new(PostgresPolicyStore::new(admin.clone()));
        let template = machine_template(organization, credential_issuer)?;
        template_store.save_template(&template).await?;
        assert_eq!(
            template_store.template_by_id(&template.id).await?.as_ref(),
            Some(&template)
        );
        // Persist the owner's actual generic wallet catalog entry so ListWallets
        // is also backed by the registry owner when a provider requests it.
        let wallet = marty_credential_template::catalog::system_wallet_catalog(now())
            .into_iter()
            .find(|wallet| wallet.id == "wr-default")
            .ok_or("generic owner wallet catalog entry is missing")?;
        template_store.save_wallet(&wallet).await?;
        let policy = machine_policy(organization, &template.id)?;
        policy_store.save_policy(&policy).await?;
        assert_eq!(
            policy_store.policy_by_id(policy.id).await?.as_ref(),
            Some(&policy)
        );

        let unused = Arc::new(UnusedAdministration);
        let template_application = Arc::new(CredentialTemplateApplication::new(
            template_store.clone(),
            unused.clone(),
        ));
        let template_registry = Arc::new(CredentialTemplateRegistryApplication::new(
            template_store.clone(),
            template_store,
            unused.clone(),
        ));
        let template_service = CredentialTemplateGrpcService::new(
            template_application,
            template_registry,
            Some(SERVICE_TOKEN.into()),
            true,
        )?;
        let policy_application = Arc::new(PolicyApplication::new(policy_store, unused));

        let files = identity("MARTY_TEST_POLICY_GRPC_SERVER_TLS", None)?;
        let ca = PathBuf::from(setting("MARTY_TEST_POLICY_WORKLOAD_CA_CERT"));
        let mut policy_config = PresentationPolicyServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            (
                "DATABASE_URL".into(),
                "postgres://localhost/disposable_owner_configuration".into(),
            ),
        ])?;
        // The server is composed with the real security constructor. The
        // disposable pool above is already connected; this URL is not opened.
        policy_config.workload_server_tls = Some(WorkloadServerTlsFiles {
            ca_certificate: ca,
            identity: files.clone(),
        });
        let policy_security = Arc::new(PresentationGrpcSecurity::from_config(&policy_config)?);
        let policy_service = PresentationPolicyGrpcService::new(
            policy_application,
            Arc::new(UnusedEvaluation),
            Some(SERVICE_TOKEN.into()),
            true,
        )?
        .with_workload_security(policy_security.clone());
        let template_acceptor = files
            .grpc_acceptor_without_client_auth(8, Duration::from_secs(5))
            .await?;
        let policy_acceptor = policy_security
            .server_tls_acceptor()
            .await?
            .ok_or("policy owner workload TLS is required")?;

        let template_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let template_address = template_listener.local_addr()?;
        let policy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let policy_address = policy_listener.local_addr()?;
        let (template_stop, mut template_shutdown) = tokio::sync::watch::channel(false);
        let (policy_stop, mut policy_shutdown) = tokio::sync::watch::channel(false);
        let template_task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    CredentialTemplateServiceServer::new(template_service)
                        .max_decoding_message_size(65_536)
                        .max_encoding_message_size(262_144),
                )
                .serve_with_incoming_shutdown(
                    keyless_incoming(template_listener, template_acceptor),
                    async move { wait_for_shutdown(&mut template_shutdown).await },
                )
                .await
                .map_err(|_| "actual credential template owner server failed".to_owned())
        });
        let policy_task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    PresentationPolicyServiceServer::new(policy_service)
                        .max_decoding_message_size(65_536)
                        .max_encoding_message_size(262_144),
                )
                .serve_with_incoming_shutdown(
                    keyless_incoming(policy_listener, policy_acceptor),
                    async move { wait_for_shutdown(&mut policy_shutdown).await },
                )
                .await
                .map_err(|_| "actual presentation policy owner server failed".to_owned())
        });
        Ok(Self {
            template,
            policy,
            template_server: Server::new(template_address, template_stop, template_task),
            policy_server: Server::new(policy_address, policy_stop, policy_task),
        })
    }

    /// Exercise actual owner serializers and authorization through TLS with the
    /// dedicated delegated-use certificate, never a borrowed Flow identity.
    pub async fn assert_read_authentication(&self) -> TestResult<()> {
        let client_identity = identity("MARTY_TEST_USE_WORKLOAD_TLS", None)?;
        let ca = PathBuf::from(setting("MARTY_TEST_POLICY_WORKLOAD_CA_CERT"));
        let template_channel = client_identity
            .grpc_channel_connected(
                &self.template_server.origin(),
                &ca,
                KeylessGrpcTransportOptions::default(),
            )
            .await?;
        let mut templates = CredentialTemplateServiceClient::new(template_channel);
        let read = templates
            .get_template(authenticated(GetTemplateRequest {
                template_id: self.template.id.clone(),
            }))
            .await?
            .into_inner();
        assert_eq!(read.id, self.template.id);
        assert_eq!(read.organization_id, self.template.organization_id);
        assert_eq!(read.status, "active");
        assert_eq!(
            read.issuer_did,
            self.template.issuer_did.as_deref().unwrap()
        );
        assert_eq!(read.credential_type, "MachineCredential");
        assert_eq!(read.compliance_profile_id, OID4VC_CORE_PROFILE_ID);
        assert_eq!(read.credential_payload_format, "jwt_vc");
        assert_eq!(read.supported_formats, ["jwt_vc"]);
        assert_eq!(read.claims.len(), 1);
        assert_eq!(read.claims[0].name, "id");
        assert!(read.jwt_vc_profile_json.is_empty());
        assert_eq!(
            templates
                .get_template(GetTemplateRequest {
                    template_id: self.template.id.clone(),
                })
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            templates
                .get_template(authenticated(GetTemplateRequest {
                    template_id: Uuid::new_v4().to_string(),
                }))
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        let wallets = templates
            .list_wallets(authenticated(ListWalletsRequest {
                organization_id: self.template.organization_id.clone(),
                active_only: true,
            }))
            .await?
            .into_inner();
        assert!(wallets.wallets.iter().any(|wallet| {
            wallet.id == "wr-default"
                && wallet.is_active
                && wallet
                    .supported_formats
                    .iter()
                    .any(|format| format == "jwt_vc")
        }));

        let policy_channel = client_identity
            .grpc_channel_connected(
                &self.policy_server.origin(),
                &ca,
                KeylessGrpcTransportOptions::default(),
            )
            .await?;
        let mut policies = PresentationPolicyServiceClient::new(policy_channel);
        let read = policies
            .get_policy(authenticated(GetPolicyRequest {
                policy_id: self.policy.id.to_string(),
            }))
            .await?
            .into_inner();
        assert_eq!(read.id, self.policy.id.to_string());
        assert_eq!(
            read.organization_id,
            self.policy.organization_id.to_string()
        );
        assert_eq!(read.status, "active");
        assert!(read.holder_binding_required);
        assert_eq!(
            serde_json::from_str::<Value>(&read.credential_requirements_json)?,
            serde_json::to_value(&self.policy.credential_requirements)?
        );
        let revision = read
            .policy_revision
            .ok_or("actual policy revision missing")?;
        assert_eq!(revision.id, self.policy.id.to_string());
        assert_eq!(
            revision.content_digest,
            marty_presentation_policy::policy_revision(&self.policy)?.content_digest
        );
        assert_eq!(
            policies
                .get_policy(GetPolicyRequest {
                    policy_id: self.policy.id.to_string(),
                })
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            policies
                .get_policy(authenticated(GetPolicyRequest {
                    policy_id: Uuid::new_v4().to_string(),
                }))
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        assert_eq!(
            policies
                .evaluate_presentation(authenticated(EvaluatePresentationMessage {
                    policy_id: self.policy.id.to_string(),
                    ..Default::default()
                }))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        // Supplying a human header cannot turn these read owners into an
        // administrative fixture authority. The actual application denies it.
        let mut suspend = authenticated(PolicyIdRequest {
            policy_id: self.policy.id.to_string(),
        });
        suspend
            .metadata_mut()
            .insert("x-user-id", "untrusted-user".parse()?);
        assert_eq!(
            policies.suspend_policy(suspend).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        Ok(())
    }

    pub async fn close(&mut self) -> TestResult<()> {
        self.policy_server.close().await?;
        self.template_server.close().await?;
        Ok(())
    }
}

fn authenticated<T>(value: T) -> Request<T> {
    let mut request = Request::new(value);
    request.set_timeout(Duration::from_secs(10));
    request
        .metadata_mut()
        .insert("x-service-token", SERVICE_TOKEN.parse().unwrap());
    request
}

fn machine_template(organization: Uuid, issuer: &str) -> TestResult<CredentialTemplate> {
    let time = now();
    let id = Uuid::new_v4().to_string();
    let claim = ClaimDefinition::from_legacy_value(
        &id,
        0,
        &json!({
            "name":"id", "display_name":"Machine subject", "claim_type":"string",
            "required":true, "selectively_disclosable":false
        }),
    )?;
    let mut template = CredentialTemplate {
        id,
        organization_id: organization.to_string(),
        name: "Disposable delegated-use machine credential".into(),
        description: Some("Actual owner record for the selected network lifecycle gate".into()),
        status: TemplateStatus::Draft,
        credential_type: "MachineCredential".into(),
        vct: String::new(),
        doctype: None,
        claims: vec![claim],
        privacy_posture: PrivacyPosture::Standard,
        selective_disclosure_fields: vec![],
        zk_predicate_claims: vec![],
        derived_attributes: vec![],
        display_style: DisplayStyle::default(),
        validity_rules: ValidityRules {
            default_validity_days: 1,
            max_validity_days: 1,
            renewable: false,
            ..ValidityRules::default()
        },
        issuer_requirements: IssuerRequirements::default(),
        supported_formats: vec![CredentialFormat::VcJwt],
        credential_payload_format: CredentialFormat::VcJwt.canonical().into(),
        jwt_vc_profile: None,
        verification_prerequisite: None,
        wallet_configs: vec![],
        compliance_profile: None,
        compliance_profile_id: Some(OID4VC_CORE_PROFILE_ID.into()),
        application_template_id: None,
        trust_profile_id: None,
        revocation_profile_id: None,
        issuer_algorithm: Some("ES256".into()),
        issuer_did: Some(issuer.into()),
        issuance_protocol: "OID4VCI_PRE_AUTH".into(),
        version: 1,
        created_at: time,
        updated_at: time,
    };
    template.validate_definition()?;
    validate_protocol_requirements(
        template.compliance_profile_id.as_deref(),
        CredentialFormat::parse(&template.credential_payload_format)?,
        IssuanceProtocol::parse(Some(&template.issuance_protocol))?,
        &template.supported_formats,
        Some(&template.vct),
        template.doctype.as_deref(),
    )?;
    template.validate_jwt_vc_profile()?;
    template.activate(time)?;
    Ok(template)
}

fn machine_policy(organization: Uuid, template_id: &str) -> TestResult<PresentationPolicy> {
    let time = now();
    let mut policy: PresentationPolicy = serde_json::from_value(json!({
        "id":Uuid::new_v4(), "organization_id":organization,
        "name":"Disposable delegated-use machine presentation", "description":null,
        "status":"draft", "display_metadata":{
            "title":"Machine delegated-use proof", "description":"Selected operation",
            "purpose":"authorization", "purpose_description":null,
            "verifier_name":"Disposable delegated-use host", "verifier_logo_url":null,
            "privacy_policy_url":null, "terms_of_service_url":null
        },
        "required_claims":[], "accepted_credential_types":[],
        "credential_requirements":[{
            "id":Uuid::new_v4(), "credential_template_id":template_id,
            "display_name":"Machine credential", "description":null,
            "required":true, "credential_payload_format":"VC_JWT",
            "expected_securing_profile":
                marty_oid4vp_contract::jwt_vc_profile::JwtVcSecuringProfile::MartyNestedVc2JwtV1,
            "requested_claims":[], "trust_profile_id":null,
            "max_age_seconds":null, "require_fresh_issuance":false
        }],
        "alternative_requirements":[], "presentation_proof_required":true,
        "trust_profile_id":null, "holder_binding":{
            "required":true, "binding_methods":["DEVICE_KEY"],
            "proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],
            "proof_freshness":{
                "challenge_required":true, "audience_binding_required":true,
                "replay_detection_required":true
            }
        },
        "freshness":null, "issuer_constraints":null,
        "credential_ranking_strategy":"MINIMAL_DISCLOSURE", "credential_ranking_weights":null,
        "purpose":"Selected delegated operation", "compliance_profile_id":null,
        "prefer_predicates":false, "fallback_policy":null, "supported_circuits":[],
        "version":1, "created_at":time, "updated_at":time
    }))?;
    policy.validate()?;
    policy.activate(time)?;
    Ok(policy)
}

struct UnusedAdministration;

#[async_trait]
impl PolicyAuthorization for UnusedAdministration {
    async fn require(&self, _: &str, _: Uuid, _: &'static str) -> Result<(), String> {
        Err("human policy administration is not part of this read-owner gate".into())
    }
}

#[async_trait]
impl CredentialTemplateControlPlane for UnusedAdministration {
    async fn require_membership(&self, _: &str, _: &str) -> Result<(), ControlPlaneError> {
        Err(ControlPlaneError::MembershipRequired)
    }
    async fn require_wallet_admin(&self, _: &str, _: &str) -> Result<(), ControlPlaneError> {
        Err(ControlPlaneError::WalletAdminRequired)
    }
    async fn require_destination_admin(&self, _: &str, _: &str) -> Result<(), ControlPlaneError> {
        Err(ControlPlaneError::DestinationAdminRequired)
    }
    async fn organization_display_name(
        &self,
        _: &str,
    ) -> Result<Option<String>, ControlPlaneError> {
        Err(unused_control_plane())
    }
    async fn resolve_active_issuer(
        &self,
        _: &str,
        _: Option<&str>,
        _: &str,
    ) -> Result<IssuerIdentity, ControlPlaneError> {
        Err(unused_control_plane())
    }
    async fn require_active_revocation_profile(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), ControlPlaneError> {
        Err(unused_control_plane())
    }
    async fn require_trust_profile_accepts_issuer(
        &self,
        _: Option<&str>,
        _: &str,
    ) -> Result<(), ControlPlaneError> {
        Err(unused_control_plane())
    }
}

fn unused_control_plane() -> ControlPlaneError {
    ControlPlaneError::Unavailable(
        "template administration is not part of this read-owner gate".into(),
    )
}

struct UnusedEvaluation;

#[async_trait]
impl PresentationVerificationOrchestrator for UnusedEvaluation {
    async fn verify(
        &self,
        _: &PresentationPolicy,
        _: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError> {
        Err(PresentationVerificationError::Unavailable)
    }
}
