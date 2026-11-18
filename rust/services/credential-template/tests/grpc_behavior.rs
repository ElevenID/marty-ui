use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::Utc;
use marty_credential_template::{
    application::{
        ControlPlaneError, CredentialTemplateApplication, CredentialTemplateControlPlane,
        CredentialTemplateRepository, IssuerIdentity,
    },
    catalog::{system_delivery_destination_catalog, system_wallet_catalog},
    credential_template_proto::{
        credential_template_service_server::CredentialTemplateService, ActivateTemplateRequest,
        ClaimDefinition, CreateTemplateRequest, DeleteTemplateRequest, DeprecateTemplateRequest,
        GetCredentialConfigurationsRequest, GetTemplateRequest, GetWalletRequest,
        HealthCheckRequest, ListTemplatesRequest, ListWalletsRequest, NewVersionRequest,
        UpdateTemplateRequest,
    },
    grpc_service::CredentialTemplateGrpcService,
    registry_application::{
        CredentialTemplateRegistryApplication, CredentialTemplateRegistryRepository,
    },
    CredentialTemplate, CredentialTemplateRepositoryError, DeliveryDestinationEntry,
    TemplateStatus, WalletRegistryEntry,
};
use serde_json::Value;
use tonic::{Code, Request};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Default)]
struct Repository {
    templates: Mutex<BTreeMap<String, CredentialTemplate>>,
}

#[async_trait]
impl CredentialTemplateRepository for Repository {
    async fn save(
        &self,
        template: &CredentialTemplate,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.templates
            .lock()
            .unwrap()
            .insert(template.id.clone(), template.clone());
        Ok(())
    }

    async fn by_id(
        &self,
        template_id: &str,
    ) -> Result<Option<CredentialTemplate>, CredentialTemplateRepositoryError> {
        Ok(self.templates.lock().unwrap().get(template_id).cloned())
    }

    async fn by_organization(
        &self,
        organization_id: &str,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        Ok(self
            .templates
            .lock()
            .unwrap()
            .values()
            .filter(|template| {
                template.organization_id == organization_id
                    && status.is_none_or(|expected| template.status == expected)
            })
            .cloned()
            .collect())
    }

    async fn all_internal(
        &self,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        Ok(self
            .templates
            .lock()
            .unwrap()
            .values()
            .filter(|template| status.is_none_or(|expected| template.status == expected))
            .cloned()
            .collect())
    }

    async fn delete(&self, template_id: &str) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(self.templates.lock().unwrap().remove(template_id).is_some())
    }
}

struct Registry {
    wallets: Mutex<BTreeMap<String, WalletRegistryEntry>>,
    destinations: Mutex<BTreeMap<String, DeliveryDestinationEntry>>,
}

#[async_trait]
impl CredentialTemplateRegistryRepository for Registry {
    async fn save_wallet(
        &self,
        wallet: &WalletRegistryEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.wallets
            .lock()
            .unwrap()
            .insert(wallet.id.clone(), wallet.clone());
        Ok(())
    }

    async fn wallet_by_id(
        &self,
        wallet_id: &str,
    ) -> Result<Option<WalletRegistryEntry>, CredentialTemplateRepositoryError> {
        Ok(self.wallets.lock().unwrap().get(wallet_id).cloned())
    }

    async fn wallets(
        &self,
        active_only: bool,
    ) -> Result<Vec<WalletRegistryEntry>, CredentialTemplateRepositoryError> {
        Ok(self
            .wallets
            .lock()
            .unwrap()
            .values()
            .filter(|wallet| !active_only || wallet.is_active)
            .cloned()
            .collect())
    }

    async fn delete_wallet(
        &self,
        wallet_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(self.wallets.lock().unwrap().remove(wallet_id).is_some())
    }

    async fn save_destination(
        &self,
        destination: &DeliveryDestinationEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.destinations
            .lock()
            .unwrap()
            .insert(destination.id.clone(), destination.clone());
        Ok(())
    }

    async fn destination_by_id(
        &self,
        destination_id: &str,
    ) -> Result<Option<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        Ok(self
            .destinations
            .lock()
            .unwrap()
            .get(destination_id)
            .cloned())
    }

    async fn destinations(
        &self,
        active_only: bool,
        organization_id: Option<&str>,
        provider: Option<&str>,
        mode_filter: Option<&str>,
    ) -> Result<Vec<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        Ok(self
            .destinations
            .lock()
            .unwrap()
            .values()
            .filter(|entry| !active_only || entry.is_enabled)
            .filter(|entry| {
                organization_id.is_none_or(|id| {
                    entry.is_system || entry.organization_id.as_deref() == Some(id)
                })
            })
            .filter(|entry| provider.is_none_or(|value| entry.provider == value))
            .filter(|entry| mode_filter.is_none_or(|value| entry.mode == value))
            .cloned()
            .collect())
    }

    async fn delete_destination(
        &self,
        destination_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(self
            .destinations
            .lock()
            .unwrap()
            .remove(destination_id)
            .is_some())
    }
}

struct ControlPlane;

#[async_trait]
impl CredentialTemplateControlPlane for ControlPlane {
    async fn require_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        if user_id == "user-1" && organization_id == "org-1" {
            Ok(())
        } else {
            Err(ControlPlaneError::MembershipRequired)
        }
    }

    async fn require_wallet_admin(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        self.require_membership(user_id, organization_id).await
    }

    async fn require_destination_admin(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        self.require_membership(user_id, organization_id).await
    }

    async fn organization_display_name(
        &self,
        _organization_id: &str,
    ) -> Result<Option<String>, ControlPlaneError> {
        Ok(Some("Example Organization".to_owned()))
    }

    async fn resolve_active_issuer(
        &self,
        _organization_id: &str,
        requested_issuer_did: Option<&str>,
        _credential_format: &str,
    ) -> Result<IssuerIdentity, ControlPlaneError> {
        Ok(IssuerIdentity {
            issuer_did: requested_issuer_did
                .unwrap_or("did:web:issuer.example")
                .to_owned(),
            issuer_algorithm: "ES256".to_owned(),
        })
    }

    async fn require_active_revocation_profile(
        &self,
        _organization_id: &str,
        revocation_profile_id: Option<&str>,
    ) -> Result<(), ControlPlaneError> {
        if revocation_profile_id == Some("revocation-1") {
            Ok(())
        } else {
            Err(ControlPlaneError::InvalidRevocationProfile(
                "missing".to_owned(),
            ))
        }
    }

    async fn require_trust_profile_accepts_issuer(
        &self,
        trust_profile_id: Option<&str>,
        _issuer_did: &str,
    ) -> Result<(), ControlPlaneError> {
        if trust_profile_id == Some("trust-1") {
            Ok(())
        } else {
            Err(ControlPlaneError::TrustProfileRejected(
                "missing".to_owned(),
            ))
        }
    }
}

fn contract() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/credential-template-grpc-behavior.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn service() -> CredentialTemplateGrpcService {
    let repository = Arc::new(Repository::default());
    let now = Utc::now();
    let registry = Arc::new(Registry {
        wallets: Mutex::new(
            system_wallet_catalog(now)
                .into_iter()
                .map(|entry| (entry.id.clone(), entry))
                .collect(),
        ),
        destinations: Mutex::new(
            system_delivery_destination_catalog(now)
                .into_iter()
                .map(|entry| (entry.id.clone(), entry))
                .collect(),
        ),
    });
    let control_plane = Arc::new(ControlPlane);
    let application = Arc::new(CredentialTemplateApplication::new(
        repository.clone(),
        control_plane.clone(),
    ));
    let registry_application = Arc::new(CredentialTemplateRegistryApplication::new(
        repository,
        registry,
        control_plane,
    ));
    CredentialTemplateGrpcService::new(
        application,
        registry_application,
        Some(TOKEN.to_owned()),
        true,
    )
    .unwrap()
}

fn authenticated<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("x-service-token", TOKEN.parse().unwrap());
    request
        .metadata_mut()
        .insert("x-user-id", "user-1".parse().unwrap());
    request
}

fn create_request(name: &str, credential_type: &str) -> CreateTemplateRequest {
    CreateTemplateRequest {
        organization_id: "org-1".to_owned(),
        name: name.to_owned(),
        credential_type: credential_type.to_owned(),
        vct: format!("https://issuer.example/{credential_type}"),
        claims: vec![ClaimDefinition {
            name: "family_name".to_owned(),
            display_name: "Family Name".to_owned(),
            claim_type: "string".to_owned(),
            required: true,
            selectively_disclosable: true,
            ..ClaimDefinition::default()
        }],
        privacy_posture: "selective_disclosure".to_owned(),
        supported_formats: vec!["sd_jwt_vc".to_owned()],
        issuance_protocol: "oid4vci".to_owned(),
        credential_payload_format: "sd_jwt_vc".to_owned(),
        issuer_did: "did:web:issuer.example".to_owned(),
        compliance_profile_id: "compliance-1".to_owned(),
        trust_profile_id: "trust-1".to_owned(),
        revocation_profile_id: "revocation-1".to_owned(),
        ..CreateTemplateRequest::default()
    }
}

#[tokio::test]
async fn all_declared_grpc_methods_share_native_behavior_and_fail_closed_security() {
    let contract = contract();
    let service = service();
    let error = service
        .health_check(Request::new(HealthCheckRequest {}))
        .await
        .unwrap_err();
    assert_eq!(
        format!("{:?}", error.code()),
        contract["security"]["missing_service_token"]
    );

    let created = service
        .create_template(authenticated(create_request("Badge", "EmployeeBadge")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.status, contract["behavior"]["created_status"]);
    assert_eq!(
        created.credential_payload_format,
        contract["behavior"]["credential_format_wire"]
    );
    let template_id = created.id.clone();

    let fetched = service
        .get_template(authenticated(GetTemplateRequest {
            template_id: template_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.id, template_id);

    let listed = service
        .list_templates(authenticated(ListTemplatesRequest {
            organization_id: "org-1".to_owned(),
            status: "draft".to_owned(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.templates.len(), 1);

    let updated = service
        .update_template(authenticated(UpdateTemplateRequest {
            template_id: template_id.clone(),
            name: "Badge Updated".to_owned(),
            update_mask: vec!["name".to_owned()],
            ..UpdateTemplateRequest::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.name, "Badge Updated");

    let version = service
        .new_version(authenticated(NewVersionRequest {
            template_id: template_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        version.version - created.version,
        contract["behavior"]["new_version_increment"]
            .as_i64()
            .unwrap() as i32
    );
    let deleted = service
        .delete_template(authenticated(DeleteTemplateRequest {
            template_id: version.id,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(deleted.success, contract["behavior"]["delete_success"]);

    let activated = service
        .activate_template(authenticated(ActivateTemplateRequest {
            template_id: template_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(activated.status, contract["behavior"]["activated_status"]);
    let deprecated = service
        .deprecate_template(authenticated(DeprecateTemplateRequest {
            template_id: template_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(deprecated.status, contract["behavior"]["deprecated_status"]);

    let active = service
        .create_template(authenticated(create_request("Member Badge", "MemberBadge")))
        .await
        .unwrap()
        .into_inner();
    service
        .activate_template(authenticated(ActivateTemplateRequest {
            template_id: active.id,
        }))
        .await
        .unwrap();
    let configurations = service
        .get_credential_configurations(authenticated(GetCredentialConfigurationsRequest {}))
        .await
        .unwrap()
        .into_inner();
    let configurations: Value = serde_json::from_str(&configurations.configurations_json).unwrap();
    assert!(configurations.get("MemberBadge").is_some());

    let wallets = service
        .list_wallets(authenticated(ListWalletsRequest {
            active_only: true,
            organization_id: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!wallets.wallets.is_empty());
    let wallet = service
        .get_wallet(authenticated(GetWalletRequest {
            wallet_id: contract["behavior"]["system_wallet_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(wallet.id, contract["behavior"]["system_wallet_id"]);

    let health = service
        .health_check(authenticated(HealthCheckRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health.status, contract["behavior"]["health_status"]);
}

#[tokio::test]
async fn internal_get_template_requires_service_auth_without_user_identity() {
    let service = service();
    let created = service
        .create_template(authenticated(create_request(
            "Service Badge",
            "ServiceBadge",
        )))
        .await
        .unwrap()
        .into_inner();
    let mut request = Request::new(GetTemplateRequest {
        template_id: created.id,
    });
    request
        .metadata_mut()
        .insert("x-service-token", TOKEN.parse().unwrap());
    let fetched = service.get_template(request).await.unwrap().into_inner();
    assert_eq!(fetched.name, "Service Badge");

    let mut list_request = Request::new(ListTemplatesRequest {
        organization_id: "org-1".to_owned(),
        status: "draft".to_owned(),
    });
    list_request
        .metadata_mut()
        .insert("x-service-token", TOKEN.parse().unwrap());
    assert_eq!(
        service
            .list_templates(list_request)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );

    let mut wallets_request = Request::new(ListWalletsRequest {
        active_only: true,
        organization_id: "org-1".to_owned(),
    });
    wallets_request
        .metadata_mut()
        .insert("x-service-token", TOKEN.parse().unwrap());
    let wallets = service
        .list_wallets(wallets_request)
        .await
        .unwrap()
        .into_inner();
    assert!(wallets
        .wallets
        .iter()
        .any(|wallet| wallet.id == contract()["behavior"]["system_wallet_id"]));
}
