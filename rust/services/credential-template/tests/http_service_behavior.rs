use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::Utc;
use marty_credential_template::{
    application::{
        ControlPlaneError, CredentialTemplateApplication, CredentialTemplateControlPlane,
        CredentialTemplateRepository, IssuerIdentity,
    },
    catalog::{system_delivery_destination_catalog, system_wallet_catalog},
    http_service::{credential_template_router, CredentialTemplateHttpState},
    registry_application::{
        CredentialTemplateRegistryApplication, CredentialTemplateRegistryRepository,
    },
    CredentialTemplate, CredentialTemplateRepositoryError, DeliveryDestinationEntry,
    RuntimeEnvironment, TemplateStatus, WalletRegistryEntry,
};
use mmf_security::ServiceTokenAuthenticator;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn registry_contract() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/credential-template-registry-behavior.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[derive(Default)]
struct Repository {
    templates: Mutex<BTreeMap<String, CredentialTemplate>>,
}

#[derive(Default)]
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
        entry: &DeliveryDestinationEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.destinations
            .lock()
            .unwrap()
            .insert(entry.id.clone(), entry.clone());
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
        _organization_id: Option<&str>,
        provider: Option<&str>,
        mode: Option<&str>,
    ) -> Result<Vec<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        Ok(self
            .destinations
            .lock()
            .unwrap()
            .values()
            .filter(|entry| !active_only || entry.is_enabled)
            .filter(|entry| provider.is_none_or(|value| entry.provider == value))
            .filter(|entry| mode.is_none_or(|value| entry.mode == value))
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
                    && status.is_none_or(|status| template.status == status)
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
            .filter(|template| status.is_none_or(|status| template.status == status))
            .cloned()
            .collect())
    }

    async fn delete(&self, template_id: &str) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(self.templates.lock().unwrap().remove(template_id).is_some())
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

    async fn resolve_active_issuer(
        &self,
        organization_id: &str,
        requested_issuer_did: Option<&str>,
        credential_format: &str,
    ) -> Result<IssuerIdentity, ControlPlaneError> {
        assert_eq!(organization_id, "org-1");
        assert_eq!(credential_format, "sd_jwt_vc");
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

fn router() -> axum::Router {
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
    credential_template_router(CredentialTemplateHttpState {
        application,
        registry_application,
        service_authenticator: Arc::new(
            ServiceTokenAuthenticator::new(Some(TOKEN.to_owned()), true).unwrap(),
        ),
        environment: RuntimeEnvironment::Test,
    })
}

fn create_body() -> Value {
    json!({
        "organization_id":"org-1",
        "name":"Employee Badge",
        "credential_type":"EmployeeBadge",
        "vct":"https://issuer.example/EmployeeBadge",
        "claims":[{"name":"family_name","display_name":"Family Name"}],
        "compliance_profile_id":"compliance-1",
        "trust_profile_id":"trust-1",
        "revocation_profile_id":"revocation-1",
        "credential_payload_format":"w3c_vcdm_v2_sd_jwt"
    })
}

fn request(method: &str, uri: &str, body: Value, authenticated: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if authenticated {
        builder = builder
            .header("x-service-token", TOKEN)
            .header("x-user-id", "user-1");
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test]
async fn template_http_routes_require_trusted_forwarded_identity() {
    let response = router()
        .oneshot(request(
            "POST",
            "/v1/credential-templates",
            create_body(),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await["detail"],
        "CREDENTIAL_TEMPLATE.SERVICE_AUTHENTICATION_REQUIRED"
    );
}

#[tokio::test]
async fn create_get_update_activate_and_delete_expose_only_public_behavior() {
    let app = router();
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/credential-templates",
            create_body(),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = json_body(response).await;
    let template_id = created["id"].as_str().unwrap();
    assert_eq!(created["status"], "DRAFT");
    assert_eq!(created["credential_payload_format"], "SD_JWT_VC");
    assert_eq!(created["claims"][0]["type"], "STRING");
    assert!(created.get("issuer_algorithm").is_none());
    assert!(created.get("supported_formats").is_none());
    assert!(created.get("wallet_configs").is_none());
    assert!(created.get("doctype").is_none());

    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            &format!("/v1/credential-templates/{template_id}"),
            json!({
                "claims":[
                    {"name":"given_name","display_name":"Given Name"},
                    {"name":"family_name","display_name":"Family Name"}
                ],
                "display_style":{"background_color":"#000000","text_color":"#ffffff"},
                "validity_rules":{"ttl_seconds":86401,"not_before_offset":900}
            }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = json_body(response).await;
    assert_eq!(updated["claims"].as_array().unwrap().len(), 2);
    assert_eq!(updated["validity_rules"]["ttl_seconds"], 172800);
    assert_eq!(updated["validity_rules"]["not_before_offset_seconds"], 900);

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/v1/credential-templates/{template_id}/activate"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await["status"], "ACTIVE");

    let response = app
        .oneshot(request(
            "DELETE",
            &format!("/v1/credential-templates/{template_id}"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn wallet_registry_routes_preserve_catalog_tenancy_routing_and_crud_behavior() {
    let contract = registry_contract();
    let app = router();
    let response = app
        .clone()
        .oneshot(request("GET", "/v1/wallet-registry", json!({}), true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let global_wallets = json_body(response).await;
    assert_eq!(
        global_wallets.as_array().unwrap().len(),
        contract["catalog"]["active_global_wallets"]
            .as_u64()
            .unwrap() as usize
    );
    assert!(global_wallets
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry.get("organization_id").is_none()));

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/wallet-registry",
            json!({
                "organization_id":"org-1",
                "name":"Campus Wallet",
                "credential_format":"sd_jwt_vc",
                "issuance_protocol":"oid4vci_authorization_code",
                "compliance_profile_code":"eudi_pid",
                "wallet_apps":["Campus Wallet"],
                "deep_link_pattern":"campus://open?inner={inner_uri_encoded}",
                "supported_protocols":["oid4vci"],
                "supported_platforms":["ios"]
            }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        contract["http"]["create_status"].as_u64().unwrap() as u16
    );
    let created = json_body(response).await;
    let wallet_id = created["id"].as_str().unwrap();
    assert_eq!(
        created["credential_format"],
        contract["normalization"]["credential_format"][1]
    );
    assert_eq!(
        created["issuance_protocol"],
        contract["normalization"]["authorization_code_protocol"][1]
    );
    assert_eq!(
        created["supported_protocols"][0],
        contract["normalization"]["pre_authorized_protocol"][1]
    );
    assert_eq!(
        created["ios_same_device_mode"],
        contract["routing"]["ios_nested_mode"]
    );

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/wallet-registry?organization_id=org-1",
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await.as_array().unwrap().len(), 10);

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!(
                "/v1/wallet-registry/{wallet_id}/open-link?inner_uri=openid-credential-offer%3A%2F%2F%3Fcredential_offer_uri%3Dhttps%253A%252F%252Fissuer.example%252Foffer&platform=ios"
            ),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let link = json_body(response).await;
    assert_eq!(link["wallet_id"], wallet_id);
    assert_eq!(link["transport"], contract["routing"]["transport"]);
    assert!(link["open_uri"].as_str().unwrap().starts_with("campus://"));

    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            &format!("/v1/wallet-registry/{wallet_id}"),
            json!({"name":"Campus Wallet 2","merge_strategy":"replace"}),
            true,
        ))
        .await
        .unwrap();
    let updated = json_body(response).await;
    assert_eq!(updated["name"], "Campus Wallet 2");
    assert_eq!(updated["merge_strategy"], "REPLACE");

    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            &format!("/v1/wallet-registry/{wallet_id}"),
            json!({"organization_id":"org-2"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        contract["http"]["ownership_transfer_status"]
            .as_u64()
            .unwrap() as u16
    );

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/wallet-registry/resolve/profile?organization_id=org-1&credential_format=SD_JWT_VC&issuance_protocol=OID4VCI_PRE_AUTH&compliance_profile_code=EUDI_PID",
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["name"], "EUDI PID Wallet");

    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            "/v1/wallet-registry/wr-marty-001",
            json!({"name":"Forbidden"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        contract["http"]["system_write_status"].as_u64().unwrap() as u16
    );

    let response = app
        .oneshot(request(
            "DELETE",
            &format!("/v1/wallet-registry/{wallet_id}"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await, contract["http"]["success_body"]);
}

#[tokio::test]
async fn template_compatibility_and_delivery_destination_routes_are_complete() {
    let contract = registry_contract();
    let app = router();
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/credential-templates",
            create_body(),
            true,
        ))
        .await
        .unwrap();
    let template_id = json_body(response).await["id"].as_str().unwrap().to_owned();
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v1/credential-templates/{template_id}/wallet-compatibility"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let compatibility = json_body(response).await;
    assert_eq!(compatibility["credential_format"], "SD_JWT_VC");
    assert_eq!(compatibility["name"], "Generic SD-JWT VC Wallet");

    let response = app
        .clone()
        .oneshot(request("GET", "/v1/delivery-destinations", json!({}), true))
        .await
        .unwrap();
    assert_eq!(
        json_body(response).await.as_array().unwrap().len(),
        contract["catalog"]["system_delivery_destinations"]
            .as_u64()
            .unwrap() as usize
    );

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/delivery-destinations",
            json!({
                "organization_id":"org-1",
                "id":"destination-campus",
                "name":"Campus Backpack",
                "provider":"open_badges_backpack",
                "mode":"learner_backpack",
                "setup_actor":"learner",
                "delivery_target":"external_api",
                "credential_format":"vc_jwt",
                "issuance_protocol":"oid4vci",
                "requires_consent":true
            }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        contract["http"]["create_status"].as_u64().unwrap() as u16
    );
    let created = json_body(response).await;
    assert_eq!(created["credential_format"], "VC_JWT");
    assert_eq!(
        created["issuance_protocol"],
        contract["normalization"]["pre_authorized_protocol"][1]
    );

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/delivery-destinations?organization_id=org-1",
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await.as_array().unwrap().len(), 5);

    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            "/v1/delivery-destinations/destination-campus",
            json!({"name":"Campus Backpack 2","is_enabled":false}),
            true,
        ))
        .await
        .unwrap();
    let updated = json_body(response).await;
    assert_eq!(updated["name"], "Campus Backpack 2");
    assert_eq!(updated["is_enabled"], false);

    let response = app
        .clone()
        .oneshot(request(
            "DELETE",
            "/v1/delivery-destinations/dd-elevenid-wallet",
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        contract["http"]["system_write_status"].as_u64().unwrap() as u16
    );

    let response = app
        .oneshot(request(
            "DELETE",
            "/v1/delivery-destinations/destination-campus",
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await, contract["http"]["success_body"]);
}
