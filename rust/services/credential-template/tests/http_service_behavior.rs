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

fn internal_contract() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/credential-template-internal-behavior.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn privacy_posture_contract() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/credential-template-privacy-posture-behavior.json");
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

    async fn organization_display_name(
        &self,
        organization_id: &str,
    ) -> Result<Option<String>, ControlPlaneError> {
        Ok((organization_id == "org-1").then(|| "Example Organization".to_owned()))
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

#[tokio::test]
async fn delegated_destination_read_enforces_service_actor_scope_and_tenant() {
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const OTHER: &str = "20000000-0000-4000-8000-000000000002";
    const KEY: &str = "10000000-0000-4000-8000-000000000001";
    let repository = Arc::new(Repository::default());
    let registry = Arc::new(Registry::default());
    let system = system_delivery_destination_catalog(Utc::now()).remove(0);
    let mut tenant = system.clone();
    tenant.id = "delegated-tenant".into();
    tenant.organization_id = Some(ORG.into());
    tenant.is_system = false;
    let mut ownerless = tenant.clone();
    ownerless.id = "delegated-ownerless".into();
    ownerless.organization_id = None;
    for entry in [&system, &tenant, &ownerless] {
        registry.save_destination(entry).await.unwrap();
    }
    for configured in [true, false] {
        let control_plane = Arc::new(ControlPlane);
        let app = credential_template_router(CredentialTemplateHttpState {
            application: Arc::new(CredentialTemplateApplication::new(
                repository.clone(),
                control_plane.clone(),
            )),
            registry_application: Arc::new(CredentialTemplateRegistryApplication::new(
                repository.clone(),
                registry.clone(),
                control_plane,
            )),
            service_authenticator: Arc::new(
                ServiceTokenAuthenticator::new(configured.then(|| TOKEN.to_owned()), configured)
                    .unwrap(),
            ),
            environment: RuntimeEnvironment::Test,
        });
        for (id, token, key, organization, scopes, expected) in [
            (
                tenant.id.as_str(),
                Some(TOKEN),
                KEY,
                ORG,
                "wallet:read",
                200,
            ),
            (
                system.id.as_str(),
                Some(TOKEN),
                KEY,
                ORG,
                "wallet:write",
                200,
            ),
            (
                ownerless.id.as_str(),
                Some(TOKEN),
                KEY,
                ORG,
                "wallet:read",
                403,
            ),
            (
                tenant.id.as_str(),
                Some(TOKEN),
                KEY,
                OTHER,
                "admin:full",
                403,
            ),
            (tenant.id.as_str(), None, KEY, ORG, "wallet:read", 401),
            (
                tenant.id.as_str(),
                Some("incorrect"),
                KEY,
                ORG,
                "wallet:read",
                401,
            ),
            (
                tenant.id.as_str(),
                Some(TOKEN),
                "malformed",
                ORG,
                "wallet:read",
                401,
            ),
            (
                tenant.id.as_str(),
                Some(TOKEN),
                KEY,
                "invalid",
                "wallet:read",
                401,
            ),
            (system.id.as_str(), Some(TOKEN), KEY, ORG, "trust:read", 403),
            (system.id.as_str(), Some(TOKEN), KEY, ORG, "", 403),
        ] {
            let mut request = Request::builder()
                .uri(format!("/v1/delivery-destinations/{id}"))
                .header("x-api-key-id", key)
                .header("x-organization-id", organization)
                .header("x-api-key-scopes", scopes)
                .header("x-user-id", "user-1");
            if let Some(token) = token {
                request = request.header("x-service-token", token);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status().as_u16(),
                if configured { expected } else { 401 },
                "destination {id}"
            );
            if response.status().is_success() {
                assert_eq!(json_body(response).await["id"], id);
            }
        }
    }
}

fn create_body() -> Value {
    json!({
        "organization_id":"org-1",
        "name":"Employee Badge",
        "credential_type":"EmployeeBadge",
        "vct":"https://issuer.example/EmployeeBadge",
        "claims":[
            {
                "name":"family_name",
                "display_name":"Family Name",
                "selectively_disclosable":false,
                "pattern":"^[A-Z][a-z]+$",
                "enum_values":["Lee", "Smith"],
                "mdoc_namespace":"org.example.employee",
                "mdoc_element_identifier":"familyName"
            },
            {
                "name":"age",
                "display_name":"Age",
                "claim_type":"INTEGER",
                "min_value":16,
                "max_value":120
            }
        ],
        "compliance_profile_id":"compliance-1",
        "trust_profile_id":"trust-1",
        "revocation_profile_id":"revocation-1",
        "credential_payload_format":"w3c_vcdm_v2_sd_jwt",
        "issuance_protocol":"openid4vci_pre_authorized"
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
async fn unsupported_schema_uri_is_rejected_instead_of_silently_discarded() {
    let mut body = create_body();
    body["schema_uri"] = json!("https://issuer.example/schema");
    let response = router()
        .oneshot(request("POST", "/v1/credential-templates", body, true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(json_body(response).await["detail"]
        .as_str()
        .unwrap()
        .contains("schema_uri"));
}

#[tokio::test]
async fn nondefault_public_configuration_survives_create_list_and_metadata_edit() {
    let app = router();
    let mut body = create_body();
    body["selective_disclosure_fields"] = json!(["age"]);
    body["zk_predicate_claims"] = json!(["age"]);
    body["derived_attributes"] = json!([{
        "name":"Age threshold", "source_claim":"age", "derivation_type":"age_over",
        "parameters":{"threshold":21}
    }]);
    body["display_style"] = json!({"background_color":"#123456", "text_color":"#abcdef", "logo_url":"https://issuer.example/logo.png"});
    let response = app
        .clone()
        .oneshot(request("POST", "/v1/credential-templates", body, true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = json_body(response).await;
    assert_eq!(
        created["derived_attributes"][0]["parameters"]["threshold"],
        21
    );
    assert_eq!(created["selective_disclosure_fields"], json!(["age"]));
    assert_eq!(created["zk_predicate_claims"], json!(["age"]));
    let id = created["id"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            &format!("/v1/credential-templates/{id}"),
            json!({"description":"metadata only"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .oneshot(request(
            "GET",
            "/v1/credential-templates?organization_id=org-1",
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = json_body(response).await;
    let after = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == id)
        .unwrap();
    for field in [
        "supported_formats",
        "selective_disclosure_fields",
        "zk_predicate_claims",
        "derived_attributes",
        "display_style",
    ] {
        assert_eq!(after[field], created[field], "{field}");
    }
}

#[tokio::test]
async fn private_derivation_parameters_are_rejected_before_create_or_update_persistence() {
    let app = router();
    let bad = json!([{"name":"Derived", "source_claim":"age", "derivation_type":"age_over", "parameters":{"nested":[{"api_key":"forbidden"}]}}]);
    let mut body = create_body();
    body["derived_attributes"] = bad.clone();
    let response = app
        .clone()
        .oneshot(request("POST", "/v1/credential-templates", body, true))
        .await
        .unwrap();
    assert!(response.status().is_client_error());
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/credential-templates?organization_id=org-1",
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await, json!([]));
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
    let created = json_body(response).await;
    let id = created["id"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            &format!("/v1/credential-templates/{id}"),
            json!({"name":"must not save", "derived_attributes":bad}),
            true,
        ))
        .await
        .unwrap();
    assert!(response.status().is_client_error());
    let response = app
        .oneshot(request(
            "GET",
            &format!("/v1/credential-templates/{id}"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await, created);
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
    assert_eq!(created["issuance_protocol"], "OID4VCI_PRE_AUTH");
    assert_eq!(created["claims"][0]["type"], "STRING");
    assert_eq!(created["claims"][0]["selectively_disclosable"], false);
    assert_eq!(created["claims"][0]["pattern"], "^[A-Z][a-z]+$");
    assert_eq!(created["claims"][0]["enum_values"], json!(["Lee", "Smith"]));
    assert_eq!(
        created["claims"][0]["mdoc_element_identifier"],
        "familyName"
    );
    assert_eq!(created["claims"][1]["min_value"], 16.0);
    assert_eq!(created["claims"][1]["max_value"], 120.0);
    assert_eq!(
        created["privacy_posture"],
        json!({
            "mode":"selective_disclosure",
            "default_disclose_all":false,
            "prefer_predicates":false,
            "sd_alg":"sha-256"
        })
    );
    assert!(created.get("issuer_algorithm").is_none());
    assert_eq!(created["supported_formats"], json!(["SD_JWT_VC"]));
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
    assert_eq!(updated["display_style"]["background_color"], "#000000");
    let before_metadata = updated.clone();
    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            &format!("/v1/credential-templates/{template_id}"),
            json!({"name":"Renamed template"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v1/credential-templates/{template_id}"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let after_metadata = json_body(response).await;
    for field in [
        "supported_formats",
        "selective_disclosure_fields",
        "zk_predicate_claims",
        "derived_attributes",
        "display_style",
    ] {
        assert_eq!(after_metadata[field], before_metadata[field], "{field}");
        assert!(!after_metadata[field].is_null(), "missing {field}");
    }

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
async fn public_privacy_posture_is_case_tolerant_and_round_trip_safe() {
    let contract = privacy_posture_contract();
    assert_eq!(contract["schema_version"], 1);
    let app = router();
    let mut last_public_posture = Value::Null;

    for (index, case) in contract["valid_inputs"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut body = create_body();
        body["name"] = json!(format!("Privacy posture {index}"));
        body["privacy_posture"] = case["input"].clone();
        let response = app
            .clone()
            .oneshot(request("POST", "/v1/credential-templates", body, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created = json_body(response).await;
        assert_eq!(created["privacy_posture"], case["expected"]);
        last_public_posture = created["privacy_posture"].clone();
    }

    let mut clone = create_body();
    clone["name"] = json!("Round-tripped minimal posture");
    clone["privacy_posture"] = last_public_posture.clone();
    let response = app
        .clone()
        .oneshot(request("POST", "/v1/credential-templates", clone, true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["privacy_posture"],
        last_public_posture
    );

    for (index, invalid) in contract["invalid_inputs"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut body = create_body();
        body["name"] = json!(format!("Invalid privacy posture {index}"));
        body["privacy_posture"] = invalid.clone();
        let response = app
            .clone()
            .oneshot(request("POST", "/v1/credential-templates", body, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
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
    assert_eq!(
        json_body(response).await.as_array().unwrap().len(),
        contract["catalog"]["active_global_wallets"]
            .as_u64()
            .unwrap() as usize
            + 1
    );

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
    let mut expected: Value = serde_json::from_str(include_str!(
        "../../../../contracts/wallet-compatibility-example.json"
    ))
    .unwrap();
    for field in ["created_at", "updated_at"] {
        chrono::DateTime::parse_from_rfc3339(compatibility[field].as_str().unwrap()).unwrap();
        expected[field] = compatibility[field].clone();
    }
    assert_eq!(compatibility, expected);

    // The generic profile retains COMPLIANCE-1, so a matching organization
    // override must apply through the real HTTP owner, not only the merge helper.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/wallet-registry",
            json!({
                "organization_id":"org-1", "name":"Campus Wallet",
                "credential_format":"SD_JWT_VC", "issuance_protocol":"OID4VCI_PRE_AUTH",
                "compliance_profile_code":"COMPLIANCE-1", "wallet_apps":["Campus Wallet"],
                "deep_link_pattern":"campus://open?inner={inner_uri_encoded}"
            }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created_override = json_body(response).await;
    let override_id = created_override["id"].as_str().unwrap();
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
    let merged = json_body(response).await;
    expected["id"] = json!(override_id);
    expected["organization_id"] = json!("org-1");
    expected["name"] = json!("Campus Wallet");
    expected["is_override"] = json!(true);
    expected["override_precedence"] = json!(50);
    expected["applied_override_ids"] = json!([override_id]);
    expected["wallet_apps"] = json!(["EUDI Wallet", "OID4VCI-compatible wallets", "Campus Wallet"]);
    expected["deep_link_pattern"] = json!("campus://open?inner={inner_uri_encoded}");
    for field in ["created_at", "updated_at"] {
        expected[field] = created_override[field].clone();
    }
    assert_eq!(merged, expected);

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

#[tokio::test]
async fn internal_routes_expose_safe_issuance_context_and_active_oid4vci_metadata() {
    let contract = internal_contract();
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
            &format!("/internal/credential-templates/{template_id}/issuance-context"),
            json!({}),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let context = json_body(response).await;
    for field in contract["issuance_context"]["private_fields"]
        .as_array()
        .unwrap()
    {
        assert!(context.get(field.as_str().unwrap()).is_some());
    }
    for field in contract["issuance_context"]["forbidden_cached_routing_fields"]
        .as_array()
        .unwrap()
    {
        assert!(context.get(field.as_str().unwrap()).is_none());
    }
    assert_eq!(context["issuer_algorithm"], "ES256");
    assert_eq!(context["supported_formats"], json!(["SD_JWT_VC"]));
    assert_eq!(context["validity_rules"]["default_validity_days"], 365);

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/internal/credential-configurations",
            json!({}),
            false,
        ))
        .await
        .unwrap();
    assert!(
        json_body(response).await["credential_configurations_supported"]
            .as_object()
            .unwrap()
            .is_empty()
    );

    app.clone()
        .oneshot(request(
            "POST",
            &format!("/v1/credential-templates/{template_id}/activate"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    let response = app
        .oneshot(request(
            "GET",
            "/internal/credential-configurations",
            json!({}),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = json_body(response).await;
    let configuration = &metadata["credential_configurations_supported"]["EmployeeBadge"];
    let sd_jwt_case = &contract["credential_configurations"][0];
    assert_eq!(configuration["format"], sd_jwt_case["expected_format"]);
    assert_eq!(
        configuration["credential_signing_alg_values_supported"],
        json!(["ES256"])
    );
    assert_eq!(metadata["issuer_display_name"], "Example Organization");
}
