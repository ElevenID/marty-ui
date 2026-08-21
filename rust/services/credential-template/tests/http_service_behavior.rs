use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_credential_template::{
    application::{
        ControlPlaneError, CredentialTemplateApplication, CredentialTemplateControlPlane,
        CredentialTemplateRepository, IssuerIdentity,
    },
    http_service::{credential_template_router, CredentialTemplateHttpState},
    CredentialTemplate, CredentialTemplateRepositoryError, TemplateStatus,
};
use mmf_security::ServiceTokenAuthenticator;
use serde_json::{json, Value};
use tower::ServiceExt;

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
    let application = Arc::new(CredentialTemplateApplication::new(
        Arc::new(Repository::default()),
        Arc::new(ControlPlane),
    ));
    credential_template_router(CredentialTemplateHttpState {
        application,
        service_authenticator: Arc::new(
            ServiceTokenAuthenticator::new(Some(TOKEN.to_owned()), true).unwrap(),
        ),
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
