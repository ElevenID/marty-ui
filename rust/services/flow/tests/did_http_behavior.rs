use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use marty_flow::{
    flow_read_router, FlowHttpApplicationApprovalOptions, FlowHttpState,
    FlowHttpVerificationOptions, FlowProviderError, FlowProviderRegistry, PostgresFlowRepository,
    SigningIdentity, SigningIdentityProvider, SigningRequest, SigningResult,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    route: [String; 2],
    identity_binding: IdentityBinding,
    content_type: String,
    cache_control: String,
    pragma: String,
    cors: String,
    verification_method_type: String,
    relationships: Vec<String>,
    private_jwk_members: String,
    provider_failure: String,
    python_fallback: String,
}

#[derive(Deserialize)]
struct IdentityBinding {
    organization_id: String,
    issuer_did: String,
    key_purpose: String,
    credential_format: String,
    algorithm: String,
}

struct Signing {
    mutation: Option<&'static str>,
}

#[async_trait]
impl SigningIdentityProvider for Signing {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
        key_purpose: &str,
        credential_format: &str,
        algorithm: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        assert_eq!(organization_id, "00000000-0000-0000-0000-000000000001");
        assert_eq!(issuer_did, "did:web:issuer.example:orgs:marty");
        assert_eq!(key_purpose, "oid4vp_request_signing");
        assert_eq!(credential_format, "oauth-authz-req+jwt");
        assert_eq!(algorithm, Some("ES256"));
        let mut identity = SigningIdentity {
            organization_id: organization_id.into(),
            issuer_did: issuer_did.into(),
            verification_method_id: format!("{issuer_did}#key-1"),
            signing_key_reference: "managed-key-1".into(),
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
            key_purpose: key_purpose.into(),
            credential_format: credential_format.into(),
            algorithm: "ES256".into(),
        };
        match self.mutation {
            Some("tenant") => identity.organization_id = "other-org".into(),
            Some("did") => identity.issuer_did = "did:web:other.example".into(),
            Some("method") => {
                identity.verification_method_id = "did:web:other.example#key-1".into()
            }
            Some("purpose") => identity.key_purpose = "credential_issuer".into(),
            Some("format") => identity.credential_format = "jwt_vc_json".into(),
            Some("algorithm") => identity.algorithm = "EdDSA".into(),
            Some("private") => {
                identity
                    .public_jwk
                    .insert("dp".into(), json!("forbidden-fixture-material"));
            }
            Some("point") => {
                identity.public_jwk.insert("x".into(), json!("invalid"));
            }
            _ => {}
        }
        Ok(identity)
    }

    async fn sign(&self, _request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        Err(FlowProviderError::Rejected {
            provider: "signing_identity",
            message: "DID publication must not sign".into(),
        })
    }
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../../contracts/flow-did-http-behavior.json"
    ))
    .unwrap()
}

fn router(with_provider: bool) -> axum::Router {
    configured_router(with_provider, None)
}

fn configured_router(with_provider: bool, mutation: Option<&'static str>) -> axum::Router {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/marty_flow_did_contract")
        .unwrap();
    let mut providers = FlowProviderRegistry::default();
    if with_provider {
        providers.signing_identity = Some(Arc::new(Signing { mutation }));
    }
    let verification = FlowHttpVerificationOptions {
        default_issuer_did: "did:web:issuer.example:orgs:marty".into(),
        ..FlowHttpVerificationOptions::default()
    };
    flow_read_router(FlowHttpState {
        issuance_prerequisite_authenticator: None,
        service_authenticator: None,
        repository: PostgresFlowRepository::new(pool),
        providers: Arc::new(providers),
        public_base_url: "https://issuer.example".into(),
        verification,
        application_approval: FlowHttpApplicationApprovalOptions::default(),
    })
}

#[tokio::test]
async fn did_document_binding_headers_and_failure_behavior_match_contract() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.route, ["GET", "/oid4vp/did.json"]);
    assert_eq!(
        contract.identity_binding.organization_id,
        "configured_marty_organization"
    );
    assert_eq!(
        contract.identity_binding.issuer_did,
        "configured_oid4vp_issuer_did"
    );
    assert_eq!(
        contract.identity_binding.key_purpose,
        "oid4vp_request_signing"
    );
    assert_eq!(
        contract.identity_binding.credential_format,
        "oauth-authz-req+jwt"
    );
    assert_eq!(contract.identity_binding.algorithm, "ES256");
    assert_eq!(contract.verification_method_type, "JsonWebKey2020");
    assert_eq!(
        contract.relationships,
        ["authentication", "assertionMethod"]
    );
    assert_eq!(contract.private_jwk_members, "forbidden");
    assert_eq!(contract.provider_failure, "fail_closed");
    assert_eq!(contract.python_fallback, "forbidden");

    let response = router(true)
        .oneshot(
            Request::get(&contract.route[1])
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], contract.content_type);
    assert_eq!(response.headers()["cache-control"], contract.cache_control);
    assert_eq!(response.headers()["pragma"], contract.pragma);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        contract.cors
    );
    let body = axum::body::to_bytes(response.into_body(), 32_768)
        .await
        .unwrap();
    let document: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        document.get("@context").is_none(),
        "the advertised representation is DID JSON"
    );
    assert_eq!(document["id"], "did:web:issuer.example:orgs:marty");
    assert_eq!(document["verificationMethod"][0]["type"], "JsonWebKey2020");
    assert_eq!(
        document["authentication"][0],
        "did:web:issuer.example:orgs:marty#key-1"
    );
    assert!(document["verificationMethod"][0]["publicKeyJwk"]
        .get("d")
        .is_none());

    let unavailable = router(false)
        .oneshot(
            Request::get(&contract.route[1])
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), 503);
}

#[tokio::test]
async fn did_publication_rejects_unbound_private_or_invalid_provider_keys() {
    for mutation in [
        "tenant",
        "did",
        "method",
        "purpose",
        "format",
        "algorithm",
        "private",
        "point",
    ] {
        let response = configured_router(true, Some(mutation))
            .oneshot(
                Request::get("/oid4vp/did.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 503, "{mutation}");
        let body = axum::body::to_bytes(response.into_body(), 32_768)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains("forbidden-fixture-material"));
        assert!(!text.contains("publicKeyJwk"));
    }
}
