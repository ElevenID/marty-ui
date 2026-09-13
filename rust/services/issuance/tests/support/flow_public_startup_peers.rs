//! Closed control-plane boundaries for actual Flow main; native admission is elsewhere.
use super::super::super::super::{
    didcomm_gateway_replay::OwnedHttp,
    issuance_named_peers::{decode_request, grpc_response},
};
use super::super::TOKEN;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode, Version},
    response::{IntoResponse, Response},
    Json, Router,
};
use marty_flow::{credential_template_proto as template, organization_proto as organization};
use serde_json::json;
use std::sync::{Arc, Mutex};

pub(super) const KEY: &str = "synthetic-legacy-physical-api-key";

#[derive(Clone)]
struct StateData {
    role: &'static str,
    attempts: Arc<Mutex<Vec<String>>>,
    accepted: Arc<Mutex<Vec<String>>>,
}

async fn request(State(state): State<StateData>, request: Request<Body>) -> Response {
    let path = request.uri().path().to_owned();
    let identity = format!("{}:{}", state.role, path);
    state.attempts.lock().unwrap().push(identity.clone());
    assert!(request.uri().query().is_none());
    let headers = request.headers().clone();
    let method = request.method().clone();
    let version = request.version();
    let bytes = to_bytes(request.into_body(), 128 * 1024).await.unwrap();
    let result = if !matches!(state.role, "organization" | "credential-grpc" | "policy") {
        assert_eq!(method, "GET");
        assert_eq!(path, "/health");
        assert!(bytes.is_empty());
        if matches!(state.role, "signing" | "legacy") {
            assert_eq!(headers["x-api-key"], KEY);
        } else {
            assert_eq!(headers["x-service-token"], TOKEN);
        }
        Json(json!({"status":"healthy"})).into_response()
    } else {
        assert_eq!(method, "POST");
        assert_eq!(version, Version::HTTP_2);
        assert_eq!(headers["content-type"], "application/grpc");
        assert_eq!(headers["x-service-token"], TOKEN);
        match path.as_str() {
            "/marty.ui.organization.v1.OrganizationService/GetMember"
                if state.role == "organization" =>
            {
                let input: organization::GetMemberRequest = decode_request(&bytes);
                assert_eq!(input.organization_id, "org-1");
                assert!(matches!(
                    input.user_id.as_str(),
                    "synthetic-user" | "foreign-user"
                ));
                grpc_response(organization::MemberResponse {
                    id: "synthetic-member".into(),
                    organization_id: if input.user_id == "synthetic-user" {
                        input.organization_id
                    } else {
                        "foreign-org".into()
                    },
                    user_id: input.user_id.clone(),
                    status: "active".into(),
                    permissions: [
                        "flow-instance:start",
                        "flow-instance:view",
                        "flow-instance:advance",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                    is_owner: input.user_id == "synthetic-user",
                    ..Default::default()
                })
            }
            "/marty.ui.credential_template.v1.CredentialTemplateService/GetTemplate"
                if state.role == "credential-grpc" =>
            {
                let input: template::GetTemplateRequest = decode_request(&bytes);
                assert_eq!(input.template_id, "template-1");
                grpc_response(template::TemplateResponse {
                    id: input.template_id,
                    organization_id: "org-1".into(),
                    status: "ACTIVE".into(),
                    credential_type: "EmployeeCredential".into(),
                    vct: "https://issuer.example/credentials/EmployeeCredential".into(),
                    issuer_did: "did:web:issuer.example".into(),
                    credential_payload_format: "dc+sd-jwt".into(),
                    issuer_algorithm: "EdDSA".into(),
                    wallet_configs_json: "[]".into(),
                    ..Default::default()
                })
            }
            _ => return StatusCode::NOT_FOUND.into_response(),
        }
    };
    state.accepted.lock().unwrap().push(identity);
    result
}

pub(super) struct Peers {
    servers: Vec<(&'static str, OwnedHttp)>,
    attempts: Arc<Mutex<Vec<String>>>,
    accepted: Arc<Mutex<Vec<String>>>,
}
impl Peers {
    pub(super) async fn start() -> Self {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let mut servers = Vec::new();
        for role in [
            "organization",
            "credential-grpc",
            "policy",
            "signing",
            "legacy",
            "template",
            "trust",
            "deployment",
        ] {
            let state = StateData {
                role,
                attempts: attempts.clone(),
                accepted: accepted.clone(),
            };
            servers.push((
                role,
                OwnedHttp::start(Router::new().fallback(request).with_state(state)).await,
            ));
        }
        Self {
            servers,
            attempts,
            accepted,
        }
    }
    pub(super) fn url(&self, role: &str) -> String {
        let server = &self.servers.iter().find(|entry| entry.0 == role).unwrap().1;
        format!("http://127.0.0.1:{}", server.port)
    }
    pub(super) fn assert_health(&self) {
        let attempts = self.attempts.lock().unwrap();
        for (role, count) in [
            ("signing", 1),
            ("legacy", 2),
            ("template", 1),
            ("trust", 1),
            ("deployment", 1),
        ] {
            assert_eq!(
                attempts
                    .iter()
                    .filter(|v| **v == format!("{role}:/health"))
                    .count(),
                count
            );
        }
    }
    pub(super) fn assert_no_unexpected(&self) {
        let mut attempts = self.attempts.lock().unwrap().clone();
        let mut accepted = self.accepted.lock().unwrap().clone();
        attempts.sort();
        accepted.sort();
        assert_eq!(
            attempts, accepted,
            "Every request must reach its exact controlled boundary"
        );
    }
    pub(super) async fn close(self) {
        self.assert_no_unexpected();
        for (_, server) in self.servers {
            server.close().await;
        }
    }
}
