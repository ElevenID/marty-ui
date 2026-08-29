use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::credential::{
    AllocatedCredentialStatus, CredentialIssuanceError, CredentialTransaction,
};

#[derive(Clone)]
pub struct HttpCredentialStatusAllocator {
    client: Client,
    base_url: Url,
    service_token: Option<String>,
}

impl std::fmt::Debug for HttpCredentialStatusAllocator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCredentialStatusAllocator")
            .field("base_url", &self.base_url)
            .field("has_service_token", &self.service_token.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpCredentialStatusAllocator {
    pub fn new(
        base_url: Url,
        service_token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, CredentialIssuanceError> {
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                lifecycle_error(format!("Unable to configure status allocator: {error}"))
            })?;
        Ok(Self {
            client,
            base_url,
            service_token: service_token.map(str::to_owned),
        })
    }

    pub async fn allocate(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
        credential_format: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        let profile_id = transaction
            .revocation_profile_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(CredentialIssuanceError::RevocationProfileRequired)?;
        let normalized_format = revocation_credential_format(credential_format);
        let mut request = self
            .client
            .post(self.endpoint(profile_id))
            .json(&ReserveIndexRequest {
                organization_id: &transaction.organization_id,
                credential_format: normalized_format,
                credential_id,
            });
        if let Some(token) = self.service_token.as_deref() {
            request = request.header("x-service-token", token);
        }
        let response = request.send().await.map_err(|error| {
            lifecycle_error(format!("Credential status allocation failed: {error}"))
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(lifecycle_error(format!(
                "Credential status allocation failed (HTTP {status})"
            )));
        }
        let response: ReserveIndexResponse = response.json().await.map_err(|error| {
            lifecycle_error(format!(
                "Credential status allocation returned invalid JSON: {error}"
            ))
        })?;
        if response.organization_id != transaction.organization_id {
            return Err(lifecycle_error(
                "Credential status allocation returned the wrong organization",
            ));
        }
        let status_list_url = response
            .status_list_url
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                lifecycle_error("Credential status allocation returned an incomplete response")
            })?;
        Ok(AllocatedCredentialStatus {
            revocation_profile_id: Some(profile_id.to_owned()),
            entries: vec![json!({
                "status_list_id": profile_id,
                "index": response.index,
                "status_list_uri": status_list_url,
                "status_list_credential": status_list_url,
                "type": if normalized_format == "mdoc" {
                    "TokenStatusListEntry"
                } else {
                    "BitstringStatusListEntry"
                },
                "status_purpose": "revocation",
            })],
        })
    }

    fn endpoint(&self, profile_id: &str) -> Url {
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(&format!(
            "{}/internal/revocation-profiles/{profile_id}/reserve-index",
            self.base_url.path().trim_end_matches('/')
        ));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        endpoint
    }
}

#[derive(Serialize)]
struct ReserveIndexRequest<'a> {
    organization_id: &'a str,
    credential_format: &'a str,
    credential_id: &'a str,
}

#[derive(Deserialize)]
struct ReserveIndexResponse {
    organization_id: String,
    index: i64,
    status_list_url: Option<String>,
}

fn revocation_credential_format(format: &str) -> &'static str {
    match format {
        "mso_mdoc" | "mdoc" => "mdoc",
        "ldp_vc" | "json_ld" | "w3c_vcdm_v2_di" => "json_ld",
        _ => "sd_jwt_vc",
    }
}

fn lifecycle_error(message: impl Into<String>) -> CredentialIssuanceError {
    CredentialIssuanceError::LifecycleUnavailable(message.into())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use axum::{
        extract::{Path, State},
        http::HeaderMap,
        routing::post,
        Json, Router,
    };
    use serde_json::{json, Map, Value};
    use tokio::sync::Mutex;

    use super::*;
    use crate::credential::{CredentialTransaction, CredentialTransactionStatus};

    type CapturedRequest = (String, HeaderMap, Value);

    #[derive(Clone, Debug, Default)]
    struct Capture(Arc<Mutex<Option<CapturedRequest>>>);

    async fn reserve(
        State(capture): State<Capture>,
        Path(profile_id): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        *capture.0.lock().await = Some((profile_id, headers, body.clone()));
        Json(json!({
            "organization_id": body["organization_id"],
            "index": 42,
            "status_list_url": "https://status.example/lists/active",
        }))
    }

    fn transaction() -> CredentialTransaction {
        CredentialTransaction {
            id: "tx-a".to_owned(),
            organization_id: "org-a".to_owned(),
            credential_template_id: "template-a".to_owned(),
            revocation_profile_id: Some("profile-a".to_owned()),
            renewal_of_credential_id: None,
            applicant_id: None,
            application_id: None,
            subject_did: None,
            status: CredentialTransactionStatus::Signing,
            pre_authorized_code: "pre-auth".to_owned(),
            nonce: None,
            claims: Map::new(),
            credential_type: Some("AccessBadge".to_owned()),
            selective_disclosure_claims: Vec::new(),
            credential_payload_format: "dc+sd-jwt".to_owned(),
            wallet_configs: Vec::new(),
            validity_days: 365,
            issuer_profile_id: Some("profile".to_owned()),
            issuer_mode: "org_managed".to_owned(),
            issuer_did: Some("did:web:issuer.example".to_owned()),
            issuer_algorithm: Some("ES256".to_owned()),
            signing_service_id: Some("service".to_owned()),
            reserved_credential_id: None,
        }
    }

    async fn allocator() -> (
        HttpCredentialStatusAllocator,
        Capture,
        tokio::task::JoinHandle<()>,
    ) {
        let capture = Capture::default();
        let app = Router::new()
            .route(
                "/revocation/internal/revocation-profiles/{profile_id}/reserve-index",
                post(reserve),
            )
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let allocator = HttpCredentialStatusAllocator::new(
            Url::parse(&format!("http://{address}/revocation")).expect("URL"),
            Some("service-token"),
            Duration::from_secs(2),
        )
        .expect("allocator");
        (allocator, capture, server)
    }

    #[tokio::test]
    async fn allocation_preserves_tenant_identity_and_mdoc_semantics() {
        let (allocator, capture, server) = allocator().await;

        let allocated = allocator
            .allocate(&transaction(), "credential-a", "mso_mdoc")
            .await
            .expect("allocation");

        assert_eq!(
            allocated.revocation_profile_id.as_deref(),
            Some("profile-a")
        );
        assert_eq!(allocated.entries[0]["type"], "TokenStatusListEntry");
        assert_eq!(allocated.entries[0]["index"], 42);
        let (profile, headers, body) = capture.0.lock().await.take().expect("captured request");
        assert_eq!(profile, "profile-a");
        assert_eq!(
            headers.get("x-service-token").expect("service token"),
            "service-token"
        );
        assert_eq!(body["organization_id"], "org-a");
        assert_eq!(body["credential_format"], "mdoc");
        assert_eq!(body["credential_id"], "credential-a");
        server.abort();
    }

    #[tokio::test]
    async fn missing_profile_fails_before_network_access() {
        let (allocator, _capture, server) = allocator().await;
        let mut transaction = transaction();
        transaction.revocation_profile_id = Some(" ".to_owned());

        let error = allocator
            .allocate(&transaction, "credential-a", "dc+sd-jwt")
            .await
            .expect_err("profile is required");

        assert_eq!(error, CredentialIssuanceError::RevocationProfileRequired);
        server.abort();
    }

    #[test]
    fn signing_formats_map_to_the_legacy_revocation_contract() {
        let expected = HashMap::from([
            ("mso_mdoc", "mdoc"),
            ("mdoc", "mdoc"),
            ("ldp_vc", "json_ld"),
            ("json_ld", "json_ld"),
            ("dc+sd-jwt", "sd_jwt_vc"),
            ("jwt_vc_json", "sd_jwt_vc"),
        ]);
        for (format, normalized) in expected {
            assert_eq!(revocation_credential_format(format), normalized);
        }
    }
}
