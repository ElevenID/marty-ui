//! Fixed-origin authenticated Flow owner acquisition. Public DTO parsing alone
//! cannot create `AcquiredPrerequisiteEvidence`.

use std::time::Duration;

use marty_oid4vp_contract::issuance_prerequisite::{
    IssuanceIntentBindingV1, IssuancePrerequisiteEvidenceRequestV1,
    IssuancePrerequisiteEvidenceResponseV1, IssuancePrerequisiteStartRequestV1,
    IssuancePrerequisiteStartResponseV1, ISSUANCE_PREREQUISITE_EVIDENCE_REQUEST_V1,
    ISSUANCE_PREREQUISITE_START_REQUEST_V1,
};
use reqwest::{header::HeaderValue, Client, Url};
use serde::Serialize;

use crate::verification_prerequisite::{now_micros, AcquiredPrerequisiteEvidence};

const MAX_OWNER_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct FlowPrerequisiteClient {
    client: Client,
    origin: Url,
    service_token: HeaderValue,
}

impl std::fmt::Debug for FlowPrerequisiteClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FlowPrerequisiteClient")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Authenticated prerequisite Flow owner is unavailable or rejected the binding")]
pub struct PrerequisiteOwnerError;

impl FlowPrerequisiteClient {
    /// Both the origin and public CA bundle are supplied by the operator. No
    /// request locator, environment proxy or system-root fallback selects trust.
    pub fn new(
        origin: &str,
        service_token: &str,
        ca_pem: &[u8],
    ) -> Result<Self, PrerequisiteOwnerError> {
        let origin = Url::parse(origin).map_err(|_| PrerequisiteOwnerError)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || origin.path() != "/"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !(32..=8192).contains(&service_token.len())
            || ca_pem.is_empty()
            || ca_pem.len() > 65536
        {
            return Err(PrerequisiteOwnerError);
        }
        let roots =
            reqwest::Certificate::from_pem_bundle(ca_pem).map_err(|_| PrerequisiteOwnerError)?;
        if roots.is_empty() {
            return Err(PrerequisiteOwnerError);
        }
        let mut service_token =
            HeaderValue::from_str(service_token).map_err(|_| PrerequisiteOwnerError)?;
        service_token.set_sensitive(true);
        let builder = Client::builder()
            .https_only(true)
            .tls_certs_only(roots)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10));
        Ok(Self {
            client: builder.build().map_err(|_| PrerequisiteOwnerError)?,
            origin,
            service_token,
        })
    }

    pub async fn start(
        &self,
        intent: &IssuanceIntentBindingV1,
    ) -> Result<IssuancePrerequisiteStartResponseV1, PrerequisiteOwnerError> {
        intent
            .validate_at(now_micros())
            .map_err(|_| PrerequisiteOwnerError)?;
        let body = IssuancePrerequisiteStartRequestV1 {
            contract: ISSUANCE_PREREQUISITE_START_REQUEST_V1.into(),
            intent: intent.clone(),
        };
        let wire = self.post(intent, "start", &body).await?;
        let result = IssuancePrerequisiteStartResponseV1::from_json(&wire)
            .map_err(|_| PrerequisiteOwnerError)?;
        result
            .validate_for_intent(intent, now_micros())
            .map_err(|_| PrerequisiteOwnerError)?;
        Ok(result)
    }

    pub(crate) async fn evidence(
        &self,
        intent: &IssuanceIntentBindingV1,
    ) -> Result<AcquiredPrerequisiteEvidence, PrerequisiteOwnerError> {
        intent
            .validate_at(now_micros())
            .map_err(|_| PrerequisiteOwnerError)?;
        let body = IssuancePrerequisiteEvidenceRequestV1 {
            contract: ISSUANCE_PREREQUISITE_EVIDENCE_REQUEST_V1.into(),
            intent: intent.clone(),
        };
        let wire = self.post(intent, "evidence", &body).await?;
        let response = IssuancePrerequisiteEvidenceResponseV1::from_json(&wire)
            .map_err(|error| {
                tracing::debug!(stage="evidence_json", reason=?error, "prerequisite owner acquisition rejected");
                PrerequisiteOwnerError
            })?;
        response
            .validate_for_intent(intent, now_micros())
            .map_err(|error| {
                tracing::debug!(stage="evidence_correspondence", reason=?error, "prerequisite owner acquisition rejected");
                PrerequisiteOwnerError
            })?;
        Ok(AcquiredPrerequisiteEvidence { response })
    }

    async fn post(
        &self,
        intent: &IssuanceIntentBindingV1,
        operation: &str,
        body: &impl Serialize,
    ) -> Result<String, PrerequisiteOwnerError> {
        let mut url = self.origin.clone();
        url.path_segments_mut()
            .map_err(|_| PrerequisiteOwnerError)?
            .pop_if_empty()
            .extend([
                "internal",
                "v1",
                "issuance-prerequisites",
                &intent.transaction_id,
                operation,
            ]);
        let mut response = self
            .client
            .post(url)
            .header("x-service-token", self.service_token.clone())
            .json(body)
            .send()
            .await
            .map_err(|error| {
                tracing::debug!(
                    stage = "transport",
                    operation,
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    "prerequisite owner acquisition rejected"
                );
                PrerequisiteOwnerError
            })?;
        if response.status() != reqwest::StatusCode::OK
            || response.headers().get_all("content-type").iter().count() != 1
            || response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .map(str::trim)
                != Some("application/json")
            || response
                .content_length()
                .is_some_and(|size| size > MAX_OWNER_RESPONSE_BYTES as u64)
        {
            tracing::debug!(
                stage = "response_headers",
                operation,
                status = response.status().as_u16(),
                "prerequisite owner acquisition rejected"
            );
            return Err(PrerequisiteOwnerError);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            tracing::debug!(
                stage = "response_body",
                operation,
                timeout = error.is_timeout(),
                "prerequisite owner acquisition rejected"
            );
            PrerequisiteOwnerError
        })? {
            if bytes.len().saturating_add(chunk.len()) > MAX_OWNER_RESPONSE_BYTES {
                return Err(PrerequisiteOwnerError);
            }
            bytes.extend_from_slice(&chunk);
        }
        String::from_utf8(bytes).map_err(|_| PrerequisiteOwnerError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::State,
        http::{Request, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
        Json, Router,
    };
    use marty_oid4vp_contract::{
        issuance_prerequisite::{
            IssuancePrerequisitePolicyV1, IssuancePrerequisiteProfileV1,
            ISSUANCE_INTENT_CONTRACT_V1, ISSUANCE_PREREQUISITE_START_RESPONSE_V1,
        },
        FrozenPolicyIdentity,
    };
    use serde_json::json;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const TOKEN: &str = "dedicated-prerequisite-test-owner-token-1234567890";

    fn intent() -> IssuanceIntentBindingV1 {
        let now = now_micros();
        IssuanceIntentBindingV1 {
            contract: ISSUANCE_INTENT_CONTRACT_V1.into(),
            organization_id: "tenant-one".into(),
            transaction_id: "issuance-one".into(),
            initiating_principal_id: "user-one".into(),
            applicant_id: None,
            application_id: None,
            subject_did: None,
            credential_template_id: "template-one".into(),
            credential_template_version: 1,
            credential_configuration_id: "EmployeeCredential#sd-jwt".into(),
            credential_payload_format: "SD_JWT_VC".into(),
            issuer_did: "did:web:issuer.example".into(),
            dataset_digest: format!("sha256:{}", "a".repeat(64)),
            prerequisite: IssuancePrerequisitePolicyV1 {
                profile: IssuancePrerequisiteProfileV1::ManagedSdJwtDcqlSameHolderV1,
                flow_definition_id: "flow-definition".into(),
                flow_definition_version: 1,
                policy: FrozenPolicyIdentity {
                    id: "policy-one".into(),
                    version: 1,
                    content_digest: format!("sha256:{}", "b".repeat(64)),
                },
                verifier_issuer_did: "did:web:verifier.example".into(),
                ttl_seconds: 120,
            },
            flow_instance_id: "flow-instance-one".into(),
            created_at_epoch_micros: now,
            expires_at_epoch_micros: now + 120_000_000,
            intent_digest: String::new(),
        }
        .seal()
        .unwrap()
    }

    async fn start(State(mode): State<Arc<AtomicUsize>>, request: Request<Body>) -> Response {
        if request
            .headers()
            .get("x-service-token")
            .and_then(|v| v.to_str().ok())
            != Some(TOKEN)
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        assert_eq!(
            request.uri().path(),
            "/internal/v1/issuance-prerequisites/issuance-one/start"
        );
        let body = axum::body::to_bytes(request.into_body(), 32_768)
            .await
            .unwrap();
        let request =
            IssuancePrerequisiteStartRequestV1::from_json(std::str::from_utf8(&body).unwrap())
                .unwrap();
        let mut response = json!({
            "contract": ISSUANCE_PREREQUISITE_START_RESPONSE_V1,
            "intent_digest": request.intent.intent_digest,
            "flow_instance_id": request.intent.flow_instance_id,
            "request_uri": "https://verifier.example/oid4vp/request/one",
            "qr_data": "openid4vp://authorize?client_id=x509_san_dns%3Averifier.example&request_uri=https%3A%2F%2Fverifier.example%2Foid4vp%2Frequest%2Fone",
            "expires_at_epoch_micros": request.intent.expires_at_epoch_micros,
        });
        match mode.load(Ordering::SeqCst) {
            1 => (
                [("content-type", "application/json")],
                format!(
                    "{{\"contract\":\"duplicate\",{}",
                    &response.to_string()[1..]
                ),
            )
                .into_response(),
            2 => {
                response["intent_digest"] = json!(format!("sha256:{}", "c".repeat(64)));
                Json(response).into_response()
            }
            3 => (
                StatusCode::TEMPORARY_REDIRECT,
                [("location", "https://other-owner.example/")],
            )
                .into_response(),
            4 => (
                [("content-type", "application/json")],
                "x".repeat(MAX_OWNER_RESPONSE_BYTES + 1),
            )
                .into_response(),
            5 => ([("content-type", "text/plain")], response.to_string()).into_response(),
            _ => Json(response).into_response(),
        }
    }

    #[tokio::test]
    async fn prerequisite_owner_transport_requires_pinned_ca_authentication_and_exact_correspondence(
    ) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let ca = certified.cert.pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            ca.as_bytes().to_vec(),
            certified.signing_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let mode = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/internal/v1/issuance-prerequisites/issuance-one/start",
                post(start),
            )
            .with_state(mode.clone());
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(router.into_make_service())
                .await
                .unwrap();
        });
        let origin = format!("https://{address}");
        let client = FlowPrerequisiteClient::new(&origin, TOKEN, ca.as_bytes()).unwrap();
        let intent = intent();
        let started = client.start(&intent).await.unwrap();
        assert_eq!(started.intent_digest, intent.intent_digest);
        for case in 1..=5 {
            mode.store(case, Ordering::SeqCst);
            assert!(
                client.start(&intent).await.is_err(),
                "response control {case}"
            );
        }
        mode.store(0, Ordering::SeqCst);
        let wrong_token = FlowPrerequisiteClient::new(
            &origin,
            "another-owner-service-token-1234567890",
            ca.as_bytes(),
        )
        .unwrap();
        assert!(wrong_token.start(&intent).await.is_err());
        let wrong_ca = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])
            .unwrap()
            .cert
            .pem();
        assert!(
            FlowPrerequisiteClient::new(&origin, TOKEN, wrong_ca.as_bytes())
                .unwrap()
                .start(&intent)
                .await
                .is_err()
        );
        assert!(FlowPrerequisiteClient::new(
            &format!("https://localhost:{}", address.port()),
            TOKEN,
            ca.as_bytes()
        )
        .unwrap()
        .start(&intent)
        .await
        .is_err());
        assert!(client.evidence(&intent).await.is_err());
        assert!(!format!("{client:?}").contains(TOKEN));
        server.abort();
    }

    #[test]
    fn prerequisite_owner_has_no_plaintext_or_ambient_root_configuration() {
        for origin in [
            "http://owner.example",
            "https://owner.example/path",
            "https://user@owner.example",
            "https://owner.example?tenant=other",
        ] {
            assert!(FlowPrerequisiteClient::new(origin, TOKEN, b"").is_err());
        }
        assert!(FlowPrerequisiteClient::new("https://owner.example", TOKEN, b"").is_err());
        assert!(
            FlowPrerequisiteClient::new("https://owner.example", TOKEN, b"not a certificate")
                .is_err()
        );
    }
}
