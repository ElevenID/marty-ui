//! Personalization bureau transport for the native physical-document service.
//! The Python reference is pinned by Credentials PR #296. Unlike that reference,
//! the document type is forwarded from the durable job instead of forced to TD3.

use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

const BATCH_PATH: &str = "v1/personalization/batches";
const BATCH_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionStatus {
    Queued,
    Printing,
    Encoding,
    QualityCheck,
    Shipped,
    Delivered,
    Failed,
    Cancelled,
}

impl ProductionStatus {
    #[must_use]
    pub const fn issuance_status(self) -> &'static str {
        match self {
            Self::Queued => "SUBMITTED",
            Self::Printing | Self::Encoding => "IN_PRODUCTION",
            Self::QualityCheck => "QUALITY_CHECK",
            Self::Shipped | Self::Delivered => "READY_FOR_ACTIVATION",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DocumentType {
    TD1,
    TD2,
    TD3,
}

#[derive(Clone, Debug)]
pub struct PersonalizationJob {
    pub id: String,
    pub application_id: String,
    pub organization_id: String,
    pub country_code: String,
    pub document_type: DocumentType,
    pub data_groups: BTreeMap<BigUint, String>,
    pub sod_der_base64: String,
    pub dsc_cert_pem: String,
    pub mrz_line_1: String,
    pub mrz_line_2: String,
    pub bureau_job_id: Option<String>,
    pub status: ProductionStatus,
    pub tracking_number: Option<String>,
    pub error_message: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl PersonalizationJob {
    fn named_data_groups(&self) -> BTreeMap<String, &String> {
        self.data_groups
            .iter()
            .map(|(number, content)| (format!("DG{number}"), content))
            .collect()
    }

    fn payload(&self) -> Value {
        json!({
            "job_id": self.id,
            "application_id": self.application_id,
            "organization_id": self.organization_id,
            "country_code": self.country_code,
            "document_type": self.document_type,
            "data_groups": self.named_data_groups(),
            "sod_der_base64": self.sod_der_base64,
            "dsc_cert_pem": self.dsc_cert_pem,
            "mrz": {"line_1": self.mrz_line_1, "line_2": self.mrz_line_2},
        })
    }

    fn batch_payload(&self) -> Value {
        json!({
            "job_id": self.id,
            "application_id": self.application_id,
            "country_code": self.country_code,
            "data_groups": self.named_data_groups(),
            "sod_der_base64": self.sod_der_base64,
            "dsc_cert_pem": self.dsc_cert_pem,
            "mrz": {"line_1": self.mrz_line_1, "line_2": self.mrz_line_2},
        })
    }
}

#[derive(Clone, Debug)]
pub struct PersonalizationBatch {
    pub id: String,
    pub organization_id: String,
    pub jobs: Vec<PersonalizationJob>,
    pub status: ProductionStatus,
    pub submitted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionOutcome {
    pub bureau_job_id: Option<String>,
    pub status: ProductionStatus,
    pub tracking_number: Option<String>,
    pub error_message: Option<String>,
}

impl SubmissionOutcome {
    fn accepted(body: &Value) -> Result<Self, BureauError> {
        let status = production_status_field(body, "status")?.unwrap_or(ProductionStatus::Queued);
        Ok(Self {
            bureau_job_id: body
                .get("bureau_job_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .or_else(|| body.get("job_id").and_then(Value::as_str))
                .map(str::to_owned),
            status,
            tracking_number: body
                .get("tracking_number")
                .and_then(Value::as_str)
                .map(str::to_owned),
            error_message: None,
        })
    }
}

fn production_status_field(
    body: &Value,
    field: &str,
) -> Result<Option<ProductionStatus>, BureauError> {
    body.get(field)
        .and_then(Value::as_str)
        .map(|status| {
            serde_json::from_value(Value::String(status.to_owned()))
                .map_err(|_| BureauError::InvalidResponse("unknown production status".into()))
        })
        .transpose()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PollOutcome {
    pub status: ProductionStatus,
    pub tracking_number: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct WebhookEvent {
    organization_id: String,
    bureau_job_id: String,
    status: ProductionStatus,
    #[serde(flatten)]
    metadata: BTreeMap<String, Value>,
}

/// Only a successful HMAC check can construct this event.
#[derive(Clone, Debug)]
pub struct VerifiedWebhookEvent(WebhookEvent);

impl VerifiedWebhookEvent {
    #[must_use]
    pub fn organization_id(&self) -> &str {
        &self.0.organization_id
    }

    #[must_use]
    pub fn bureau_job_id(&self) -> &str {
        &self.0.bureau_job_id
    }

    #[must_use]
    pub fn status(&self) -> ProductionStatus {
        self.0.status
    }

    #[must_use]
    pub fn tracking_number(&self) -> Option<&str> {
        self.0
            .metadata
            .get("tracking_number")
            .and_then(Value::as_str)
    }

    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        self.0.metadata.get("error_message").and_then(Value::as_str)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BureauError {
    #[error(
        "Personalization bureau not configured. Set PERSONALIZATION_BUREAU_URL environment variable."
    )]
    NotConfigured,
    #[error("Personalization bureau URL is invalid")]
    InvalidUrl,
    #[error("Personalization bureau transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Personalization bureau returned invalid response: {0}")]
    InvalidResponse(String),
    #[error("Invalid personalization webhook signature")]
    InvalidWebhookSignature,
    #[error("Invalid personalization webhook event")]
    InvalidWebhookEvent,
}

#[derive(Clone)]
pub struct BureauClient {
    base_url: Url,
    api_key: String,
    webhook_secret: Option<Vec<u8>>,
    http: Client,
}

impl BureauClient {
    pub fn new(
        base_url: &str,
        api_key: &str,
        webhook_secret: Option<&str>,
    ) -> Result<Self, BureauError> {
        if base_url.is_empty() {
            return Err(BureauError::NotConfigured);
        }
        let base_url = Url::parse(&format!("{}/", base_url.trim_end_matches('/')))
            .map_err(|_| BureauError::InvalidUrl)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(BureauError::InvalidUrl);
        }
        Ok(Self {
            base_url,
            api_key: api_key.to_owned(),
            webhook_secret: webhook_secret
                .filter(|secret| !secret.is_empty())
                .map(str::as_bytes)
                .map(<[u8]>::to_vec),
            http: Client::new(),
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, BureauError> {
        self.base_url
            .join(path)
            .map_err(|_| BureauError::InvalidUrl)
    }

    pub async fn submit(&self, job: &PersonalizationJob) -> Result<SubmissionOutcome, BureauError> {
        let response = self
            .http
            .post(self.endpoint("v1/personalization/jobs")?)
            .bearer_auth(&self.api_key)
            .json(&job.payload())
            .timeout(Duration::from_secs(30))
            .send()
            .await?;
        let status = response.status();
        if !matches!(
            status,
            StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED
        ) {
            return Ok(SubmissionOutcome {
                bureau_job_id: None,
                status: ProductionStatus::Failed,
                tracking_number: None,
                error_message: Some(format!("Bureau returned HTTP {}", status.as_u16())),
            });
        }
        let body: Value = response.json().await?;
        SubmissionOutcome::accepted(&body)
    }

    pub async fn submit_batch(
        &self,
        batch: &PersonalizationBatch,
    ) -> Result<PersonalizationBatch, BureauError> {
        let jobs = batch
            .jobs
            .iter()
            .map(PersonalizationJob::batch_payload)
            .collect::<Vec<_>>();
        let response = self
            .http
            .post(self.endpoint(BATCH_PATH)?)
            .bearer_auth(&self.api_key)
            .json(&json!({
                "batch_id": batch.id,
                "organization_id": batch.organization_id,
                "jobs": jobs,
            }))
            .timeout(BATCH_TIMEOUT)
            .send()
            .await?;
        if !matches!(
            response.status(),
            StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED
        ) {
            let mut result = batch.clone();
            result.status = ProductionStatus::Failed;
            return Ok(result);
        }
        let body: Value = response.json().await?;
        let status = production_status_field(&body, "status")?.unwrap_or(ProductionStatus::Queued);
        let mut outcome = batch.clone();
        outcome.status = status;
        if let Some(reported_jobs) = body.get("jobs").and_then(Value::as_array) {
            for reported in reported_jobs {
                let Some(id) = reported.get("job_id").and_then(Value::as_str) else {
                    continue;
                };
                for job in &mut outcome.jobs {
                    if job.id == id {
                        job.bureau_job_id = reported
                            .get("bureau_job_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        job.status = production_status_field(reported, "status")?
                            .unwrap_or(ProductionStatus::Queued);
                    }
                }
            }
        }
        Ok(outcome)
    }

    pub async fn poll(&self, bureau_job_id: &str) -> Result<PollOutcome, BureauError> {
        let mut url = self.endpoint("v1/personalization/jobs")?;
        url.path_segments_mut()
            .map_err(|_| BureauError::InvalidUrl)?
            .push(bureau_job_id);
        Ok(self
            .http
            .get(url)
            .bearer_auth(&self.api_key)
            .timeout(Duration::from_secs(15))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    #[must_use]
    pub fn verify_webhook(&self, body: &[u8], signature: &str) -> bool {
        verify_webhook_signature(self.webhook_secret.as_deref(), body, signature)
    }

    #[must_use]
    pub(crate) fn webhook_secret(&self) -> Option<&[u8]> {
        self.webhook_secret.as_deref()
    }

    pub fn parse_webhook(
        &self,
        body: &[u8],
        signature: &str,
    ) -> Result<VerifiedWebhookEvent, BureauError> {
        parse_verified_webhook(self.webhook_secret(), body, signature)
    }
}

#[must_use]
pub(crate) fn verify_webhook_signature(
    secret: Option<&[u8]>,
    body: &[u8],
    signature: &str,
) -> bool {
    let Some(secret) = secret else {
        return false;
    };
    // The released webhook accepts the lowercase hexdigest, not alternate
    // encodings of the same MAC.
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    let Ok(signature) = hex::decode(signature) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&signature).is_ok()
}

pub(crate) fn parse_verified_webhook(
    secret: Option<&[u8]>,
    body: &[u8],
    signature: &str,
) -> Result<VerifiedWebhookEvent, BureauError> {
    if !verify_webhook_signature(secret, body, signature) {
        return Err(BureauError::InvalidWebhookSignature);
    }
    let event: WebhookEvent =
        serde_json::from_slice(body).map_err(|_| BureauError::InvalidWebhookEvent)?;
    if event.organization_id.trim().is_empty() || event.bureau_job_id.trim().is_empty() {
        return Err(BureauError::InvalidWebhookEvent);
    }
    Ok(VerifiedWebhookEvent(event))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> Value {
        serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap()
    }

    fn job(document_type: DocumentType) -> PersonalizationJob {
        PersonalizationJob {
            id: "job-1".into(),
            application_id: "application-1".into(),
            organization_id: "organization-1".into(),
            country_code: "UTO".into(),
            document_type,
            data_groups: BTreeMap::from([
                (BigUint::from(1u8), "ZzE=".into()),
                (BigUint::from(2u8), "ZzI=".into()),
            ]),
            sod_der_base64: "c29k".into(),
            dsc_cert_pem: "certificate".into(),
            mrz_line_1: "line-1".into(),
            mrz_line_2: "line-2".into(),
            bureau_job_id: None,
            status: ProductionStatus::Queued,
            tracking_number: None,
            error_message: None,
            submitted_at: Utc::now(),
            updated_at: Utc::now(),
            completed_at: None,
        }
    }

    #[test]
    fn all_accepted_document_types_reach_bureau_payload() {
        for (document_type, expected) in [
            (DocumentType::TD1, "TD1"),
            (DocumentType::TD2, "TD2"),
            (DocumentType::TD3, "TD3"),
        ] {
            let payload = job(document_type).payload();
            assert_eq!(payload["document_type"], expected);
            assert!(reference()["document_types"]
                .as_array()
                .unwrap()
                .contains(&Value::String(expected.into())));
            assert_eq!(payload["data_groups"], json!({"DG1":"ZzE=","DG2":"ZzI="}));
        }
    }

    #[test]
    fn bureau_payload_preserves_wide_python_data_group_number() {
        let frozen = reference();
        let wide = &frozen["wide_data_group_number_observation"];
        let number =
            BigUint::parse_bytes(wide["normalized_number"].as_str().unwrap().as_bytes(), 10)
                .unwrap();
        let mut candidate = job(DocumentType::TD3);
        candidate.data_groups.insert(number, "Yw==".into());
        assert_eq!(
            candidate.payload()["data_groups"][wide["input_name"].as_str().unwrap()],
            "Yw=="
        );
    }

    #[test]
    fn bureau_status_projection_matches_frozen_route() {
        for (status, expected) in [
            (ProductionStatus::Queued, "SUBMITTED"),
            (ProductionStatus::Printing, "IN_PRODUCTION"),
            (ProductionStatus::Encoding, "IN_PRODUCTION"),
            (ProductionStatus::QualityCheck, "QUALITY_CHECK"),
            (ProductionStatus::Shipped, "READY_FOR_ACTIVATION"),
            (ProductionStatus::Delivered, "READY_FOR_ACTIVATION"),
            (ProductionStatus::Failed, "FAILED"),
            (ProductionStatus::Cancelled, "CANCELLED"),
        ] {
            assert_eq!(status.issuance_status(), expected);
            let wire_status = serde_json::to_value(status).unwrap();
            assert_eq!(
                reference()["bureau_status_projection"][wire_status.as_str().unwrap()],
                expected
            );
        }
    }

    #[test]
    fn accepted_submission_preserves_fallback_and_rejects_unknown_status() {
        let fallback =
            SubmissionOutcome::accepted(&json!({"bureau_job_id": null, "job_id": "provider-1"}))
                .unwrap();
        assert_eq!(fallback.bureau_job_id.as_deref(), Some("provider-1"));
        assert_eq!(fallback.status, ProductionStatus::Queued);
        assert!(matches!(
            SubmissionOutcome::accepted(&json!({"status": "UNRECOGNIZED"})),
            Err(BureauError::InvalidResponse(_))
        ));
    }

    #[test]
    fn webhook_signature_fails_closed() {
        for url in [
            "https://user:password@bureau.example",
            "https://bureau.example?token=secret",
            "https://bureau.example#fragment",
        ] {
            assert!(matches!(
                BureauClient::new(url, "key", Some("secret")),
                Err(BureauError::InvalidUrl)
            ));
        }
        let missing = BureauClient::new("https://bureau.example", "key", None).unwrap();
        assert!(!missing.verify_webhook(b"{}", ""));
        let configured =
            BureauClient::new("https://bureau.example", "key", Some("secret")).unwrap();
        let body = br#"{"organization_id":"org-1","bureau_job_id":"job-1","status":"SHIPPED"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(body);
        let signature = hex::encode(mac.finalize().into_bytes());
        assert!(configured.verify_webhook(body, &signature));
        assert!(!configured.verify_webhook(b"{}", &signature));
        assert!(!configured.verify_webhook(body, &signature.to_uppercase()));
        assert!(!configured.verify_webhook(body, "not-hex"));
        let event = configured.parse_webhook(body, &signature).unwrap();
        assert_eq!(event.organization_id(), "org-1");
        assert_eq!(event.bureau_job_id(), "job-1");
        assert_eq!(event.status(), ProductionStatus::Shipped);
        assert_eq!(event.tracking_number(), None);
        assert!(matches!(
            configured.parse_webhook(b"{}", &signature),
            Err(BureauError::InvalidWebhookSignature)
        ));
        let missing_tenant = br#"{"bureau_job_id":"job-1","status":"SHIPPED"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(missing_tenant);
        let signature = hex::encode(mac.finalize().into_bytes());
        assert!(matches!(
            configured.parse_webhook(missing_tenant, &signature),
            Err(BureauError::InvalidWebhookEvent)
        ));
    }

    #[tokio::test]
    async fn batch_submission_preserves_python_envelope_and_input_order() {
        use std::sync::{Arc, Mutex};

        use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};

        type Observed = Arc<Mutex<Vec<(String, Value)>>>;
        async fn submit_batch(
            State(observed): State<Observed>,
            headers: HeaderMap,
            Json(payload): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            let failed = payload["batch_id"] == "failure";
            let partial = payload["batch_id"] == "partial";
            observed.lock().unwrap().push((
                headers["authorization"].to_str().unwrap().to_owned(),
                payload,
            ));
            if failed {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"private":"do-not-expose"})),
                );
            }
            if partial {
                return (
                    StatusCode::ACCEPTED,
                    Json(json!({"jobs":[{"job_id":"job-second", "status":"PRINTING"}]})),
                );
            }
            (
                StatusCode::ACCEPTED,
                Json(reference()["bureau_batch_provider"]["frozen_exchange"]["response"].clone()),
            )
        }
        fn job_from_wire(wire: &Value, document_type: DocumentType) -> PersonalizationJob {
            let mut job = job(document_type);
            job.id = wire["job_id"].as_str().unwrap().into();
            job.application_id = wire["application_id"].as_str().unwrap().into();
            job.country_code = wire["country_code"].as_str().unwrap().into();
            job.data_groups = wire["data_groups"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, content)| {
                    (
                        name.strip_prefix("DG").unwrap().parse().unwrap(),
                        content.as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            job.sod_der_base64 = wire["sod_der_base64"].as_str().unwrap().into();
            job.dsc_cert_pem = wire["dsc_cert_pem"].as_str().unwrap().into();
            job.mrz_line_1 = wire["mrz"]["line_1"].as_str().unwrap().into();
            job.mrz_line_2 = wire["mrz"]["line_2"].as_str().unwrap().into();
            job
        }
        let frozen = reference();
        let exchange = &frozen["bureau_batch_provider"]["frozen_exchange"];
        assert_eq!(format!("/{BATCH_PATH}"), exchange["path"].as_str().unwrap());
        assert_eq!(
            BATCH_TIMEOUT.as_secs(),
            exchange["timeout_seconds"].as_u64().unwrap()
        );
        assert_eq!(exchange["method"], "POST");
        let observed: Observed = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route(&format!("/{BATCH_PATH}"), post(submit_batch))
            .with_state(observed.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let api_key = exchange["authorization"]
            .as_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap();
        let client = BureauClient::new(&format!("http://{address}"), api_key, None).unwrap();
        let jobs = exchange["json"]["jobs"].as_array().unwrap();
        let second = job_from_wire(&jobs[1], DocumentType::TD1);
        let mut first = job_from_wire(&jobs[0], DocumentType::TD3);
        first.status = ProductionStatus::Shipped;
        first.bureau_job_id = Some("prior-bureau".into());
        first.tracking_number = Some("prior-tracking".into());
        first.error_message = Some("prior-error".into());
        first.completed_at = Some(Utc::now());
        let batch = PersonalizationBatch {
            id: exchange["json"]["batch_id"].as_str().unwrap().into(),
            organization_id: exchange["json"]["organization_id"].as_str().unwrap().into(),
            jobs: vec![first, second],
            status: ProductionStatus::Queued,
            submitted_at: Utc::now(),
        };
        let outcome = client.submit_batch(&batch).await.unwrap();
        assert_eq!(outcome.status, ProductionStatus::Queued);
        assert_eq!(outcome.id, exchange["json"]["batch_id"].as_str().unwrap());
        assert_eq!(
            outcome.organization_id,
            exchange["json"]["organization_id"].as_str().unwrap()
        );
        assert_eq!(outcome.submitted_at, batch.submitted_at);
        assert_eq!(
            outcome
                .jobs
                .iter()
                .map(|job| (job.id.as_str(), job.bureau_job_id.as_deref(), job.status))
                .collect::<Vec<_>>(),
            vec![
                (
                    "job-reference",
                    Some("bureau-reference"),
                    ProductionStatus::Queued
                ),
                (
                    "job-second",
                    Some("bureau-second"),
                    ProductionStatus::Printing
                ),
            ]
        );
        let (authorization, payload) = observed.lock().unwrap()[0].clone();
        assert_eq!(authorization, exchange["authorization"].as_str().unwrap());
        assert_eq!(payload, exchange["json"]);
        assert_eq!(
            outcome.jobs[0].tracking_number.as_deref(),
            Some("prior-tracking")
        );
        assert_eq!(
            outcome.jobs[0].error_message.as_deref(),
            Some("prior-error")
        );
        assert_eq!(outcome.jobs[0].completed_at, batch.jobs[0].completed_at);

        let mut partial_batch = batch;
        partial_batch.id = "partial".into();
        let partial = client.submit_batch(&partial_batch).await.unwrap();
        assert_eq!(partial.status, ProductionStatus::Queued);
        assert_eq!(partial.jobs[0].status, ProductionStatus::Shipped);
        assert_eq!(
            partial.jobs[0].bureau_job_id.as_deref(),
            Some("prior-bureau")
        );
        assert_eq!(
            partial.jobs[0].tracking_number.as_deref(),
            Some("prior-tracking")
        );
        assert_eq!(partial.jobs[1].status, ProductionStatus::Printing);
        assert!(partial.jobs[1].bureau_job_id.is_none());

        let mut failed_batch = partial_batch;
        failed_batch.id = "failure".into();
        let failed = client.submit_batch(&failed_batch).await.unwrap();
        assert_eq!(failed.status, ProductionStatus::Failed);
        assert_eq!(failed.jobs[0].status, ProductionStatus::Shipped);
        assert_eq!(
            failed.jobs[0].bureau_job_id.as_deref(),
            Some("prior-bureau")
        );
        assert_eq!(failed.jobs[1].status, ProductionStatus::Queued);
        assert!(failed.jobs[1].bureau_job_id.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn bureau_http_preserves_auth_payload_status_and_private_error_boundary() {
        use std::sync::{Arc, Mutex};

        use axum::{
            extract::{Path, State},
            http::{HeaderMap, StatusCode},
            routing::{get, post},
            Json, Router,
        };

        type Observed = Arc<Mutex<Vec<(String, String, Value)>>>;
        async fn submit(
            State(observed): State<Observed>,
            headers: HeaderMap,
            Json(payload): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            let rejected = payload["job_id"] == "private-job";
            observed.lock().unwrap().push((
                "POST".into(),
                headers["authorization"].to_str().unwrap().into(),
                payload,
            ));
            if rejected {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "private applicant details"})),
                );
            }
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "bureau_job_id": "bureau-1",
                    "status": "SHIPPED",
                    "tracking_number": "track-1"
                })),
            )
        }
        async fn poll(
            State(observed): State<Observed>,
            Path(job_id): Path<String>,
            headers: HeaderMap,
        ) -> Json<Value> {
            observed.lock().unwrap().push((
                "GET".into(),
                headers["authorization"].to_str().unwrap().into(),
                json!({"job_id": job_id}),
            ));
            Json(json!({"status": "PRINTING", "tracking_number": "track-2"}))
        }

        let observed: Observed = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/v1/personalization/jobs", post(submit))
            .route("/v1/personalization/jobs/{job_id}", get(poll))
            .with_state(observed.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client =
            BureauClient::new(&format!("http://{address}"), "bureau-key", Some("hmac")).unwrap();

        let submitted = client.submit(&job(DocumentType::TD2)).await.unwrap();
        assert_eq!(submitted.status, ProductionStatus::Shipped);
        assert_eq!(submitted.bureau_job_id.as_deref(), Some("bureau-1"));
        assert_eq!(submitted.tracking_number.as_deref(), Some("track-1"));
        let polled = client.poll("bureau-1").await.unwrap();
        assert_eq!(polled.status, ProductionStatus::Printing);
        let mut rejected_job = job(DocumentType::TD3);
        rejected_job.id = "private-job".into();
        let rejected = client.submit(&rejected_job).await.unwrap();
        assert_eq!(rejected.status, ProductionStatus::Failed);
        assert_eq!(
            rejected.error_message.as_deref(),
            Some("Bureau returned HTTP 503")
        );
        let requests = observed.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0, "POST");
        assert_eq!(requests[0].1, "Bearer bureau-key");
        assert_eq!(requests[0].2["document_type"], "TD2");
        assert_eq!(requests[0].2["mrz"]["line_1"], "line-1");
        assert_eq!(requests[1].0, "GET");
        assert_eq!(requests[1].1, "Bearer bureau-key");
        assert_eq!(requests[1].2["job_id"], "bureau-1");
        server.abort();
    }
}
