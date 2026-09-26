//! Beta-only, non-physical personalization simulator. It never stores MRZ,
//! data groups, certificates, or SOD bytes and cannot start outside beta.

use std::{env, net::SocketAddr, time::Duration};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{redirect::Policy, Client, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, time::interval};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const SCHEMA: &str = include_str!("passport_beta_bureau_schema.sql");

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    database_url: String,
    service_token: String,
    signing_api_key: String,
    signing_url: Url,
    callback_url: Url,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        if !beta_gate(
            env::var("ENVIRONMENT").ok().as_deref(),
            env::var("PASSPORT_BETA_BUREAU_ENABLED").ok().as_deref(),
        ) {
            return Err(
                "passport bureau simulator is beta-only and must be explicitly enabled".into(),
            );
        }
        let service_token = required("GRPC_SERVICE_TOKEN")?;
        if service_token.len() < 32 || service_token.starts_with("dev-") {
            return Err("a non-development internal service token is required".into());
        }
        let signing_api_key = required("SIGNING_KEYS_INTERNAL_API_KEY")?;
        if signing_api_key.starts_with("dev-") {
            return Err("a non-development signing-keys internal credential is required".into());
        }
        let signing_base = required_url("SIGNING_KEYS_INTERNAL_URL")?;
        if !private_signing_gateway(&signing_base) {
            return Err(
                "SIGNING_KEYS_INTERNAL_URL must name the isolated beta callback signer".into(),
            );
        }
        let callback_url = required_url("PASSPORT_BUREAU_CALLBACK_URL")?;
        if !private_native_callback(&callback_url) {
            return Err(
                "PASSPORT_BUREAU_CALLBACK_URL must name the private native callback route".into(),
            );
        }
        let listen = env::var("PASSPORT_BETA_BUREAU_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:8020".into())
            .parse()
            .map_err(|_| "invalid PASSPORT_BETA_BUREAU_LISTEN")?;
        let database_url =
            required("DATABASE_URL")?.replacen("postgresql+asyncpg://", "postgresql://", 1);
        if !private_beta_database(&database_url) {
            return Err("DATABASE_URL must name the private beta database".into());
        }
        Ok(Self {
            listen,
            database_url,
            service_token,
            signing_api_key,
            signing_url: signing_base,
            callback_url,
        })
    }
}

fn beta_gate(environment: Option<&str>, enabled: Option<&str>) -> bool {
    environment == Some("beta") && enabled == Some("true")
}

fn private_signing_gateway(url: &Url) -> bool {
    url.as_str().trim_end_matches('/') == "http://passport-callback-signer:8018/internal/documents"
}

fn private_native_callback(url: &Url) -> bool {
    url.as_str() == "http://issuance-native:8005/v1/passport/webhooks/personalization"
}

fn private_beta_database(value: &str) -> bool {
    Url::parse(value).ok().is_some_and(|url| {
        matches!(url.scheme(), "postgres" | "postgresql")
            && url.host_str() == Some("postgres")
            && url.port() == Some(5432)
            && url.path() == "/marty"
            && url.username() == "marty"
            && url.password().is_some_and(|password| !password.is_empty())
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn required_url(name: &str) -> Result<Url, String> {
    let value = required(name)?;
    let url = Url::parse(&value).map_err(|_| format!("{name} is invalid"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!("{name} must be a credential-free HTTP URL"));
    }
    Ok(url)
}

#[derive(Clone)]
struct AppState {
    config: Config,
    pool: PgPool,
    http: Client,
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Invalid,
    Conflict,
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            Self::Invalid => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid personalization job",
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "Job id already used with different content",
            ),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "Bureau unavailable"),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

fn authorize(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let supplied = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if supplied.len() == expected.len()
        && supplied.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1
    {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

struct JobInput<'a> {
    organization_id: &'a str,
    job_id: &'a str,
    digest: Vec<u8>,
}

fn nonempty_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, ApiError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty() && text.len() <= 256)
        .ok_or(ApiError::Invalid)
}

fn nonempty_document_field(value: &Value, field: &str) -> Result<(), ApiError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(|_| ())
        .ok_or(ApiError::Invalid)
}

fn validate_job<'a>(
    value: &'a Value,
    inherited_organization_id: Option<&'a str>,
) -> Result<JobInput<'a>, ApiError> {
    let organization_id = inherited_organization_id
        .map(Ok)
        .unwrap_or_else(|| nonempty_field(value, "organization_id"))?;
    if let Some(explicit) = value.get("organization_id") {
        if explicit.as_str() != Some(organization_id) {
            return Err(ApiError::Invalid);
        }
    }
    let job_id = nonempty_field(value, "job_id")?;
    let _ = nonempty_field(value, "application_id")?;
    let country = nonempty_field(value, "country_code")?;
    if country.len() != 3 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(ApiError::Invalid);
    }
    // The frozen batch client omits document_type. Accept it there for wire
    // compatibility, while requiring the explicit type on single submissions.
    let document_type = value.get("document_type").and_then(Value::as_str);
    if !(matches!(document_type, Some("TD1" | "TD2" | "TD3"))
        || (inherited_organization_id.is_some() && document_type.is_none()))
    {
        return Err(ApiError::Invalid);
    }
    if !value.get("data_groups").is_some_and(Value::is_object)
        || nonempty_document_field(value, "sod_der_base64").is_err()
        || nonempty_document_field(value, "dsc_cert_pem").is_err()
        || value.get("mrz").is_none_or(|mrz| {
            nonempty_field(mrz, "line_1").is_err() || nonempty_field(mrz, "line_2").is_err()
        })
    {
        return Err(ApiError::Invalid);
    }
    // SOD signatures and the accompanying public DSC may change when an
    // accepted request is retried after its response is lost. The document
    // content and tenant-bound source job must remain identical.
    let document_identity = json!({
        "organization_id": organization_id,
        "job_id": job_id,
        "application_id": value["application_id"],
        "country_code": country,
        "document_type": document_type,
        "data_groups": value["data_groups"],
        "mrz": value["mrz"],
    });
    let digest =
        Sha256::digest(serde_json::to_vec(&document_identity).map_err(|_| ApiError::Invalid)?)
            .to_vec();
    Ok(JobInput {
        organization_id,
        job_id,
        digest,
    })
}

async fn upsert_job(pool: &PgPool, job: &JobInput<'_>) -> Result<Uuid, ApiError> {
    let proposed = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO issuance_service.passport_beta_bureau_jobs
         (bureau_job_id, organization_id, source_job_id, request_sha256, status, next_transition_at)
         VALUES ($1, $2, $3, $4, 'QUEUED', NOW() + INTERVAL '5 seconds')
         ON CONFLICT (organization_id, source_job_id) DO NOTHING",
    )
    .bind(proposed)
    .bind(job.organization_id)
    .bind(job.job_id)
    .bind(&job.digest)
    .execute(pool)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    let row = sqlx::query(
        "SELECT bureau_job_id, request_sha256 FROM issuance_service.passport_beta_bureau_jobs
         WHERE organization_id = $1 AND source_job_id = $2",
    )
    .bind(job.organization_id)
    .bind(job.job_id)
    .fetch_one(pool)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    let existing_digest: Vec<u8> = row
        .try_get("request_sha256")
        .map_err(|_| ApiError::Unavailable)?;
    if existing_digest != job.digest {
        return Err(ApiError::Conflict);
    }
    row.try_get("bureau_job_id")
        .map_err(|_| ApiError::Unavailable)
}

async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&headers, &state.config.service_token)?;
    let value: Value = serde_json::from_slice(&body).map_err(|_| ApiError::Invalid)?;
    let job = validate_job(&value, None)?;
    let bureau_job_id = upsert_job(&state.pool, &job).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "bureau_job_id": bureau_job_id,
            "status": "QUEUED"
        })),
    ))
}

async fn submit_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&headers, &state.config.service_token)?;
    let value: Value = serde_json::from_slice(&body).map_err(|_| ApiError::Invalid)?;
    let organization_id = nonempty_field(&value, "organization_id")?;
    let _ = nonempty_field(&value, "batch_id")?;
    let jobs = value
        .get("jobs")
        .and_then(Value::as_array)
        .filter(|jobs| !jobs.is_empty() && jobs.len() <= 100)
        .ok_or(ApiError::Invalid)?;
    let validated = jobs
        .iter()
        .map(|job| validate_job(job, Some(organization_id)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut outcomes = Vec::with_capacity(validated.len());
    for job in &validated {
        let bureau_job_id = upsert_job(&state.pool, job).await?;
        outcomes.push(
            json!({"job_id": job.job_id, "bureau_job_id": bureau_job_id, "status": "QUEUED"}),
        );
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"status": "QUEUED", "jobs": outcomes})),
    ))
}

async fn poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(bureau_job_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&headers, &state.config.service_token)?;
    let row = sqlx::query(
        "SELECT status FROM issuance_service.passport_beta_bureau_jobs WHERE bureau_job_id = $1",
    )
    .bind(bureau_job_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| ApiError::Unavailable)?
    .ok_or(ApiError::Invalid)?;
    let status: String = row.try_get("status").map_err(|_| ApiError::Unavailable)?;
    let tracking = (status == "SHIPPED").then(|| format!("BETA-SIM-{}", bureau_job_id.simple()));
    Ok(Json(json!({"status": status, "tracking_number": tracking})))
}

fn next_status(status: &str) -> Option<&'static str> {
    match status {
        "QUEUED" => Some("PRINTING"),
        "PRINTING" => Some("ENCODING"),
        "ENCODING" => Some("QUALITY_CHECK"),
        "QUALITY_CHECK" => Some("SHIPPED"),
        _ => None,
    }
}

async fn deliver_one(state: &AppState) -> Result<bool, String> {
    let lease = Uuid::new_v4();
    let row = sqlx::query(
        "UPDATE issuance_service.passport_beta_bureau_jobs SET
             callback_lease_token = $1, callback_lease_until = NOW() + INTERVAL '30 seconds'
         WHERE bureau_job_id = (
             SELECT bureau_job_id FROM issuance_service.passport_beta_bureau_jobs
             WHERE next_transition_at <= NOW()
               AND (callback_lease_until IS NULL OR callback_lease_until < NOW())
               AND status <> 'SHIPPED'
             ORDER BY next_transition_at, bureau_job_id FOR UPDATE SKIP LOCKED LIMIT 1
         ) RETURNING bureau_job_id, organization_id, status",
    )
    .bind(lease)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| "database claim failed")?;
    let Some(row) = row else { return Ok(false) };
    let bureau_job_id: Uuid = row
        .try_get("bureau_job_id")
        .map_err(|_| "invalid database row")?;
    let organization_id: String = row
        .try_get("organization_id")
        .map_err(|_| "invalid database row")?;
    let status: String = row.try_get("status").map_err(|_| "invalid database row")?;
    let next = next_status(&status).ok_or("invalid database status")?;
    let mut callback = json!({
        "organization_id": organization_id,
        "bureau_job_id": bureau_job_id,
        "status": next
    });
    if next == "SHIPPED" {
        callback["tracking_number"] = json!(format!("BETA-SIM-{}", bureau_job_id.simple()));
    }
    let body = serde_json::to_vec(&callback).map_err(|_| "callback serialization failed")?;
    let mut sign_url = state.config.signing_url.clone();
    sign_url
        .path_segments_mut()
        .map_err(|()| "invalid private signing URL")?
        .push(&organization_id)
        .push("passport-callbacks")
        .push("sign");
    let signed = state
        .http
        .post(sign_url)
        .header("x-api-key", &state.config.signing_api_key)
        .json(&json!({"body_b64": STANDARD.encode(&body)}))
        .send()
        .await
        .map_err(|_| "KMS callback signing unavailable")?;
    if !signed.status().is_success() {
        return Err("KMS callback signing refused".into());
    }
    let signature = signed
        .json::<Value>()
        .await
        .map_err(|_| "invalid KMS signing response")?
        .get("signature")
        .and_then(Value::as_str)
        .filter(|signature| signature.starts_with("vault:v"))
        .ok_or("missing KMS callback signature")?
        .to_owned();
    let delivered = state
        .http
        .post(state.config.callback_url.clone())
        .header("x-personalization-signature", signature)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| "native callback transport unavailable")?;
    if !delivered.status().is_success() {
        return Err("native callback refused signed event".into());
    }
    let updated = sqlx::query(
        "UPDATE issuance_service.passport_beta_bureau_jobs SET status = $1,
             next_transition_at = CASE WHEN $1 = 'SHIPPED' THEN NULL ELSE NOW() + INTERVAL '5 seconds' END,
             callback_lease_token = NULL, callback_lease_until = NULL, updated_at = NOW()
         WHERE bureau_job_id = $2 AND callback_lease_token = $3 AND status = $4",
    )
    .bind(next).bind(bureau_job_id).bind(lease).bind(&status)
    .execute(&state.pool).await.map_err(|_| "database transition failed")?;
    if updated.rows_affected() != 1 {
        return Err("callback lease was lost".into());
    }
    info!(bureau_job_id = %bureau_job_id, status = next, "beta passport simulation advanced");
    Ok(true)
}

async fn run_callbacks(state: AppState) {
    let mut timer = interval(Duration::from_secs(2));
    loop {
        timer.tick().await;
        for _ in 0..20 {
            match deliver_one(&state).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(reason) => {
                    warn!(reason, "beta passport callback deferred");
                    break;
                }
            }
        }
    }
}

async fn health() -> &'static str {
    "ok"
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/personalization/jobs", post(submit))
        .route("/v1/personalization/batches", post(submit_batch))
        .route("/v1/personalization/jobs/{bureau_job_id}", get(poll))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = Config::from_env().map_err(|reason| {
        error!(reason, "invalid beta passport bureau configuration");
        reason
    })?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    sqlx::raw_sql(SCHEMA).execute(&pool).await?;
    let http = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let listen = config.listen;
    let state = AppState { config, pool, http };
    let app = router(state.clone());
    let listener = TcpListener::bind(listen).await?;
    info!(%listen, "starting beta-only non-physical passport bureau simulator");
    tokio::spawn(run_callbacks(state));
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    fn disposable_database_url(value: &str) -> bool {
        Url::parse(value).ok().is_some_and(|url| {
            matches!(url.scheme(), "postgres" | "postgresql")
                && url.host_str() == Some("127.0.0.1")
                && url.path() == "/marty_passport_bureau_test"
        })
    }

    #[test]
    fn bureau_database_contract_refuses_nonlocal_or_wrong_database() {
        assert!(disposable_database_url(
            "postgresql://postgres@127.0.0.1:5432/marty_passport_bureau_test"
        ));
        for value in [
            "postgresql://postgres@127.0.0.1:5432/marty",
            "postgresql://postgres@test.example:5432/marty_passport_bureau_test",
            "postgresql://postgres@localhost:5432/marty_passport_bureau_test",
            "postgresql://postgres@127.0.0.1:5432/marty_passport_bureau_test_extra",
            "https://127.0.0.1/marty_passport_bureau_test",
        ] {
            assert!(
                !disposable_database_url(value),
                "unexpected database URL accepted"
            );
        }
    }

    #[test]
    fn startup_database_must_match_the_private_beta_compose_target() {
        assert!(private_beta_database(
            "postgresql://marty:synthetic@postgres:5432/marty"
        ));
        for value in [
            "postgresql://marty:synthetic@production.example:5432/marty",
            "postgresql://marty:synthetic@postgres:5432/production",
            "postgresql://admin:synthetic@postgres:5432/marty",
            "postgresql://marty@postgres:5432/marty",
            "postgresql://marty:synthetic@postgres:5432/marty?sslmode=disable",
            "postgresql://marty:synthetic@postgres:5432/marty#other",
            "postgresql://marty:synthetic@postgres/marty",
        ] {
            assert!(
                !private_beta_database(value),
                "unexpected database URL accepted"
            );
        }
    }

    async fn synthetic_sign(
        Path(organization_id): Path<String>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(headers.get("x-api-key").unwrap(), "synthetic-signing-auth");
        assert_eq!(organization_id, "test-org-a");
        let body = STANDARD
            .decode(request["body_b64"].as_str().unwrap())
            .unwrap();
        let event: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(event["organization_id"], "test-org-a");
        assert_eq!(event["status"], "PRINTING");
        Json(json!({"signature": format!("vault:v1:{}", STANDARD.encode([7u8; 32]))}))
    }

    async fn synthetic_callback(headers: HeaderMap, body: Bytes) -> StatusCode {
        assert!(headers
            .get("x-personalization-signature")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("vault:v1:"));
        let event: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(event["organization_id"], "test-org-a");
        assert_eq!(event["status"], "PRINTING");
        StatusCode::NO_CONTENT
    }

    #[test]
    fn rejects_missing_credentials_and_beta_gate() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            authorize(&headers, "synthetic-token"),
            Err(ApiError::Unauthorized)
        ));
        headers.insert("authorization", "Bearer synthetic-token".parse().unwrap());
        assert!(authorize(&headers, "synthetic-token").is_ok());
        assert!(matches!(
            authorize(&headers, "synthetic-other"),
            Err(ApiError::Unauthorized)
        ));
        assert!(beta_gate(Some("beta"), Some("true")));
        assert!(!beta_gate(Some("production"), Some("true")));
        assert!(!beta_gate(Some("beta"), None));
        assert!(private_signing_gateway(
            &Url::parse("http://passport-callback-signer:8018/internal/documents").unwrap()
        ));
        assert!(!private_signing_gateway(
            &Url::parse("http://gateway:8000/internal/signing-keys").unwrap()
        ));
        assert!(private_native_callback(
            &Url::parse("http://issuance-native:8005/v1/passport/webhooks/personalization")
                .unwrap()
        ));
        assert!(!private_native_callback(
            &Url::parse("http://external.example/v1/passport/webhooks/personalization").unwrap()
        ));
    }

    #[test]
    fn validates_tenant_and_sensitive_payload_without_retaining_it() {
        let value = json!({
            "job_id": "job-1", "application_id": "app-1", "organization_id": "org-1",
            "country_code": "USA", "document_type": "TD3", "data_groups": {"DG1": "sensitive"},
            "sod_der_base64": "c29k", "dsc_cert_pem": "public-cert",
            "mrz": {"line_1": "private-1", "line_2": "private-2"}
        });
        let job = validate_job(&value, None).unwrap();
        assert_eq!(job.organization_id, "org-1");
        assert_eq!(job.digest.len(), 32);
        assert!(!job.digest.windows(7).any(|part| part == b"private"));
        let mut resigned = value.clone();
        resigned["sod_der_base64"] = json!("other-signature");
        resigned["dsc_cert_pem"] = json!("renewed-public-cert");
        assert_eq!(validate_job(&resigned, None).unwrap().digest, job.digest);
        resigned["mrz"]["line_2"] = json!("changed-document");
        assert_ne!(validate_job(&resigned, None).unwrap().digest, job.digest);
        assert!(validate_job(&value, Some("foreign-org")).is_err());
        let mut wrong = value;
        wrong["document_type"] = json!("VISA");
        assert!(validate_job(&wrong, None).is_err());
    }

    #[test]
    fn simulation_has_closed_nonphysical_status_sequence() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/passport-beta-bureau-behavior.json"
        ))
        .unwrap();
        assert_eq!(contract["startup_gate"]["ENVIRONMENT"], "beta");
        assert_eq!(
            contract["security"]["maximum_request_bytes"],
            MAX_REQUEST_BYTES
        );
        let frozen = contract["status_sequence"].as_array().unwrap();
        let actual = ["QUEUED", "PRINTING", "ENCODING", "QUALITY_CHECK", "SHIPPED"];
        assert_eq!(frozen, &actual.map(|status| json!(status)));
        assert_eq!(next_status("QUEUED"), Some("PRINTING"));
        assert_eq!(next_status("PRINTING"), Some("ENCODING"));
        assert_eq!(next_status("ENCODING"), Some("QUALITY_CHECK"));
        assert_eq!(next_status("QUALITY_CHECK"), Some("SHIPPED"));
        assert_eq!(next_status("SHIPPED"), None);
        assert_eq!(next_status("FAILED"), None);
    }

    #[tokio::test]
    async fn postgres_bureau_jobs_are_durable_idempotent_and_tenant_bound_when_configured() {
        let Ok(database_url) = env::var("PASSPORT_BUREAU_TEST_DATABASE_URL") else {
            return;
        };
        assert!(
            disposable_database_url(&database_url),
            "refuse a nonlocal or non-disposable database"
        );
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        sqlx::query("CREATE SCHEMA IF NOT EXISTS issuance_service")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(SCHEMA).execute(&pool).await.unwrap();
        let source = format!("test-{}", Uuid::new_v4());
        let first = JobInput {
            organization_id: "test-org-a",
            job_id: &source,
            digest: vec![7; 32],
        };
        let other = JobInput {
            organization_id: "test-org-b",
            job_id: &source,
            digest: vec![8; 32],
        };
        let first_id = upsert_job(&pool, &first).await.unwrap();
        assert_eq!(upsert_job(&pool, &first).await.unwrap(), first_id);
        let second_id = upsert_job(&pool, &other).await.unwrap();
        assert_ne!(first_id, second_id);
        let conflicting = JobInput {
            organization_id: "test-org-a",
            job_id: &source,
            digest: vec![9; 32],
        };
        assert!(matches!(
            upsert_job(&pool, &conflicting).await,
            Err(ApiError::Conflict)
        ));
        let rows = sqlx::query("SELECT organization_id, source_job_id, request_sha256, status FROM issuance_service.passport_beta_bureau_jobs WHERE source_job_id = $1 ORDER BY organization_id")
            .bind(&source).fetch_all(&pool).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("organization_id"), "test-org-a");
        assert_eq!(rows[1].get::<String, _>("organization_id"), "test-org-b");
        assert_eq!(rows[0].get::<String, _>("status"), "QUEUED");
        let columns: Vec<String> = sqlx::query_scalar("SELECT column_name FROM information_schema.columns WHERE table_schema = 'issuance_service' AND table_name = 'passport_beta_bureau_jobs'")
            .fetch_all(&pool).await.unwrap();
        for forbidden in [
            "mrz",
            "data_groups",
            "sod_der_base64",
            "dsc_cert_pem",
            "payload",
        ] {
            assert!(!columns.iter().any(|column| column == forbidden));
        }
        let mock = Router::new()
            .route(
                "/internal/documents/{organization_id}/passport-callbacks/sign",
                post(synthetic_sign),
            )
            .route(
                "/v1/passport/webhooks/personalization",
                post(synthetic_callback),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        let state = AppState {
            config: Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                database_url: database_url.clone(),
                service_token: "synthetic-bureau-auth".into(),
                signing_api_key: "synthetic-signing-auth".into(),
                signing_url: Url::parse(&format!("http://{address}/internal/documents")).unwrap(),
                callback_url: Url::parse(&format!(
                    "http://{address}/v1/passport/webhooks/personalization"
                ))
                .unwrap(),
            },
            pool: pool.clone(),
            http: Client::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        };
        sqlx::query("UPDATE issuance_service.passport_beta_bureau_jobs SET next_transition_at = NOW() - INTERVAL '1 second' WHERE bureau_job_id = $1")
            .bind(first_id).execute(&pool).await.unwrap();
        assert!(deliver_one(&state).await.unwrap());
        let first_status: String = sqlx::query_scalar("SELECT status FROM issuance_service.passport_beta_bureau_jobs WHERE bureau_job_id = $1")
            .bind(first_id).fetch_one(&pool).await.unwrap();
        let other_status: String = sqlx::query_scalar("SELECT status FROM issuance_service.passport_beta_bureau_jobs WHERE bureau_job_id = $1")
            .bind(second_id).fetch_one(&pool).await.unwrap();
        assert_eq!(first_status, "PRINTING");
        assert_eq!(other_status, "QUEUED");
        let http_source = format!("{source}-http");
        let payload = json!({
            "job_id": http_source, "application_id": "app-1", "organization_id": "test-org-a",
            "country_code": "USA", "document_type": "TD3", "data_groups": {"DG1": "synthetic"},
            "sod_der_base64": "c29k", "dsc_cert_pem": "public-cert",
            "mrz": {"line_1": "synthetic-1", "line_2": "synthetic-2"}
        });
        let unauthorized = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/personalization/jobs")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let accepted = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/personalization/jobs")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer synthetic-bureau-auth")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let response: Value =
            serde_json::from_slice(&to_bytes(accepted.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(response["status"], "QUEUED");
        let bureau_job_id = response["bureau_job_id"].as_str().unwrap();
        sqlx::query("UPDATE issuance_service.passport_beta_bureau_jobs SET status = 'PRINTING' WHERE organization_id = 'test-org-a' AND source_job_id = $1")
            .bind(&http_source)
            .execute(&pool)
            .await
            .unwrap();
        let mut resigned_payload = payload.clone();
        resigned_payload["sod_der_base64"] = json!("changed-signature");
        resigned_payload["dsc_cert_pem"] = json!("renewed-public-cert");
        let retry = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/personalization/jobs")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer synthetic-bureau-auth")
                    .body(Body::from(resigned_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::ACCEPTED);
        let retry: Value =
            serde_json::from_slice(&to_bytes(retry.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(retry["bureau_job_id"], bureau_job_id);
        let stored_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM issuance_service.passport_beta_bureau_jobs WHERE organization_id = 'test-org-a' AND source_job_id = $1",
        )
        .bind(&http_source)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored_count, 1);
        let persisted_status: String = sqlx::query_scalar(
            "SELECT status FROM issuance_service.passport_beta_bureau_jobs WHERE organization_id = 'test-org-a' AND source_job_id = $1",
        )
        .bind(&http_source)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(persisted_status, "PRINTING");
        resigned_payload["data_groups"]["DG1"] = json!("different-document");
        let conflict = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/personalization/jobs")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer synthetic-bureau-auth")
                    .body(Body::from(resigned_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let polled = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/personalization/jobs/{bureau_job_id}"))
                    .header("authorization", "Bearer synthetic-bureau-auth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(polled.status(), StatusCode::OK);
        let polled: Value =
            serde_json::from_slice(&to_bytes(polled.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(polled["status"], "PRINTING");
        let batch_job_id = format!("{source}-batch");
        let batch = json!({"batch_id": "synthetic-batch", "organization_id": "test-org-a", "jobs": [{
            "job_id": batch_job_id, "application_id": "app-2", "country_code": "USA",
            "data_groups": {"DG1": "synthetic"}, "sod_der_base64": "c29k",
            "dsc_cert_pem": "public-cert", "mrz": {"line_1": "synthetic-1", "line_2": "synthetic-2"}
        }]});
        let accepted_batch = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/personalization/batches")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer synthetic-bureau-auth")
                    .body(Body::from(batch.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted_batch.status(), StatusCode::ACCEPTED);
        let batch_response: Value =
            serde_json::from_slice(&to_bytes(accepted_batch.into_body(), 8192).await.unwrap())
                .unwrap();
        assert_eq!(batch_response["jobs"][0]["job_id"], batch_job_id);
        server.abort();
        sqlx::query("DELETE FROM issuance_service.passport_beta_bureau_jobs WHERE source_job_id IN ($1, $2, $3) AND organization_id IN ('test-org-a', 'test-org-b')")
            .bind(&source).bind(&http_source).bind(&batch_job_id).execute(&pool).await.unwrap();
    }
}
