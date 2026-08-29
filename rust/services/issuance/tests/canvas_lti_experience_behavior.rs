use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use chrono::{DateTime, TimeZone, Utc};
use marty_issuance_service::{
    canvas_lti_experience::{
        canvas_lti_experience_exchange_metadata, sha256_hex, CanvasLtiExperienceExchangeError,
        CanvasLtiExperienceExchangePersistence, CanvasLtiExperienceExchangeRecord,
        CanvasLtiExperienceExchangeRepository, CanvasLtiExperienceExchangeResult,
        CanvasLtiExperienceExchangeService, CanvasLtiExperienceSessionGenerator,
        CanvasLtiExperienceSessionSeed, SecureCanvasLtiExperienceSessionGenerator,
    },
    canvas_lti_launch::CanvasLtiClock,
    http::router_with_canvas_lti_experience_exchange,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use tower::ServiceExt;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-lti-foundation.json"
    ))
    .expect("valid Canvas LTI contract")
}

#[derive(Default)]
struct ExchangeRepository {
    requests: Mutex<Vec<CanvasLtiExperienceExchangePersistence>>,
    fail: Mutex<bool>,
    invalid: Mutex<bool>,
}

#[async_trait]
impl CanvasLtiExperienceExchangeRepository for ExchangeRepository {
    async fn exchange_experience_code(
        &self,
        request: &CanvasLtiExperienceExchangePersistence,
        generator: &dyn CanvasLtiExperienceSessionGenerator,
        clock: &dyn CanvasLtiClock,
    ) -> Result<CanvasLtiExperienceExchangeRecord, CanvasLtiExperienceExchangeError> {
        if *self.fail.lock().unwrap() {
            return Err(CanvasLtiExperienceExchangeError::RepositoryUnavailable);
        }
        if *self.invalid.lock().unwrap() {
            return Err(CanvasLtiExperienceExchangeError::InvalidCode);
        }
        self.requests.lock().unwrap().push(request.clone());
        let session = generator.generate();
        let created_at = clock.now();
        let expires_at = created_at
            + chrono::Duration::from_std(request.session_ttl)
                .map_err(|_| CanvasLtiExperienceExchangeError::InvalidConfiguration)?;
        Ok(CanvasLtiExperienceExchangeRecord {
            experience_code_id: "experience-code-id-1".to_owned(),
            session,
            created_at,
            expires_at,
            session_metadata: json!({}),
            spent_code_metadata: json!({}),
        })
    }
}

struct FixedGenerator;

impl CanvasLtiExperienceSessionGenerator for FixedGenerator {
    fn generate(&self) -> CanvasLtiExperienceSessionSeed {
        let token = "session-token-contract-0123456789abcdef".to_owned();
        CanvasLtiExperienceSessionSeed {
            id: "experience-session-id-1".to_owned(),
            state_digest: sha256_hex(&token),
            token,
            nonce: "experience-session-nonce-1".to_owned(),
        }
    }
}

struct CountingGenerator(AtomicUsize);

impl CanvasLtiExperienceSessionGenerator for CountingGenerator {
    fn generate(&self) -> CanvasLtiExperienceSessionSeed {
        self.0.fetch_add(1, Ordering::SeqCst);
        FixedGenerator.generate()
    }
}

struct FixedClock(DateTime<Utc>);

impl CanvasLtiClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

struct CountingClock {
    now: DateTime<Utc>,
    calls: AtomicUsize,
}

fn exchange_service(
    repository: Arc<ExchangeRepository>,
    session_ttl: Duration,
) -> Result<CanvasLtiExperienceExchangeService, CanvasLtiExperienceExchangeError> {
    CanvasLtiExperienceExchangeService::new(
        repository,
        Arc::new(FixedGenerator),
        Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 8, 29, 12, 2, 0).unwrap(),
        )),
        session_ttl,
    )
}

impl CanvasLtiClock for CountingClock {
    fn now(&self) -> DateTime<Utc> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.now
    }
}

fn exchange_service(
    repository: Arc<ExchangeRepository>,
    generator: Arc<dyn CanvasLtiExperienceSessionGenerator>,
) -> CanvasLtiExperienceExchangeService {
    CanvasLtiExperienceExchangeService::new(
        repository,
        generator,
        Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 8, 29, 12, 2, 0).unwrap(),
        )),
        Duration::from_secs(30 * 60),
    )
    .unwrap()
}

fn exchange_app(service: CanvasLtiExperienceExchangeService) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    router_with_canvas_lti_experience_exchange(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.test", "Issuer"),
        TransportPolicy::new(Vec::new()),
        service,
    )
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap()
}

#[test]
fn exchange_metadata_replays_the_complete_frozen_vector() {
    let vector = &contract()["experience"]["exchange"]["vector"];
    let created_at = DateTime::parse_from_rfc3339(vector["session_created_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);

    let (session, spent) = canvas_lti_experience_exchange_metadata(
        &vector["code_metadata"],
        vector["experience_code_id"].as_str().unwrap(),
        vector["session_id"].as_str().unwrap(),
        created_at,
    );

    assert_eq!(session, vector["expected_session_metadata"]);
    assert_eq!(spent, vector["expected_spent_code_metadata"]);
    assert_eq!(
        sha256_hex(vector["session_token"].as_str().unwrap()),
        vector["expected_session_state"]
    );
}

#[tokio::test]
async fn exchange_normalizes_the_code_and_responds_after_persistence() {
    let repository = Arc::new(ExchangeRepository::default());
    let service = exchange_service(repository.clone(), Duration::from_secs(30 * 60)).unwrap();

    let result = service
        .exchange("  experience-code-contract-0123456789  ")
        .await
        .unwrap();

    assert_eq!(
        result.session_token,
        "session-token-contract-0123456789abcdef"
    );
    assert_eq!(result.expires_at.to_rfc3339(), "2026-08-29T12:32:00+00:00");
    let requests = repository.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].code, "experience-code-contract-0123456789");
    assert_eq!(requests[0].session_ttl, Duration::from_secs(30 * 60));
}

#[tokio::test]
async fn exchange_failure_returns_no_session_token() {
    let repository = Arc::new(ExchangeRepository::default());
    *repository.fail.lock().unwrap() = true;
    let generator = Arc::new(CountingGenerator(AtomicUsize::new(0)));
    let clock = Arc::new(CountingClock {
        now: Utc::now(),
        calls: AtomicUsize::new(0),
    });
    let service = CanvasLtiExperienceExchangeService::new(
        repository,
        generator.clone(),
        clock.clone(),
        Duration::from_secs(30 * 60),
    )
    .unwrap();

    assert_eq!(
        service
            .exchange("experience-code-contract-0123456789")
            .await
            .unwrap_err(),
        CanvasLtiExperienceExchangeError::RepositoryUnavailable
    );
    assert_eq!(generator.0.load(Ordering::SeqCst), 0);
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn exchange_rejects_invalid_session_ttls_at_construction() {
    assert_eq!(
        exchange_service(Arc::new(ExchangeRepository::default()), Duration::ZERO,).unwrap_err(),
        CanvasLtiExperienceExchangeError::InvalidConfiguration
    );
    assert_eq!(
        exchange_service(
            Arc::new(ExchangeRepository::default()),
            Duration::from_secs(u64::MAX),
        )
        .unwrap_err(),
        CanvasLtiExperienceExchangeError::InvalidConfiguration
    );
}

#[tokio::test]
async fn exchange_rejects_out_of_contract_codes_before_persistence() {
    let repository = Arc::new(ExchangeRepository::default());
    let service = exchange_service(repository.clone(), Duration::from_secs(30 * 60)).unwrap();

    for code in ["x".repeat(31), "x".repeat(257)] {
        assert_eq!(
            service.exchange(&code).await.unwrap_err(),
            CanvasLtiExperienceExchangeError::InvalidCode
        );
    }
    assert!(repository.requests.lock().unwrap().is_empty());
}

#[test]
fn exchange_debug_output_redacts_plaintext_secrets() {
    let session = FixedGenerator.generate();
    let record = CanvasLtiExperienceExchangeRecord {
        experience_code_id: "experience-code-id-1".to_owned(),
        session: session.clone(),
        created_at: Utc.with_ymd_and_hms(2026, 8, 29, 12, 2, 0).unwrap(),
        expires_at: Utc.with_ymd_and_hms(2026, 8, 29, 12, 32, 0).unwrap(),
        session_metadata: json!({"private": "session-metadata-secret"}),
        spent_code_metadata: json!({"private": "spent-code-metadata-secret"}),
    };
    let persistence = CanvasLtiExperienceExchangePersistence {
        code: "experience-code-contract-0123456789".to_owned(),
        session_ttl: Duration::from_secs(30 * 60),
    };
    let result = CanvasLtiExperienceExchangeResult {
        session_token: session.token.clone(),
        expires_at: record.expires_at,
    };

    for (rendered, secret) in [
        (format!("{session:?}"), session.token.as_str()),
        (format!("{session:?}"), session.nonce.as_str()),
        (format!("{record:?}"), "session-metadata-secret"),
        (format!("{record:?}"), "spent-code-metadata-secret"),
        (format!("{persistence:?}"), persistence.code.as_str()),
        (format!("{result:?}"), result.session_token.as_str()),
    ] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn secure_generator_never_reuses_the_plaintext_as_the_digest() {
    let generated = SecureCanvasLtiExperienceSessionGenerator.generate();
    assert_eq!(generated.token.len(), 43);
    assert_eq!(generated.nonce.len(), 43);
    assert_eq!(generated.state_digest, sha256_hex(&generated.token));
    assert_ne!(generated.state_digest, generated.token);
}

#[tokio::test]
async fn exchange_http_replays_success_headers_body_and_trimmed_consumption() {
    let repository = Arc::new(ExchangeRepository::default());
    let response = exchange_app(exchange_service(
        repository.clone(),
        Arc::new(FixedGenerator),
    ))
    .oneshot(
        Request::post("/v1/integrations/canvas/lti/experience-sessions/exchange")
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(Body::from(
                json!({"code": "  experience-code-contract-0000000000  "}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert_eq!(
        response_json(response).await,
        contract()["experience"]["exchange"]["vector"]["expected_response"]
    );
    assert_eq!(
        repository.requests.lock().unwrap()[0].code,
        "experience-code-contract-0000000000"
    );
}

#[tokio::test]
async fn exchange_http_replays_every_frozen_schema_failure() {
    let cases = [
        (
            json!({}),
            json!({
                "type": "missing",
                "loc": ["body", "code"],
                "msg": "Field required",
                "input": {},
            }),
        ),
        (
            json!({"code": "x".repeat(31)}),
            json!({
                "type": "string_too_short",
                "loc": ["body", "code"],
                "msg": "String should have at least 32 characters",
                "input": "x".repeat(31),
                "ctx": {"min_length": 32},
            }),
        ),
        (
            json!({"code": "x".repeat(257)}),
            json!({
                "type": "string_too_long",
                "loc": ["body", "code"],
                "msg": "String should have at most 256 characters",
                "input": "x".repeat(257),
                "ctx": {"max_length": 256},
            }),
        ),
        (
            json!({"code": "x".repeat(32), "extra": 1}),
            json!({
                "type": "extra_forbidden",
                "loc": ["body", "extra"],
                "msg": "Extra inputs are not permitted",
                "input": 1,
            }),
        ),
    ];
    assert_eq!(
        contract()["experience"]["exchange"]["request"]["schema_failure_cases"]
            .as_array()
            .unwrap()
            .len(),
        cases.len()
    );
    for (body, expected) in cases {
        let repository = Arc::new(ExchangeRepository::default());
        let response = exchange_app(exchange_service(
            repository.clone(),
            Arc::new(FixedGenerator),
        ))
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/experience-sessions/exchange")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response_json(response).await, json!({"detail": [expected]}));
        assert!(repository.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn exchange_http_accepts_only_json_media_types() {
    let repository = Arc::new(ExchangeRepository::default());
    let app = exchange_app(exchange_service(repository, Arc::new(FixedGenerator)));
    let rejected = app
        .clone()
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/experience-sessions/exchange")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("code=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        response_json(rejected).await,
        json!({"detail": "Content-Type must be application/json"})
    );

    let accepted = app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/experience-sessions/exchange")
                .header(header::CONTENT_TYPE, "application/vnd.elevenid+json")
                .body(Body::from(json!({"code": "x".repeat(32)}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
}

#[tokio::test]
async fn exchange_http_sanitizes_failures_and_never_returns_a_token() {
    let invalid_repository = Arc::new(ExchangeRepository::default());
    *invalid_repository.invalid.lock().unwrap() = true;
    let invalid_generator = Arc::new(CountingGenerator(AtomicUsize::new(0)));
    let invalid = exchange_app(exchange_service(
        invalid_repository,
        invalid_generator.clone(),
    ))
    .oneshot(
        Request::post("/v1/integrations/canvas/lti/experience-sessions/exchange")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"code": "x".repeat(32)}).to_string()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid_generator.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        response_json(invalid).await,
        json!({"detail": "Canvas LTI experience code has expired, is invalid, or was already used"})
    );

    let failed_repository = Arc::new(ExchangeRepository::default());
    *failed_repository.fail.lock().unwrap() = true;
    let failed_generator = Arc::new(CountingGenerator(AtomicUsize::new(0)));
    let failed = exchange_app(exchange_service(
        failed_repository,
        failed_generator.clone(),
    ))
    .oneshot(
        Request::post("/v1/integrations/canvas/lti/experience-sessions/exchange")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"code": "x".repeat(32)}).to_string()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed_generator.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        to_bytes(failed.into_body(), 1024).await.unwrap(),
        "Internal Server Error"
    );
}
