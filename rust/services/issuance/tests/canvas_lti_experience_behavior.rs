use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use marty_issuance_service::{
    canvas_lti_experience::{
        canvas_lti_experience_exchange_metadata, sha256_hex, CanvasLtiExperienceExchangeError,
        CanvasLtiExperienceExchangePersistence, CanvasLtiExperienceExchangeRecord,
        CanvasLtiExperienceExchangeRepository, CanvasLtiExperienceExchangeService,
        CanvasLtiExperienceSessionGenerator, CanvasLtiExperienceSessionSeed,
        SecureCanvasLtiExperienceSessionGenerator,
    },
    canvas_lti_launch::CanvasLtiClock,
};
use serde_json::{json, Value};

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

impl CanvasLtiClock for CountingClock {
    fn now(&self) -> DateTime<Utc> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.now
    }
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
    let service = CanvasLtiExperienceExchangeService::new(
        repository.clone(),
        Arc::new(FixedGenerator),
        Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 8, 29, 12, 2, 0).unwrap(),
        )),
        Duration::from_secs(30 * 60),
    )
    .unwrap();

    let result = service.exchange("  experience-code-1  ").await.unwrap();

    assert_eq!(
        result.session_token,
        "session-token-contract-0123456789abcdef"
    );
    assert_eq!(result.expires_at.to_rfc3339(), "2026-08-29T12:32:00+00:00");
    let requests = repository.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].code, "experience-code-1");
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
        service.exchange("experience-code-1").await.unwrap_err(),
        CanvasLtiExperienceExchangeError::RepositoryUnavailable
    );
    assert_eq!(generator.0.load(Ordering::SeqCst), 0);
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn secure_generator_never_reuses_the_plaintext_as_the_digest() {
    let generated = SecureCanvasLtiExperienceSessionGenerator.generate();
    assert_eq!(generated.token.len(), 43);
    assert_eq!(generated.nonce.len(), 43);
    assert_eq!(generated.state_digest, sha256_hex(&generated.token));
    assert_ne!(generated.state_digest, generated.token);
}
