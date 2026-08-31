use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_verification_service::credentials_compat::{
    migrate_session_schema, ClaimState, EvidenceFailureReason, GovernanceEngine, GovernancePurpose,
    PersistedEvidence, PostgresSessionRepository, ProcessingLease, ProcessingToken, SessionDraft,
    SessionDurationSeconds, SessionRepository, SessionStatus, Sha256Digest, TerminalDecision,
    VerificationMethod, VerifierNonce,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, Row};

fn draft(id: &str, nonce_character: char) -> SessionDraft {
    let fixture: Value =
        serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
    let governance = GovernanceEngine::new(&fixture["governance"].to_string())
        .unwrap()
        .authorize("purpose-scoped-test-key", GovernancePurpose::SessionCreate)
        .unwrap();
    SessionDraft {
        id: id.into(),
        organization_id: "org-1".into(),
        verifier_did: "did:web:verifier.example".into(),
        presentation_definition: json!({"id":"pd-1","input_descriptors":[]}),
        required_credential_types: Vec::new(),
        trusted_issuers: vec!["did:web:issuer.example".into()],
        required_claims: Vec::new(),
        verification_evidence: PersistedEvidence::pending(&governance),
        request_uri: format!("https://verifier.example/request/{id}"),
        nonce: VerifierNonce::parse(URL_SAFE_NO_PAD.encode([nonce_character as u8; 32])).unwrap(),
    }
}

fn token(value: &str) -> ProcessingToken {
    ProcessingToken::parse(value).unwrap()
}

#[tokio::test]
async fn released_migration_and_atomic_repository_contract_hold_on_postgres() {
    let Some(database_url) = std::env::var("VERIFICATION_SESSION_TEST_DATABASE_URL").ok() else {
        eprintln!("VERIFICATION_SESSION_TEST_DATABASE_URL is not configured; skipping");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&database_url)
        .await
        .unwrap();

    sqlx::raw_sql(
        "DROP TABLE IF EXISTS public.verification_sessions;
         DROP SCHEMA IF EXISTS verification_service CASCADE;
         CREATE SCHEMA verification_service;
         CREATE TABLE verification_service.alembic_version(version_num VARCHAR(32) NOT NULL);
         INSERT INTO verification_service.alembic_version(version_num) VALUES('202608081900');",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/verification/202608081900_base.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let duplicate_nonce = "d".repeat(43);
    let terminal_digest = Sha256Digest::calculate("legacy-terminal");
    sqlx::query(
        "INSERT INTO public.verification_sessions (
             id,organization_id,verifier_did,presentation_definition,status,
             presentation_data,verification_evidence,created_at,updated_at,expires_at,nonce
         ) VALUES
         ('legacy-terminal','org-1','did:web:verifier.example','{}','VERIFIED',
          '{\"raw\":\"credential\"}',jsonb_build_object('presentation_sha256',$1),
          clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',$2),
         ('legacy-pending-a','org-1','did:web:verifier.example','{}','PENDING',
          NULL,'{}',clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',$2),
         ('legacy-pending-b','org-1','did:web:verifier.example','{}','PENDING',
          NULL,'{}',clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',$2),
         ('legacy-in-progress','org-1','did:web:verifier.example','{}','IN_PROGRESS',
          NULL,'{}',clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',$3),
         ('legacy-invalid','org-1','did:web:verifier.example','{}','PENDING',
          NULL,'{}',clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour','short'),
         ('legacy-deadline','org-1','did:web:verifier.example','{}','PENDING',
          NULL,'{}',clock_timestamp(),clock_timestamp(),clock_timestamp()-interval '1 second',$4)",
    )
    .bind(terminal_digest.as_str())
    .bind(&duplicate_nonce)
    .bind("i".repeat(43))
    .bind("e".repeat(43))
    .execute(&pool)
    .await
    .unwrap();

    migrate_session_schema(&pool).await.unwrap();
    let head: String =
        sqlx::query_scalar("SELECT version_num FROM verification_service.alembic_version")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(head, "202608091200");
    let rows = sqlx::query(
        "SELECT id,status,nonce,submission_sha256,presentation_data
         FROM public.verification_sessions WHERE id LIKE 'legacy-%'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let migrated = rows
        .into_iter()
        .map(|row| (row.get::<String, _>("id"), row))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        migrated["legacy-terminal"].get::<String, _>("status"),
        "VERIFIED"
    );
    assert_eq!(
        migrated["legacy-terminal"].get::<Option<String>, _>("submission_sha256"),
        Some(terminal_digest.as_str().into())
    );
    assert!(migrated["legacy-terminal"]
        .get::<Option<serde_json::Value>, _>("presentation_data")
        .is_none());
    for id in [
        "legacy-pending-a",
        "legacy-pending-b",
        "legacy-in-progress",
        "legacy-invalid",
        "legacy-deadline",
    ] {
        assert_eq!(migrated[id].get::<String, _>("status"), "EXPIRED");
        assert!(migrated[id].get::<Option<String>, _>("nonce").is_none());
    }

    let repository = PostgresSessionRepository::new(pool.clone());
    let lifetime = SessionDurationSeconds::new(600).unwrap();
    let lease = ProcessingLease::from_seconds(60).unwrap();

    repository
        .create(draft("race-session", 'r'), lifetime)
        .await
        .unwrap();
    let race_digest = Sha256Digest::calculate("header.payload.signature");
    let token_one = token("worker-token-1");
    let token_two = token("worker-token-2");
    let (first, second) = tokio::join!(
        repository.claim("race-session", &race_digest, &token_one, lease),
        repository.claim("race-session", &race_digest, &token_two, lease),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert!(
        (first.state == ClaimState::Claimed && second.state == ClaimState::Busy)
            || (first.state == ClaimState::Busy && second.state == ClaimState::Claimed)
    );
    let (winner, loser) = if first.state == ClaimState::Claimed {
        (&token_one, &token_two)
    } else {
        (&token_two, &token_one)
    };
    let stored_token: String = sqlx::query_scalar(
        "SELECT processing_token_sha256 FROM public.verification_sessions WHERE id='race-session'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored_token.len(), 64);
    assert_ne!(stored_token, "worker-token-1");
    assert_ne!(stored_token, "worker-token-2");

    let stale = repository
        .finalize(
            "race-session",
            &race_digest,
            loser,
            TerminalDecision::failed(
                PersistedEvidence::fail_closed(
                    &race_digest,
                    EvidenceFailureReason::CanonicalResultBuildFailed,
                ),
                Some(VerificationMethod::JwtVp),
                "Verification failed".into(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(stale.state, ClaimState::Stale);
    let finalized = repository
        .finalize(
            "race-session",
            &race_digest,
            winner,
            TerminalDecision::failed(
                PersistedEvidence::fail_closed(
                    &race_digest,
                    EvidenceFailureReason::CanonicalResultBuildFailed,
                ),
                Some(VerificationMethod::JwtVp),
                "Verification failed".into(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(finalized.state, ClaimState::Finalized);
    assert_eq!(finalized.session.unwrap().status, SessionStatus::Failed);

    sqlx::query(
        "UPDATE public.verification_sessions
         SET expires_at=clock_timestamp()-interval '1 second'
         WHERE id='race-session'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repository
            .claim("race-session", &race_digest, &token("retry-token"), lease)
            .await
            .unwrap()
            .state,
        ClaimState::Terminal
    );
    assert_eq!(
        repository
            .claim(
                "race-session",
                &Sha256Digest::calculate("different"),
                &token("conflict-token"),
                lease,
            )
            .await
            .unwrap()
            .state,
        ClaimState::Conflict
    );

    repository
        .create(draft("recovery-session", 'y'), lifetime)
        .await
        .unwrap();
    let recovery_digest = Sha256Digest::calculate("recovery");
    let original_token = token("original-token");
    let recovery_token = token("recovery-token");
    assert_eq!(
        repository
            .claim("recovery-session", &recovery_digest, &original_token, lease)
            .await
            .unwrap()
            .state,
        ClaimState::Claimed
    );
    sqlx::query(
        "UPDATE public.verification_sessions
         SET processing_started_at=clock_timestamp()-interval '2 seconds',
             processing_expires_at=clock_timestamp()-interval '1 second'
         WHERE id='recovery-session'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let stale_before_reclaim = repository
        .finalize(
            "recovery-session",
            &recovery_digest,
            &original_token,
            TerminalDecision::failed(
                PersistedEvidence::fail_closed(
                    &recovery_digest,
                    EvidenceFailureReason::CanonicalResultBuildFailed,
                ),
                Some(VerificationMethod::JwtVp),
                "late".into(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(stale_before_reclaim.state, ClaimState::Stale);
    assert_eq!(
        repository
            .claim("recovery-session", &recovery_digest, &recovery_token, lease)
            .await
            .unwrap()
            .state,
        ClaimState::Claimed
    );
    assert_eq!(
        repository
            .finalize(
                "recovery-session",
                &recovery_digest,
                &original_token,
                TerminalDecision::failed(
                    PersistedEvidence::fail_closed(
                        &recovery_digest,
                        EvidenceFailureReason::CanonicalResultBuildFailed,
                    ),
                    Some(VerificationMethod::JwtVp),
                    "stale".into(),
                ),
            )
            .await
            .unwrap()
            .state,
        ClaimState::Stale
    );
    assert_eq!(
        repository
            .finalize(
                "recovery-session",
                &recovery_digest,
                &recovery_token,
                TerminalDecision::failed(
                    PersistedEvidence::fail_closed(
                        &recovery_digest,
                        EvidenceFailureReason::CanonicalResultBuildFailed,
                    ),
                    Some(VerificationMethod::JwtVp),
                    "Verification failed".into(),
                ),
            )
            .await
            .unwrap()
            .state,
        ClaimState::Finalized
    );

    repository
        .create(draft("exact-deadline", 'x'), lifetime)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE public.verification_sessions
         SET expires_at=clock_timestamp() AT TIME ZONE 'UTC'
         WHERE id='exact-deadline'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let expired = repository
        .claim(
            "exact-deadline",
            &Sha256Digest::calculate("expired"),
            &token("expired-token"),
            lease,
        )
        .await
        .unwrap();
    assert_eq!(expired.state, ClaimState::Expired);
    assert!(expired.session.unwrap().nonce.is_none());

    repository
        .create(draft("lease-cap", 'c'), lifetime)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE public.verification_sessions
         SET expires_at=(clock_timestamp() AT TIME ZONE 'UTC')+interval '10 seconds'
         WHERE id='lease-cap'",
    )
    .execute(&pool)
    .await
    .unwrap();
    repository
        .claim(
            "lease-cap",
            &Sha256Digest::calculate("lease-cap"),
            &token("lease-cap-token"),
            lease,
        )
        .await
        .unwrap();
    let capped: bool = sqlx::query_scalar(
        "SELECT processing_expires_at=expires_at
         FROM public.verification_sessions WHERE id='lease-cap'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(capped);

    // Head adoption/idempotence must not replay the legacy transform and
    // expire a currently fenced worker.
    migrate_session_schema(&pool).await.unwrap();
    assert_eq!(
        repository.get("lease-cap").await.unwrap().unwrap().status,
        SessionStatus::InProgress
    );

    repository
        .create(draft("read-only-expiry", 'o'), lifetime)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE public.verification_sessions
         SET expires_at=clock_timestamp()-interval '1 second'
         WHERE id='read-only-expiry'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repository
            .get("read-only-expiry")
            .await
            .unwrap()
            .unwrap()
            .status,
        SessionStatus::Pending
    );

    repository
        .create(draft("duplicate-nonce-a", 'u'), lifetime)
        .await
        .unwrap();
    assert!(repository
        .create(draft("duplicate-nonce-b", 'u'), lifetime)
        .await
        .is_err());
    assert!(sqlx::query(
        "INSERT INTO public.verification_sessions (
             id,organization_id,verifier_did,presentation_definition,status,
             verification_evidence,created_at,updated_at,nonce)
         VALUES('invalid-check','org-1','did:web:verifier.example','{}','PENDING',
                '{}',clock_timestamp(),clock_timestamp(),'short')",
    )
    .execute(&pool)
    .await
    .is_err());

    sqlx::query(
        "INSERT INTO public.verification_sessions (
             id,organization_id,verifier_did,presentation_definition,status,
             verification_evidence,created_at,updated_at,nonce,submission_sha256)
         VALUES('historical-null-digest','org-1','did:web:verifier.example','{}','VERIFIED',
                '{}',clock_timestamp(),clock_timestamp(),NULL,NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repository
            .claim(
                "historical-null-digest",
                &Sha256Digest::calculate("anything"),
                &token("historical-token"),
                lease,
            )
            .await
            .unwrap()
            .state,
        ClaimState::Conflict
    );

    pool.close().await;
}
