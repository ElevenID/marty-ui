// SPDX-License-Identifier: AGPL-3.0-only
//! Child of the existing disposable journal fixture in the focused harness.
//! Synthetic identity is supplied by tests, not a real Gateway authentication.
use super::*;
use crate::external_observation_ingress::{submit_observation, IngressError};
use crate::external_observation_wire::{WireError, MAX_BODY_BYTES};
use http::{HeaderMap, HeaderValue};
use serde_json::{json, Value};

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert(
        "idempotency-key",
        HeaderValue::from_static("observation-one"),
    );
    headers
}

fn envelope(fixture: &Fixture) -> Value {
    json!({
        "binding_id": "binding-one", "binding_revision": 1,
        "observation_id": "observation-one", "sequence": 1,
        "observed_at_ms": fixture.now, "effective_at_ms": fixture.now,
        "claims": {"completed": false, "score": null}
    })
}

#[tokio::test]
async fn wire_to_journal_commits_only_unsigned_core_bound_observation() {
    let fixture = Fixture::new().await;
    let (journal, _) = fixture.journal(Hook::None);
    let receipt = submit_observation(
        &journal,
        &Fixture::identity(),
        &headers(),
        &serde_json::to_vec(&envelope(&fixture)).unwrap(),
    )
    .await
    .unwrap();
    assert!(!receipt.replayed);
    assert_eq!(fixture.counts().await, (1, 1, 1));
    let row = sqlx::query("SELECT organization_id, api_key_id, subject_id, provider, envelope FROM issuance_service.external_observation_receipts")
        .fetch_one(&fixture.pool).await.unwrap();
    assert_eq!(row.get::<String, _>("organization_id"), "org-one");
    assert_eq!(row.get::<String, _>("api_key_id"), "key-one");
    assert_eq!(row.get::<String, _>("subject_id"), "learner-one");
    assert_eq!(row.get::<String, _>("provider"), "synthetic-lms");
    let stored: Value = row.get("envelope");
    assert_eq!(stored["claims"]["completed"], false);
    assert!(stored["claims"]["score"].is_null());
    assert!(stored.get("verified").is_none());
    fixture.pool.close().await;
}

#[tokio::test]
async fn malformed_wire_is_rejected_even_with_closed_database_pool() {
    let fixture = Fixture::new().await;
    let (journal, authority) = fixture.journal(Hook::None);
    assert_eq!(fixture.counts().await, (0, 0, 0));
    fixture.pool.close().await;
    for body in [
        b"{}".to_vec(),
        b"{\"claims\":{\"score\":1,\"score\":2}}".to_vec(),
    ] {
        let result = submit_observation(&journal, &Fixture::identity(), &headers(), &body).await;
        assert_eq!(
            result.err(),
            Some(IngressError::Request(WireError::InvalidEnvelope))
        );
    }
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_headers_and_oversized_body_never_enter_the_journal() {
    let fixture = Fixture::new().await;
    let (journal, authority) = fixture.journal(Hook::None);
    let body = serde_json::to_vec(&envelope(&fixture)).unwrap();
    let mut duplicate = headers();
    duplicate.append(
        "idempotency-key",
        HeaderValue::from_static("observation-one"),
    );
    assert_eq!(
        submit_observation(&journal, &Fixture::identity(), &duplicate, &body)
            .await
            .err(),
        Some(IngressError::Request(WireError::InvalidHeaders))
    );
    assert_eq!(
        submit_observation(
            &journal,
            &Fixture::identity(),
            &headers(),
            &vec![b' '; MAX_BODY_BYTES + 1]
        )
        .await
        .err(),
        Some(IngressError::Request(WireError::BodyTooLarge))
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counts().await, (0, 0, 0));
    fixture.pool.close().await;
}

#[tokio::test]
async fn forwarded_identity_headers_cannot_override_the_authenticated_identity() {
    let fixture = Fixture::new().await;
    let (journal, _) = fixture.journal(Hook::None);
    let body = serde_json::to_vec(&envelope(&fixture)).unwrap();
    let mut spoofed = headers();
    spoofed.insert("x-organization-id", HeaderValue::from_static("org-one"));
    spoofed.insert("x-api-key-id", HeaderValue::from_static("key-one"));
    spoofed.insert("x-scopes", HeaderValue::from_static("evidence:submit"));
    let foreign = ProducerIdentity {
        api_key_id: "key-one".into(),
        organization_id: "foreign".into(),
    };
    assert_eq!(
        submit_observation(&journal, &foreign, &spoofed, &body)
            .await
            .err(),
        Some(IngressError::Journal(JournalError::Denied(
            Denial::NotAuthorized
        )))
    );
    assert_eq!(fixture.counts().await, (0, 0, 0));
    spoofed.insert("x-organization-id", HeaderValue::from_static("foreign"));
    let receipt = submit_observation(&journal, &Fixture::identity(), &spoofed, &body)
        .await
        .unwrap();
    assert!(!receipt.replayed);
    let organization: String = sqlx::query_scalar(
        "SELECT organization_id FROM issuance_service.external_observation_receipts",
    )
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(organization, "org-one");
    fixture.pool.close().await;
}

#[tokio::test]
async fn decoder_does_not_replace_current_scope_or_revocation_checks() {
    let fixture = Fixture::new().await;
    let (journal, _) = fixture.journal(Hook::None);
    let body = serde_json::to_vec(&envelope(&fixture)).unwrap();
    sqlx::query("UPDATE observation_test.authority SET scopes = ARRAY['integrations:write']")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        submit_observation(&journal, &Fixture::identity(), &headers(), &body)
            .await
            .err(),
        Some(IngressError::Journal(JournalError::Denied(
            Denial::ScopeMissing
        )))
    );
    sqlx::query("UPDATE observation_test.authority SET scopes = ARRAY['evidence:submit'], key_active = false")
        .execute(&fixture.pool).await.unwrap();
    assert_eq!(
        submit_observation(&journal, &Fixture::identity(), &headers(), &body)
            .await
            .err(),
        Some(IngressError::Journal(JournalError::Denied(
            Denial::AuthenticationRequired
        )))
    );
    assert_eq!(fixture.counts().await, (0, 0, 0));
    fixture.pool.close().await;
}

#[tokio::test]
async fn semantically_equal_reformatted_retry_is_read_only_and_changed_claim_conflicts() {
    let fixture = Fixture::new().await;
    let (journal, _) = fixture.journal(Hook::None);
    let mut value = envelope(&fixture);
    let first = submit_observation(
        &journal,
        &Fixture::identity(),
        &headers(),
        &serde_json::to_vec(&value).unwrap(),
    )
    .await
    .unwrap();
    let retry = submit_observation(
        &journal,
        &Fixture::identity(),
        &headers(),
        &serde_json::to_vec_pretty(&value).unwrap(),
    )
    .await
    .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.receipt_id, first.receipt_id);
    value["claims"]["score"] = json!(100);
    assert_eq!(
        submit_observation(
            &journal,
            &Fixture::identity(),
            &headers(),
            &serde_json::to_vec(&value).unwrap()
        )
        .await
        .err(),
        Some(IngressError::Journal(JournalError::Denied(
            Denial::ReplayConflict
        )))
    );
    assert_eq!(fixture.counts().await, (1, 1, 1));
    fixture.pool.close().await;
}

#[tokio::test]
async fn syntactically_valid_claims_still_require_the_core_allowlist_and_ranges() {
    let fixture = Fixture::new().await;
    let (journal, _) = fixture.journal(Hook::None);
    for (field, claim) in [
        ("verified", json!(true)),
        ("policy_allowed", json!(true)),
        ("score", json!(101)),
        ("completed", json!("false")),
    ] {
        let mut value = envelope(&fixture);
        value["claims"][field] = claim;
        assert_eq!(
            submit_observation(
                &journal,
                &Fixture::identity(),
                &headers(),
                &serde_json::to_vec(&value).unwrap()
            )
            .await
            .err(),
            Some(IngressError::Journal(JournalError::Denied(
                Denial::InvalidClaims
            )))
        );
    }
    assert_eq!(fixture.counts().await, (0, 0, 0));
    fixture.pool.close().await;
}

#[tokio::test]
async fn duplicate_claims_are_rejected_before_json_can_choose_the_last_value() {
    let fixture = Fixture::new().await;
    let (journal, authority) = fixture.journal(Hook::None);
    let original = serde_json::to_string(&envelope(&fixture)).unwrap();
    let body = original.replace(
        "\"completed\":false",
        "\"completed\":false,\"completed\":true",
    );
    assert_ne!(body, original);
    assert_eq!(
        submit_observation(&journal, &Fixture::identity(), &headers(), body.as_bytes())
            .await
            .err(),
        Some(IngressError::Request(WireError::InvalidEnvelope))
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counts().await, (0, 0, 0));
    fixture.pool.close().await;
}
