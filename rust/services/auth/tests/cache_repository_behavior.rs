use std::sync::Arc;

use chrono::{Duration, Utc};
use marty_auth::{
    AuthCacheKeySpace, AuthCacheRepository, AuthenticatedUser, PkceState, PkceStateRepository,
    Session, SessionRepository, SessionSpec, UserType,
};
use mmf_data::{CacheStore, MemoryCache};

fn user(user_id: &str) -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: user_id.to_owned(),
        email: format!("{user_id}@example.com"),
        username: None,
        given_name: None,
        family_name: None,
        user_type: UserType::Applicant,
        applicant_id: None,
        roles: Vec::new(),
        organization_id: None,
        organization_name: None,
        organization: None,
        default_organization_id: None,
        default_organization_name: None,
        organizations: Vec::new(),
        organization_context_unavailable: false,
        organization_context_error: None,
        onboarding_completed: None,
        picture: None,
        impersonation: None,
        did_subject: None,
    }
}

fn repository(cache: Arc<MemoryCache>) -> AuthCacheRepository {
    AuthCacheRepository::new(cache, AuthCacheKeySpace::default())
}

fn session(user_id: &str) -> Session {
    Session::create(SessionSpec {
        user: user(user_id),
        ttl_seconds: 3_600,
        now: Utc::now(),
        ip_address: Some("127.0.0.1".to_owned()),
        user_agent: Some("browser".to_owned()),
        id_token: Some("id-token".to_owned()),
        refresh_token: Some("refresh-token".to_owned()),
        oidc_claims: Some(serde_json::json!({"trusted": true})),
    })
}

#[tokio::test]
async fn sessions_round_trip_and_user_index_operations_preserve_behavior() {
    let repository = repository(Arc::new(MemoryCache::default()));
    let first = session("user-1");
    let second = session("user-1");
    SessionRepository::save(&repository, &first)
        .await
        .expect("save first session");
    SessionRepository::save(&repository, &second)
        .await
        .expect("save second session");
    assert_eq!(
        repository.get(&first.session_id).await.expect("get first"),
        Some(first.clone())
    );
    assert_eq!(
        repository
            .get_by_user("user-1")
            .await
            .expect("sessions by user")
            .len(),
        2
    );
    assert_eq!(
        repository
            .delete_all_for_user("user-1")
            .await
            .expect("delete all"),
        2
    );
    assert!(repository
        .get(&first.session_id)
        .await
        .expect("deleted first")
        .is_none());
    assert!(repository
        .get_by_user("user-1")
        .await
        .expect("empty user sessions")
        .is_empty());
}

#[tokio::test]
async fn expired_sessions_are_not_persisted() {
    let repository = repository(Arc::new(MemoryCache::default()));
    let mut expired = session("user-1");
    expired.expires_at = Utc::now() - Duration::minutes(1);
    SessionRepository::save(&repository, &expired)
        .await
        .expect("ignore expired session");
    assert!(repository
        .get(&expired.session_id)
        .await
        .expect("expired absent")
        .is_none());
}

#[tokio::test]
async fn pkce_state_is_consumed_atomically() {
    let repository = repository(Arc::new(MemoryCache::default()));
    let now = Utc::now();
    let state = PkceState {
        state: "state-1".to_owned(),
        code_verifier: "verifier".to_owned(),
        redirect_uri: "/console".to_owned(),
        oidc_redirect_uri: Some("https://ui.example/v1/auth/callback".to_owned()),
        nonce: Some("nonce".to_owned()),
        created_at: now,
        expires_at: now + Duration::minutes(10),
    };
    PkceStateRepository::save(&repository, &state)
        .await
        .expect("save PKCE state");
    assert_eq!(
        repository.take("state-1").await.expect("take PKCE state"),
        Some(state)
    );
    assert_eq!(
        repository.take("state-1").await.expect("replay PKCE state"),
        None
    );
}

#[tokio::test]
async fn malformed_cached_state_fails_closed_with_typed_error() {
    let cache = Arc::new(MemoryCache::default());
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).expect("current time is positive");
    cache
        .set("pkce:bad", b"not-json".to_vec(), Some(600), now_ms)
        .await
        .expect("seed malformed PKCE state");
    let error = repository(cache)
        .take("bad")
        .await
        .expect_err("malformed state must fail closed");
    assert_eq!(error.code, "invalid_cached_pkce_state");
}
