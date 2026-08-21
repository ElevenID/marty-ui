use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, TimeZone as _, Utc};
use marty_auth::{
    CredentialAccount, CredentialAccountResolver, CredentialCallbackApplication,
    CredentialCallbackConfig, CredentialCallbackContext, CredentialCallbackHeaders,
    CredentialCallbackPolicy, CredentialCallbackResult, CredentialLoginStateStore,
    CredentialVerifiedPayload, PendingCredentialLogin, PortError, ResolveCredentialAccount,
    Session, SessionRepository, AUTH_CALLBACK_AUDIENCE,
};
use mmf_data::MemoryCache;
use mmf_push::{payload_digest, sign_event};
use serde_json::{json, Value};

const SECRET: &str = "test-flow-webhook-secret-at-least-32-bytes";

#[derive(Default)]
struct Sessions(Mutex<Vec<Session>>);

#[async_trait]
impl SessionRepository for Sessions {
    async fn save(&self, session: &Session) -> Result<(), PortError> {
        let mut sessions = self.0.lock().unwrap();
        if let Some(existing) = sessions
            .iter_mut()
            .find(|candidate| candidate.session_id == session.session_id)
        {
            *existing = session.clone();
        } else {
            sessions.push(session.clone());
        }
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<Option<Session>, PortError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|session| session.session_id == session_id)
            .cloned())
    }

    async fn delete(&self, session_id: &str) -> Result<(), PortError> {
        self.0
            .lock()
            .unwrap()
            .retain(|session| session.session_id != session_id);
        Ok(())
    }

    async fn get_by_user(&self, user_id: &str) -> Result<Vec<Session>, PortError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|session| session.user.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_all_for_user(&self, user_id: &str) -> Result<usize, PortError> {
        let mut sessions = self.0.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|session| session.user.user_id != user_id);
        Ok(before - sessions.len())
    }
}

struct NoAccount;

#[async_trait]
impl CredentialAccountResolver for NoAccount {
    async fn resolve(
        &self,
        _request: &ResolveCredentialAccount,
    ) -> Result<Option<CredentialAccount>, PortError> {
        Ok(None)
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn policy() -> CredentialCallbackPolicy {
    CredentialCallbackPolicy {
        secret: SECRET.into(),
        expected_policy_id: "policy-1".into(),
        expected_organization_id: "org-1".into(),
        maximum_timestamp_skew_seconds: 300,
        pending_ttl_seconds: 900,
        completion_ttl_seconds: 300,
        claim_lease_seconds: 30,
    }
}

fn config() -> CredentialCallbackConfig {
    CredentialCallbackConfig {
        default_organization_id: "org-1".into(),
        session_ttl_seconds: 86_400,
        require_existing_keycloak_user: false,
        create_keycloak_users: false,
    }
}

fn pending(nonce: &str) -> PendingCredentialLogin {
    PendingCredentialLogin {
        nonce: nonce.into(),
        flow_instance_id: "flow-1".into(),
        presentation_policy_id: "policy-1".into(),
        organization_id: "org-1".into(),
        status: "pending".into(),
        revocation_checked: false,
    }
}

fn signed_payload(claims: Value) -> (CredentialVerifiedPayload, CredentialCallbackHeaders) {
    let mut payload = CredentialVerifiedPayload {
        flow_instance_id: "flow-1".into(),
        result: "passed".into(),
        decision: "allow".into(),
        decision_reason: String::new(),
        verified_claims: serde_json::from_value(claims).unwrap(),
        presentation_policy_id: "policy-1".into(),
        completed_at: now().to_rfc3339(),
        evidence_digest: "a".repeat(64),
        decision_digest: String::new(),
    };
    let mut basis = serde_json::to_value(&payload).unwrap();
    basis.as_object_mut().unwrap().remove("decision_digest");
    payload.decision_digest = payload_digest(&basis).unwrap();
    let value = serde_json::to_value(&payload).unwrap();
    let timestamp = now().to_rfc3339();
    let headers = CredentialCallbackHeaders {
        event: "flow.verification_completed".into(),
        audience: AUTH_CALLBACK_AUDIENCE.into(),
        event_id: "flow-1".into(),
        timestamp: timestamp.clone(),
        signature: sign_event(
            SECRET,
            AUTH_CALLBACK_AUDIENCE,
            "flow.verification_completed",
            "flow-1",
            &timestamp,
            &value,
        )
        .unwrap(),
    };
    (payload, headers)
}

async fn build_application(
    nonce: &str,
    accounts: Option<Arc<dyn CredentialAccountResolver>>,
    config: CredentialCallbackConfig,
) -> (CredentialCallbackApplication, Arc<Sessions>) {
    let state = Arc::new(
        CredentialLoginStateStore::new(Arc::new(MemoryCache::default()), policy()).unwrap(),
    );
    state
        .save_pending(&pending(nonce), now().timestamp_millis() as u64)
        .await
        .unwrap();
    let sessions = Arc::new(Sessions::default());
    (
        CredentialCallbackApplication::new(state, sessions.clone(), accounts, None, config),
        sessions,
    )
}

fn context(nonce: &str) -> CredentialCallbackContext {
    CredentialCallbackContext {
        nonce: nonce.into(),
        ip_address: Some("127.0.0.1".into()),
        user_agent: Some("callback-test".into()),
    }
}

#[tokio::test]
async fn claim_only_login_sanitizes_authorization_and_is_retry_idempotent() {
    let (application, sessions) = build_application("nonce-1", None, config()).await;
    let (payload, headers) = signed_payload(json!({
        "email": "alice@example.com",
        "given_name": "Alice",
        "role": "administrator",
        "organization_id": "attacker-org",
        "organization": {"attacker-org": {"name": "Attacker"}},
        "revocation_checked": true,
        "revocation_status": "valid"
    }));
    let result = application
        .handle(&payload, &headers, &context("nonce-1"), now())
        .await
        .unwrap();
    let session_id = match result {
        CredentialCallbackResult::Completed { session_id } => session_id,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(
        application
            .handle(&payload, &headers, &context("nonce-1"), now())
            .await
            .unwrap(),
        CredentialCallbackResult::AlreadyProcessed
    );
    let sessions = sessions.0.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, session_id);
    assert_eq!(sessions[0].user.roles, ["applicant"]);
    assert_eq!(sessions[0].user.organization_id.as_deref(), Some("org-1"));
    assert!(sessions[0].id_token.is_none());
}

#[tokio::test]
async fn required_account_policy_denies_missing_resolver_or_user() {
    let mut required = config();
    required.require_existing_keycloak_user = true;
    let (without_admin, sessions) = build_application("nonce-admin", None, required).await;
    let (payload, headers) = signed_payload(json!({"email": "alice@example.com"}));
    assert_eq!(
        without_admin
            .handle(&payload, &headers, &context("nonce-admin"), now())
            .await
            .unwrap(),
        CredentialCallbackResult::Denied {
            reason_code: "keycloak_admin_unavailable".into()
        }
    );
    assert!(sessions.0.lock().unwrap().is_empty());

    let (missing_user, sessions) =
        build_application("nonce-user", Some(Arc::new(NoAccount)), config()).await;
    assert_eq!(
        missing_user
            .handle(&payload, &headers, &context("nonce-user"), now())
            .await
            .unwrap(),
        CredentialCallbackResult::Denied {
            reason_code: "keycloak_user_not_found".into()
        }
    );
    assert!(sessions.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_verification_and_missing_email_complete_as_denials() {
    let (application, sessions) = build_application("nonce-denied", None, config()).await;
    let (mut payload, _) = signed_payload(json!({"email": "alice@example.com"}));
    payload.result = "failed".into();
    payload.decision = "deny".into();
    payload.decision_reason = "credential is revoked".into();
    let (payload, headers) = signed_payload_from(payload);
    assert_eq!(
        application
            .handle(&payload, &headers, &context("nonce-denied"), now())
            .await
            .unwrap(),
        CredentialCallbackResult::Denied {
            reason_code: "credential_revoked".into()
        }
    );
    assert!(sessions.0.lock().unwrap().is_empty());

    let (application, sessions) = build_application("nonce-email", None, config()).await;
    let (payload, headers) = signed_payload(json!({"given_name": "Alice"}));
    assert_eq!(
        application
            .handle(&payload, &headers, &context("nonce-email"), now())
            .await
            .unwrap(),
        CredentialCallbackResult::Denied {
            reason_code: "missing_email_claim".into()
        }
    );
    assert!(sessions.0.lock().unwrap().is_empty());
}

fn signed_payload_from(
    mut payload: CredentialVerifiedPayload,
) -> (CredentialVerifiedPayload, CredentialCallbackHeaders) {
    payload.decision_digest.clear();
    let mut basis = serde_json::to_value(&payload).unwrap();
    basis.as_object_mut().unwrap().remove("decision_digest");
    payload.decision_digest = payload_digest(&basis).unwrap();
    let value = serde_json::to_value(&payload).unwrap();
    let timestamp = now().to_rfc3339();
    let headers = CredentialCallbackHeaders {
        event: "flow.verification_completed".into(),
        audience: AUTH_CALLBACK_AUDIENCE.into(),
        event_id: payload.flow_instance_id.clone(),
        timestamp: timestamp.clone(),
        signature: sign_event(
            SECRET,
            AUTH_CALLBACK_AUDIENCE,
            "flow.verification_completed",
            &payload.flow_instance_id,
            &timestamp,
            &value,
        )
        .unwrap(),
    };
    (payload, headers)
}
