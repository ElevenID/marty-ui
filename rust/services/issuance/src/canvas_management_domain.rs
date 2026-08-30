//! Pure Canvas management lifecycle decisions.
//!
//! Provider I/O and persistence stay in adapters. This module owns the state
//! transitions that must remain identical across HTTP and worker consumers.

use chrono::{DateTime, Utc};
use marty_oid4vci::lti::{
    normalize_canvas_base_url, CANVAS_LTI_TRUST_HOSTED_GLOBAL,
    CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::canvas_management::{
    CanvasPlatformRequest, CanvasRequestValidationError, ValidateCanvasRequest,
};

const ENABLED_INTENT: &str = "enabled_intent";
const LTI_CAPABILITY_INTENT: &str = "lti_capability_intent";
const LTI_CONFIG_TOKEN_HASH: &str = "lti_config_token_hash";
const LTI_CONFIG_TOKEN_STATUS: &str = "lti_config_token_status";
const LTI_CONFIG_TOKEN_ISSUED_AT: &str = "lti_config_token_issued_at";
const LTI_CONFIG_TOKEN_REVOKED_AT: &str = "lti_config_token_revoked_at";
const OAUTH_STATUS: &str = "oauth_status";
const OAUTH_PENDING_AUTHORIZATION_ID: &str = "oauth_pending_authorization_id";

#[derive(Debug, Error, PartialEq)]
pub enum CanvasManagementDomainError {
    #[error(transparent)]
    InvalidRequest(#[from] CanvasRequestValidationError),
    #[error("Canvas base URL is not permitted by operator policy")]
    OriginUntrusted,
    #[error("Canvas platform configuration version is exhausted")]
    VersionExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCanvasOrigin {
    pub origin: String,
    pub trust_profile: String,
}

/// Operator-owned origin policy. No management request can widen these sets.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanvasOriginPolicy {
    pub allow_http_localhost: bool,
    pub private_origin_allowlist: Vec<String>,
    pub self_managed_origin_allowlist: Vec<String>,
}

impl CanvasOriginPolicy {
    pub fn resolve(
        &self,
        candidate: &str,
    ) -> Result<ValidatedCanvasOrigin, CanvasManagementDomainError> {
        let hardened = normalize_canvas_base_url(candidate, false, self.allow_http_localhost);
        let origin = match hardened {
            Ok(origin) => origin,
            Err(_) => {
                let permissive =
                    normalize_canvas_base_url(candidate, true, self.allow_http_localhost)
                        .map_err(|_| CanvasManagementDomainError::OriginUntrusted)?;
                if !self
                    .normalized_allowlist(&self.private_origin_allowlist)
                    .iter()
                    .any(|allowed| allowed == &permissive)
                {
                    return Err(CanvasManagementDomainError::OriginUntrusted);
                }
                permissive
            }
        };

        let trust_profile = if self
            .normalized_allowlist(&self.self_managed_origin_allowlist)
            .iter()
            .any(|allowed| allowed == &origin)
        {
            CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN
        } else {
            CANVAS_LTI_TRUST_HOSTED_GLOBAL
        };

        Ok(ValidatedCanvasOrigin {
            origin,
            trust_profile: trust_profile.to_owned(),
        })
    }

    fn normalized_allowlist(&self, values: &[String]) -> Vec<String> {
        values
            .iter()
            .filter_map(|value| {
                normalize_canvas_base_url(value, true, self.allow_http_localhost).ok()
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasPlatformRecord {
    pub id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub display_name: Option<String>,
    pub canvas_base_url: Option<String>,
    pub lti_client_id: Option<String>,
    pub lti_deployment_id: Option<String>,
    pub lti_trust_profile: String,
    pub lti_issuer: Option<String>,
    pub lti_jwks_url: Option<String>,
    pub lti_jwks_json: Option<Value>,
    pub lti_jwks_fetched_at: Option<DateTime<Utc>>,
    pub lti_jwks_expires_at: Option<DateTime<Utc>>,
    pub lti_openid_configuration: Option<Value>,
    pub registration_status: String,
    pub connection_config: Map<String, Value>,
    pub capability_snapshot: Map<String, Value>,
    pub last_validated_at: Option<DateTime<Utc>>,
    pub last_connection_error: Option<String>,
    pub config_version: i64,
    pub archived_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CanvasPlatformRecord {
    pub fn new_draft(
        organization_id: String,
        request: CanvasPlatformRequest,
        origin: ValidatedCanvasOrigin,
        now: DateTime<Utc>,
    ) -> Result<Self, CanvasManagementDomainError> {
        request.validate()?;
        let id = Uuid::new_v4().to_string();
        let mut connection_config = Map::new();
        connection_config.insert(ENABLED_INTENT.to_owned(), json!(request.enabled));
        connection_config.insert(LTI_CAPABILITY_INTENT.to_owned(), json!(["ags", "nrps"]));
        Ok(Self {
            canvas_account_id: format!("unverified:{id}"),
            id,
            organization_id,
            display_name: request.display_name,
            canvas_base_url: Some(origin.origin),
            lti_client_id: request.lti_client_id,
            lti_deployment_id: request.lti_deployment_id,
            lti_trust_profile: origin.trust_profile,
            lti_issuer: None,
            lti_jwks_url: None,
            lti_jwks_json: None,
            lti_jwks_fetched_at: None,
            lti_jwks_expires_at: None,
            lti_openid_configuration: None,
            registration_status: "draft".to_owned(),
            connection_config,
            capability_snapshot: Map::new(),
            last_validated_at: None,
            last_connection_error: None,
            config_version: 1,
            archived_at: None,
            enabled: false,
            created_at: now,
            updated_at: now,
        })
    }

    /// Apply caller-owned configuration and return whether readiness became stale.
    pub fn reconfigure(
        &mut self,
        request: CanvasPlatformRequest,
        origin: ValidatedCanvasOrigin,
        now: DateTime<Utc>,
    ) -> Result<bool, CanvasManagementDomainError> {
        request.validate()?;
        let previous_origin = self.canvas_base_url.clone();
        let previous_trust_profile = self.lti_trust_profile.clone();
        let previous = (
            self.display_name.clone(),
            previous_origin.clone(),
            self.lti_client_id.clone(),
            self.lti_deployment_id.clone(),
            previous_trust_profile.clone(),
            self.enabled_intent(),
        );

        self.display_name = request.display_name;
        self.canvas_base_url = Some(origin.origin);
        self.lti_client_id = request.lti_client_id;
        self.lti_deployment_id = request.lti_deployment_id;
        self.lti_trust_profile = origin.trust_profile;
        self.connection_config
            .insert(ENABLED_INTENT.to_owned(), json!(request.enabled));
        self.connection_config
            .entry(LTI_CAPABILITY_INTENT.to_owned())
            .or_insert_with(|| json!(["ags", "nrps"]));

        let current = (
            self.display_name.clone(),
            self.canvas_base_url.clone(),
            self.lti_client_id.clone(),
            self.lti_deployment_id.clone(),
            self.lti_trust_profile.clone(),
            self.enabled_intent(),
        );
        let changed = current != previous;
        if changed {
            self.config_version = self
                .config_version
                .checked_add(1)
                .ok_or(CanvasManagementDomainError::VersionExhausted)?;
            self.enabled = false;
            self.registration_status = "draft".to_owned();
            self.capability_snapshot.clear();
            self.last_validated_at = None;
            self.last_connection_error = None;
            if self.canvas_base_url != previous_origin
                || self.lti_trust_profile != previous_trust_profile
            {
                self.clear_trust_metadata();
            }
        }
        self.archived_at = None;
        self.updated_at = now;
        Ok(changed)
    }

    /// Apply the local archival state after durable OAuth revocation was queued.
    pub fn archive(
        &mut self,
        oauth_connection_exists: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, CanvasManagementDomainError> {
        if self.archived_at.is_some() {
            return Ok(false);
        }
        self.config_version = self
            .config_version
            .checked_add(1)
            .ok_or(CanvasManagementDomainError::VersionExhausted)?;
        self.enabled = false;
        self.archived_at = Some(now);
        self.registration_status = "archived".to_owned();
        self.revoke_lti_config_token(now);
        self.apply_archival_oauth_state(oauth_connection_exists);
        self.updated_at = now;
        Ok(true)
    }

    /// Reconcile an already archived platform with the durable OAuth queue.
    /// This closes the callback/publication race without making archival
    /// non-idempotent or reviving any public registration state.
    pub fn synchronize_archived_oauth_state(
        &mut self,
        oauth_connection_exists: bool,
        now: DateTime<Utc>,
    ) -> bool {
        if self.archived_at.is_none() {
            return false;
        }
        let expected_status = if oauth_connection_exists {
            "revocation_pending"
        } else {
            "disconnected"
        };
        let changed = self
            .connection_config
            .get(OAUTH_STATUS)
            .and_then(Value::as_str)
            != Some(expected_status)
            || self
                .connection_config
                .contains_key(OAUTH_PENDING_AUTHORIZATION_ID);
        self.apply_archival_oauth_state(oauth_connection_exists);
        if changed {
            self.updated_at = now;
        }
        changed
    }

    pub fn issue_lti_config_token(&mut self, token_hash: String, now: DateTime<Utc>) {
        self.connection_config
            .insert(LTI_CONFIG_TOKEN_HASH.to_owned(), json!(token_hash));
        self.connection_config
            .insert(LTI_CONFIG_TOKEN_STATUS.to_owned(), json!("active"));
        self.connection_config.insert(
            LTI_CONFIG_TOKEN_ISSUED_AT.to_owned(),
            json!(now.to_rfc3339()),
        );
        self.connection_config.remove(LTI_CONFIG_TOKEN_REVOKED_AT);
        self.updated_at = now;
    }

    pub fn revoke_lti_config_token(&mut self, now: DateTime<Utc>) {
        self.connection_config.remove(LTI_CONFIG_TOKEN_HASH);
        self.connection_config
            .insert(LTI_CONFIG_TOKEN_STATUS.to_owned(), json!("revoked"));
        self.connection_config.insert(
            LTI_CONFIG_TOKEN_REVOKED_AT.to_owned(),
            json!(now.to_rfc3339()),
        );
        self.updated_at = now;
    }

    #[must_use]
    pub fn active_lti_config_token_hash(&self) -> Option<&str> {
        (self
            .connection_config
            .get(LTI_CONFIG_TOKEN_STATUS)
            .and_then(Value::as_str)
            == Some("active"))
        .then(|| {
            self.connection_config
                .get(LTI_CONFIG_TOKEN_HASH)
                .and_then(Value::as_str)
        })
        .flatten()
        .filter(|value| !value.is_empty())
    }

    fn apply_archival_oauth_state(&mut self, oauth_connection_exists: bool) {
        self.connection_config.insert(
            OAUTH_STATUS.to_owned(),
            json!(if oauth_connection_exists {
                "revocation_pending"
            } else {
                "disconnected"
            }),
        );
        self.connection_config
            .remove(OAUTH_PENDING_AUTHORIZATION_ID);
    }

    fn enabled_intent(&self) -> bool {
        self.connection_config
            .get(ENABLED_INTENT)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn clear_trust_metadata(&mut self) {
        self.lti_issuer = None;
        self.lti_jwks_url = None;
        self.lti_jwks_json = None;
        self.lti_jwks_fetched_at = None;
        self.lti_jwks_expires_at = None;
        self.lti_openid_configuration = None;
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn now(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 20, 0, second).unwrap()
    }

    fn request(origin: &str, enabled: bool) -> CanvasPlatformRequest {
        CanvasPlatformRequest {
            display_name: Some("University Canvas".to_owned()),
            canvas_base_url: origin.to_owned(),
            lti_client_id: Some("client-1".to_owned()),
            lti_deployment_id: Some("deployment-1".to_owned()),
            enabled,
        }
    }

    fn hosted(origin: &str) -> ValidatedCanvasOrigin {
        ValidatedCanvasOrigin {
            origin: origin.to_owned(),
            trust_profile: CANVAS_LTI_TRUST_HOSTED_GLOBAL.to_owned(),
        }
    }

    #[test]
    fn origin_policy_requires_exact_private_allowlist_and_derives_trust() {
        let policy = CanvasOriginPolicy {
            private_origin_allowlist: vec!["https://10.1.2.3".to_owned()],
            self_managed_origin_allowlist: vec!["https://10.1.2.3".to_owned()],
            ..CanvasOriginPolicy::default()
        };
        assert_eq!(
            policy.resolve("https://10.1.2.4"),
            Err(CanvasManagementDomainError::OriginUntrusted)
        );
        let accepted = policy.resolve("https://10.1.2.3/").unwrap();
        assert_eq!(accepted.origin, "https://10.1.2.3");
        assert_eq!(
            accepted.trust_profile,
            CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN
        );
    }

    #[test]
    fn origin_policy_rejects_paths_credentials_fragments_and_unapproved_http() {
        let policy = CanvasOriginPolicy::default();
        for origin in [
            "https://canvas.example/path",
            "https://user:secret@canvas.example",
            "https://canvas.example/#fragment",
            "http://localhost:8000",
        ] {
            assert_eq!(
                policy.resolve(origin),
                Err(CanvasManagementDomainError::OriginUntrusted),
                "{origin}"
            );
        }
    }

    #[test]
    fn create_persists_intent_but_stays_disabled_until_probe() {
        let platform = CanvasPlatformRecord::new_draft(
            "org-1".to_owned(),
            request("https://canvas.example", true),
            hosted("https://canvas.example"),
            now(0),
        )
        .unwrap();
        assert_eq!(
            platform.canvas_account_id,
            format!("unverified:{}", platform.id)
        );
        assert_eq!(platform.config_version, 1);
        assert_eq!(platform.registration_status, "draft");
        assert!(!platform.enabled);
        assert_eq!(platform.connection_config[ENABLED_INTENT], json!(true));
        assert_eq!(
            platform.connection_config[LTI_CAPABILITY_INTENT],
            json!(["ags", "nrps"])
        );
    }

    #[test]
    fn same_configuration_does_not_invalidate_readiness() {
        let mut platform = CanvasPlatformRecord::new_draft(
            "org-1".to_owned(),
            request("https://canvas.example", true),
            hosted("https://canvas.example"),
            now(0),
        )
        .unwrap();
        platform.enabled = true;
        platform.registration_status = "active".to_owned();
        platform
            .capability_snapshot
            .insert("ags".to_owned(), json!(true));
        platform.last_validated_at = Some(now(1));

        assert!(!platform
            .reconfigure(
                request("https://canvas.example", true),
                hosted("https://canvas.example"),
                now(2),
            )
            .unwrap());
        assert_eq!(platform.config_version, 1);
        assert!(platform.enabled);
        assert_eq!(platform.registration_status, "active");
        assert_eq!(platform.capability_snapshot["ags"], json!(true));
    }

    #[test]
    fn configuration_change_invalidates_state_and_origin_change_clears_trust() {
        let mut platform = CanvasPlatformRecord::new_draft(
            "org-1".to_owned(),
            request("https://canvas.example", true),
            hosted("https://canvas.example"),
            now(0),
        )
        .unwrap();
        platform.enabled = true;
        platform.registration_status = "active".to_owned();
        platform
            .capability_snapshot
            .insert("ags".to_owned(), json!(true));
        platform.last_validated_at = Some(now(1));
        platform.last_connection_error = Some("old".to_owned());
        platform.lti_issuer = Some("https://canvas.instructure.com".to_owned());
        platform.lti_jwks_url = Some("https://sso.canvaslms.com/jwks".to_owned());
        platform.lti_jwks_json = Some(json!({"keys": []}));
        platform.lti_openid_configuration = Some(json!({"issuer": "old"}));

        assert!(platform
            .reconfigure(
                request("https://canvas-two.example", true),
                hosted("https://canvas-two.example"),
                now(2),
            )
            .unwrap());
        assert_eq!(platform.config_version, 2);
        assert!(!platform.enabled);
        assert_eq!(platform.registration_status, "draft");
        assert!(platform.capability_snapshot.is_empty());
        assert!(platform.last_validated_at.is_none());
        assert!(platform.last_connection_error.is_none());
        assert!(platform.lti_issuer.is_none());
        assert!(platform.lti_jwks_url.is_none());
        assert!(platform.lti_jwks_json.is_none());
        assert!(platform.lti_openid_configuration.is_none());
    }

    #[test]
    fn archive_is_idempotent_and_revokes_local_registration_state() {
        let mut platform = CanvasPlatformRecord::new_draft(
            "org-1".to_owned(),
            request("https://canvas.example", true),
            hosted("https://canvas.example"),
            now(0),
        )
        .unwrap();
        platform.enabled = true;
        platform.connection_config.insert(
            LTI_CONFIG_TOKEN_HASH.to_owned(),
            json!("digest-not-plaintext"),
        );
        platform.connection_config.insert(
            OAUTH_PENDING_AUTHORIZATION_ID.to_owned(),
            json!("authorization-1"),
        );

        assert!(platform.archive(true, now(1)).unwrap());
        assert_eq!(platform.config_version, 2);
        assert!(!platform.enabled);
        assert_eq!(platform.registration_status, "archived");
        assert_eq!(
            platform.connection_config[LTI_CONFIG_TOKEN_STATUS],
            json!("revoked")
        );
        assert_eq!(
            platform.connection_config[OAUTH_STATUS],
            json!("revocation_pending")
        );
        assert!(!platform
            .connection_config
            .contains_key(LTI_CONFIG_TOKEN_HASH));
        assert!(!platform
            .connection_config
            .contains_key(OAUTH_PENDING_AUTHORIZATION_ID));

        assert!(!platform.archive(false, now(2)).unwrap());
        assert_eq!(platform.config_version, 2);
        assert_eq!(platform.updated_at, now(1));
    }

    #[test]
    fn archived_platform_reconciles_an_oauth_connection_published_during_the_race_window() {
        let mut platform = CanvasPlatformRecord::new_draft(
            "org-1".to_owned(),
            request("https://canvas.example", true),
            hosted("https://canvas.example"),
            now(0),
        )
        .unwrap();
        assert!(platform.archive(false, now(1)).unwrap());
        assert_eq!(
            platform.connection_config[OAUTH_STATUS],
            json!("disconnected")
        );

        assert!(platform.synchronize_archived_oauth_state(true, now(2)));
        assert_eq!(platform.config_version, 2);
        assert_eq!(platform.updated_at, now(2));
        assert_eq!(
            platform.connection_config[OAUTH_STATUS],
            json!("revocation_pending")
        );
        assert!(!platform.synchronize_archived_oauth_state(true, now(3)));
        assert_eq!(platform.updated_at, now(2));
    }

    #[test]
    fn registration_token_lifecycle_retains_only_the_active_digest() {
        let mut platform = CanvasPlatformRecord::new_draft(
            "org-1".to_owned(),
            request("https://canvas.example", false),
            hosted("https://canvas.example"),
            now(0),
        )
        .unwrap();
        platform.issue_lti_config_token("a".repeat(64), now(1));
        assert_eq!(
            platform.active_lti_config_token_hash(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(platform.updated_at, now(1));
        assert!(!platform
            .connection_config
            .contains_key(LTI_CONFIG_TOKEN_REVOKED_AT));

        platform.revoke_lti_config_token(now(2));
        assert!(platform.active_lti_config_token_hash().is_none());
        assert_eq!(
            platform.connection_config[LTI_CONFIG_TOKEN_STATUS],
            json!("revoked")
        );
        assert_eq!(platform.updated_at, now(2));
    }
}
