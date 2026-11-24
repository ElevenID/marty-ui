use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::{OidcConfig, OidcMaxAge, OidcProviderMode, OidcValidatedIdentity, PortError};

/// Public configuration, never a service-role or management key.
#[derive(Clone, Debug)]
pub struct SupabaseNativeConfig {
    pub authorization_origin: String,
    pub publishable_key: String,
}

impl SupabaseNativeConfig {
    pub fn validate(self, oidc: &OidcConfig) -> Result<Self, PortError> {
        let invalid = || {
            PortError::new("invalid_supabase_native_configuration", "Native Supabase proof requires an exact HTTPS authorization origin, publishable key and external ES256 issuer with max_age=0")
        };
        let origin = Url::parse(&self.authorization_origin).map_err(|_| invalid())?;
        let key = self
            .publishable_key
            .strip_prefix("sb_publishable_")
            .ok_or_else(invalid)?;
        if oidc.provider_mode != OidcProviderMode::External
            || !oidc.external_issuer_url.ends_with("/auth/v1")
            || oidc.max_age != OidcMaxAge::Seconds(0)
            || oidc.allowed_algorithms != ["ES256"]
            || Uuid::parse_str(&oidc.client_id).is_err()
            || origin.scheme() != "https"
            || origin.origin().ascii_serialization() != self.authorization_origin
            || !(16..=256).contains(&key.len())
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(invalid());
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OidcUserInfo;
    use serde_json::json;

    const ISSUER: &str = "https://project.example.invalid/auth/v1";
    const NOW: i64 = 1_800_000_000;

    fn identity() -> OidcValidatedIdentity {
        let claims = json!({"iss":ISSUER, "sub":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "email":"fixture@example.invalid", "email_verified":true});
        OidcValidatedIdentity {
            user_info: OidcUserInfo::from_claims(&claims, None),
            id_token_claims: claims,
            access_token_claims: json!({}),
        }
    }

    fn claims() -> Value {
        json!({"iss":ISSUER, "aud":"authenticated", "sub":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "email":"fixture@example.invalid",
            "session_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc", "aal":"aal2", "iat":NOW, "exp":NOW+3600,
            "amr":[{"method":"password", "timestamp":NOW-2}, {"method":"totp", "timestamp":NOW-1}]})
    }

    fn verify(claims: &Value) -> Result<NativeAuthenticationEvidence, PortError> {
        NativeAuthenticationEvidence::from_verified_claims(
            claims,
            &identity(),
            ISSUER,
            NOW - 3,
            NOW,
        )
    }

    #[test]
    fn retains_actual_events_separately_from_unchanged_identity_claims() {
        let identity = identity();
        let original = identity.id_token_claims.clone();
        let evidence = NativeAuthenticationEvidence::from_verified_claims(
            &claims(),
            &identity,
            ISSUER,
            NOW - 3,
            NOW,
        )
        .unwrap();
        assert_eq!(evidence.password_authenticated_at, NOW - 2);
        assert_eq!(evidence.factor_authenticated_at, NOW - 1);
        assert_eq!(identity.id_token_claims, original);
        assert!(identity.id_token_claims.get("aal").is_none());
        let mut alias = claims();
        alias["amr"][1]["method"] = json!("mfa/totp");
        assert!(verify(&alias).is_ok());
    }

    #[test]
    fn rejects_wrong_provenance_assurance_account_session_and_token_times() {
        for (field, value) in [
            ("iss", json!("https://attacker.invalid/auth/v1")),
            ("aud", json!("another-client")),
            ("aud", json!(["authenticated", "other"])),
            ("aal", json!("aal1")),
            ("sub", json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
            ("email", json!("other@example.invalid")),
            ("session_id", json!("bad-session")),
            ("session_id", Value::Null),
            ("iat", json!(NOW + 6)),
            ("exp", json!(NOW)),
            ("exp", json!(NOW + 86_401)),
            ("amr", json!(["password", "totp"])),
            ("amr", Value::Null),
        ] {
            let mut invalid = claims();
            invalid[field] = value;
            assert!(verify(&invalid).is_err(), "accepted invalid {field}");
        }
        let mut unverified = identity();
        unverified.user_info.email_verified = false;
        assert!(NativeAuthenticationEvidence::from_verified_claims(
            &claims(),
            &unverified,
            ISSUER,
            NOW - 3,
            NOW
        )
        .is_err());
    }

    #[test]
    fn refreshed_tokens_cannot_make_stale_password_or_factor_events_fresh() {
        for index in [0, 1] {
            for timestamp in [NOW - 9, NOW + 6, 0] {
                let mut invalid = claims();
                invalid["amr"][index]["timestamp"] = json!(timestamp);
                invalid["user_metadata"] = json!({"aal":"aal2", "auth_time":NOW});
                assert!(verify(&invalid).is_err());
            }
        }
        let mut duplicate = claims();
        duplicate["amr"]
            .as_array_mut()
            .unwrap()
            .push(json!({"method":"mfa/totp", "timestamp":NOW}));
        assert!(verify(&duplicate).is_err());
        assert!(NativeAuthenticationEvidence::from_verified_claims(
            &claims(),
            &identity(),
            ISSUER,
            NOW + 1,
            NOW
        )
        .is_err());
    }
}

/// Verified bootstrap provenance. Never overwrite the actual signed ID claims
/// with these facts or retain the native bearer token in an application session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAuthenticationEvidence {
    pub issuer: String,
    pub subject: String,
    pub provider_session_id: String,
    pub password_authenticated_at: i64,
    pub factor_authenticated_at: i64,
}

impl NativeAuthenticationEvidence {
    /// Input claims MUST already have passed asymmetric signature, exact issuer,
    /// audience, algorithm and expiry validation against the configured JWKS.
    pub(crate) fn from_verified_claims(
        claims: &Value,
        identity: &OidcValidatedIdentity,
        issuer: &str,
        started_at: i64,
        now: i64,
    ) -> Result<Self, PortError> {
        let invalid = || {
            PortError::new(
                "supabase_native_proof_invalid",
                "Fresh matching native password and TOTP authentication was not established",
            )
        };
        let string = |name: &str| claims.get(name).and_then(Value::as_str).ok_or_else(invalid);
        let subject = string("sub")?;
        let session = string("session_id")?;
        let issued = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(invalid)?;
        let expires = claims
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or_else(invalid)?;
        if string("iss")? != issuer
            || string("aud")? != "authenticated"
            || string("aal")? != "aal2"
            || subject != identity.user_info.sub
            || string("email")? != identity.user_info.email
            || !identity.user_info.email_verified
            || Uuid::parse_str(subject).is_err()
            || Uuid::parse_str(session).is_err()
            || started_at <= 0
            || started_at > now
            || issued <= 0
            || issued > now.saturating_add(5)
            || expires <= now
            || expires <= issued
            || expires.saturating_sub(issued) > 86_400
        {
            return Err(invalid());
        }
        let methods = claims
            .get("amr")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        if methods.len() > 16 {
            return Err(invalid());
        }
        let event = |names: &[&str]| -> Result<i64, PortError> {
            let mut matches = methods.iter().filter(|entry| {
                entry
                    .get("method")
                    .and_then(Value::as_str)
                    .is_some_and(|method| names.contains(&method))
            });
            let stamp = matches
                .next()
                .and_then(|entry| entry.get("timestamp"))
                .and_then(Value::as_i64)
                .ok_or_else(invalid)?;
            if matches.next().is_some()
                || stamp <= 0
                || stamp < started_at.saturating_sub(5)
                || stamp > issued.saturating_add(5)
                || stamp > now.saturating_add(5)
            {
                return Err(invalid());
            }
            Ok(stamp)
        };
        Ok(Self {
            issuer: issuer.into(),
            subject: subject.into(),
            provider_session_id: session.into(),
            password_authenticated_at: event(&["password"])?,
            factor_authenticated_at: event(&["totp", "mfa/totp"])?,
        })
    }
}
