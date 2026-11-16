//! Explicit public-only verifier registration owned by Trust Profile.
//! Issuer relationships and machine-identity trust never imply this purpose.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ComplianceStatus, TrustProfile, TrustProfileApplicationError, TrustProfileStatus, TrustPurpose,
    TrustSource, TrustSourceType,
};

pub const WALLET_VERIFIER_AUTHORITY_CONTRACT: &str = "marty.wallet/verifier-authority/v1";

#[derive(Clone, Debug, Serialize)]
pub struct WalletVerifierAuthoritySnapshot {
    pub contract: &'static str,
    pub organization_id: String,
    pub trust_profile_id: String,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub authority: RegisteredVerifierAuthority,
}

#[derive(Clone, Debug, Serialize)]
pub struct RegisteredVerifierAuthority {
    pub authority_id: String,
    pub revision: String,
    pub key_purpose: &'static str,
    pub algorithm: &'static str,
    pub request_clock_skew_seconds: u32,
    pub max_request_lifetime_seconds: u32,
    pub registration: RegisteredVerifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredVerifier {
    pub client_id: String,
    pub request_key_id: String,
    pub public_jwk: Value,
    pub response_uris: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

pub(crate) fn validate_profile_policy(
    profile: &TrustProfile,
) -> Result<(), TrustProfileApplicationError> {
    if profile.profile_type != crate::TrustProfileType::Custom
        || !profile
            .validation_rules
            .allowed_algorithms
            .iter()
            .any(|algorithm| algorithm == "ES256")
        || profile.validation_rules.min_key_size_ec > 256
        || !profile.validation_rules.extensions.is_empty()
        || profile
            .trusted_assertion_formats
            .as_ref()
            .is_some_and(|formats| !formats.contains(&crate::TrustedAssertionFormat::Jwt))
        || profile.time_policy.max_clock_skew_seconds < 30
        || profile.verification_policy_set_id.is_some()
        || profile.revocation_profile_id.is_some()
        || !profile.compatible_compliance_codes.is_empty()
    {
        return Err(TrustProfileApplicationError::Invalid(
            "registered_verifier_policy",
        ));
    }
    Ok(())
}

/// Project one current registration from its owner profile, without resolving
/// issuer relationships, remote URLs, or request-supplied keys.
pub fn project_wallet_verifier_authority(
    profile: &TrustProfile,
    organization_id: &str,
    client_id: &str,
    now: DateTime<Utc>,
) -> Result<WalletVerifierAuthoritySnapshot, TrustProfileApplicationError> {
    validate_profile_policy(profile)?;
    if !text(client_id)
        || profile.organization_id != organization_id
        || !text(organization_id)
        || profile.id.is_nil()
        || profile.status != TrustProfileStatus::Active
        || profile.compliance_status != ComplianceStatus::Compliant
        || !profile
            .trust_purposes
            .as_ref()
            .is_some_and(|purposes| purposes.contains(&TrustPurpose::PresentationVerifier))
        || !profile
            .validation_rules
            .allowed_algorithms
            .iter()
            .any(|algorithm| algorithm == "ES256")
    {
        return Err(invalid());
    }
    let mut clients = BTreeSet::new();
    let mut selected = None;
    for source in profile
        .trust_sources
        .iter()
        .filter(|source| source.source_type == TrustSourceType::RegisteredVerifier)
    {
        let registration = registration(source)?;
        if !clients.insert(registration.client_id.clone()) {
            return Err(invalid());
        }
        if registration.client_id == client_id && source.enabled {
            selected = Some((source.id, registration));
        }
    }
    let (source_id, registration) = selected.ok_or_else(invalid)?;
    if registration.valid_from > now || registration.valid_until <= now {
        return Err(invalid());
    }
    let revision = marty_oid4vp_contract::digest_domain_json(
        "marty.trust/registered-verifier-authority/v1",
        &serde_json::json!({
            "organization_id":profile.organization_id,"profile_id":profile.id,
            "profile_updated_at":profile.updated_at,"profile_status":profile.status,
            "compliance_status":profile.compliance_status,"trust_purposes":profile.trust_purposes,
            "allowed_algorithms":profile.validation_rules.allowed_algorithms,
            "min_key_size_ec":profile.validation_rules.min_key_size_ec,
            "trusted_assertion_formats":profile.trusted_assertion_formats,
            "profile_max_clock_skew_seconds":profile.time_policy.max_clock_skew_seconds,
            "request_clock_skew_seconds":30,"max_request_lifetime_seconds":900,
            "source_id":source_id,"registration":registration,
        }),
    )
    .map_err(|_| invalid())?;
    let expires_at = now
        .checked_add_signed(chrono::Duration::seconds(60))
        .ok_or_else(invalid)?
        .min(registration.valid_until);
    let snapshot = WalletVerifierAuthoritySnapshot {
        contract: WALLET_VERIFIER_AUTHORITY_CONTRACT,
        organization_id: profile.organization_id.clone(),
        trust_profile_id: profile.id.to_string(),
        observed_at: now,
        expires_at,
        authority: RegisteredVerifierAuthority {
            authority_id: format!("{}/{source_id}", profile.id),
            revision,
            key_purpose: "oid4vp_request_signing",
            algorithm: "ES256",
            request_clock_skew_seconds: 30,
            max_request_lifetime_seconds: 900,
            registration,
        },
    };
    if serde_json::to_vec(&snapshot).map_err(|_| invalid())?.len() > 65536 {
        return Err(invalid());
    }
    Ok(snapshot)
}

fn invalid() -> TrustProfileApplicationError {
    TrustProfileApplicationError::Invalid("registered_verifier")
}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Validate the explicit source on every owner-authorized profile write and
/// again before projection. This does not activate or provision a verifier.
pub(crate) fn registration(
    source: &TrustSource,
) -> Result<RegisteredVerifier, TrustProfileApplicationError> {
    if source.source_type != TrustSourceType::RegisteredVerifier
        || source.id.is_nil()
        || source.purposes.as_deref() != Some(&[TrustPurpose::PresentationVerifier])
        || source.url.is_some()
        || source.certificate_pem.is_some()
        || source.issuer_did.is_some()
        || !source.pinned_certificates.is_empty()
        || source.registry_sync.is_some()
        || source.registry_sync_token.is_some()
        || source.registry_sequence != 0
        || !source.registry_entries.is_empty()
        || source.registry_last_synced_at.is_some()
        || source.extensions.len() != 1
    {
        return Err(invalid());
    }
    let value = source
        .extensions
        .get("registered_verifier")
        .ok_or_else(invalid)?;
    crate::reject_private_custody_metadata(value)?;
    let registration: RegisteredVerifier =
        serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if !text(&registration.client_id)
        || registration.client_id.contains(':')
        || !text(&registration.request_key_id)
        || registration.valid_until <= registration.valid_from
        || registration.valid_from.timestamp_subsec_nanos() != 0
        || registration.valid_until.timestamp_subsec_nanos() != 0
        || registration.response_uris.is_empty()
        || registration.response_uris.len() > 8
        || serde_json::to_vec(&registration.public_jwk)
            .map_err(|_| invalid())?
            .len()
            > 2048
    {
        return Err(invalid());
    }
    let jwk = registration.public_jwk.as_object().ok_or_else(invalid)?;
    if jwk.keys().any(|key| {
        !["kty", "crv", "x", "y", "kid", "alg", "use", "key_ops"].contains(&key.as_str())
    }) || jwk
        .get("kid")
        .is_some_and(|kid| kid.as_str() != Some(registration.request_key_id.as_str()))
        || marty_oid4vp_contract::trust_authority::issuer_public_key_algorithm(
            &registration.public_jwk,
        )
        .map_err(|_| invalid())?
            != "ES256"
    {
        return Err(invalid());
    }
    let mut recipients = BTreeSet::new();
    for uri in &registration.response_uris {
        let url = url::Url::parse(uri).map_err(|_| invalid())?;
        if !text(uri)
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !recipients.insert(uri)
        {
            return Err(invalid());
        }
    }
    Ok(registration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile() -> TrustProfile {
        let now = DateTime::parse_from_rfc3339("2026-11-16T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut source = source();
        source.enabled = true;
        TrustProfile {
            id: uuid::Uuid::from_u128(2),
            organization_id: "org-a".into(),
            name: "Verifiers".into(),
            description: None,
            status: TrustProfileStatus::Active,
            profile_type: crate::TrustProfileType::Custom,
            compliance_status: ComplianceStatus::Compliant,
            trust_purposes: Some(vec![TrustPurpose::PresentationVerifier]),
            trust_sources: vec![source],
            validation_rules: crate::ValidationRules::default(),
            allowed_issuers: None,
            denied_issuers: None,
            system_issuer_overrides: Default::default(),
            compatible_compliance_codes: vec![],
            verification_policy_set_id: None,
            auto_generated: false,
            revocation_policy: Default::default(),
            revocation_profile_id: None,
            time_policy: Default::default(),
            supported_formats: vec![],
            trusted_assertion_formats: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn projection_binds_current_owner_registration_and_separates_snapshot_from_key_validity() {
        let mut profile = profile();
        let now = profile.updated_at;
        let first =
            project_wallet_verifier_authority(&profile, "org-a", "registered-client", now).unwrap();
        assert_eq!(first.contract, WALLET_VERIFIER_AUTHORITY_CONTRACT);
        assert_eq!(first.expires_at, now + chrono::Duration::seconds(60));
        assert!(first.authority.registration.valid_until > first.expires_at);
        let second = project_wallet_verifier_authority(
            &profile,
            "org-a",
            "registered-client",
            now + chrono::Duration::seconds(1),
        )
        .unwrap();
        assert_eq!(first.authority.revision, second.authority.revision);
        profile.updated_at += chrono::Duration::seconds(2);
        let changed = project_wallet_verifier_authority(
            &profile,
            "org-a",
            "registered-client",
            now + chrono::Duration::seconds(2),
        )
        .unwrap();
        assert_ne!(first.authority.revision, changed.authority.revision);
        let value = serde_json::to_value(changed).unwrap();
        assert_eq!(value["authority"]["key_purpose"], "oid4vp_request_signing");
        assert!(value.get("issuer_relationships").is_none());
    }

    #[test]
    fn projection_refuses_cross_tenant_inactive_implicit_or_expired_authority() {
        let profile = profile();
        let now = profile.updated_at;
        assert!(
            project_wallet_verifier_authority(&profile, "org-b", "registered-client", now).is_err()
        );
        assert!(
            project_wallet_verifier_authority(&profile, "org-a", "unknown-client", now).is_err()
        );
        assert!(project_wallet_verifier_authority(
            &profile,
            "org-a",
            "registered-client",
            now + chrono::Duration::days(30)
        )
        .is_err());
        for change in 0..5 {
            let mut profile = profile.clone();
            match change {
                0 => profile.status = TrustProfileStatus::Suspended,
                1 => profile.compliance_status = ComplianceStatus::SetupRequired,
                2 => profile.trust_purposes = None,
                3 => profile.trust_sources[0].enabled = false,
                _ => profile.trust_sources.push(profile.trust_sources[0].clone()),
            }
            assert!(
                project_wallet_verifier_authority(&profile, "org-a", "registered-client", now)
                    .is_err()
            );
        }
    }

    #[test]
    fn verifier_authority_enforces_applicable_profile_controls_without_policy_fallback() {
        let baseline = profile();
        let now = baseline.updated_at;
        let first = project_wallet_verifier_authority(&baseline, "org-a", "registered-client", now)
            .unwrap();
        for case in 0..8 {
            let mut profile = baseline.clone();
            match case {
                0 => profile.validation_rules.min_key_size_ec = 384,
                1 => {
                    profile.trusted_assertion_formats =
                        Some(vec![crate::TrustedAssertionFormat::X509Certificate])
                }
                2 => profile.validation_rules.allowed_algorithms = vec!["ES384".into()],
                3 => profile.time_policy.max_clock_skew_seconds = 0,
                4 => {
                    profile
                        .validation_rules
                        .extensions
                        .insert("unknown_policy".into(), json!(true));
                }
                5 => profile.verification_policy_set_id = Some("unsupported-policy".into()),
                6 => profile.revocation_profile_id = Some("unsupported-revocation".into()),
                _ => profile.profile_type = crate::TrustProfileType::Eudi,
            }
            assert!(
                project_wallet_verifier_authority(&profile, "org-a", "registered-client", now)
                    .is_err(),
                "ignored policy {case}"
            );
        }
        let mut restricted = baseline.clone();
        restricted.trusted_assertion_formats = Some(vec![crate::TrustedAssertionFormat::Jwt]);
        restricted.time_policy.max_clock_skew_seconds = 30;
        let second =
            project_wallet_verifier_authority(&restricted, "org-a", "registered-client", now)
                .unwrap();
        assert_ne!(first.authority.revision, second.authority.revision);
        assert_eq!(second.authority.request_clock_skew_seconds, 30);
        assert_eq!(second.authority.max_request_lifetime_seconds, 900);
    }

    fn source() -> TrustSource {
        serde_json::from_str(include_str!(
            "../tests/fixtures/registered-verifier-source.json"
        ))
        .unwrap()
    }

    #[test]
    fn distinct_registration_is_public_only_and_not_machine_identity() {
        let source = source();
        assert!(!TrustPurpose::PresentationVerifier.is_machine_identity());
        assert_eq!(
            registration(&source).unwrap().client_id,
            "registered-client"
        );
        assert!(!source.enabled, "validation must not activate the source");
    }

    #[test]
    fn issuer_or_machine_purpose_and_unrelated_source_selectors_are_refused() {
        for purpose in [
            TrustPurpose::CredentialIssuer,
            TrustPurpose::AttestationVerifier,
        ] {
            let mut source = source();
            source.purposes = Some(vec![purpose]);
            assert!(registration(&source).is_err());
        }
        let mut wrong = source();
        wrong.source_type = TrustSourceType::PinnedIssuer;
        assert!(registration(&wrong).is_err());
        for field in [
            "url",
            "certificate_pem",
            "issuer_did",
            "registry_sync_token",
        ] {
            let mut value = serde_json::to_value(source()).unwrap();
            value[field] = json!("unexpected");
            assert!(registration(&serde_json::from_value(value).unwrap()).is_err());
        }
    }

    #[test]
    fn registration_refuses_unsupported_keys_recipients_and_semantics() {
        for (field, value) in [
            (
                "client_id",
                json!("decentralized_identifier:did:example:verifier"),
            ),
            (
                "response_uris",
                json!(["https://verifier.example/response#fragment"]),
            ),
            ("response_uris", json!(["http://verifier.example/response"])),
            (
                "response_uris",
                json!([
                    "https://verifier.example/response",
                    "https://verifier.example/response"
                ]),
            ),
            ("client_metadata", json!({})),
            ("valid_until", json!("2026-10-01T00:00:00Z")),
        ] {
            let mut source = source();
            source.extensions.get_mut("registered_verifier").unwrap()[field] = value;
            assert!(registration(&source).is_err(), "accepted {field}");
        }
        for (field, value) in [
            ("d", json!("private")),
            ("kid", json!("wrong-key")),
            ("key_ops", json!(["sign"])),
            ("x", json!("invalid")),
            ("jku", json!("https://attacker.example/keys")),
        ] {
            let mut source = source();
            source.extensions.get_mut("registered_verifier").unwrap()["public_jwk"][field] = value;
            assert!(registration(&source).is_err(), "accepted JWK {field}");
        }
    }
}
