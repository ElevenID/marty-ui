//! Closed persisted contracts for explicitly selected JWT-VC issuance.
//! These values select preparation; they do not authenticate credentials or grant signing authority.

use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::{JwtVcProfileBinding, JwtVcProfileTiming, JwtVcSecuringProfile};
use serde::{Deserialize, Deserializer, Serialize};

/// Older issuers reject this discriminator before selecting a signing kernel.
/// The accompanying database constraints also reject unsupported old writers.
pub const DIRECT_PAYLOAD_FORMAT: &str = "VC_JWT_DIRECT_V1";
pub const DIRECT_WIRE_FORMAT: &str = "application/vc+jwt";
pub const DIRECT_CONFIGURATION_SUFFIX: &str = "#vc2-jose-2026-v1";
pub const MAX_SIGNATURE_LIFETIME_SECONDS: i64 = 366 * 86_400;
pub const MAX_CREDENTIAL_VALIDITY_SECONDS: i64 = 1095 * 86_400;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid explicit JWT-VC issuance profile")]
pub struct ProfileError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum TemplateContract {
    #[serde(rename = "marty.jwt-vc-template-profile/v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TemplatePolicyWire {
    contract: TemplateContract,
    securing_profile: JwtVcSecuringProfile,
    signature_lifetime_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "TemplatePolicyWire", into = "TemplatePolicyWire")]
pub struct JwtVcTemplatePolicy(TemplatePolicyWire);

impl TryFrom<TemplatePolicyWire> for JwtVcTemplatePolicy {
    type Error = ProfileError;

    fn try_from(value: TemplatePolicyWire) -> Result<Self, Self::Error> {
        if value.securing_profile != JwtVcSecuringProfile::W3cVc2Jose2026V1
            || !(1..=MAX_SIGNATURE_LIFETIME_SECONDS).contains(&value.signature_lifetime_seconds)
        {
            return Err(ProfileError);
        }
        Ok(Self(value))
    }
}

impl From<JwtVcTemplatePolicy> for TemplatePolicyWire {
    fn from(value: JwtVcTemplatePolicy) -> Self {
        value.0
    }
}

impl JwtVcTemplatePolicy {
    pub fn new(signature_lifetime_seconds: i64) -> Result<Self, ProfileError> {
        TemplatePolicyWire {
            contract: TemplateContract::V1,
            securing_profile: JwtVcSecuringProfile::W3cVc2Jose2026V1,
            signature_lifetime_seconds,
        }
        .try_into()
    }

    pub fn binding(&self) -> JwtVcProfileBinding {
        JwtVcProfileBinding::new(self.0.securing_profile)
    }

    pub fn configuration_id(&self, credential_type: &str) -> Result<String, ProfileError> {
        if matches!(
            credential_type.to_ascii_lowercase().as_str(),
            "dtc" | "com.icao.mrv" | "com.icao.dtc.1" | "com.icao.dtc.2"
        ) {
            return Err(ProfileError);
        }
        self.0
            .securing_profile
            .configuration_id(credential_type)
            .map_err(|_| ProfileError)
    }

    pub fn signature_lifetime_seconds(&self) -> i64 {
        self.0.signature_lifetime_seconds
    }

    pub fn profile_metadata(
        &self,
        credential_type: &str,
        mut metadata: serde_json::Value,
    ) -> Result<(String, serde_json::Value), ProfileError> {
        if metadata.get("format").and_then(serde_json::Value::as_str) != Some("jwt_vc_json")
            || !metadata
                .get("credential_definition")
                .is_some_and(serde_json::Value::is_object)
        {
            return Err(ProfileError);
        }
        let id = self.configuration_id(credential_type)?;
        if matches!(
            credential_type.to_ascii_lowercase().as_str(),
            "open_badge" | "open_badge_v3" | "openbadgecredential"
        ) {
            // Core's existing OB3 preparation canonicalizes these historical
            // type aliases. Discovery must describe the actual signed type.
            metadata["credential_definition"]["type"] =
                serde_json::json!(["VerifiableCredential", "OpenBadgeCredential"]);
        }
        metadata["format"] = serde_json::json!(DIRECT_WIRE_FORMAT);
        metadata["marty_securing_profile"] = serde_json::json!(self.0.securing_profile);
        marty_oid4vci::metadata::admit_profiled_jwt_vc_configuration(&id, &metadata)
            .map_err(|_| ProfileError)?;
        Ok((id, metadata))
    }
}

/// Omission preserves legacy behavior; an explicitly supplied null is invalid.
pub fn optional_policy<'de, D>(deserializer: D) -> Result<Option<JwtVcTemplatePolicy>, D::Error>
where
    D: Deserializer<'de>,
{
    JwtVcTemplatePolicy::deserialize(deserializer).map(Some)
}

pub fn parse_optional_policy_json(
    value: &str,
) -> Result<Option<JwtVcTemplatePolicy>, ProfileError> {
    if value.is_empty() {
        Ok(None)
    } else {
        serde_json::from_str(value)
            .map(Some)
            .map_err(|_| ProfileError)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum SelectionContract {
    #[serde(rename = "marty.jwt-vc-issuance-selection/v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SelectionWire {
    contract: SelectionContract,
    policy: JwtVcTemplatePolicy,
    credential_configuration_id: String,
    credential_format: String,
    credential_type: String,
    template_id: String,
    template_version: i32,
    credential_validity_seconds: i64,
    not_before_offset_seconds: i64,
}

/// Immutable selection retained before an offer is exposed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "SelectionWire", into = "SelectionWire")]
pub struct JwtVcIssuanceSelection(SelectionWire);

impl TryFrom<SelectionWire> for JwtVcIssuanceSelection {
    type Error = ProfileError;

    fn try_from(value: SelectionWire) -> Result<Self, Self::Error> {
        if value.credential_format != DIRECT_WIRE_FORMAT
            || value.credential_configuration_id
                != value.policy.configuration_id(&value.credential_type)?
            || value.template_id.is_empty()
            || value.template_id.len() > 255
            || value.template_id.chars().any(char::is_control)
            || value.template_version <= 0
            || !(1..=MAX_CREDENTIAL_VALIDITY_SECONDS).contains(&value.credential_validity_seconds)
            || value.not_before_offset_seconds < -MAX_CREDENTIAL_VALIDITY_SECONDS
            || value.not_before_offset_seconds > MAX_CREDENTIAL_VALIDITY_SECONDS
            || value.not_before_offset_seconds >= value.policy.signature_lifetime_seconds()
            || value.not_before_offset_seconds + value.credential_validity_seconds <= 0
        {
            return Err(ProfileError);
        }
        Ok(Self(value))
    }
}

impl From<JwtVcIssuanceSelection> for SelectionWire {
    fn from(value: JwtVcIssuanceSelection) -> Self {
        value.0
    }
}

impl JwtVcIssuanceSelection {
    pub fn new(
        policy: JwtVcTemplatePolicy,
        credential_type: &str,
        template_id: &str,
        template_version: i32,
        credential_validity_seconds: i64,
        not_before_offset_seconds: i64,
    ) -> Result<Self, ProfileError> {
        SelectionWire {
            contract: SelectionContract::V1,
            credential_configuration_id: policy.configuration_id(credential_type)?,
            policy,
            credential_format: DIRECT_WIRE_FORMAT.into(),
            credential_type: credential_type.into(),
            template_id: template_id.into(),
            template_version,
            credential_validity_seconds,
            not_before_offset_seconds,
        }
        .try_into()
    }

    pub fn configuration_id(&self) -> &str {
        &self.0.credential_configuration_id
    }
    pub fn credential_type(&self) -> &str {
        &self.0.credential_type
    }
    pub fn template_id(&self) -> &str {
        &self.0.template_id
    }
    pub fn binding(&self) -> JwtVcProfileBinding {
        self.0.policy.binding()
    }

    /// Called by the winning signing claim, never by offer creation or replay.
    pub fn timing_at(&self, signature_issued_at: i64) -> Result<JwtVcProfileTiming, ProfileError> {
        let issued = DateTime::<Utc>::from_timestamp(signature_issued_at, 0).ok_or(ProfileError)?;
        let signature_expires_at = signature_issued_at
            .checked_add(self.0.policy.signature_lifetime_seconds())
            .ok_or(ProfileError)?;
        let valid_from = issued
            .checked_add_signed(Duration::seconds(self.0.not_before_offset_seconds))
            .ok_or(ProfileError)?;
        let valid_until = valid_from
            .checked_add_signed(Duration::seconds(self.0.credential_validity_seconds))
            .ok_or(ProfileError)?;
        JwtVcProfileTiming::new(
            signature_issued_at,
            signature_expires_at,
            valid_from,
            Some(valid_until),
        )
        .map_err(|_| ProfileError)
    }

    pub fn validate_timing(&self, timing: JwtVcProfileTiming) -> Result<(), ProfileError> {
        if self.timing_at(timing.signature_issued_at())? != timing {
            return Err(ProfileError);
        }
        Ok(())
    }

    pub fn validate_target(
        &self,
        payload_format: &str,
        template_id: &str,
        credential_type: Option<&str>,
    ) -> Result<(), ProfileError> {
        if payload_format != DIRECT_PAYLOAD_FORMAT
            || template_id != self.template_id()
            || credential_type != Some(self.credential_type())
        {
            return Err(ProfileError);
        }
        Ok(())
    }
}

pub fn validate_selection(
    payload_format: &str,
    template_id: &str,
    credential_type: Option<&str>,
    selection: Option<&JwtVcIssuanceSelection>,
    timing: Option<JwtVcProfileTiming>,
) -> Result<(), ProfileError> {
    match selection {
        Some(selection) => {
            selection.validate_target(payload_format, template_id, credential_type)?;
            if let Some(timing) = timing {
                selection.validate_timing(timing)?;
            }
        }
        None if payload_format.eq_ignore_ascii_case(DIRECT_PAYLOAD_FORMAT) || timing.is_some() => {
            return Err(ProfileError)
        }
        None => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn selection() -> JwtVcIssuanceSelection {
        JwtVcIssuanceSelection::new(
            JwtVcTemplatePolicy::new(3600).unwrap(),
            "OpenBadgeCredential",
            "template-1",
            2,
            365 * 86_400,
            -30,
        )
        .unwrap()
    }

    #[test]
    fn explicit_policy_rejects_null_unknown_conflicting_and_unbounded_inputs() {
        let good = serde_json::to_value(JwtVcTemplatePolicy::new(3600).unwrap()).unwrap();
        assert!(serde_json::from_value::<JwtVcTemplatePolicy>(good.clone()).is_ok());
        for invalid in [
            ValueCase::Null,
            ValueCase::Profile,
            ValueCase::Extra,
            ValueCase::Lifetime,
        ] {
            let mut value = good.clone();
            match invalid {
                ValueCase::Null => value = serde_json::Value::Null,
                ValueCase::Profile => value["securing_profile"] = json!("marty_nested_vc2_jwt_v1"),
                ValueCase::Extra => value["credential_format"] = json!("jwt_vc_json"),
                ValueCase::Lifetime => value["signature_lifetime_seconds"] = json!(0),
            }
            assert!(serde_json::from_value::<JwtVcTemplatePolicy>(value).is_err());
        }
        assert_eq!(parse_optional_policy_json("").unwrap(), None);
        assert!(parse_optional_policy_json("null").is_err());
    }
    enum ValueCase {
        Null,
        Profile,
        Extra,
        Lifetime,
    }

    #[test]
    fn selection_and_timing_round_trip_without_coupling_intervals() {
        let selection = selection();
        let restored: JwtVcIssuanceSelection =
            serde_json::from_value(serde_json::to_value(&selection).unwrap()).unwrap();
        assert_eq!(restored, selection);
        let timing = restored.timing_at(1_800_000_000).unwrap();
        assert_eq!(timing.signature_expires_at(), 1_800_003_600);
        assert_eq!(timing.credential_valid_from().timestamp(), 1_799_999_970);
        assert_eq!(
            timing.credential_valid_until().unwrap().timestamp(),
            1_831_535_970
        );
        assert!(restored.validate_timing(timing).is_ok());
        let mut changed = serde_json::to_value(timing).unwrap();
        changed["signature_expires_at"] = json!(1_800_003_601);
        assert!(restored
            .validate_timing(serde_json::from_value(changed).unwrap())
            .is_err());
        let mut changed = serde_json::to_value(&selection).unwrap();
        changed["credential_configuration_id"] = json!("OpenBadgeCredential");
        assert!(serde_json::from_value::<JwtVcIssuanceSelection>(changed).is_err());
        assert!(validate_selection(
            "jwt_vc_json",
            "template-1",
            Some("OpenBadgeCredential"),
            Some(&selection),
            Some(timing)
        )
        .is_err());
        assert!(validate_selection(
            DIRECT_PAYLOAD_FORMAT,
            "template-1",
            Some("OpenBadgeCredential"),
            None,
            None
        )
        .is_err());
        assert!(validate_selection("w3c_vcdm_v2_jwt_vc", "legacy", None, None, None).is_ok());
    }
    #[test]
    fn independent_intervals_require_a_nonempty_overlap_without_coupling_boundaries() {
        let policy = JwtVcTemplatePolicy::new(3600).unwrap();
        for offset in [3600, 3601, -86400, -86401] {
            assert!(JwtVcIssuanceSelection::new(
                policy.clone(),
                "EmployeeBadge",
                "template",
                1,
                86400,
                offset
            )
            .is_err());
        }
        for offset in [3599, 0, -86399] {
            let selection = JwtVcIssuanceSelection::new(
                policy.clone(),
                "EmployeeBadge",
                "template",
                1,
                86400,
                offset,
            )
            .unwrap();
            let timing = selection.timing_at(1800000000).unwrap();
            assert_eq!(timing.signature_expires_at(), 1800003600);
            assert_eq!(
                timing.credential_valid_from().timestamp(),
                1800000000 + offset
            );
            assert_eq!(
                timing.credential_valid_until().unwrap().timestamp(),
                1800086400 + offset
            );
        }
    }

    #[test]
    fn marked_metadata_preserves_exact_config_and_the_signed_credential_type() {
        for (input_type, signed_type) in [
            ("EmployeeBadge", "EmployeeBadge"),
            ("open_badge", "OpenBadgeCredential"),
            ("open_badge_v3", "OpenBadgeCredential"),
            ("OpenBadgeCredential", "OpenBadgeCredential"),
            ("Openbadgecredential", "OpenBadgeCredential"),
            ("OPENBADGECREDENTIAL", "OpenBadgeCredential"),
        ] {
            let policy = JwtVcTemplatePolicy::new(3600).unwrap();
            let base = json!({"format":"jwt_vc_json", "credential_definition":{"type":["VerifiableCredential",input_type]},"display":[{"name":"Public synthetic credential"}]});
            let (id, metadata) = policy.profile_metadata(input_type, base).unwrap();
            assert_eq!(id, format!("{input_type}#vc2-jose-2026-v1"));
            assert_eq!(metadata["format"], DIRECT_WIRE_FORMAT);
            assert_eq!(metadata["marty_securing_profile"], "w3c_vc2_jose_2026_v1");
            assert_eq!(
                metadata["credential_definition"]["type"],
                json!(["VerifiableCredential", signed_type])
            );
            assert_eq!(
                metadata["display"][0]["name"],
                "Public synthetic credential"
            );
        }
    }

    #[test]
    fn explicit_profile_rejects_types_owned_by_retired_dtc_migrations() {
        let policy = JwtVcTemplatePolicy::new(3600).unwrap();
        for retired in ["dtc", "com.icao.mrv", "com.icao.dtc.1", "com.icao.dtc.2"] {
            assert!(policy.configuration_id(retired).is_err());
        }
    }
}
