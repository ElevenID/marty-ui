//! Trust Profile request field metadata. This does not grant authorization,
//! define value validation, or turn request admission into response filtering.

macro_rules! profile_fields {
    ($($field:literal),* $(,)?) => {
        pub const UPDATE_FIELDS: &[&str] = &[$($field),*];
        pub const CREATE_FIELDS: &[&str] = &["organization_id", $($field),*];
    };
}

profile_fields![
    "name",
    "description",
    "profile_type",
    "compliance_status",
    "trust_purposes",
    "trust_sources",
    "validation_rules",
    "allowed_algorithms",
    "min_key_size_rsa",
    "min_key_size_ec",
    "require_key_usage",
    "max_chain_depth",
    "allow_self_signed",
    "revocation_policy",
    "revocation_profile_id",
    "time_policy",
    "supported_formats",
    "trusted_assertion_formats",
    "allowed_issuers",
    "denied_issuers",
    "system_issuer_overrides",
    "compatible_compliance_codes",
    "verification_policy_set_id",
    "auto_generated",
];

// Admission metadata only; organization scope, patch values and authority stay at callers.
pub const ISSUER_UPDATE_FIELDS: &[&str] = &[
    "organization_id",
    "display_name",
    "description",
    "issuer_type",
    "compliance_status",
    "accreditation_body",
    "accreditations",
    "accreditation_date",
    "valid_from",
    "valid_until",
    "trust_anchor_id",
    "metadata",
    "revocation_reason",
];

pub const RELATIONSHIP_UPDATE_FIELDS: &[&str] = &[
    "trust_level",
    "relationship_status",
    "cascade_revocation_policy",
    "metadata",
];
