//! Admission metadata for the public organization resource defaults subresource.
//! Resource access, ownership and lifecycle checks belong to service adapters.

pub const FIELDS: &[&str] = &[
    "default_trust_profile_id",
    "default_policy_id",
    "default_template_id",
];

pub const MAX_REFERENCE_ID_LENGTH: usize = 255;

/// Defaults contain opaque resource identifiers, never paths or URLs.
#[must_use]
pub fn valid_reference_id(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value.chars().count() <= MAX_REFERENCE_ID_LENGTH
        && !value.chars().any(|character| {
            character.is_whitespace() || character.is_control() || "/\\?#%".contains(character)
        })
}

#[cfg(test)]
mod tests {
    use super::valid_reference_id;

    #[test]
    fn resource_identifiers_cannot_change_the_dependency_path() {
        assert!(valid_reference_id("11111111-1111-4111-8111-111111111111"));
        assert!(valid_reference_id("existing-template_1"));
        for invalid in [
            "",
            ".",
            "..",
            " ",
            " id",
            "id\n",
            "../id",
            "id?org=other",
            "id#fragment",
            "id%2fother",
            "id\\other",
        ] {
            assert!(!valid_reference_id(invalid), "{invalid:?}");
        }
        assert!(!valid_reference_id(&"a".repeat(256)));
    }
}
