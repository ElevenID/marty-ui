//! Small build surface for the same product-owned official evidence policy.
//! The policy modules are compiled from their canonical release-evidence files.

#[path = "../../../rust/crates/release-evidence/src/json_evidence.rs"]
mod json_evidence;
#[path = "../../../rust/crates/release-evidence/src/official.rs"]
pub mod official;
#[path = "../../../rust/crates/release-evidence/src/official_automation.rs"]
pub mod official_automation;
#[path = "../../../rust/crates/release-evidence/src/official_review.rs"]
pub mod official_review;

fn is_source(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_github_login(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 39
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        && !value.contains("--")
}
