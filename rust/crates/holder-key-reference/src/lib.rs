//! Canonical scoped names for remotely held signing keys.

use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MAX_REFERENCE_BYTES: usize = 128;

fn namespace(purpose: &str) -> Option<&'static str> {
    match purpose {
        "holder_binding" => Some("cred-holder"),
        "presentation_signing" => Some("cred-presenter"),
        _ => None,
    }
}

fn prefix(organization_id: &str, registration_id: &str, purpose: &str) -> Option<String> {
    if organization_id.is_empty()
        || organization_id.len() > 36
        || registration_id.is_empty()
        || registration_id.len() > 36
    {
        return None;
    }
    let namespace = namespace(purpose)?;
    let org = Sha256::digest(organization_id.as_bytes());
    let registration = Sha256::digest(registration_id.as_bytes());
    Some(format!(
        "{namespace}-{}-{}-",
        hex::encode(&org[..16]),
        hex::encode(&registration[..16])
    ))
}

pub fn new_reference(
    organization_id: &str,
    registration_id: &str,
    purpose: &str,
) -> Option<String> {
    let prefix = prefix(organization_id, registration_id, purpose)?;
    let reference = format!("{prefix}{}", Uuid::new_v4().simple());
    (reference.len() <= MAX_REFERENCE_BYTES).then_some(reference)
}

pub fn belongs_to(
    reference: &str,
    organization_id: &str,
    registration_id: &str,
    purpose: &str,
) -> bool {
    if reference.len() > MAX_REFERENCE_BYTES {
        return false;
    }
    prefix(organization_id, registration_id, purpose).is_some_and(|prefix| {
        reference.strip_prefix(&prefix).is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_reference_binds_purpose_tenant_and_registration() {
        for purpose in ["holder_binding", "presentation_signing"] {
            let reference = new_reference("org-a", "registration-a", purpose).unwrap();
            assert!(belongs_to(&reference, "org-a", "registration-a", purpose));
            assert!(!belongs_to(&reference, "org-b", "registration-a", purpose));
            assert!(!belongs_to(&reference, "org-a", "registration-b", purpose));
            assert!(!belongs_to(
                &reference,
                "org-a",
                "registration-a",
                if purpose == "holder_binding" {
                    "presentation_signing"
                } else {
                    "holder_binding"
                }
            ));
            assert!(reference.len() <= MAX_REFERENCE_BYTES);
            assert!(!belongs_to(
                &reference.to_ascii_uppercase(),
                "org-a",
                "registration-a",
                purpose
            ));
        }
        assert!(new_reference("org-a", "registration-a", "issuer").is_none());
    }
}
