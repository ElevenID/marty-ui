//! Shared wire identity and bounds for integration-secret envelopes.
//! Provider custody, envelope parsing and public errors stay at the adapters.

pub const SCHEMA: &str = "marty.integration-secret-envelope/v1";
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = 200 * 1024;

/// Check original UTF-8 byte lengths; trimming only detects blank identities.
pub fn valid_identity(
    organization_id: &str,
    secret_id: &str,
    provider: &str,
    purpose: &str,
) -> bool {
    [organization_id, secret_id, provider, purpose]
        .iter()
        .all(|part| !part.trim().is_empty())
        && organization_id.len() <= 256
        && secret_id.len() <= 256
        && provider.len() <= 80
        && purpose.len() <= 80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(parts: &[String; 4]) -> bool {
        valid_identity(&parts[0], &parts[1], &parts[2], &parts[3])
    }

    #[test]
    fn every_identity_part_has_an_inclusive_raw_byte_limit() {
        for (index, limit) in [256, 256, 80, 80].into_iter().enumerate() {
            let mut parts = ["org", "secret", "canvas", "oauth_client_secret"].map(str::to_owned);
            for blank in ["", " \t\n", "\u{2003}"] {
                parts[index] = blank.into();
                assert!(!valid(&parts), "blank field {index}");
            }
            parts[index] = "x".repeat(limit);
            assert!(valid(&parts), "field {index} at limit");
            parts[index].push('x');
            assert!(!valid(&parts), "field {index} above limit");
            parts[index] = "é".repeat(limit / 2);
            assert!(valid(&parts), "UTF-8 field {index} at byte limit");
            parts[index].push('é');
            assert!(!valid(&parts), "UTF-8 field {index} above byte limit");
        }
    }

    #[test]
    fn nonblank_padding_is_accepted_but_counts_toward_each_limit() {
        assert!(valid_identity(" org ", " secret ", " canvas ", " purpose "));
        for (index, limit) in [256, 256, 80, 80].into_iter().enumerate() {
            let mut parts = ["org", "secret", "canvas", "purpose"].map(str::to_owned);
            parts[index] = format!("{}x", " ".repeat(limit));
            assert!(!valid(&parts), "raw padding in field {index}");
        }
    }
}
