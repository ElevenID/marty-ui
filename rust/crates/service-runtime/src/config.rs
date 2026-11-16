//! Parsing mechanics only; callers own names, defaults, ranges and public errors.
use std::{ops::RangeInclusive, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidValue;

/// Reject blank values while retaining the original bytes.
pub fn nonblank(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

pub fn trimmed_nonempty(value: Option<&str>) -> Option<&str> {
    nonblank(value).map(str::trim)
}

/// Apply the existing bootstrap slug grammar; the caller owns its fallback.
pub fn canonical_slug(value: &str, fallback: &str) -> String {
    let normalized: String = value
        .trim()
        .to_lowercase()
        .chars()
        .filter(|ch| ch.is_alphanumeric() || "._-".contains(*ch))
        .collect();
    if normalized.is_empty() {
        fallback.to_owned()
    } else {
        normalized
    }
}

/// Preserve the signing bootstrap's authority grammar and candidate precedence.
/// Callers supply their own fallback; this does not select an issuer identity.
pub fn configured_authority(explicit: Option<&str>, candidates: &[&str], fallback: &str) -> String {
    if let Some(configured) = trimmed_nonempty(explicit) {
        return configured
            .split_once("://")
            .map(|(_, tail)| tail.split('/').next().unwrap_or(tail))
            .unwrap_or(configured)
            .trim_matches('/')
            .into();
    }
    for candidate in candidates
        .iter()
        .filter_map(|value| trimmed_nonempty(Some(value)))
    {
        let with_scheme = if candidate.contains("://") {
            candidate.to_owned()
        } else {
            format!("https://{candidate}")
        };
        if let Ok(parsed) = url::Url::parse(&with_scheme) {
            if let Some(host) = parsed.host_str() {
                return parsed
                    .port()
                    .map(|port| format!("{host}:{port}"))
                    .unwrap_or_else(|| host.to_owned());
            }
        }
    }
    fallback.to_owned()
}

/// Construct a configured DID without selecting an issuer or changing a key.
/// Authority, path segments, fallback policy and validation belong to callers.
pub fn configured_did_web(explicit: Option<&str>, authority: &str, segments: &[&str]) -> String {
    if let Some(did) = trimmed_nonempty(explicit) {
        return did.to_owned();
    }
    format!(
        "did:web:{}:{}",
        authority.replace(':', "%3A").replace('/', ":"),
        segments.join(":")
    )
}

pub fn optional_number<T: FromStr>(value: Option<&str>) -> Result<Option<T>, InvalidValue> {
    value
        .map(|value| value.parse().map_err(|_| InvalidValue))
        .transpose()
}

pub fn number_or<T: FromStr>(value: Option<&str>, default: T) -> Result<T, InvalidValue> {
    optional_number(value).map(|value| value.unwrap_or(default))
}

pub fn bounded_number<T: FromStr + PartialOrd>(
    value: &str,
    range: RangeInclusive<T>,
) -> Result<T, InvalidValue> {
    let value = value.parse().map_err(|_| InvalidValue)?;
    range.contains(&value).then_some(value).ok_or(InvalidValue)
}

#[derive(Clone, Copy, Debug)]
pub enum BooleanVocabulary {
    AsciiInsensitive,
    AsciiInsensitiveWithOnOff,
    ExactWithOnOff,
}

/// Whitespace handling is deliberately left to the caller.
pub fn boolean(value: &str, vocabulary: BooleanVocabulary) -> Result<bool, InvalidValue> {
    let insensitive = !matches!(vocabulary, BooleanVocabulary::ExactWithOnOff);
    let matches =
        |expected| value == expected || (insensitive && value.eq_ignore_ascii_case(expected));
    if ["true", "1", "yes"].into_iter().any(matches) {
        return Ok(true);
    }
    if ["false", "0", "no"].into_iter().any(matches) {
        return Ok(false);
    }
    if !matches!(vocabulary, BooleanVocabulary::AsciiInsensitive) {
        if matches("on") {
            return Ok(true);
        }
        if matches("off") {
            return Ok(false);
        }
    }
    Err(InvalidValue)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn whitespace_defaults_overflow_and_inclusive_bounds_are_explicit() {
        assert_eq!(nonblank(Some(" 12 ")), Some(" 12 "));
        assert_eq!(trimmed_nonempty(Some(" 12 ")), Some("12"));
        assert_eq!(trimmed_nonempty(Some(" \t")), None);
        assert_eq!(number_or::<u8>(None, 9), Ok(9));
        for raw in ["256", "-1", " 1 ", ""] {
            assert!(number_or::<u8>(Some(raw), 9).is_err());
        }
        for raw in ["1", "5"] {
            assert!(bounded_number::<u8>(raw, 1..=5).is_ok());
        }
        for raw in ["0", "6"] {
            assert!(bounded_number::<u8>(raw, 1..=5).is_err());
        }
    }
    #[test]
    fn configured_authority_preserves_bootstrap_precedence_and_caller_fallbacks() {
        for (explicit, candidates, fallback, expected) in [
            (
                Some(" beta.example "),
                vec!["https://ignored.example"],
                "fallback",
                "beta.example",
            ),
            (
                Some("https://beta.example/path"),
                vec![],
                "fallback",
                "beta.example",
            ),
            (
                Some("https://localhost:29876/path"),
                vec![],
                "fallback",
                "localhost:29876",
            ),
            (
                Some("localhost:29876"),
                vec![],
                "fallback",
                "localhost:29876",
            ),
            (
                None,
                vec!["https://first.example/path", "https://second.example"],
                "fallback",
                "first.example",
            ),
            (
                Some(" "),
                vec!["", "https://second.example:29876/path"],
                "fallback",
                "second.example:29876",
            ),
            (None, vec![], "localhost", "localhost"),
            (None, vec![], "beta.elevenidllc.com", "beta.elevenidllc.com"),
        ] {
            assert_eq!(
                configured_authority(explicit, &candidates, fallback),
                expected
            );
        }
    }

    #[test]
    fn configured_did_preserves_explicit_identity_and_shared_slug_port_rules() {
        let slug = canonical_slug(" Marty-Identity-Platform ", "marty");
        assert_eq!(slug, "marty-identity-platform");
        assert_eq!(canonical_slug("$$", "marty"), "marty");
        assert_eq!(
            configured_did_web(None, "localhost:29876", &["orgs", &slug]),
            "did:web:localhost%3A29876:orgs:marty-identity-platform"
        );
        assert_eq!(
            configured_did_web(
                Some(" did:web:owned.example:orgs:legacy "),
                "new.example",
                &["orgs", &slug]
            ),
            "did:web:owned.example:orgs:legacy"
        );
    }
    #[test]
    fn boolean_vocabularies_do_not_expand_each_other() {
        use BooleanVocabulary::*;
        assert_eq!(boolean("YES", AsciiInsensitive), Ok(true));
        assert!(boolean("on", AsciiInsensitive).is_err());
        assert_eq!(boolean("OFF", AsciiInsensitiveWithOnOff), Ok(false));
        assert!(boolean("OFF", ExactWithOnOff).is_err());
        assert_eq!(boolean("off", ExactWithOnOff), Ok(false));
        assert!(boolean(" true ", AsciiInsensitive).is_err());
    }
}
