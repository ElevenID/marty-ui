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
