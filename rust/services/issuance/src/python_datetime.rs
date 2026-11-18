use chrono::{DateTime, SecondsFormat, Utc};

/// Match Python `datetime.isoformat()` for UTC values sourced from PostgreSQL.
///
/// Python emits no fractional component for whole seconds and exactly six
/// digits whenever microseconds are present. Chrono's `AutoSi` shortens exact
/// milliseconds to three digits, which changes public response bodies.
pub(crate) fn isoformat(value: DateTime<Utc>) -> String {
    let precision = if value.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    value.to_rfc3339_opts(precision, false)
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use super::isoformat;

    #[test]
    fn preserves_python_whole_second_and_microsecond_shapes() {
        for (input, expected) in [
            ("2026-08-20T12:34:56+00:00", "2026-08-20T12:34:56+00:00"),
            (
                "2026-08-20T12:34:56.120000+00:00",
                "2026-08-20T12:34:56.120000+00:00",
            ),
            (
                "2026-08-20T12:34:56.000001+00:00",
                "2026-08-20T12:34:56.000001+00:00",
            ),
        ] {
            let value = DateTime::parse_from_rfc3339(input)
                .expect("timestamp")
                .to_utc();
            assert_eq!(isoformat(value), expected);
        }
    }
}
