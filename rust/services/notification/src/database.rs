//! Bounded primary database pool settings shared by the runtime and its tests.

use std::io;

/// Keep the existing pool default unless an explicit, bounded ceiling is supplied.
/// The external PostgreSQL installer profile selects two for runtime and one for
/// the sequential notification migration job.
pub fn database_max_connections(value: Option<&str>) -> Result<u32, io::Error> {
    let invalid =
        || io::Error::other("NOTIFICATION_DATABASE_MAX_CONNECTIONS must be between 1 and 128");
    let maximum = value
        .map_or(Ok(30), |value| value.parse::<u32>())
        .map_err(|_| invalid())?;
    if !(1..=128).contains(&maximum) {
        return Err(invalid());
    }
    Ok(maximum)
}

#[cfg(test)]
mod tests {
    use super::database_max_connections;

    #[test]
    fn keeps_default_and_accepts_a_small_external_database_pool() {
        assert_eq!(database_max_connections(None).unwrap(), 30);
        assert_eq!(database_max_connections(Some("1")).unwrap(), 1);
        assert_eq!(database_max_connections(Some("2")).unwrap(), 2);
        assert_eq!(database_max_connections(Some("128")).unwrap(), 128);
    }

    #[test]
    fn rejects_invalid_pool_limits_without_echoing_input() {
        for value in ["", "0", "129", "-1", "private-invalid-value"] {
            assert_eq!(
                database_max_connections(Some(value))
                    .unwrap_err()
                    .to_string(),
                "NOTIFICATION_DATABASE_MAX_CONNECTIONS must be between 1 and 128"
            );
        }
    }
}
