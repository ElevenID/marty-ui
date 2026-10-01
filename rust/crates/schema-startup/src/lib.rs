//! Shared schema startup policy for Rust services with an external migration gate.

use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaStartupMode {
    Migrate,
    Validate,
}

impl SchemaStartupMode {
    pub fn from_env() -> io::Result<Self> {
        match std::env::var("MARTY_SCHEMA_STARTUP_MODE") {
            Ok(value) => Self::parse(Some(&value)),
            Err(std::env::VarError::NotPresent) => Ok(Self::Migrate),
            Err(std::env::VarError::NotUnicode(_)) => Err(invalid_mode()),
        }
    }

    pub fn parse(value: Option<&str>) -> io::Result<Self> {
        match value {
            None | Some("migrate") => Ok(Self::Migrate),
            Some("validate") => Ok(Self::Validate),
            _ => Err(invalid_mode()),
        }
    }
}

fn invalid_mode() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "MARTY_SCHEMA_STARTUP_MODE must be migrate or validate",
    )
}

#[cfg(test)]
mod tests {
    use super::SchemaStartupMode;

    #[test]
    fn default_is_migration_and_only_explicit_validate_skips_ddl() {
        assert_eq!(
            SchemaStartupMode::parse(None).unwrap(),
            SchemaStartupMode::Migrate
        );
        assert_eq!(
            SchemaStartupMode::parse(Some("migrate")).unwrap(),
            SchemaStartupMode::Migrate
        );
        assert_eq!(
            SchemaStartupMode::parse(Some("validate")).unwrap(),
            SchemaStartupMode::Validate
        );
        for invalid in ["", "VALIDATE", "migrate-only", "other"] {
            assert!(SchemaStartupMode::parse(Some(invalid)).is_err());
        }
    }
}
