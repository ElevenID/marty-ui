//! Bounded schema-only commands. Never connect providers/Redis or start a server.
use sqlx::{postgres::PgPoolOptions, ConnectOptions};
use std::{error::Error, io, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaCommand {
    Migrate,
    Verify,
}

pub fn parse(mut arguments: impl Iterator<Item = String>) -> io::Result<Option<SchemaCommand>> {
    match (arguments.next().as_deref(), arguments.next()) {
        (None, None) => Ok(None),
        (Some("migrate"), None) => Ok(Some(SchemaCommand::Migrate)),
        (Some("verify-owned-schema"), None) => Ok(Some(SchemaCommand::Verify)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Flow accepts only migrate or verify-owned-schema subcommands",
        )),
    }
}

pub async fn run(command: SchemaCommand) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(120), execute(command))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Flow schema command deadline exceeded; reconcile database outcome before retry",
            )
        })?
}

async fn execute(command: SchemaCommand) -> Result<(), Box<dyn Error>> {
    // Same private DATABASE_URL transport as the existing issuer schema CLI.
    // No full Flow configuration or other dependency credentials are loaded.
    let options = std::env::var("DATABASE_URL")?
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .disable_statement_logging();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(options)
        .await?;
    let result = match command {
        SchemaCommand::Migrate => marty_flow::migrate_flow_schema(&pool).await,
        SchemaCommand::Verify => marty_flow::validate_flow_schema(&pool).await,
    };
    pool.close().await;
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse, SchemaCommand};

    #[test]
    fn only_exact_schema_commands_exit_before_service_startup() {
        for (arguments, expected) in [
            (vec![], None),
            (vec!["migrate"], Some(SchemaCommand::Migrate)),
            (vec!["verify-owned-schema"], Some(SchemaCommand::Verify)),
        ] {
            assert_eq!(
                parse(arguments.into_iter().map(str::to_owned)).unwrap(),
                expected
            );
        }
        for arguments in [vec!["unknown"], vec!["migrate", "extra"], vec![""]] {
            assert!(parse(arguments.into_iter().map(str::to_owned)).is_err());
        }
    }
}
