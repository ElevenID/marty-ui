use sqlx::{postgres::PgConnectOptions, Connection, PgConnection};

// Separate from the production migration's transaction lock: these tests reset
// the same schemas from different integration-test binaries.
const TEST_SCHEMA_LOCK_ID: i64 = 718_431_212;

pub async fn lock_shared_test_schemas(
    options: &PgConnectOptions,
) -> Result<PgConnection, sqlx::Error> {
    let mut connection = PgConnection::connect_with(options).await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(TEST_SCHEMA_LOCK_ID)
        .execute(&mut connection)
        .await?;
    // The dedicated connection is held for the complete test and releases the
    // session lock when dropped, including on a panic.
    Ok(connection)
}
