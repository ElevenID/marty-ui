use sqlx::{PgPool, Row};

const REQUIRED_COLUMNS: &[(&str, &str)] = &[
    ("issuance_transactions", "access_token_expires_at"),
    ("authorization_sessions", "access_token_expires_at"),
];

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('issuance_oid4vci_public_v1', 0))")
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0001_oid4vci_public_protocol.sql"
    ))
    .execute(&mut *transaction)
    .await?;

    let rows = sqlx::query(
        "SELECT table_name, column_name, udt_name
         FROM information_schema.columns
         WHERE table_schema = 'issuance_service'
           AND column_name = 'access_token_expires_at'",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for &(table, column) in REQUIRED_COLUMNS {
        if !rows.iter().any(|row| {
            matches!(row.try_get::<String, _>("table_name"), Ok(value) if value == table)
                && matches!(row.try_get::<String, _>("column_name"), Ok(value) if value == column)
                && matches!(row.try_get::<String, _>("udt_name"), Ok(value) if value == "timestamptz")
        }) {
            return Err(sqlx::Error::Protocol(format!(
                "OID4VCI migration did not create compatible timestamptz {table}.{column}"
            )));
        }
    }

    let binding_index = sqlx::query(
        "SELECT index.indisunique, index.indisvalid, index.indisready,
                index.indnkeyatts,
                pg_get_indexdef(index.indexrelid, 1, false) AS indexed_expression,
                pg_get_expr(index.indpred, index.indrelid) AS predicate
         FROM pg_index AS index
         JOIN pg_class AS relation ON relation.oid = index.indexrelid
         JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'issuance_service'
           AND relation.relname = 'ux_issuance_events_oid4vci_notification_id'
           AND index.indrelid = 'issuance_service.issuance_events'::regclass",
    )
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(binding_index) = binding_index else {
        return Err(sqlx::Error::Protocol(
            "OID4VCI notification binding index is missing".into(),
        ));
    };
    let expression = binding_index.try_get::<String, _>("indexed_expression")?;
    let predicate = binding_index
        .try_get::<Option<String>, _>("predicate")?
        .unwrap_or_default();
    if !binding_index.try_get::<bool, _>("indisunique")?
        || !binding_index.try_get::<bool, _>("indisvalid")?
        || !binding_index.try_get::<bool, _>("indisready")?
        || binding_index.try_get::<i16, _>("indnkeyatts")? != 1
        || normalize_catalog_expression(&expression) != "metadata->>'notification_id'"
        || normalize_catalog_expression(&predicate) != "event_type='oid4vci_notification_binding'"
    {
        return Err(sqlx::Error::Protocol(
            "OID4VCI notification binding index is incompatible".into(),
        ));
    }
    transaction.commit().await
}

fn normalize_catalog_expression(value: &str) -> String {
    value
        .replace("::text", "")
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && !matches!(character, '(' | ')'))
        .collect()
}
