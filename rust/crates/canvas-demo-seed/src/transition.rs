//! Read-only Canvas demo transition evidence from the issuance database.

use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};

pub fn transition_summary(
    application: Value,
    latest_fact: Option<Value>,
    issued_credential: Option<Value>,
    delivery_records: Vec<Value>,
    canvas_mirror_delivery_records: i64,
) -> Value {
    json!({
        "application": application,
        "latest_fact": latest_fact,
        "issued_credential": issued_credential,
        "delivery_records": delivery_records,
        "canvas_mirror_delivery_records": canvas_mirror_delivery_records,
    })
}

pub async fn lookup_transition(
    database_url: &str,
    application_id: &str,
) -> Result<Option<Value>, String> {
    let mut connection = PgConnection::connect(database_url)
        .await
        .map_err(|error| error.to_string())?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    let application: Option<Value> = sqlx::query_scalar(
        r#"SELECT to_jsonb(x) FROM (
            SELECT a.id AS application_id, a.status AS application_status,
                   a.issuance_transaction_id, t.credential_type,
                   t.credential_template_id, t.status AS transaction_status,
                   t.issuer_profile_id, t.issuer_mode, t.issuer_did_override,
                   t.signing_service_id, t.delivery_mode,
                   t.credential_payload_format,
                   t.pre_auth_code IS NOT NULL AS has_pre_auth_code
            FROM issuance_service.applications a
            LEFT JOIN issuance_service.issuance_transactions t
              ON t.id = a.issuance_transaction_id
            WHERE a.id = $1
        ) x"#,
    )
    .bind(application_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| error.to_string())?;
    let Some(application) = application else {
        transaction
            .commit()
            .await
            .map_err(|error| error.to_string())?;
        return Ok(None);
    };
    let latest_fact: Option<Value> = sqlx::query_scalar(
        r#"SELECT to_jsonb(x) FROM (
            SELECT provider, fact_type, scope, assertion, verification, created_at
            FROM issuance_service.evidence_facts
            WHERE application_id = $1 ORDER BY created_at DESC LIMIT 1
        ) x"#,
    )
    .bind(application_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| error.to_string())?;
    let transaction_id = application["issuance_transaction_id"].as_str();
    let (issued_credential, delivery_records, canvas_mirror_delivery_records) =
        if let Some(transaction_id) = transaction_id.filter(|value| !value.is_empty()) {
            let issued: Option<Value> = sqlx::query_scalar(
                r#"SELECT to_jsonb(x) FROM (
                    SELECT id, subject_did, issuer_did, revocation_profile_id,
                           status_list_entries, status, issued_at, expires_at
                    FROM issuance_service.issued_credentials
                    WHERE transaction_id = $1 ORDER BY issued_at DESC LIMIT 1
                ) x"#,
            )
            .bind(transaction_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?;
            let deliveries: Vec<Value> = sqlx::query_scalar(
                r#"SELECT to_jsonb(x) - 'created_at' FROM (
                    SELECT id, delivery_target, delivery_mode, status,
                           external_credential_id, external_issuer_id, last_error,
                           metadata, updated_at, created_at
                    FROM issuance_service.credential_delivery_records
                    WHERE transaction_id = $1 ORDER BY created_at ASC
                ) x"#,
            )
            .bind(transaction_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?;
            let count: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM issuance_service.credential_delivery_records
                   WHERE transaction_id = $1 AND delivery_target = 'canvas_credentials'"#,
            )
            .bind(transaction_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?;
            (issued, deliveries, count)
        } else {
            (None, Vec::new(), 0)
        };
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    Ok(Some(transition_summary(
        application,
        latest_fact,
        issued_credential,
        delivery_records,
        canvas_mirror_delivery_records,
    )))
}
