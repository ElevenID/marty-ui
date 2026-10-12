use crate::{application_template_payload, credential_template_payload, GatewaySeedConfig};
use serde_json::Value;
use sqlx::{Connection, PgConnection, Postgres, Transaction};

fn value(payload: &Value, key: &str) -> Result<String, String> {
    match payload.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(value) if !value.is_null() => serde_json::to_string(value).map_err(|e| e.to_string()),
        _ => Err(format!("Canvas demo template missing {key}")),
    }
}

async fn table_exists(tx: &mut Transaction<'_, Postgres>, table: &str) -> Result<bool, String> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| e.to_string())
}

async fn column_exists(
    tx: &mut Transaction<'_, Postgres>,
    schema: &str,
    table: &str,
    column: &str,
) -> Result<bool, String> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 AND column_name=$3)")
        .bind(schema)
        .bind(table)
        .bind(column)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| e.to_string())
}

async fn upsert_credential_template(
    tx: &mut Transaction<'_, Postgres>,
    payload: &Value,
    legacy_remote: bool,
) -> Result<(), String> {
    let legacy_columns = if legacy_remote {
        ",key_access_mode,issuer_key_id,issuer_algorithm,remote_signing_config"
    } else {
        ""
    };
    let legacy_values = if legacy_remote {
        ",$21,$22,$23,$24::jsonb"
    } else {
        ""
    };
    let legacy_updates = if legacy_remote {
        ",key_access_mode=EXCLUDED.key_access_mode,issuer_key_id=EXCLUDED.issuer_key_id,issuer_algorithm=EXCLUDED.issuer_algorithm,remote_signing_config=EXCLUDED.remote_signing_config"
    } else {
        ""
    };
    let sql = format!(
        "INSERT INTO credential_template_service.credential_templates (id,organization_id,name,description,status,credential_type,vct,doctype,claims,privacy_posture,selective_disclosure_fields,zk_predicate_claims,derived_attributes,display_style,validity_rules,issuer_requirements,supported_formats,credential_payload_format,wallet_configs,version{legacy_columns},created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14::jsonb,$15::jsonb,$16::jsonb,$17::jsonb,$18,$19::jsonb,$20::integer{legacy_values},NOW(),NOW()) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,status=EXCLUDED.status,credential_type=EXCLUDED.credential_type,vct=EXCLUDED.vct,doctype=EXCLUDED.doctype,claims=EXCLUDED.claims,privacy_posture=EXCLUDED.privacy_posture,selective_disclosure_fields=EXCLUDED.selective_disclosure_fields,zk_predicate_claims=EXCLUDED.zk_predicate_claims,derived_attributes=EXCLUDED.derived_attributes,display_style=EXCLUDED.display_style,validity_rules=EXCLUDED.validity_rules,issuer_requirements=EXCLUDED.issuer_requirements,supported_formats=EXCLUDED.supported_formats,credential_payload_format=EXCLUDED.credential_payload_format,wallet_configs=EXCLUDED.wallet_configs{legacy_updates},updated_at=NOW()"
    );
    let mut values = [
        "id",
        "organization_id",
        "name",
        "description",
        "status",
        "credential_type",
        "vct",
        "doctype",
        "claims",
        "privacy_posture",
        "selective_disclosure_fields",
        "zk_predicate_claims",
        "derived_attributes",
        "display_style",
        "validity_rules",
        "issuer_requirements",
        "supported_formats",
        "credential_payload_format",
        "wallet_configs",
        "version",
    ]
    .iter()
    .map(|key| value(payload, key))
    .collect::<Result<Vec<_>, _>>()?;
    if legacy_remote {
        values.extend(
            [
                "key_access_mode",
                "issuer_key_id",
                "issuer_algorithm",
                "remote_signing_config",
            ]
            .iter()
            .map(|key| value(payload, key))
            .collect::<Result<Vec<_>, _>>()?,
        );
    }
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
    for item in &values {
        query = query.bind(item);
    }
    query.execute(&mut **tx).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn upsert_application_template(
    tx: &mut Transaction<'_, Postgres>,
    payload: &Value,
    legacy_auto_rules: bool,
) -> Result<(), String> {
    let auto_column = if legacy_auto_rules {
        ",auto_approval_rules"
    } else {
        ""
    };
    let auto_value = if legacy_auto_rules { ",$12::json" } else { "" };
    let ui_position = if legacy_auto_rules { 13 } else { 12 };
    let notification_position = ui_position + 1;
    let status_position = ui_position + 2;
    let auto_update = if legacy_auto_rules {
        ",auto_approval_rules=EXCLUDED.auto_approval_rules"
    } else {
        ""
    };
    let sql = format!(
        "INSERT INTO issuance_service.application_templates (id,organization_id,name,description,credential_template_id,form_fields,evidence_requirements,claim_collection_rules,required_checks,approval_strategy,approval_policy_set_id,application_validity_days{auto_column},ui_config,notification_config,status,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6::json,$7::json,$8::json,$9::json,$10,NULL,$11::integer{auto_value},${ui_position}::json,${notification_position}::json,${status_position},NOW(),NOW()) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,credential_template_id=EXCLUDED.credential_template_id,form_fields=EXCLUDED.form_fields,evidence_requirements=EXCLUDED.evidence_requirements,claim_collection_rules=EXCLUDED.claim_collection_rules,required_checks=EXCLUDED.required_checks,approval_strategy=EXCLUDED.approval_strategy,approval_policy_set_id=EXCLUDED.approval_policy_set_id,application_validity_days=EXCLUDED.application_validity_days{auto_update},ui_config=EXCLUDED.ui_config,notification_config=EXCLUDED.notification_config,status=EXCLUDED.status,updated_at=NOW()"
    );
    let mut values = [
        "id",
        "organization_id",
        "name",
        "description",
        "credential_template_id",
        "form_fields",
        "evidence_requirements",
        "claim_collection_rules",
        "required_checks",
        "approval_strategy",
        "application_validity_days",
    ]
    .iter()
    .map(|key| value(payload, key))
    .collect::<Result<Vec<_>, _>>()?;
    if legacy_auto_rules {
        values.push(value(payload, "auto_approval_rules")?);
    }
    values.extend(
        ["ui_config", "notification_config", "status"]
            .iter()
            .map(|key| value(payload, key))
            .collect::<Result<Vec<_>, _>>()?,
    );
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
    for item in &values {
        query = query.bind(item);
    }
    query.execute(&mut **tx).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Upserts both templates in one transaction. Current Rust schemas have no
/// `auto_approval_rules` or key-material columns; older schemas remain accepted.
pub async fn seed_open_badge_templates(
    database_url: &str,
    cfg: &GatewaySeedConfig,
    scope: &Value,
) -> Result<(), String> {
    let credential = credential_template_payload(cfg);
    let application = application_template_payload(cfg, scope);
    let mut connection = PgConnection::connect(database_url)
        .await
        .map_err(|e| e.to_string())?;
    let mut tx = connection.begin().await.map_err(|e| e.to_string())?;
    for table in [
        "credential_template_service.credential_templates",
        "issuance_service.application_templates",
    ] {
        if !table_exists(&mut tx, table).await? {
            return Err(format!("{table} does not exist"));
        }
    }
    let legacy_remote = column_exists(
        &mut tx,
        "credential_template_service",
        "credential_templates",
        "remote_signing_config",
    )
    .await?;
    if legacy_remote {
        for column in ["key_access_mode", "issuer_key_id", "issuer_algorithm"] {
            if !column_exists(
                &mut tx,
                "credential_template_service",
                "credential_templates",
                column,
            )
            .await?
            {
                return Err(format!(
                    "incomplete legacy remote signing schema: missing {column}"
                ));
            }
        }
    }
    let legacy_auto_rules = column_exists(
        &mut tx,
        "issuance_service",
        "application_templates",
        "auto_approval_rules",
    )
    .await?;
    upsert_credential_template(&mut tx, &credential, legacy_remote).await?;
    upsert_application_template(&mut tx, &application, legacy_auto_rules).await?;
    tx.commit().await.map_err(|e| e.to_string())
}
