//! Read-only Canvas demo transition evidence from the issuance database.

use crate::ConnectorRunConfig;
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};
use std::collections::HashMap;
use url::form_urlencoded;

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

fn display(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => {
            if *value {
                "True".into()
            } else {
                "False".into()
            }
        }
        other => other.to_string(),
    }
}

fn nonempty<'a>(values: impl IntoIterator<Item = &'a Value>) -> Option<&'a str> {
    values.into_iter().find_map(|value| {
        value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn canvas_credentials_base_url(env: &HashMap<String, String>) -> String {
    let configured = env
        .get("CANVAS_CREDENTIALS_PUBLIC_BASE_URL")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if !configured.is_empty() {
        return configured.trim_end_matches('/').into();
    }
    let public_host = env
        .get("CANVAS_SANDBOX_PUBLIC_HOST")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let scheme = env
        .get("CANVAS_SANDBOX_SCHEME")
        .map(String::as_str)
        .unwrap_or("https")
        .trim();
    let scheme = if scheme.is_empty() { "https" } else { scheme };
    if !public_host.is_empty() {
        return format!("{scheme}://{public_host}")
            .trim_end_matches('/')
            .into();
    }
    let host = env
        .get("CANVAS_SANDBOX_HOST")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let port = env
        .get("CANVAS_SANDBOX_PORT")
        .map(String::as_str)
        .unwrap_or("8017")
        .trim();
    let port = if port.is_empty() { "8017" } else { port };
    if !host.is_empty() {
        if host.contains(':') || !matches!(host, "localhost" | "127.0.0.1" | "canvas-sandbox") {
            return format!("{scheme}://{host}").trim_end_matches('/').into();
        }
        return format!("{scheme}://{host}:{port}")
            .trim_end_matches('/')
            .into();
    }
    let host_port = env
        .get("CANVAS_SANDBOX_HOST_PORT")
        .map(String::as_str)
        .unwrap_or("8017")
        .trim();
    format!(
        "http://localhost:{}",
        if host_port.is_empty() {
            "8017"
        } else {
            host_port
        }
    )
}

pub fn transition_display_lines(
    summary: &Value,
    connector: &ConnectorRunConfig,
    env: &HashMap<String, String>,
) -> Vec<String> {
    if !summary.is_object() {
        return vec!["WARN: Demo transition verification could not find the application.".into()];
    }
    let app = &summary["application"];
    let fact = &summary["latest_fact"];
    let assertion = &fact["assertion"];
    let verification = &fact["verification"];
    let records = summary["delivery_records"].as_array();
    let mirror_metadata = records
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["delivery_target"] == "canvas_credentials")
        })
        .map(|item| &item["metadata"])
        .filter(|value| value.is_object())
        .unwrap_or(&Value::Null);
    let tx_id = &app["issuance_transaction_id"];
    let mut lines = vec![
        "  OK MIP transition verified".into(),
        format!("    evidence_provider:   {}", display(&fact["provider"])),
        format!("    evidence_fact_type:  {}", display(&fact["fact_type"])),
        format!(
            "    evidence_status:     {} via {}",
            display(&verification["status"]),
            display(&verification["method"])
        ),
        format!(
            "    score_percent:       {}",
            display(&assertion["score_percent"])
        ),
        format!(
            "    application_status:  {}",
            display(&app["application_status"])
        ),
        format!("    transaction_id:      {}", display(tx_id)),
        format!(
            "    transaction_status:  {}",
            display(&app["transaction_status"])
        ),
        format!(
            "    credential_type:     {}",
            display(&app["credential_type"])
        ),
        format!(
            "    issuer_profile_id:   {}",
            display(&app["issuer_profile_id"])
        ),
        format!(
            "    issuer_did:          {}",
            display(&app["issuer_did_override"])
        ),
        format!(
            "    signing_service_id:  {}",
            display(&app["signing_service_id"])
        ),
        format!(
            "    delivery_mode:       {}",
            display(&app["delivery_mode"])
        ),
        format!(
            "    canvas_platform_id:  {}",
            display(&mirror_metadata["canvas_platform_id"])
        ),
        format!(
            "    canvas_binding_id:   {}",
            display(&mirror_metadata["canvas_program_binding_id"])
        ),
        format!(
            "    mirror_records:      {}",
            display(&summary["canvas_mirror_delivery_records"])
        ),
    ];
    let issued = &summary["issued_credential"];
    if issued.is_object() {
        lines.extend([
            format!("    issued_credential:   {}", display(&issued["id"])),
            format!("    credential_status:   {}", display(&issued["status"])),
            format!(
                "    revocation_profile:  {}",
                display(&issued["revocation_profile_id"])
            ),
        ]);
        if let Some(first) = issued["status_list_entries"]
            .as_array()
            .and_then(|items| items.first())
        {
            lines.push(format!(
                "    status_list_index:   {}",
                display(&first["index"])
            ));
            lines.push(format!(
                "    status_list_uri:     {}",
                display(&first["status_list_uri"])
            ));
        }
        lines.push(format!(
            "    subject_did:         {}",
            display(&issued["subject_did"])
        ));
    }
    let public_base = env
        .get("PUBLIC_API_URL")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let public_base = if public_base.is_empty() {
        connector.issuance_base_url.as_str()
    } else {
        public_base
    };
    for record in records.into_iter().flatten() {
        if !record.is_object() {
            continue;
        }
        let target = &record["delivery_target"];
        lines.push(format!(
            "    delivery_record:    {} status={} external={}",
            display(target),
            display(&record["status"]),
            display(&record["external_credential_id"])
        ));
        if target == "canvas_credentials" {
            if let Some(external_id) = record["external_credential_id"]
                .as_str()
                .filter(|value| !value.is_empty())
            {
                let metadata = &record["metadata"];
                let publish = &metadata["publish_response"];
                let provider = nonempty([&metadata["provider"], &publish["provider"]])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let real_provider =
                    matches!(provider.as_str(), "badgr_api" | "canvas_credentials_api");
                let canvas_url = nonempty([
                    &metadata["credential_url"],
                    &metadata["open_badge_id"],
                    &publish["credential_url"],
                    &publish["openBadgeId"],
                ])
                .map(str::to_owned)
                .or_else(|| {
                    if real_provider {
                        None
                    } else {
                        let encoded: String =
                            form_urlencoded::byte_serialize(external_id.as_bytes()).collect();
                        Some(format!(
                            "{}/credentials/{encoded}",
                            canvas_credentials_base_url(env)
                        ))
                    }
                });
                let query = form_urlencoded::Serializer::new(String::new())
                    .append_pair("external_credential_id", external_id)
                    .append_pair("canvas_account_id", &connector.canvas_account_id)
                    .append_pair("organization_id", &connector.organization_id)
                    .finish();
                let provenance = nonempty([
                    &metadata["console_provenance_url"],
                    &publish["console_provenance_url"],
                ])
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    format!(
                        "{}/console/org/operate/verify?{query}",
                        public_base.trim_end_matches('/')
                    )
                });
                lines.push(format!(
                    "      canvas_display:   {}",
                    canvas_url
                        .unwrap_or_else(|| "not returned by Canvas Credentials provider".into())
                ));
                lines.push(format!("      console_provenance: {provenance}"));
            }
        }
        if !record["last_error"].is_null() && record["last_error"] != "" {
            lines.push(format!(
                "      last_error:        {}",
                display(&record["last_error"])
            ));
        }
    }
    if !tx_id.is_null() && tx_id != "" {
        lines.push(format!(
            "    offer_endpoint:      {}/v1/issuance/offers/{}",
            public_base.trim_end_matches('/'),
            display(tx_id)
        ));
    }
    lines
}
