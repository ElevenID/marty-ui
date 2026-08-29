use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use marty_oid4vci::discovery::{
    TenantClaimDisplay, TenantClaimMetadata, TenantCredentialMetadata, TenantCredentialTemplate,
    TenantDisplayStyle,
};
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::error;

use crate::tenant_discovery::{TenantDiscoveryError, TenantDiscoveryRepository};

#[derive(Clone)]
pub struct PostgresTenantDiscoveryRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresTenantDiscoveryRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresTenantDiscoveryRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresTenantDiscoveryRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Default)]
struct TemplateProjection {
    formats: BTreeSet<String>,
    metadata: Option<TenantCredentialMetadata>,
}

struct TemplateRow {
    credential_type: String,
    name: Option<String>,
    description: Option<String>,
    claims: Option<Value>,
    display_style: Option<Value>,
    vct: Option<String>,
    issuer_did: Option<String>,
    supported_formats: Option<Value>,
}

#[async_trait]
impl TenantDiscoveryRepository for PostgresTenantDiscoveryRepository {
    async fn templates(
        &self,
        organization_id: &str,
    ) -> Result<Vec<TenantCredentialTemplate>, TenantDiscoveryError> {
        let rows = sqlx::query(
            "SELECT credential_type, name, description, claims, display_style, vct, issuer_did,
                    supported_formats
             FROM credential_template_service.credential_templates
             WHERE organization_id = $1
               AND status IN ('active', 'draft')
               AND credential_type IS NOT NULL
             ORDER BY credential_type,
                      CASE WHEN status = 'active' THEN 0 ELSE 1 END,
                      updated_at DESC",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|cause| {
            error!(%cause, "tenant discovery repository query failed");
            TenantDiscoveryError::RepositoryUnavailable
        })?;

        let rows = rows
            .into_iter()
            .map(template_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(project_rows(rows))
    }
}

fn template_row(row: PgRow) -> Result<TemplateRow, TenantDiscoveryError> {
    Ok(TemplateRow {
        credential_type: row.try_get("credential_type").map_err(row_error)?,
        name: row.try_get("name").map_err(row_error)?,
        description: row.try_get("description").map_err(row_error)?,
        claims: row.try_get("claims").map_err(row_error)?,
        display_style: row.try_get("display_style").map_err(row_error)?,
        vct: row.try_get("vct").map_err(row_error)?,
        issuer_did: row.try_get("issuer_did").map_err(row_error)?,
        supported_formats: row.try_get("supported_formats").map_err(row_error)?,
    })
}

fn project_rows(rows: Vec<TemplateRow>) -> Vec<TenantCredentialTemplate> {
    let mut projections = BTreeMap::<String, TemplateProjection>::new();
    for row in rows {
        let credential_type = row.credential_type;
        let projection = projections.entry(credential_type.clone()).or_default();
        if let Some(Value::Array(formats)) = row.supported_formats {
            projection.formats.extend(
                formats
                    .into_iter()
                    .filter_map(|format| format.as_str().map(str::to_owned)),
            );
        }
        if projection.metadata.is_none() {
            let name = row
                .name
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| credential_type.clone());
            let claims = row.claims.map_or_else(Vec::new, claims);
            let display_style = row
                .display_style
                .map_or_else(TenantDisplayStyle::default, display_style);
            projection.metadata = Some(TenantCredentialMetadata {
                name: Some(name),
                description: row.description,
                claims,
                display_style,
                vct: row.vct,
                issuer_did: row.issuer_did,
            });
        }
    }

    projections
        .into_iter()
        .map(|(credential_type, projection)| TenantCredentialTemplate {
            credential_type,
            supported_formats: projection.formats.into_iter().collect(),
            metadata: projection.metadata.unwrap_or_default(),
        })
        .collect()
}

fn row_error(cause: sqlx::Error) -> TenantDiscoveryError {
    error!(%cause, "tenant discovery repository row is invalid");
    TenantDiscoveryError::RepositoryUnavailable
}

fn claims(value: Value) -> Vec<TenantClaimMetadata> {
    let Value::Array(values) = value else {
        return Vec::new();
    };
    values
        .into_iter()
        .filter_map(|value| {
            let Value::Object(value) = value else {
                return None;
            };
            let name = truthy_string(value.get("name"))?;
            let display = value.get("display").and_then(|display| {
                let Value::Object(display) = display else {
                    return None;
                };
                Some(TenantClaimDisplay {
                    label: string(display.get("label")),
                    name: string(display.get("name")),
                })
            });
            Some(TenantClaimMetadata {
                name,
                display,
                display_name: string(value.get("display_name")),
                required: value.get("required").is_some_and(python_truthy),
            })
        })
        .collect()
}

fn display_style(value: Value) -> TenantDisplayStyle {
    let Value::Object(value) = value else {
        return TenantDisplayStyle::default();
    };
    TenantDisplayStyle {
        background_color: string(value.get("background_color")),
        text_color: string(value.get("text_color")),
        logo_url: string(value.get("logo_url")),
    }
}

fn string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

fn truthy_string(value: Option<&Value>) -> Option<String> {
    let value = value?;
    if !python_truthy(value) {
        return None;
    }
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(if *value { "True" } else { "False" }.to_owned()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{claims, display_style, project_rows, TemplateRow};

    #[test]
    fn template_json_projection_preserves_python_display_and_claim_semantics() {
        let claims = claims(json!([
            {
                "name": "employee_id",
                "display": {"label": "Employee ID"},
                "required": true
            },
            {"name": "department", "display_name": "Department"},
            {"name": ""},
            "invalid"
        ]));
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].name, "employee_id");
        assert_eq!(
            claims[0]
                .display
                .as_ref()
                .and_then(|display| display.label.as_deref()),
            Some("Employee ID")
        );
        assert!(claims[0].required);
        assert_eq!(claims[1].display_name.as_deref(), Some("Department"));

        let style = display_style(json!({
            "background_color": "#112233",
            "text_color": "#ffffff",
            "logo_url": "https://issuer.example/logo.png",
            "ignored": true
        }));
        assert_eq!(style.background_color.as_deref(), Some("#112233"));
        assert_eq!(style.text_color.as_deref(), Some("#ffffff"));
        assert_eq!(
            style.logo_url.as_deref(),
            Some("https://issuer.example/logo.png")
        );
    }

    #[test]
    fn duplicate_types_merge_formats_but_keep_the_first_ordered_metadata_row() {
        let templates = project_rows(vec![
            TemplateRow {
                credential_type: "EmployeeBadge".to_owned(),
                name: Some("Active Badge".to_owned()),
                description: Some("active".to_owned()),
                claims: Some(json!([])),
                display_style: Some(json!({})),
                vct: Some("urn:active".to_owned()),
                issuer_did: Some("did:web:active.example".to_owned()),
                supported_formats: Some(json!(["jwt_vc_json"])),
            },
            TemplateRow {
                credential_type: "EmployeeBadge".to_owned(),
                name: Some("Newer Draft Badge".to_owned()),
                description: Some("draft".to_owned()),
                claims: Some(json!([])),
                display_style: Some(json!({})),
                vct: Some("urn:draft".to_owned()),
                issuer_did: Some("did:web:draft.example".to_owned()),
                supported_formats: Some(json!(["sd_jwt_vc", "jwt_vc_json"])),
            },
        ]);
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].supported_formats, ["jwt_vc_json", "sd_jwt_vc"]);
        assert_eq!(templates[0].metadata.name.as_deref(), Some("Active Badge"));
        assert_eq!(templates[0].metadata.vct.as_deref(), Some("urn:active"));
        assert_eq!(
            templates[0].metadata.issuer_did.as_deref(),
            Some("did:web:active.example")
        );
    }
}
