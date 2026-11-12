//! Seed Marty application templates while installing the fresh Rust baseline.

use serde_json::{json, Map, Value};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

const TEMPLATE_NAMESPACE: &str = "c7ad7bbb-3cc8-46bc-a648-f0f66be0473a";
const MEMBERSHIP_CRITERIA_NARRATIVE: &str = "Submit a membership application that is approved under the issuing organization's configured approval policy.";

pub(super) async fn seed_marty_application_templates(
    connection: &mut PgConnection,
    organization_id: Uuid,
) -> Result<(), sqlx::Error> {
    let has_templates: bool = sqlx::query_scalar(
        "SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !has_templates {
        return Err(sqlx::Error::Protocol(
            "credential template catalog must exist before the fresh issuance baseline".into(),
        ));
    }

    let organization_name: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(name, ''), slug, '')
         FROM organization_service.organizations WHERE id = $1::uuid",
    )
    .bind(organization_id)
    .fetch_optional(&mut *connection)
    .await?;
    let organization_name = organization_name.unwrap_or_default();
    let organization_id = organization_id.to_string();
    let rows = sqlx::query(
        "SELECT id, name, description, credential_type, doctype, vct, claims, issuer_requirements
         FROM credential_template_service.credential_templates
         WHERE organization_id = $1
           AND lower(coalesce(status, 'active')) = 'active'
         ORDER BY created_at, id",
    )
    .bind(&organization_id)
    .fetch_all(&mut *connection)
    .await?;
    let namespace = Uuid::parse_str(TEMPLATE_NAMESPACE)
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    for row in rows {
        let credential_template_id: String = row.try_get("id")?;
        let display_name = row
            .try_get::<Option<String>, _>("name")?
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "Credential".into());
        let description = row
            .try_get::<Option<String>, _>("description")?
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("Application flow for {display_name}"));
        let claims: Value = row
            .try_get::<Option<Value>, _>("claims")?
            .unwrap_or(Value::Null);
        let requirements: Value = row
            .try_get::<Option<Value>, _>("issuer_requirements")?
            .unwrap_or(Value::Null);
        let template_id = Uuid::new_v5(
            &namespace,
            format!("{organization_id}:{credential_template_id}").as_bytes(),
        )
        .to_string();
        let membership_badge = is_stock_membership_badge(
            &credential_template_id,
            &display_name,
            &row.try_get::<String, _>("credential_type")?,
            row.try_get::<Option<String>, _>("doctype")?.as_deref(),
            &row.try_get::<String, _>("vct")?,
        );
        let (fields, rules, ui_config, valid) =
            final_template_projection(&claims, &display_name, &organization_name, membership_badge);
        let approval_strategy = if truthy(requirements.get("approval_required")) {
            "manual"
        } else {
            "auto"
        };
        sqlx::query(
            "INSERT INTO issuance_service.application_templates (
                id, organization_id, name, description, credential_template_id,
                form_fields, evidence_requirements, claim_collection_rules,
                required_checks, approval_strategy, application_validity_days,
                ui_config, notification_config, status, created_at, updated_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, '[]'::json, $7,
                '[]'::json, $8, 30, $9, $10, $11, NOW(), NOW()
             ) ON CONFLICT (id) DO NOTHING",
        )
        .bind(template_id)
        .bind(&organization_id)
        .bind(format!("{display_name} Application"))
        .bind(description)
        .bind(credential_template_id)
        .bind(fields)
        .bind(rules)
        .bind(approval_strategy)
        .bind(ui_config)
        .bind(json!({"send_confirmation": true, "send_status_updates": true}))
        .bind(if valid { "ACTIVE" } else { "DRAFT" })
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

fn final_template_projection(
    claims: &Value,
    display_name: &str,
    organization_name: &str,
    membership_badge: bool,
) -> (Value, Value, Value, bool) {
    let mut original_fields = Vec::new();
    let mut original_rules = Vec::new();
    let mut canonical_fields = Vec::new();
    let mut canonical_rules = Vec::new();
    let mut valid = true;
    for claim in claims.as_array().into_iter().flatten() {
        let Some(name) = claim
            .get("name")
            .and_then(Value::as_str)
            .filter(|x| !x.is_empty())
        else {
            continue;
        };
        let label = claim
            .get("display_name")
            .and_then(Value::as_str)
            .filter(|x| !x.is_empty())
            .unwrap_or(name);
        let required = truthy(claim.get("required"));
        let options = claim
            .get("enum_values")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let old_type = legacy_field_type(claim.get("claim_type").and_then(Value::as_str));
        original_fields.push(json!({
            "field_id": name, "field_type": old_type, "label": label,
            "required": required, "options": options, "validation_pattern": null
        }));
        original_rules.push(json!({
            "claim_name": name, "source": "form", "source_field": name,
            "required": required
        }));
        let canonical_name = name.trim();
        if canonical_name.is_empty() {
            valid = false;
            continue;
        }
        canonical_fields.push(json!({
            "field_id": canonical_name, "field_type": old_type.to_ascii_uppercase(),
            "label": label, "required": required, "options": options
        }));
        canonical_rules.push(json!({
            "claim_name": canonical_name, "source": "FORM_FIELD",
            "source_config": {"field_id": name}
        }));
    }

    let mut ui = Map::new();
    ui.insert("theme".into(), json!("default"));
    ui.insert(
        "instructions".into(),
        json!(format!(
            "Complete this application to request {display_name}."
        )),
    );
    if !original_fields.is_empty() {
        ui.insert(
            "mip_0_3_migration".into(),
            json!({
                "original_form_fields": original_fields,
                "original_claim_collection_rules": original_rules,
                "requires_correction": !valid
            }),
        );
    }

    let before_system_fields = canonical_fields.clone();
    let before_system_rules = canonical_rules.clone();
    let mut system_rules = Vec::new();
    canonical_fields.retain(|field| {
        let name = field["field_id"].as_str().unwrap_or_default();
        let Some(source_config) = system_source(name, organization_name, membership_badge) else {
            return true;
        };
        system_rules.push(json!({
            "claim_name": name, "source": "SYSTEM", "source_config": source_config
        }));
        false
    });
    if !system_rules.is_empty() {
        canonical_rules.retain(|rule| {
            !system_rules
                .iter()
                .any(|system| system["claim_name"] == rule["claim_name"])
        });
        canonical_rules.extend(system_rules);
        ui.insert(
            "mip_0_3_system_claim_migration".into(),
            json!({
                "original_form_fields": before_system_fields,
                "original_claim_collection_rules": before_system_rules
            }),
        );
    }

    (
        Value::Array(canonical_fields),
        Value::Array(canonical_rules),
        Value::Object(ui),
        valid,
    )
}

fn legacy_field_type(claim_type: Option<&str>) -> &'static str {
    match claim_type
        .unwrap_or("string")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "bool" | "boolean" => "boolean",
        "int" | "integer" | "number" | "float" | "double" | "decimal" => "number",
        "date" | "datetime" | "timestamp" => "date",
        _ => "text",
    }
}

fn is_stock_membership_badge(
    id: &str,
    name: &str,
    credential_type: &str,
    doctype: Option<&str>,
    vct: &str,
) -> bool {
    id == "50000000-0000-0000-0000-000000000040"
        && name == "Marty Verified Member Badge"
        && matches!(
            credential_type.to_ascii_lowercase().as_str(),
            "open_badge" | "open_badge_v3" | "openbadgecredential"
        )
        && doctype == Some("org.openbadges.v3")
        && vct.ends_with("/credentials/marty-verified-member-badge")
}

fn system_source(name: &str, organization_name: &str, membership_badge: bool) -> Option<Value> {
    let system_field = match name {
        "member_id" | "user_id" => "applicant.user_id",
        "organization_id" => "application.organization_id",
        "issued_at" => "current.datetime",
        "issue_date" | "date_of_issue" => "current.date",
        "expiry_date" | "date_of_expiry" => "validity.expiry_date",
        "document_number" | "employee_id" => "application.reference_number",
        "achievement_name" => "template.name",
        "achievement_description" => "template.description",
        "achievement_criteria" if membership_badge => {
            return Some(json!({
                "system_field": "constant",
                "value": {"narrative": MEMBERSHIP_CRITERIA_NARRATIVE}
            }));
        }
        "organization_name" | "issuing_authority" if !organization_name.is_empty() => {
            return Some(json!({"system_field": "constant", "value": organization_name}));
        }
        "role" => return Some(json!({"system_field": "constant", "value": "applicant"})),
        _ => return None,
    };
    Some(json!({"system_field": system_field}))
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|x| x != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_tenant_configuration_preserves_default_and_validates_customer_uuid() {
        assert_eq!(
            crate::migration::seed_organization_id(None)
                .unwrap()
                .to_string(),
            "00000000-0000-0000-0000-000000000001",
        );
        assert_eq!(
            crate::migration::seed_organization_id(Some(" 750e8400-e29b-41d4-a716-446655440001 "))
                .unwrap()
                .to_string(),
            "750e8400-e29b-41d4-a716-446655440001",
        );
        assert!(crate::migration::seed_organization_id(Some("not-a-uuid")).is_err());
    }

    #[test]
    fn customer_application_claims_use_customer_name_as_a_system_value() {
        let (fields, rules, _, valid) = final_template_projection(
            &json!([
                {"name":"organization_name","claim_type":"string"},
                {"name":"learner_name","claim_type":"string"},
            ]),
            "Course Completion Badge",
            "Canyon Skills Academy",
            false,
        );
        assert!(valid);
        assert_eq!(fields.as_array().unwrap().len(), 1);
        assert_eq!(fields[0]["field_id"], "learner_name");
        assert!(rules.as_array().unwrap().contains(&json!({
            "claim_name":"organization_name", "source":"SYSTEM",
            "source_config":{"system_field":"constant","value":"Canyon Skills Academy"},
        })));
    }

    #[test]
    fn stock_membership_criteria_are_issuer_owned_and_keep_their_object_shape() {
        let (fields, rules, _, valid) = final_template_projection(
            &json!([
                {"name":"email","claim_type":"string","required":true},
                {"name":"achievement_criteria","claim_type":"object","required":true}
            ]),
            "Marty Verified Member Badge",
            "Customer Organization",
            true,
        );
        assert!(valid);
        assert_eq!(fields.as_array().unwrap().len(), 1);
        assert_eq!(fields[0]["field_id"], "email");
        let form = json!({"email":"applicant@example.test","achievement_criteria":{"narrative":"forged form value"}})
            .as_object().unwrap().clone();
        let mut claims = form.clone();
        marty_claim_collection::apply_rules(
            &mut claims,
            &form,
            rules.as_array().unwrap(),
            &Map::new(),
            &[],
        );
        assert_eq!(claims["email"], "applicant@example.test");
        assert_eq!(
            claims["achievement_criteria"],
            json!({"narrative":MEMBERSHIP_CRITERIA_NARRATIVE})
        );
    }

    #[test]
    fn membership_defaults_are_not_applied_to_customer_course_templates() {
        let id = "50000000-0000-0000-0000-000000000040";
        let name = "Marty Verified Member Badge";
        let vct = "https://customer.example/credentials/marty-verified-member-badge";
        assert!(is_stock_membership_badge(
            id,
            name,
            "open_badge",
            Some("org.openbadges.v3"),
            vct
        ));
        for (id, name, credential_type, doctype, vct) in [
            (
                "customer-template",
                name,
                "open_badge",
                Some("org.openbadges.v3"),
                vct,
            ),
            (
                id,
                "Course Completion Badge",
                "open_badge",
                Some("org.openbadges.v3"),
                vct,
            ),
            (id, name, "MemberCredential", Some("org.openbadges.v3"), vct),
            (id, name, "open_badge", None, vct),
            (
                id,
                name,
                "open_badge",
                Some("org.openbadges.v3"),
                "https://customer.example/course",
            ),
        ] {
            assert!(!is_stock_membership_badge(
                id,
                name,
                credential_type,
                doctype,
                vct
            ));
        }
        let (fields, rules, _, _) = final_template_projection(
            &json!([{"name":"achievement_criteria","claim_type":"object"}]),
            "Course Completion Badge",
            "Canyon Skills Academy",
            false,
        );
        assert_eq!(fields[0]["field_id"], "achievement_criteria");
        assert_eq!(rules[0]["source"], "FORM_FIELD");
        let form = json!({"achievement_criteria":{"narrative":"Customer course criterion","extension":true}})
            .as_object().unwrap().clone();
        let mut claims = Map::new();
        marty_claim_collection::apply_rules(
            &mut claims,
            &form,
            rules.as_array().unwrap(),
            &Map::new(),
            &[],
        );
        assert_eq!(claims["achievement_criteria"], form["achievement_criteria"]);
    }
}
