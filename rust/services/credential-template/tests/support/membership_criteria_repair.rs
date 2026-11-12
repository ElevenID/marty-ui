//! Exercise both owners' forward data repairs in one rolled-back transaction.
//! This runs in the existing credential-template PostgreSQL CI obligation.
use std::collections::BTreeMap;

use marty_credential_template::{
    catalog::marty_login_badge, migration::migrate_credential_template_schema,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, Row};

const BADGE: &str = "50000000-0000-0000-0000-000000000040";
const ORGANIZATION: &str = "750e8400-e29b-41d4-a716-446655440001";
const TEMPLATE_REPAIR: &str =
    include_str!("../../migrations/0003_membership_achievement_criteria.sql");
const APPLICATION_REPAIR: &str =
    include_str!("../../../issuance/migrations/0012_membership_achievement_criteria.sql");
const NARRATIVE: &str = "Submit a membership application that is approved under the issuing organization's configured approval policy.";

#[tokio::test]
async fn stock_repairs_preserve_customer_criteria_mappings_and_repeat_without_changes() {
    let Ok(database_url) = std::env::var("CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL") else {
        return;
    };
    assert!(url::Url::parse(&database_url)
        .unwrap()
        .path()
        .ends_with("_test"));
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    migrate_credential_template_schema(&pool).await.unwrap();
    let mut transaction = pool.begin().await.unwrap();
    // The independently scheduled credential-template contract may run before
    // issuance. Only the columns used by this data repair are needed here;
    // an existing native application table remains intact and is rolled back.
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS issuance_service;
         CREATE TABLE IF NOT EXISTS issuance_service.application_templates (
            id text PRIMARY KEY, organization_id text NOT NULL,
            name text NOT NULL, description text, credential_template_id text NOT NULL,
            form_fields json NOT NULL, evidence_requirements json NOT NULL,
            claim_collection_rules json NOT NULL, required_checks json NOT NULL,
            approval_strategy text NOT NULL, application_validity_days integer NOT NULL,
            ui_config json NOT NULL, notification_config json NOT NULL,
            status text NOT NULL, management_version bigint NOT NULL DEFAULT 1,
            created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
         );",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();

    let badge = marty_login_badge(
        chrono::Utc::now(),
        ORGANIZATION,
        "https://customer.example",
        "did:web:customer.example:orgs:customer",
    );
    let mut prior_claims = serde_json::to_value(&badge.claims).unwrap();
    let fresh_criteria = prior_claims.as_array_mut().unwrap().remove(
        badge
            .claims
            .iter()
            .position(|claim| claim.name == "achievement_criteria")
            .unwrap(),
    );
    sqlx::query("DELETE FROM credential_template_service.credential_templates WHERE id=$1")
        .bind(BADGE)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO credential_template_service.credential_templates
         (id,organization_id,name,credential_type,vct,doctype,claims,compliance_profile_id,version,created_at,updated_at)
         VALUES ($1,$2,'Marty Verified Member Badge','open_badge',
            'https://customer.example/credentials/marty-verified-member-badge','org.openbadges.v3',$3,
            '10000000-0000-0000-0000-000000000003',4,NOW(),NOW())",
    ).bind(BADGE).bind(ORGANIZATION).bind(&prior_claims)
        .execute(&mut *transaction).await.unwrap();

    let stock_rules = json!([
        {"claim_name":"achievement_name","source":"SYSTEM","source_config":{"system_field":"template.name"}},
        {"claim_name":"achievement_description","source":"SYSTEM","source_config":{"system_field":"template.description"}}
    ]);
    let stock = json!({
        "organization_id":ORGANIZATION,"name":"Marty Verified Member Badge Application",
        "credential_template_id":BADGE,"form_fields":[{"field_id":"email","field_type":"TEXT"}],
        "claim_collection_rules":stock_rules,"ui_config":{"mip_0_3_system_claim_migration":{}}
    });
    let mut fixtures = vec![("stock", stock.clone())];
    for (label, value) in [
        ("empty-criteria", json!({})),
        (
            "customer-criteria",
            json!({"narrative":"Customer-defined criterion","extension":true}),
        ),
    ] {
        let mut custom = stock.clone();
        custom["claim_collection_rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "claim_name":"achievement_criteria","source":"SYSTEM",
                "source_config":{"system_field":"constant","value":value}
            }));
        fixtures.push((label, custom));
    }
    for name in ["achievement_criteria", "achievement"] {
        let mut custom = stock.clone();
        custom["claim_collection_rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "claim_name":name,"source":"FORM_FIELD","source_config":{"field_id":name}
            }));
        fixtures.push((name, custom));
    }
    for (label, field, value) in [
        ("course", "name", json!("Customer Course Application")),
        (
            "foreign",
            "organization_id",
            json!("750e8400-e29b-41d4-a716-446655440002"),
        ),
        (
            "custom-template",
            "credential_template_id",
            json!("50000000-0000-0000-0000-000000000041"),
        ),
        ("custom-ui", "ui_config", json!({})),
        (
            "criteria-form",
            "form_fields",
            json!([{"field_id":"achievement_criteria","field_type":"TEXT"}]),
        ),
    ] {
        let mut custom = stock.clone();
        custom[field] = value;
        fixtures.push((label, custom));
    }
    let mut before = BTreeMap::<String, Value>::new();
    let mut stock_id = String::new();
    for (label, fixture) in fixtures {
        let id = uuid::Uuid::new_v4().to_string();
        if label == "stock" {
            stock_id.clone_from(&id);
        }
        let row: Value = sqlx::query_scalar(
            "INSERT INTO issuance_service.application_templates
             (id,organization_id,name,credential_template_id,form_fields,claim_collection_rules,
              ui_config,evidence_requirements,required_checks,approval_strategy,application_validity_days,
              notification_config,status,management_version,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,'[]','[]','AUTO',30,'{}','ACTIVE',1,NOW(),NOW())
             RETURNING to_jsonb(application_templates)-'updated_at'",
        ).bind(&id).bind(fixture["organization_id"].as_str().unwrap())
            .bind(fixture["name"].as_str().unwrap())
            .bind(fixture["credential_template_id"].as_str().unwrap())
            .bind(&fixture["form_fields"]).bind(&fixture["claim_collection_rules"])
            .bind(&fixture["ui_config"]).fetch_one(&mut *transaction).await.unwrap();
        before.insert(id, row);
    }
    // A partial upgrade must fail before its caller records the repair version;
    // it cannot silently consume the migration while the catalog is absent.
    for missing_catalog in [
        "ALTER TABLE credential_template_service.credential_templates RENAME TO membership_criteria_missing_catalog",
        "DELETE FROM credential_template_service.credential_templates WHERE id='50000000-0000-0000-0000-000000000040'",
    ] {
        sqlx::raw_sql("SAVEPOINT missing_catalog").execute(&mut *transaction).await.unwrap();
        sqlx::raw_sql(missing_catalog).execute(&mut *transaction).await.unwrap();
        let error = sqlx::raw_sql(APPLICATION_REPAIR).execute(&mut *transaction).await.unwrap_err();
        assert!(error.to_string().contains("MEMBERSHIP_CRITERIA_CATALOG_MISSING"));
        sqlx::raw_sql("ROLLBACK TO SAVEPOINT missing_catalog; RELEASE SAVEPOINT missing_catalog")
            .execute(&mut *transaction).await.unwrap();
    }
    for repairs in [
        [APPLICATION_REPAIR, TEMPLATE_REPAIR],
        [TEMPLATE_REPAIR, APPLICATION_REPAIR],
    ] {
        sqlx::query("UPDATE credential_template_service.credential_templates SET claims=$1,version=4 WHERE id=$2")
            .bind(&prior_claims).bind(BADGE).execute(&mut *transaction).await.unwrap();
        sqlx::query("UPDATE issuance_service.application_templates SET claim_collection_rules=$1,management_version=1 WHERE id=$2")
            .bind(&stock_rules).bind(&stock_id).execute(&mut *transaction).await.unwrap();
        for _ in 0..2 {
            for repair in repairs {
                sqlx::raw_sql(repair)
                    .execute(&mut *transaction)
                    .await
                    .unwrap();
            }
            let row = sqlx::query("SELECT claims,version FROM credential_template_service.credential_templates WHERE id=$1")
            .bind(BADGE).fetch_one(&mut *transaction).await.unwrap();
            let mut expected_claims = prior_claims.clone();
            expected_claims
                .as_array_mut()
                .unwrap()
                .push(fresh_criteria.clone());
            assert_eq!(row.get::<Value, _>("claims"), expected_claims);
            assert_eq!(row.get::<i32, _>("version"), 5);
            for (id, original) in &before {
                let after: Value = sqlx::query_scalar("SELECT to_jsonb(application_templates)-'updated_at' FROM issuance_service.application_templates WHERE id=$1")
                .bind(id).fetch_one(&mut *transaction).await.unwrap();
                let mut expected = original.clone();
                if id == &stock_id {
                    expected["claim_collection_rules"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "claim_name":"achievement_criteria","source":"SYSTEM",
                        "source_config":{"system_field":"constant","value":{"narrative":NARRATIVE}}
                    }));
                    expected["management_version"] = json!(2);
                }
                assert_eq!(
                    after, expected,
                    "repair changed customer content or repeated its update: {id}"
                );
            }
        }
    }
    // Existing flat/nested claim definitions are owner-controlled, including a
    // custom description or type: a repair must not silently replace them.
    let nested = json!({"name":"achievement","claim_type":"object","description":"Customer-owned definition"});
    let mut extended_criteria = fresh_criteria.clone();
    extended_criteria["customer_extension"] = json!(true);
    for definitions in [
        vec![
            json!({"name":"achievement_criteria","claim_type":"object","description":"Customer-owned definition"}),
        ],
        vec![nested.clone()],
        vec![fresh_criteria.clone(), nested],
        vec![fresh_criteria.clone(), fresh_criteria.clone()],
        vec![extended_criteria],
    ] {
        let mut custom_claims = prior_claims.clone();
        custom_claims.as_array_mut().unwrap().extend(definitions);
        sqlx::query(
            "UPDATE credential_template_service.credential_templates SET claims=$1 WHERE id=$2",
        )
        .bind(&custom_claims)
        .bind(BADGE)
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query("UPDATE issuance_service.application_templates SET claim_collection_rules=$1,management_version=1 WHERE id=$2")
            .bind(&stock_rules).bind(&stock_id).execute(&mut *transaction).await.unwrap();
        sqlx::raw_sql(TEMPLATE_REPAIR)
            .execute(&mut *transaction)
            .await
            .unwrap();
        let after: Value = sqlx::query_scalar(
            "SELECT claims FROM credential_template_service.credential_templates WHERE id=$1",
        )
        .bind(BADGE)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        assert_eq!(after, custom_claims);
        sqlx::raw_sql(APPLICATION_REPAIR)
            .execute(&mut *transaction)
            .await
            .unwrap();
        let unchanged: Value = sqlx::query_scalar("SELECT to_jsonb(application_templates)-'updated_at' FROM issuance_service.application_templates WHERE id=$1")
            .bind(&stock_id).fetch_one(&mut *transaction).await.unwrap();
        assert_eq!(unchanged, before[&stock_id]);
    }
    sqlx::query("UPDATE credential_template_service.credential_templates SET name='Customer Course Badge',claims=$1 WHERE id=$2")
        .bind(&prior_claims).bind(BADGE).execute(&mut *transaction).await.unwrap();
    sqlx::raw_sql(TEMPLATE_REPAIR)
        .execute(&mut *transaction)
        .await
        .unwrap();
    let after: Value = sqlx::query_scalar(
        "SELECT claims FROM credential_template_service.credential_templates WHERE id=$1",
    )
    .bind(BADGE)
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(
        after, prior_claims,
        "matching the stable ID alone is insufficient"
    );
    transaction.rollback().await.unwrap();
    pool.close().await;
}
