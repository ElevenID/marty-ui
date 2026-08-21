use std::collections::BTreeMap;

use chrono::Utc;
use marty_credential_template::{
    migration::migrate_credential_template_schema, ClaimDefinition, ClaimType, CredentialFormat,
    CredentialTemplate, DeliveryDestinationEntry, DisplayStyle, IssuerRequirements, MergeStrategy,
    PostgresCredentialTemplateStore, PrivacyPosture, TemplateStatus, ValidityRules, WalletConfig,
    WalletRegistryEntry,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn complete_repository_round_trip_is_tenant_bound_when_configured() {
    let Ok(database_url) = std::env::var("CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("credential-template PostgreSQL contract database must connect");
    migrate_credential_template_schema(&pool)
        .await
        .expect("Credential Template migration must pass");
    let store = PostgresCredentialTemplateStore::new(pool);
    let now = Utc::now();
    let suffix = "rust-contract-fixed";
    let template_id = format!("ct-{suffix}");
    let wallet_id = format!("wr-{suffix}");
    let system_destination_id = format!("dd-system-{suffix}");
    let tenant_destination_id = format!("dd-tenant-{suffix}");
    let other_destination_id = format!("dd-other-{suffix}");
    for destination_id in [
        &system_destination_id,
        &tenant_destination_id,
        &other_destination_id,
    ] {
        store
            .delete_destination(destination_id)
            .await
            .expect("destination cleanup must pass");
    }
    store
        .delete_wallet(&wallet_id)
        .await
        .expect("wallet cleanup must pass");
    store
        .delete_template(&template_id)
        .await
        .expect("template cleanup must pass");

    let template = CredentialTemplate {
        id: template_id.clone(),
        organization_id: "org-rust-contract".to_owned(),
        name: "Rust Contract Credential".to_owned(),
        description: Some("Complete persistence contract".to_owned()),
        status: TemplateStatus::Active,
        credential_type: "RustContractCredential".to_owned(),
        vct: "https://issuer.example/credentials/rust-contract".to_owned(),
        doctype: None,
        claims: vec![ClaimDefinition {
            id: "claim-rust-contract".to_owned(),
            name: "family_name".to_owned(),
            display_name: "Family Name".to_owned(),
            description: None,
            claim_type: ClaimType::String,
            required: true,
            selectively_disclosable: true,
            derivable: false,
            derived_from: None,
            pattern: None,
            enum_values: None,
            min_value: None,
            max_value: None,
            mdoc_namespace: None,
            mdoc_element_identifier: None,
            display_icon: None,
        }],
        privacy_posture: PrivacyPosture::SelectiveDisclosure,
        selective_disclosure_fields: vec!["family_name".to_owned()],
        zk_predicate_claims: vec!["age_over_18".to_owned()],
        derived_attributes: Vec::new(),
        display_style: DisplayStyle::default(),
        validity_rules: ValidityRules {
            not_before_offset_seconds: -60,
            ..ValidityRules::default()
        },
        issuer_requirements: IssuerRequirements::default(),
        supported_formats: vec![CredentialFormat::SdJwtVc],
        credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
        wallet_configs: vec![WalletConfig {
            wallet_id: wallet_id.clone(),
            ..WalletConfig::default()
        }],
        compliance_profile: Some(json!({"compliance_code":"CUSTOM"})),
        compliance_profile_id: Some("profile-rust-contract".to_owned()),
        application_template_id: Some("application-rust-contract".to_owned()),
        trust_profile_id: Some("trust-rust-contract".to_owned()),
        revocation_profile_id: Some("revocation-rust-contract".to_owned()),
        issuer_algorithm: Some("ES256".to_owned()),
        issuer_did: Some("did:web:issuer.example".to_owned()),
        issuance_protocol: "OID4VCI_AUTH_CODE".to_owned(),
        version: 2,
        created_at: now,
        updated_at: now,
    };
    store
        .save_template(&template)
        .await
        .expect("template save must pass");
    let hydrated = store
        .template_by_id(&template_id)
        .await
        .expect("template lookup must pass")
        .expect("template must exist");
    assert_eq!(hydrated, template);
    assert_eq!(
        store
            .templates_by_organization("org-rust-contract", Some(TemplateStatus::Active))
            .await
            .expect("tenant template list must pass")
            .len(),
        1
    );

    let wallet = WalletRegistryEntry {
        id: wallet_id.clone(),
        organization_id: Some("org-rust-contract".to_owned()),
        is_override: true,
        override_precedence: 80,
        merge_strategy: MergeStrategy::Replace,
        credential_format: Some("SD_JWT_VC".to_owned()),
        issuance_protocol: Some("OID4VCI_AUTH_CODE".to_owned()),
        compliance_profile_code: Some("CUSTOM".to_owned()),
        name: "Rust Contract Wallet".to_owned(),
        description: Some("Complete wallet profile".to_owned()),
        wallet_apps: vec!["ios".to_owned()],
        specifications: vec!["HAIP".to_owned()],
        logo_url: None,
        deep_link_template: "wallet://open?uri={inner_uri_encoded}".to_owned(),
        routing_templates: BTreeMap::from([("ios".to_owned(), "wallet://".to_owned())]),
        install_urls: BTreeMap::from([(
            "ios".to_owned(),
            "https://apps.example/wallet".to_owned(),
        )]),
        ios_scheme: Some("wallet".to_owned()),
        universal_link_template: Some("https://wallet.example/open".to_owned()),
        android_package: Some("example.wallet".to_owned()),
        supported_formats: vec!["sd_jwt_vc".to_owned()],
        supported_protocols: vec!["OID4VCI_AUTH_CODE".to_owned()],
        platforms: vec!["ios".to_owned(), "android".to_owned()],
        supports_qr: true,
        supports_deeplink: true,
        supports_digital_credentials: true,
        supports_haip: true,
        docs_url: Some("https://wallet.example/docs".to_owned()),
        is_active: true,
        created_at: now,
        updated_at: now,
    };
    store
        .save_wallet(&wallet)
        .await
        .expect("wallet save must pass");
    let hydrated_wallet = store
        .wallet_by_id(&wallet_id)
        .await
        .expect("wallet lookup must pass")
        .expect("wallet must exist");
    assert_eq!(hydrated_wallet.id, wallet.id);
    assert_eq!(hydrated_wallet.routing_templates, wallet.routing_templates);
    assert_eq!(hydrated_wallet.install_urls, wallet.install_urls);
    assert!(hydrated_wallet.supports_digital_credentials);
    assert!(hydrated_wallet.supports_haip);
    assert!(hydrated_wallet.updated_at >= wallet.updated_at);

    for (id, organization_id, is_system, name) in [
        (&system_destination_id, None, true, "Zulu System"),
        (
            &tenant_destination_id,
            Some("org-rust-contract"),
            false,
            "alpha Tenant",
        ),
        (
            &other_destination_id,
            Some("org-other"),
            false,
            "Other Tenant",
        ),
    ] {
        store
            .save_destination(&DeliveryDestinationEntry {
                id: id.clone(),
                organization_id: organization_id.map(str::to_owned),
                is_system,
                name: name.to_owned(),
                description: None,
                provider: "custom".to_owned(),
                mode: "direct_delivery".to_owned(),
                setup_actor: "system".to_owned(),
                delivery_target: "webhook".to_owned(),
                wallet_profile_id: None,
                credential_format: Some("SD_JWT_VC".to_owned()),
                issuance_protocol: Some("OID4VCI_PRE_AUTH".to_owned()),
                compliance_profile_code: None,
                connector_type: Some("webhook".to_owned()),
                connector_id: None,
                requires_consent: false,
                claim_projection_policy: json!({}),
                setup_requirements: Vec::new(),
                capabilities: BTreeMap::from([("push".to_owned(), true)]),
                docs_url: None,
                is_enabled: true,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("destination save must pass");
    }
    let destinations = store
        .destinations(true, Some("org-rust-contract"), Some("custom"), None)
        .await
        .expect("tenant destination list must pass");
    assert_eq!(
        destinations
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            system_destination_id.as_str(),
            tenant_destination_id.as_str()
        ]
    );

    for destination_id in [
        &system_destination_id,
        &tenant_destination_id,
        &other_destination_id,
    ] {
        store
            .delete_destination(destination_id)
            .await
            .expect("destination cleanup must pass");
    }
    assert!(store
        .delete_wallet(&wallet_id)
        .await
        .expect("wallet cleanup must pass"));
    assert!(store
        .delete_template(&template_id)
        .await
        .expect("template cleanup must pass"));
}
