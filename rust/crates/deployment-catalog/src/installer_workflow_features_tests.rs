use super::*;
use serde_json::json;

fn selection(value: Value) -> Configuration {
    serde_json::from_value(value).unwrap()
}

fn awaiting() -> Configuration {
    selection(json!({"public_verification":{"activation":"awaiting_owner_configuration"}}))
}

fn ordinary_service() -> Value {
    json!({"environment":{"GRPC_SERVICE_TOKEN_FILE":"/run/secrets/grpc_service_token"},
        "secrets":[{"source":"grpc_service_token","target":"grpc_service_token"}], "volumes":[]})
}

fn feature_file(service: &mut Value, key: &str, name: &str) {
    service["environment"][key] = json!(format!("/run/feature-profile/{name}"));
    service["volumes"].as_array_mut().unwrap().push(json!({
        "type":"bind", "source":format!("/native/feature-profile-secrets/{name}"),
        "target":format!("/run/feature-profile/{name}"), "read_only":true,
        "bind":{"create_host_path":false}
    }));
}

fn awaiting_model() -> Value {
    let mut signing = ordinary_service();
    feature_file(&mut signing, "BAO_TOKEN_FILE", SIGNING_CUSTODY_TOKEN);
    feature_file(
        &mut signing,
        "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE",
        GRANT_VERIFY_TOKEN,
    );
    feature_file(
        &mut signing,
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
        SIGNING_READ_KEY,
    );
    let mut flow = ordinary_service();
    feature_file(
        &mut flow,
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
        SIGNING_READ_KEY,
    );
    json!({"services":{"flow":flow, "signing-keys":signing}})
}

fn catalog() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "catalog":{
            "organization_id":"00000000-0000-4000-8000-000000000123",
            "application_origin":"https://console.example.test",
            "notice":"Synthetic source fixture; not a live operator catalog.",
            "scenarios":[{"id":"age","choices":[]}]
        },
        "principal_id":"owner-subject", "issuer_did":"did:web:issuer.example.test",
        "limits":{"starts_per_minute":5,"starts_per_day":50,"maximum_active":10}
    }))
    .unwrap()
}

#[test]
fn typed_selection_is_closed_and_default_off() {
    assert!(selection(json!({})).validate().is_err());
    for value in [
        json!({"verification_prerequisite":"true"}),
        json!({"wallet_governance":{"flow_producer_id":"flow","owner_url":"http://elsewhere"}}),
        json!({"public_verification":{"activation":"awaiting_owner_configuration","catalog_file":"/fake"}}),
        json!({"environment":{"MARTY_EXTERNAL_OBSERVATIONS_ENABLED":true}}),
    ] {
        assert!(
            serde_json::from_value::<Configuration>(value.clone()).is_err(),
            "{value}"
        );
    }
    assert!(selection(json!({"external_associations":true}))
        .validate()
        .is_err());
    assert!(
        selection(json!({"wallet_governance":{"flow_producer_id":"flow\nINJECT=true"}}))
            .validate()
            .is_err()
    );
    let configured = selection(json!({"verification_prerequisite":true}));
    assert!(configured.validate().is_ok());
    assert!(configured.input_files().unwrap().is_empty());
    assert_eq!(
        configured.generated_secret_names(),
        BTreeSet::from([PREREQUISITE_TOKEN])
    );
    assert!(configured
        .layers()
        .iter()
        .all(|path| path.starts_with("deploy-config/compose/selfhost-installer/feature-profile/")));
}

#[test]
fn awaiting_catalog_cannot_mount_an_unreviewed_active_configuration() {
    let config = awaiting();
    assert!(config.input_files().unwrap().is_empty());
    assert!(!config
        .layers()
        .iter()
        .any(|v| v.ends_with("compose.workflow-public-verification.yml")));
    let mut model = awaiting_model();
    config.validate_model(&model).unwrap();
    feature_file(
        &mut model["services"]["flow"],
        "FLOW_PUBLIC_VERIFICATION_CONFIG_FILE",
        CATALOG,
    );
    assert!(config.validate_model(&model).is_err());
    assert!(config
        .validate_imported(&BTreeMap::from([(CATALOG.into(), catalog())]))
        .is_err());
}

#[test]
fn imported_catalog_is_bound_to_its_exact_browser_origin_and_private_path() {
    let good = json!({"public_verification":{"activation":"configured",
        "application_origin":"https://console.example.test", "catalog_file":"/private/catalog.json"}});
    let config = selection(good.clone());
    let bytes = catalog();
    config
        .validate_imported(&BTreeMap::from([(CATALOG.into(), bytes.clone())]))
        .unwrap();
    for origin in [
        "http://console.example.test",
        "https://console.example.test/",
        "https://user@console.example.test",
        "https://console.example.test/path",
    ] {
        let mut changed = good.clone();
        changed["public_verification"]["application_origin"] = json!(origin);
        assert!(selection(changed).validate().is_err());
    }
    for path in [
        "relative.json",
        "/private/../catalog.json",
        "/private//catalog.json",
        "/private/catalog\n.json",
    ] {
        let mut changed = good.clone();
        changed["public_verification"]["catalog_file"] = json!(path);
        assert!(selection(changed).validate().is_err());
    }
    let mut wrong: Value = serde_json::from_slice(&bytes).unwrap();
    wrong["catalog"]["application_origin"] = json!("https://other.example.test");
    assert!(config
        .validate_imported(&BTreeMap::from([(
            CATALOG.into(),
            serde_json::to_vec(&wrong).unwrap()
        )]))
        .is_err());
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"principal_id\":",
        "\"principal_id\":\"substitute\",\"principal_id\":",
        1,
    );
    assert!(config
        .validate_imported(&BTreeMap::from([(CATALOG.into(), duplicate.into_bytes())]))
        .is_err());
    let mut environment =
        BTreeMap::from([("UI_BASE_URL".into(), "https://other.example.test".into())]);
    assert!(config.apply_environment(&mut environment).is_err());
    environment.insert("UI_BASE_URL".into(), "https://console.example.test".into());
    config.apply_environment(&mut environment).unwrap();
}

#[test]
fn scoped_catalog_and_mint_files_cannot_leak_to_other_services_or_become_writable() {
    let config = selection(json!({"public_verification":{"activation":"configured",
        "application_origin":"https://console.example.test", "catalog_file":"/private/catalog.json"}}));
    let mut model = awaiting_model();
    feature_file(
        &mut model["services"]["flow"],
        "FLOW_PUBLIC_VERIFICATION_CONFIG_FILE",
        CATALOG,
    );
    feature_file(
        &mut model["services"]["flow"],
        "FLOW_DEMO_HOLDER_SIGN_GRANT_MINT_TOKEN_FILE",
        HOLDER_MINT_TOKEN,
    );
    model["services"]["flow"]["environment"]["MARTY_SIGNING_GRANT_PROVIDER"] =
        json!("openbao-transit");
    config.validate_model(&model).unwrap();
    for change in [
        "writable",
        "automatic-create",
        "renamed-target",
        "another-service",
    ] {
        let mut changed = model.clone();
        match change {
            "writable" => changed["services"]["flow"]["volumes"][0]["read_only"] = json!(false),
            "automatic-create" => {
                changed["services"]["flow"]["volumes"][0]["bind"]["create_host_path"] = json!(true)
            }
            "renamed-target" => {
                changed["services"]["flow"]["volumes"][0]["target"] = json!("/run/catalog")
            }
            _ => {
                changed["services"]["notification"] = ordinary_service();
                feature_file(
                    &mut changed["services"]["notification"],
                    "UNEXPECTED_FILE",
                    HOLDER_MINT_TOKEN,
                );
            }
        }
        assert!(config.validate_model(&changed).is_err(), "{change}");
    }
}

#[test]
fn native_activation_binds_installation_profile_owner_and_catalog_without_mutating_selection() {
    let config = awaiting();
    let bytes = catalog();
    let install = uuid::Uuid::from_u128(42);
    let profile = "a".repeat(64);
    let receipt = PublicVerificationActivation {
        schema: "elevenid.installer-public-verification-activation/v1".into(),
        installation_id: install,
        feature_profile_sha256: profile.clone(),
        catalog_sha256: crate::installer_release::sha256(&bytes),
        owner_api_receipt_sha256: "b".repeat(64),
        application_origin: "https://console.example.test".into(),
        organization_id: uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000123").unwrap(),
        principal_id: "owner-subject".into(),
    };
    let activate = |record: &PublicVerificationActivation, raw: &[u8]| {
        config.activate_public_verification(
            record,
            raw,
            "/native/activation-1/catalog.json".into(),
            install,
            &profile,
            "https://console.example.test",
        )
    };
    let active = activate(&receipt, &bytes).unwrap();
    assert!(matches!(
        config.public_verification,
        Some(PublicVerification::AwaitingOwnerConfiguration {})
    ));
    assert!(active
        .layers()
        .iter()
        .any(|v| v.ends_with("compose.workflow-public-verification.yml")));
    for alteration in ["installation", "profile", "owner", "catalog", "receipt"] {
        let mut changed = receipt.clone();
        match alteration {
            "installation" => changed.installation_id = uuid::Uuid::from_u128(43),
            "profile" => changed.feature_profile_sha256 = "c".repeat(64),
            "owner" => changed.principal_id = "different-owner".into(),
            "catalog" => changed.catalog_sha256 = "d".repeat(64),
            _ => changed.owner_api_receipt_sha256 = "unbound".into(),
        }
        assert!(activate(&changed, &bytes).is_err(), "{alteration}");
    }
    let mut substituted = bytes.clone();
    substituted.push(b' ');
    assert!(activate(&receipt, &substituted).is_err());
}

#[test]
fn restricted_issuance_cannot_retain_its_schema_owner_password_or_fallback_template() {
    let config = selection(json!({"application_ownership":true}));
    let mut issuance = ordinary_service();
    issuance["environment"]["MARTY_APPLICATION_OWNERSHIP_ENABLED"] = json!("true");
    issuance["environment"]["MARTY_SCHEMA_STARTUP_MODE"] = json!("validate");
    issuance["environment"]["ISSUANCE_API_KEY_FILE"] = json!("/run/secrets/issuance_api_key");
    issuance["secrets"]
        .as_array_mut()
        .unwrap()
        .push(json!("issuance_api_key"));
    feature_file(
        &mut issuance,
        "DATABASE_URL_FILE",
        "feature_issuance_runtime_database_url",
    );
    feature_file(&mut issuance, "PGSSLROOTCERT", "feature_postgres_ca");
    let model = json!({"services":{"issuance":issuance}, "secrets":{"marty_db_password":{"file":"/native/base-secrets/marty_db_password"}}});
    config.validate_model(&model).unwrap();
    for alteration in [
        "template",
        "owner-password",
        "whole-directory",
        "new-migrations",
    ] {
        let mut changed = model.clone();
        match alteration {
            "template" => changed["services"]["issuance"]["environment"]["DATABASE_URL_TEMPLATE"] = json!("postgresql://owner:password@postgres/marty"),
            "owner-password" => changed["services"]["issuance"]["secrets"].as_array_mut().unwrap().push(json!("marty_db_password")),
            "whole-directory" => changed["services"]["issuance"]["volumes"].as_array_mut().unwrap().push(json!({"type":"bind","source":"/native/base-secrets","target":"/elsewhere","read_only":true})),
            _ => changed["services"]["issuance"]["environment"]["MARTY_SCHEMA_STARTUP_MODE"] = json!("migrate"),
        }
        assert!(config.validate_model(&changed).is_err(), "{alteration}");
    }
}
