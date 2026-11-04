use chrono::{TimeZone, Utc};
use marty_flow::{
    create_definition_record, parse_request, DefinitionStatus, PublicVerificationCatalog,
    PublicVerificationCatalogError as Error, PublicVerificationSelection,
};
use serde_json::{json, Value};

fn configuration() -> Value {
    json!({
        "organization_id": "org-marty-demo",
        "application_origin": "https://www.example.test",
        "notice": "Use a synthetic credential for this demonstration. Review the request before continuing.",
        "scenarios": [{
            "id": "age", "label": "Age requirement",
            "choices": [{
                "id": "over-18", "label": "18 or older",
                "definition": { "organization_id": "org-marty-demo", "definition_id": "flow-age-18", "version": 1 },
                "presentation_policy_id": "policy-age-18",
                "policy_configuration_digest": format!("sha256:{}", "a".repeat(64))
            }, {
                "id": "over-21", "label": "21 or older",
                "definition": { "organization_id": "org-marty-demo", "definition_id": "flow-age-21", "version": 1 },
                "presentation_policy_id": "policy-age-21",
                "policy_configuration_digest": format!("sha256:{}", "b".repeat(64))
            }]
        }]
    })
}

fn catalog(value: &Value) -> PublicVerificationCatalog {
    PublicVerificationCatalog::from_json(&value.to_string(), false).unwrap()
}

fn selection(catalog: &PublicVerificationCatalog) -> PublicVerificationSelection {
    PublicVerificationSelection {
        catalog_revision: catalog.public_view().revision.into(),
        scenario_id: "age".into(),
        choice_id: "over-18".into(),
        consent: true,
    }
}

#[test]
fn public_catalog_only_exposes_visitor_choices_and_notice() {
    let catalog = catalog(&configuration());
    let value = serde_json::to_value(catalog.public_view()).unwrap();
    assert_eq!(
        value["scenarios"][0]["choices"][0],
        json!({"id":"over-18", "label":"18 or older"})
    );
    let raw = value.to_string();
    for private in [
        "org-marty-demo",
        "flow-age",
        "policy-age",
        "definition",
        "configuration_digest",
        "application_origin",
    ] {
        assert!(!raw.contains(private), "leaked {private}");
    }
    let selected = catalog.select(&selection(&catalog)).unwrap();
    assert_eq!(selected.presentation_policy_id, "policy-age-18");
    let mut second = selection(&catalog);
    second.choice_id = "over-21".into();
    assert_eq!(
        catalog.select(&second).unwrap().presentation_policy_id,
        "policy-age-21"
    );
}

#[test]
fn consent_and_exact_current_selection_are_required() {
    let catalog = catalog(&configuration());
    let mut request = selection(&catalog);
    request.consent = false;
    assert!(matches!(
        catalog.select(&request),
        Err(Error::ConsentRequired)
    ));
    request = selection(&catalog);
    request.catalog_revision = "stale".into();
    assert!(matches!(
        catalog.select(&request),
        Err(Error::CatalogChanged)
    ));
    request = selection(&catalog);
    request.scenario_id = "membership".into();
    assert!(matches!(
        catalog.select(&request),
        Err(Error::ChoiceUnavailable)
    ));
    request = selection(&catalog);
    request.choice_id = "custom-policy".into();
    assert!(matches!(
        catalog.select(&request),
        Err(Error::ChoiceUnavailable)
    ));
}

#[test]
fn every_configuration_and_consent_change_invalidates_prior_selection() {
    let original = catalog(&configuration());
    let request = selection(&original);
    for variant in 0..7 {
        let mut value = configuration();
        match variant {
            0 => value["notice"] = json!("A different consent notice."),
            1 => value["scenarios"][0]["label"] = json!("Updated scenario"),
            2 => value["scenarios"][0]["choices"][0]["label"] = json!("Updated requirement"),
            3 => value["scenarios"][0]["choices"][0]["definition"]["version"] = json!(2),
            4 => {
                value["scenarios"][0]["choices"][0]["presentation_policy_id"] = json!("new-policy")
            }
            5 => {
                value["scenarios"][0]["choices"][0]["policy_configuration_digest"] =
                    json!(format!("sha256:{}", "c".repeat(64)))
            }
            _ => value["application_origin"] = json!("https://new.example.test"),
        }
        assert!(
            matches!(catalog(&value).select(&request), Err(Error::CatalogChanged)),
            "variant {variant}"
        );
    }
    // Formatting and object-key order do not cause a spurious revision change.
    let reformatted = PublicVerificationCatalog::from_json(
        &serde_json::to_string_pretty(&configuration()).unwrap(),
        false,
    )
    .unwrap();
    assert_eq!(
        original.public_view().revision,
        reformatted.public_view().revision
    );
}

#[test]
fn catalog_rejects_cross_tenant_unbounded_ambiguous_and_malformed_configuration() {
    for variant in 0..17 {
        let mut value = configuration();
        match variant {
            0 => value["organization_id"] = json!("foreign-org"),
            1 => value["notice"] = json!(""),
            2 => value["scenarios"] = json!([]),
            3 => value["scenarios"][0]["choices"] = json!([]),
            4 => value["scenarios"][0]["choices"][0]["id"] = json!("../../management"),
            5 => value["scenarios"][0]["choices"][0]["definition"]["version"] = json!(0),
            6 => value["scenarios"][0]["choices"][0]["definition"]["definition_id"] = json!(" "),
            7 => value["scenarios"][0]["choices"][0]["presentation_policy_id"] = json!(""),
            8 => {
                value["scenarios"][0]["choices"][0]["policy_configuration_digest"] =
                    json!("invalid")
            }
            9 => {
                value["scenarios"][0]["choices"][0]["policy_configuration_digest"] =
                    json!(format!("sha256:{}", "A".repeat(64)))
            }
            10 => value["scenarios"][0]["label"] = json!("a".repeat(121)),
            11 => value["notice"] = json!("invisible\ncontrol"),
            12 => value["scenarios"][0]["choices"][1]["id"] = json!("over-18"),
            13 => value["scenarios"] = json!(vec![value["scenarios"][0].clone(); 2]),
            14 => value["scenarios"] = json!(vec![value["scenarios"][0].clone(); 9]),
            15 => {
                value["scenarios"][0]["choices"] =
                    json!(vec![value["scenarios"][0]["choices"][0].clone(); 9])
            }
            _ => value["arbitrary_rules"] = json!({"accept_all": true}),
        }
        assert!(
            matches!(
                PublicVerificationCatalog::from_json(&value.to_string(), false),
                Err(Error::InvalidConfiguration)
            ),
            "variant {variant}"
        );
    }
    assert!(PublicVerificationCatalog::from_json(&" ".repeat(65_537), false).is_err());
    assert!(PublicVerificationCatalog::from_json("not JSON", false).is_err());
}

#[test]
fn browser_origin_must_match_exactly_and_cannot_be_opaque_or_missing() {
    let catalog = catalog(&configuration());
    catalog
        .require_origin(Some("https://www.example.test"))
        .unwrap();
    for origin in [
        None,
        Some("null"),
        Some("https://evil.example.test"),
        Some("https://www.example.test.evil.test"),
        Some("https://www.example.test/"),
        Some("http://www.example.test"),
    ] {
        assert_eq!(catalog.require_origin(origin), Err(Error::OriginRejected));
    }
}

#[test]
fn origin_configuration_is_canonical_and_loopback_http_is_explicit() {
    for origin in [
        "*",
        "null",
        "http://www.example.test",
        "https://www.example.test/path",
        "https://www.example.test/",
        "https://user:password@www.example.test",
        "https://www.example.test?query",
        "https://www.example.test#fragment",
    ] {
        let mut value = configuration();
        value["application_origin"] = json!(origin);
        assert!(
            PublicVerificationCatalog::from_json(&value.to_string(), true).is_err(),
            "{origin}"
        );
    }
    for origin in [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://[::1]:3000",
    ] {
        let mut value = configuration();
        value["application_origin"] = json!(origin);
        assert!(PublicVerificationCatalog::from_json(&value.to_string(), false).is_err());
        assert!(
            PublicVerificationCatalog::from_json(&value.to_string(), true).is_ok(),
            "{origin}"
        );
    }
}

#[test]
fn visitors_cannot_supply_management_ids_or_arbitrary_policy_overrides() {
    let catalog = catalog(&configuration());
    let request = serde_json::to_value(selection(&catalog)).unwrap();
    for field in [
        "organization_id",
        "flow_definition_id",
        "presentation_policy_id",
        "policy_configuration_digest",
        "principal_id",
        "callback_url",
        "rules",
        "trust_profile_id",
    ] {
        let mut candidate = request.clone();
        candidate[field] = json!("visitor-controlled");
        assert!(
            serde_json::from_value::<PublicVerificationSelection>(candidate).is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn choice_rejects_wrong_definition_policy_version_or_configuration() {
    let mut definition = create_definition_record(
        parse_request(json!({
            "organization_id": "org-marty-demo", "name": "Website age example",
            "flow_type": "oid4vp_presentation", "presentation_policy_id": "policy-age-18"
        }))
        .unwrap(),
        Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap(),
    )
    .unwrap();
    definition.id = "flow-age-18".into();
    definition.status = DefinitionStatus::Active;
    let catalog = catalog(&configuration());
    let choice = catalog.select(&selection(&catalog)).unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    choice.validate_definition(&definition, &digest).unwrap();
    assert_eq!(
        choice.validate_definition(&definition, &format!("sha256:{}", "b".repeat(64))),
        Err(Error::ConfigurationChanged)
    );
    for variant in 0..6 {
        let mut candidate = definition.clone();
        match variant {
            0 => candidate.organization_id = "foreign-org".into(),
            1 => candidate.id = "other-definition".into(),
            2 => candidate.version += 1,
            3 => candidate.presentation_policy_id = Some("other-policy".into()),
            4 => candidate.status = DefinitionStatus::Paused,
            _ => candidate.preconditions.push("approval".into()),
        }
        assert_eq!(
            choice.validate_definition(&candidate, &digest),
            Err(Error::ConfigurationChanged),
            "variant {variant}"
        );
    }
}
