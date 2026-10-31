use super::*;
use std::{
    collections::VecDeque,
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

const REVISION: &str = "\"r-00000000-0000-0000-0000-000000000001\"";
const NEW_REVISION: &str = "\"r-00000000-0000-0000-0000-000000000002\"";

fn service(id: &str) -> Value {
    json!({"id":id,"name":"Existing AWS key","service_type":"aws-kms","region":"us-east-2",
        "auth_mode":"iam_role","key_reference":format!("arn:aws:kms:us-east-2:111122223333:key/{id}"),
        "algorithms":["ES256"],"key_purposes":["vc_jwt_issuer"]})
}

fn plan() -> RegistrationPlan {
    RegistrationPlan::decode(&serde_json::to_vec(&json!({"services":[service("aws-a")]})).unwrap())
        .unwrap()
}

fn registry() -> Value {
    json!({"services":[{"id":"existing-bao","name":"Existing provider", "auth_reference":"", "auth_configured":true}],
        "default_service_id":"existing-bao","type_defaults":{"lti_tool_signing":"existing-bao"},
        "format_defaults":{"jwt_vc_json":"existing-bao"},
        "key_reference_purposes":{"existing-bao":{"key-1":["lti_tool_signing"]}},
        "service_type_catalog":["metadata must not be sent back"],"config_revision":REVISION})
}

struct Call {
    method: Method,
    path: &'static str,
    body: Option<Value>,
    revision: Option<String>,
}

struct Api {
    responses: VecDeque<Result<ApiResponse>>,
    calls: Vec<Call>,
}

impl RegistryApi for Api {
    async fn request(
        &mut self,
        method: Method,
        path: &'static str,
        body: Option<&Value>,
        revision: Option<&str>,
    ) -> Result<ApiResponse> {
        self.calls.push(Call {
            method,
            path,
            body: body.cloned(),
            revision: revision.map(str::to_owned),
        });
        self.responses.pop_front().expect("unexpected API call")
    }
}

fn response(document: Value, revision: Option<&str>) -> Result<ApiResponse> {
    Ok(ApiResponse {
        document,
        revision: revision.map(str::to_owned),
    })
}

#[test]
fn additive_registration_preserves_multiple_services_credentials_and_defaults() {
    let mut input = json!({"services":[service("aws-a"),service("aws-b")]});
    input["services"][1]["key_purposes"] = json!(["lti_tool_signing"]);
    let plan = RegistrationPlan::decode(&serde_json::to_vec(&input).unwrap()).unwrap();
    let existing = registry();
    let (merged, added) = add_registrations(&existing, &plan).unwrap();
    assert_eq!(added, 2);
    assert_eq!(merged["services"].as_array().unwrap().len(), 3);
    assert_eq!(merged["services"][0], existing["services"][0]);
    assert_eq!(merged["default_service_id"], "existing-bao");
    assert_eq!(merged["format_defaults"], existing["format_defaults"]);
    assert_eq!(merged["type_defaults"], existing["type_defaults"]);
    assert_eq!(
        merged["key_reference_purposes"]["existing-bao"],
        existing["key_reference_purposes"]["existing-bao"]
    );
    assert_eq!(
        merged["key_reference_purposes"]["aws-b"]["arn:aws:kms:us-east-2:111122223333:key/aws-b"],
        json!(["lti_tool_signing"])
    );
    assert!(merged.get("service_type_catalog").is_none());
    assert!(merged.get("config_revision").is_none());
}

#[test]
fn additive_registration_preserves_an_explicit_null_default() {
    let mut current = registry();
    current["default_service_id"] = Value::Null;
    let (next, _) = add_registrations(&current, &plan()).unwrap();
    assert!(next["default_service_id"].is_null());
    current["services"] = json!([]);
    current["key_reference_purposes"] = json!({});
    current["type_defaults"] = json!({});
    current["format_defaults"] = json!({});
    let (first, _) = add_registrations(&current, &plan()).unwrap();
    assert_eq!(first["default_service_id"], "aws-a");
}

#[test]
fn rerun_does_not_replace_a_service_or_restore_a_default_changed_in_ui() {
    let plan = plan();
    let (saved, _) = add_registrations(&registry(), &plan).unwrap();
    assert_eq!(
        add_registrations(&saved, &plan).unwrap(),
        (saved.clone(), 0)
    );
    let mut changed = saved.clone();
    changed["services"][1]["key_reference"] = json!("different-key");
    assert!(add_registrations(&changed, &plan).is_err());
    let mut plan = plan;
    plan.default_service_id = Some("aws-a".into());
    assert!(add_registrations(&saved, &plan).is_err());
    let mut changed = saved.clone();
    changed["key_reference_purposes"]["aws-a"] = json!({"foreign":["vc_jwt_issuer"]});
    assert!(add_registrations(&changed, &plan).is_err());
}

#[test]
fn canonical_registry_vector_is_accepted_without_rewriting_a_normalized_service() {
    // This is the same expected document exercised by Signing Keys' golden
    // normalizer test, not an installer-owned copy of provider normalization.
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../services/signing-keys/tests/fixtures/registry_vectors.json"
    ))
    .unwrap();
    let normalized = vectors["normalize_service_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "aws_mdoc_service_preserves_released_shape")
        .unwrap()["expected"]
        .clone();
    let mut request = serde_json::Map::new();
    for name in [
        "id",
        "name",
        "service_type",
        "region",
        "auth_mode",
        "key_reference",
        "algorithms",
        "key_purposes",
    ] {
        request.insert(name.into(), normalized[name].clone());
    }
    let plan =
        RegistrationPlan::decode(&serde_json::to_vec(&json!({"services":[request]})).unwrap())
            .unwrap();
    let mut current = registry();
    current["services"]
        .as_array_mut()
        .unwrap()
        .push(normalized.clone());
    current["key_reference_purposes"][normalized["id"].as_str().unwrap()] = json!({
        (normalized["key_reference"].as_str().unwrap()):normalized["key_purposes"]
    });
    let (next, added) = add_registrations(&current, &plan).unwrap();
    assert_eq!(added, 0);
    assert_eq!(next, writable_registry(&current).unwrap());
    assert!(existing_configuration_preserved(&current, &next, &next));
}

#[tokio::test]
async fn registration_uses_public_console_paths_one_conditional_write_and_readback() {
    let plan = plan();
    let existing = registry();
    let (saved, _) = add_registrations(&existing, &plan).unwrap();
    let mut api = Api {
        calls: Vec::new(),
        responses: VecDeque::from([
            response(existing, Some(REVISION)),
            response(json!({"ok":true,"basis":"live"}), None),
            response(saved.clone(), Some(NEW_REVISION)),
            response(saved.clone(), Some(NEW_REVISION)),
        ]),
    };
    let report = register(&mut api, &plan).await.unwrap();
    assert_eq!(report["added_services"], 1);
    assert_eq!(report["installation_ready"], false);
    assert_eq!(
        api.calls
            .iter()
            .map(|call| (call.method.as_str(), call.path))
            .collect::<Vec<_>>(),
        [
            ("GET", CONFIG_PATH),
            ("POST", "/v1/signing-keys/config/validate"),
            ("PATCH", CONFIG_PATH),
            ("GET", CONFIG_PATH)
        ]
    );
    let mut validation = service("aws-a");
    validation["live_probe"] = json!(true);
    assert_eq!(api.calls[1].body.as_ref(), Some(&validation));
    assert_eq!(api.calls[2].revision.as_deref(), Some(REVISION));
    assert_eq!(api.calls[2].body.as_ref(), Some(&saved));
    assert!(api.responses.is_empty());
}

#[tokio::test]
async fn rerun_validates_and_reads_without_a_second_write() {
    let plan = plan();
    let (saved, _) = add_registrations(&registry(), &plan).unwrap();
    let mut api = Api {
        calls: Vec::new(),
        responses: VecDeque::from([
            response(saved.clone(), Some(REVISION)),
            response(json!({"ok":true,"basis":"live"}), None),
            response(saved, Some(REVISION)),
        ]),
    };
    assert_eq!(
        register(&mut api, &plan).await.unwrap()["registry_changed"],
        false
    );
    assert!(api.calls.iter().all(|call| call.method != Method::PATCH));
}

#[tokio::test]
async fn rerun_accepts_reordered_binding_purposes_without_writing_but_rejects_changed_sets() {
    for (purposes, valid) in [
        (json!(["jwks_signing", "vc_jwt_issuer"]), true),
        (json!(["vc_jwt_issuer"]), false),
        (
            json!(["vc_jwt_issuer", "jwks_signing", "holder_binding"]),
            false,
        ),
        (json!(["vc_jwt_issuer", "jwks_signing", 1]), false),
    ] {
        let mut plan = plan();
        plan.services[0].key_purposes.push("jwks_signing".into());
        let (mut saved, _) = add_registrations(&registry(), &plan).unwrap();
        saved["key_reference_purposes"]["aws-a"][&plan.services[0].key_reference] = purposes;
        let mut responses = VecDeque::from([response(saved.clone(), Some(REVISION))]);
        if valid {
            responses.push_back(response(json!({"ok":true,"basis":"live"}), None));
            responses.push_back(response(saved, Some(REVISION)));
        }
        let mut api = Api {
            calls: Vec::new(),
            responses,
        };
        let result = register(&mut api, &plan).await;
        assert_eq!(result.is_ok(), valid);
        if let Ok(report) = result {
            assert_eq!(report["registry_changed"], false);
            assert_eq!(report["added_services"], 0);
        }
        assert!(api.calls.iter().all(|call| call.method != Method::PATCH));
        assert!(api.responses.is_empty());
    }
}

#[tokio::test]
async fn rerun_validates_saved_runtime_settings_and_rejects_failed_endpoint_probe() {
    for valid in [false, true] {
        let plan = plan();
        let (mut saved, _) = add_registrations(&registry(), &plan).unwrap();
        saved["services"][1]["endpoint"] = json!("https://kms.example.test");
        saved["services"][1]["auth_configured"] = json!(true);
        let mut validation = saved["services"][1].clone();
        validation["live_probe"] = json!(true);
        let mut responses = VecDeque::from([
            response(saved.clone(), Some(REVISION)),
            response(json!({"ok":valid,"basis":"live"}), None),
        ]);
        if valid {
            responses.push_back(response(saved, Some(REVISION)));
        }
        let mut api = Api {
            calls: Vec::new(),
            responses,
        };
        assert_eq!(register(&mut api, &plan).await.is_ok(), valid);
        assert_eq!(api.calls[1].path, "/v1/signing-keys/config/validate");
        assert_eq!(api.calls[1].body.as_ref(), Some(&validation));
        assert!(api.calls.iter().all(|call| call.method != Method::PATCH));
        assert!(api.responses.is_empty());
    }
}

#[tokio::test]
async fn validation_failure_or_revision_conflict_never_retries_a_write() {
    for conflict in [false, true] {
        let mut responses = VecDeque::from([
            response(registry(), Some(REVISION)),
            response(json!({"ok":conflict,"basis":"live"}), None),
        ]);
        if conflict {
            responses.push_back(Err("KMS registry changed".into()));
        }
        let mut api = Api {
            calls: Vec::new(),
            responses,
        };
        assert!(register(&mut api, &plan()).await.is_err());
        assert_eq!(
            api.calls
                .iter()
                .filter(|call| call.method == Method::PATCH)
                .count(),
            usize::from(conflict)
        );
        assert!(api.responses.is_empty());
    }
}

#[tokio::test]
async fn registration_and_rerun_require_explicit_successful_live_validation() {
    let validation_results = [
        (
            "legacy warned failure",
            json!({"ok":true,"checks":[{
                "name":"Provider connectivity","status":"warning",
                "detail":"Adapter live validation failed unexpectedly.","source":"adapter"
            }]}),
        ),
        (
            "configuration only",
            json!({"ok":true,"basis":"configuration"}),
        ),
        ("unknown basis", json!({"ok":true,"basis":"unknown"})),
        ("null basis", json!({"ok":true,"basis":null})),
        ("boolean basis", json!({"ok":true,"basis":true})),
        ("array basis", json!({"ok":true,"basis":["live"]})),
        ("object basis", json!({"ok":true,"basis":{"live":true}})),
        ("padded basis", json!({"ok":true,"basis":"live "})),
        ("failed live probe", json!({"ok":false,"basis":"live"})),
        ("nonboolean success", json!({"ok":"true","basis":"live"})),
        ("missing success", json!({"basis":"live"})),
    ];
    let plan = plan();
    for rerun in [false, true] {
        let original = if rerun {
            add_registrations(&registry(), &plan).unwrap().0
        } else {
            registry()
        };
        for (case, validation) in &validation_results {
            let mut api = Api {
                calls: Vec::new(),
                responses: VecDeque::from([
                    response(original.clone(), Some(REVISION)),
                    response(validation.clone(), None),
                ]),
            };
            assert!(
                register(&mut api, &plan).await.is_err(),
                "{case} must not complete registration (rerun={rerun})"
            );
            assert_eq!(
                api.calls
                    .iter()
                    .map(|call| (call.method.as_str(), call.path))
                    .collect::<Vec<_>>(),
                [
                    ("GET", CONFIG_PATH),
                    ("POST", "/v1/signing-keys/config/validate")
                ],
                "{case} must stop before any registry mutation (rerun={rerun})"
            );
            assert!(api.responses.is_empty());
        }
    }
}

#[tokio::test]
async fn readback_rejects_revision_drift_or_loss_of_unrelated_service() {
    for drift in [false, true] {
        let plan = plan();
        let (mut saved, _) = add_registrations(&registry(), &plan).unwrap();
        if !drift {
            saved["services"].as_array_mut().unwrap().remove(0);
        }
        let mut api = Api {
            calls: Vec::new(),
            responses: VecDeque::from([
                response(registry(), Some(REVISION)),
                response(json!({"ok":true,"basis":"live"}), None),
                response(saved.clone(), Some(NEW_REVISION)),
                response(saved, Some(if drift { REVISION } else { NEW_REVISION })),
            ]),
        };
        assert!(register(&mut api, &plan).await.is_err());
        assert_eq!(
            api.calls
                .iter()
                .filter(|call| call.method == Method::PATCH)
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn explicit_resolution_checks_use_existing_resolver_and_reject_wrong_key() {
    for correct in [false, true] {
        let mut plan = plan();
        plan.resolution_checks.push(ResolutionCheck {
            credential_format: "jwt_vc_json".into(),
            key_purpose: "vc_jwt_issuer".into(),
            algorithm: "ES256".into(),
            expected_service_id: "aws-a".into(),
            expected_key_reference: plan.services[0].key_reference.clone(),
        });
        let (saved, _) = add_registrations(&registry(), &plan).unwrap();
        let mut resolved = service("aws-a");
        if !correct {
            resolved["key_reference"] = json!("wrong-key");
        }
        let mut responses = VecDeque::from([
            response(saved.clone(), Some(REVISION)),
            response(json!({"ok":true,"basis":"live"}), None),
            response(saved.clone(), Some(REVISION)),
            response(json!({"service":resolved}), None),
        ]);
        if correct {
            responses.push_back(response(saved, Some(REVISION)));
        }
        let mut api = Api {
            calls: Vec::new(),
            responses,
        };
        assert_eq!(register(&mut api, &plan).await.is_ok(), correct);
        assert_eq!(api.calls[3].path, "/v1/signing-keys/config/resolve");
        assert!(api.calls.iter().all(|call| call.method != Method::PATCH));
    }
}

#[test]
fn registration_rejects_blank_or_padded_fields_before_server_normalization() {
    for field in [
        "id",
        "name",
        "region",
        "key_reference",
        "algorithms",
        "key_purposes",
    ] {
        let mut registration = service("aws-a");
        let list = registration[field].is_array();
        let value = if list {
            registration[field][0].as_str().unwrap()
        } else {
            registration[field].as_str().unwrap()
        };
        for invalid in [
            String::new(),
            "  ".into(),
            format!(" {value}"),
            format!("{value} "),
        ] {
            // Empty region is an existing canonical shape; provider validation
            // owns whether it can resolve the region from the key or workload.
            if field == "region" && invalid.is_empty() {
                continue;
            }
            if list {
                registration[field] = json!([invalid]);
            } else {
                registration[field] = json!(invalid);
            }
            let bytes = serde_json::to_vec(&json!({"services":[registration]})).unwrap();
            assert!(RegistrationPlan::decode(&bytes).is_err(), "field: {field}");
        }
    }
}

#[test]
fn private_input_refuses_links_permissions_and_credential_carrying_registration() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let input = directory.path().join("registration.json");
    fs::write(
        &input,
        serde_json::to_vec(&json!({"services":[service("aws-a")]})).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(RegistrationPlan::decode(&private_input(&input).unwrap()).is_ok());
    let alias = directory.path().join("alias");
    symlink(&input, &alias).unwrap();
    assert!(private_input(&alias).is_err());
    fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(private_input(&input).is_err());
    let mut secret = service("aws-a");
    secret["auth_reference"] = json!("sensitive-sentinel");
    assert!(
        RegistrationPlan::decode(&serde_json::to_vec(&json!({"services":[secret]})).unwrap())
            .is_err()
    );
    assert!(RegistrationPlan::decode(br#"{"services":[],"services":[]}"#).is_err());
}
