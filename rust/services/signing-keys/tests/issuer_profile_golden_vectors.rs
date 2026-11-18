use marty_signing_keys::profiles::{
    duplicate_profile, find_profiles, normalize_profile, validate_binding, DuplicateProfileRequest,
    FindProfilesRequest, NormalizeProfileRequest, ValidateBindingRequest,
};
use serde_json::{json, Value};

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap()
}

#[test]
fn profile_normalization_matches_the_language_neutral_vector() {
    let vectors = vectors();
    let case = &vectors["normalize"];
    let profile = normalize_profile(
        case["organization_id"].as_str().unwrap(),
        NormalizeProfileRequest {
            body: case["body"].clone(),
            existing: None,
            now: case["now"].as_str().map(str::to_string),
            profile_id: case["profile_id"].as_str().map(str::to_string),
        },
    )
    .unwrap();
    assert_eq!(profile, case["expected"]);

    for invalid in vectors["invalid_normalize"].as_array().unwrap() {
        let error = normalize_profile(
            "org-a",
            NormalizeProfileRequest {
                body: invalid["body"].clone(),
                existing: None,
                now: Some("2026-08-14T00:00:00Z".to_string()),
                profile_id: Some("ip-invalid".to_string()),
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(invalid["error_contains"].as_str().unwrap()),
            "{error}"
        );
    }
}

#[test]
fn attestation_policy_validates_roots_origins_and_algorithms() {
    let certificate_vectors: Value =
        serde_json::from_str(include_str!("fixtures/document_vectors.json")).unwrap();
    let root = certificate_vectors["certificate"]["cert_pem"]
        .as_str()
        .unwrap();
    let profile = normalize_profile(
        "org-a",
        NormalizeProfileRequest {
            body: json!({
                "issuer_did": "did:web:issuer.example",
                "signing_service_id": "svc-a",
                "key_attestation_policy": {
                    "mode": "required",
                    "trusted_root_certificates_pem": [root],
                    "allowed_algorithms": ["ES256"],
                    "required_key_storage": ["iso_18045_high"],
                    "required_user_authentication": ["iso_18045_high"],
                    "max_age_seconds": 600,
                    "require_nonce": true,
                    "status_validation": "required",
                    "status_list_allowed_origins": ["https://STATUS.wallet-provider.example:443/"],
                    "status_list_trusted_root_certificates_pem": [root],
                    "status_list_allowed_algorithms": ["ES256"],
                    "status_list_max_age_seconds": 43200,
                    "status_list_allow_private_hosts": false
                }
            }),
            existing: None,
            now: Some("2026-08-14T00:00:00Z".to_string()),
            profile_id: Some("ip-policy".to_string()),
        },
    )
    .unwrap();
    assert_eq!(
        profile["key_attestation_policy"]["status_list_allowed_origins"],
        json!(["https://status.wallet-provider.example"])
    );
    assert_eq!(
        profile["key_attestation_policy"]["trusted_root_certificates_pem"][0],
        root.trim()
    );

    for policy in [
        json!({"mode": "required", "allowed_algorithms": ["ES256"]}),
        json!({"mode": "required", "trusted_root_certificates_pem": ["invalid"], "allowed_algorithms": ["ES256"]}),
        json!({"mode": "required", "trusted_root_certificates_pem": [root], "allowed_algorithms": ["HS256"]}),
        json!({"mode": "required", "trusted_root_certificates_pem": [root], "allowed_algorithms": ["ES256"], "status_validation": "required"}),
    ] {
        assert!(normalize_profile(
            "org-a",
            NormalizeProfileRequest {
                body: json!({"issuer_did": "did:web:issuer.example", "signing_service_id": "svc-a", "key_attestation_policy": policy}),
                existing: None,
                now: None,
                profile_id: Some("ip-invalid".to_string()),
            },
        )
        .is_err());
    }
}

#[test]
fn duplicate_repair_selection_and_binding_match_language_neutral_vectors() {
    let vectors = vectors();
    let duplicate = &vectors["duplicate"];
    let request: DuplicateProfileRequest =
        serde_json::from_value(duplicate["request"].clone()).unwrap();
    let result = duplicate_profile(duplicate["profiles"].as_array().unwrap(), &request).unwrap();
    assert!(result.found);
    assert_eq!(result.profile.unwrap(), duplicate["expected"]);

    let find = &vectors["find"];
    let request: FindProfilesRequest = serde_json::from_value(find["request"].clone()).unwrap();
    let matches = find_profiles(
        find["profiles"].as_array().unwrap(),
        find["organization_id"].as_str().unwrap(),
        &request,
    );
    assert_eq!(
        matches
            .iter()
            .map(|profile| profile["id"].clone())
            .collect::<Vec<_>>(),
        find["expected_ids"].as_array().unwrap().clone()
    );

    let binding: ValidateBindingRequest =
        serde_json::from_value(vectors["binding"].clone()).unwrap();
    validate_binding(&binding).unwrap();
    let invalid_lti = ValidateBindingRequest {
        registry: json!({"key_reference_purposes": {"svc-a": {"key-a": ["lti_tool_signing"]}}}),
        ..binding
    };
    assert!(validate_binding(&invalid_lti).is_err());
}
