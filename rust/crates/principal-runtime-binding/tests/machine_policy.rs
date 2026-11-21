use chrono::{DateTime, Duration, Utc};
use marty_principal_runtime_binding::{
    machine_policy::{qualify_machine_binding, MachineAuthenticationPolicy, MachinePolicyError},
    parse_binding_record, parse_configuration, parse_machine_snapshot,
};
use serde_json::{json, Value};
use uuid::Uuid;

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-17T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn source() -> Value {
    let mut value: Value = serde_json::from_str(include_str!(
        "fixtures/managed-service-with-rotating-candidate.json"
    ))
    .unwrap();
    let machine_id = value["machine_identity"]["machine_id"].clone();
    for target in ["configuration", "record"] {
        value[target]["principal"] = json!({"type": "MACHINE_IDENTITY", "id": machine_id});
    }
    value["machine_identity"]["credential_ids"] = json!(["0c53f847-e5f4-4209-916d-eb944a9d7802"]);
    value["machine_identity"]["identity_keys"][0]["valid_until"] =
        json!((now() + Duration::hours(1)).to_rfc3339());
    value
}

fn policy() -> Value {
    json!({
        "id": "910188cf-2dc0-46c3-bb6a-3d290b12c460",
        "organization_id": source()["configuration"]["organization_id"],
        "name": "Synthetic current machine policy",
        "trust_profile_id": "4e3efcd4-d613-4f35-94d0-4d0d8ce38266",
        "required_credential_types": ["MachineCredential"],
        "allowed_machine_types": ["SECURE_PROCESSING_RUNTIME"],
        "machine_binding": {
            "binding_methods": ["MACHINE_KEY"],
            "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
            "proof_freshness": {
                "challenge_required": true,
                "audience_binding_required": true,
                "replay_detection_required": true,
                "max_proof_age_seconds": 120
            }
        },
        "status": "ACTIVE",
        "created_at": "2026-11-01T00:00:00Z",
        "updated_at": "2026-11-02T00:00:00Z"
    })
}

fn parse(value: &Value) -> Result<MachineAuthenticationPolicy, MachinePolicyError> {
    MachineAuthenticationPolicy::from_trusted_document(&serde_json::to_vec(value).unwrap())
}

fn qualify(value: &Value, selected: &Value) -> Result<(), MachinePolicyError> {
    let organization_id =
        Uuid::parse_str(value["configuration"]["organization_id"].as_str().unwrap()).unwrap();
    let parsed = parse(selected)?;
    let record = parse_binding_record(&serde_json::to_vec(&value["record"]).unwrap())
        .map_err(|_| MachinePolicyError::BindingMismatch)?;
    let config = parse_configuration(&serde_json::to_vec(&value["configuration"]).unwrap())
        .map_err(|_| MachinePolicyError::BindingMismatch)?;
    let machine = parse_machine_snapshot(&serde_json::to_vec(&value["machine_identity"]).unwrap())
        .map_err(|_| MachinePolicyError::BindingMismatch)?;
    qualify_machine_binding(organization_id, &parsed, &record, &config, &machine, now()).map(|_| ())
}

#[test]
fn active_full_machine_selection_preserves_all_policy_requirements() {
    let policy = parse(&policy()).unwrap();
    assert_eq!(policy.select_oid4vp_machine_key().unwrap(), 120);
    assert_eq!(policy.required_credential_types(), &["MachineCredential"]);
    assert!(policy.required_attestation().is_none());
    assert!(policy.authorization_policy_set_id().is_none());
    let value = source();
    let organization_id =
        Uuid::parse_str(value["configuration"]["organization_id"].as_str().unwrap()).unwrap();
    let record = parse_binding_record(&serde_json::to_vec(&value["record"]).unwrap()).unwrap();
    let config =
        parse_configuration(&serde_json::to_vec(&value["configuration"]).unwrap()).unwrap();
    let machine =
        parse_machine_snapshot(&serde_json::to_vec(&value["machine_identity"]).unwrap()).unwrap();
    let qualified =
        qualify_machine_binding(organization_id, &policy, &record, &config, &machine, now())
            .unwrap();
    assert_eq!(
        qualified.binding().principal_id(),
        value["machine_identity"]["machine_id"].as_str().unwrap()
    );
    assert_eq!(qualified.key_id(), "document-worker-active");
    assert_eq!(
        qualified.key_valid_until(),
        Some(now() + Duration::hours(1))
    );
    assert_eq!(qualified.credential_ids().len(), 1);
    assert_eq!(
        format!("{qualified:?}"),
        "QualifiedMachineBinding { <private> }"
    );
}

#[test]
fn strict_policy_rejects_unknown_duplicate_null_and_weakened_requirements() {
    let original = policy();
    let mutations: &[fn(&mut Value)] = &[
        |v| v["caller_verified"] = json!(true),
        |v| v["name"] = json!(""),
        |v| v["description"] = Value::Null,
        |v| v["required_credential_types"] = json!([]),
        |v| v["required_credential_types"] = json!(["MachineCredential", "MachineCredential"]),
        |v| v["required_credential_types"] = json!([null]),
        |v| v["allowed_machine_types"] = json!([]),
        |v| v["allowed_machine_types"] = json!(["AGENT"]),
        |v| v["machine_binding"]["binding_methods"] = json!(["MACHINE_KEY", "MACHINE_KEY"]),
        |v| v["machine_binding"]["proof_profiles"] = json!(["ENROLL_MANAGED_KEY"]),
        |v| v["machine_binding"]["proof_freshness"]["challenge_required"] = json!(false),
        |v| v["machine_binding"]["proof_freshness"]["audience_binding_required"] = json!(false),
        |v| v["machine_binding"]["proof_freshness"]["replay_detection_required"] = json!(false),
        |v| v["machine_binding"]["proof_freshness"]["max_proof_age_seconds"] = json!(0),
        |v| v["machine_binding"]["proof_freshness"]["unexpected"] = json!(true),
        |v| v["attestation_requirement"] = Value::Null,
        |v| v["status"] = json!("PROVISIONED"),
        |v| v["created_at"] = json!("yesterday"),
        |v| v["updated_at"] = json!("2026-10-31T00:00:00Z"),
        |v| v["updated_at"] = Value::Null,
        |v| v["trust_profile_id"] = json!(Uuid::nil()),
    ];
    for (index, mutation) in mutations.iter().enumerate() {
        let mut value = original.clone();
        mutation(&mut value);
        assert!(parse(&value).is_err(), "accepted mutation {index}");
    }
    let encoded = serde_json::to_string(&original).unwrap();
    let duplicate = encoded.replacen("{", "{\"status\":\"DRAFT\",", 1);
    assert!(MachineAuthenticationPolicy::from_trusted_document(duplicate.as_bytes()).is_err());
    assert!(MachineAuthenticationPolicy::from_trusted_document(&vec![b' '; 70_000]).is_err());
}

#[test]
fn valid_but_unimplemented_profile_selections_fail_closed() {
    for status in ["DRAFT", "ARCHIVED"] {
        let mut value = policy();
        value["status"] = json!(status);
        assert_eq!(
            parse(&value).unwrap().select_oid4vp_machine_key(),
            Err(MachinePolicyError::InactivePolicy)
        );
    }
    let mutations: &[fn(&mut Value)] = &[
        |v| v["machine_binding"]["binding_methods"] = json!(["CREDENTIAL_KEY"]),
        |v| v["machine_binding"]["proof_profiles"] = json!(["SIGNED_CHALLENGE"]),
        |v| {
            v["machine_binding"]["proof_freshness"]
                .as_object_mut()
                .unwrap()
                .remove("max_proof_age_seconds");
        },
        |v| v["machine_binding"]["proof_freshness"]["max_proof_age_seconds"] = Value::Null,
        |v| v["machine_binding"]["proof_freshness"]["max_proof_age_seconds"] = json!(29),
        |v| v["machine_binding"]["proof_freshness"]["max_proof_age_seconds"] = json!(601),
    ];
    for mutation in mutations {
        let mut value = policy();
        mutation(&mut value);
        assert_eq!(
            parse(&value).unwrap().select_oid4vp_machine_key(),
            Err(MachinePolicyError::UnsupportedSelection)
        );
    }
}

#[test]
fn mandatory_attestation_has_no_defaults_and_preserves_policy_set_selection() {
    let mut value = policy();
    value["attestation_requirement"] = json!({
        "required": true,
        "accepted_formats": ["EAT"],
        "verifier_trust_profile_id": "449aef04-6550-4ccd-bd6f-e3828d88776c",
        "max_age_seconds": 60,
        "challenge_required": true,
        "identity_key_binding_required": true
    });
    value["authorization_policy_set_id"] = json!("1266200b-2b58-48ba-8b68-9b241bb72672");
    let parsed = parse(&value).unwrap();
    let attestation = parsed.required_attestation().unwrap();
    assert_eq!(attestation.accepted_formats(), &["EAT"]);
    assert_eq!(attestation.max_age_seconds(), Some(60));
    assert!(parsed.authorization_policy_set_id().is_some());
    for name in [
        "accepted_formats",
        "verifier_trust_profile_id",
        "max_age_seconds",
        "challenge_required",
        "identity_key_binding_required",
    ] {
        let mut changed = value.clone();
        changed["attestation_requirement"]
            .as_object_mut()
            .unwrap()
            .remove(name);
        assert!(parse(&changed).is_err(), "accepted missing {name}");
        let mut changed = value.clone();
        changed["attestation_requirement"][name] = Value::Null;
        assert!(parse(&changed).is_err(), "accepted null {name}");
    }
    value["attestation_requirement"] = json!({"required": false});
    assert!(parse(&value).unwrap().required_attestation().is_none());
}

#[test]
fn key_validity_is_checked_at_the_exact_current_clock() {
    let mut value = source();
    value["machine_identity"]["identity_keys"][0]["valid_until"] = json!(now().to_rfc3339());
    assert_eq!(
        qualify(&value, &policy()),
        Err(MachinePolicyError::KeyNotCurrent)
    );
    value = source();
    value["machine_identity"]["identity_keys"][0]["valid_from"] =
        json!((now() + Duration::nanoseconds(1)).to_rfc3339());
    assert_eq!(
        qualify(&value, &policy()),
        Err(MachinePolicyError::KeyNotCurrent)
    );
    value["machine_identity"]["identity_keys"][0]["valid_from"] = json!(now().to_rfc3339());
    assert!(qualify(&value, &policy()).is_ok());
    value["machine_identity"]["identity_keys"][0]["valid_until"] = Value::Null;
    assert!(qualify(&value, &policy()).is_ok());
}

#[test]
fn inventory_service_accounts_are_not_promoted_to_real_machine_identities() {
    let mut value = source();
    for target in ["record", "configuration"] {
        value[target]["principal"]["type"] = json!("SERVICE_ACCOUNT");
    }
    assert_eq!(
        qualify(&value, &policy()),
        Err(MachinePolicyError::FullMachineIdentityRequired)
    );
    for status in ["PROVISIONED", "SUSPENDED", "REVOKED", "RETIRED"] {
        let mut changed = source();
        changed["machine_identity"]["status"] = json!(status);
        assert!(qualify(&changed, &policy()).is_err(), "accepted {status}");
    }
}

#[test]
fn tenant_type_deployment_and_current_state_must_match() {
    let mut changed_policy = policy();
    changed_policy["organization_id"] = json!(Uuid::new_v4());
    assert_eq!(
        qualify(&source(), &changed_policy),
        Err(MachinePolicyError::TenantMismatch)
    );
    changed_policy = policy();
    changed_policy["allowed_machine_types"] = json!(["VERIFICATION_APPLIANCE"]);
    assert_eq!(
        qualify(&source(), &changed_policy),
        Err(MachinePolicyError::MachineTypeDenied)
    );
    let mutations: &[fn(&mut Value)] = &[
        |v| {
            v["machine_identity"]
                .as_object_mut()
                .unwrap()
                .remove("assignments");
        },
        |v| v["machine_identity"]["assignments"]["deployment_profile_id"] = Value::Null,
        |v| v["machine_identity"]["assignments"]["deployment_profile_id"] = json!(Uuid::new_v4()),
        |v| {
            v["machine_identity"]["assignments"]["operator_organization_id"] = json!(Uuid::new_v4())
        },
        |v| v["machine_identity"]["suspended_at"] = json!("2026-11-01T00:00:00Z"),
        |v| v["machine_identity"]["revoked_at"] = json!("2026-11-01T00:00:00Z"),
        |v| v["machine_identity"]["retired_at"] = json!("2026-11-01T00:00:00Z"),
        |v| v["machine_identity"]["created_at"] = json!("2027-01-01T00:00:00Z"),
        |v| v["machine_identity"]["updated_at"] = json!("2027-01-01T00:00:00Z"),
    ];
    for mutation in mutations {
        let mut value = source();
        mutation(&mut value);
        assert!(qualify(&value, &policy()).is_err());
    }
}

#[test]
fn credentials_must_be_registered_nonempty_unique_and_bounded() {
    let mutations: &[fn(&mut Value)] = &[
        |v| {
            v["machine_identity"]
                .as_object_mut()
                .unwrap()
                .remove("credential_ids");
        },
        |v| v["machine_identity"]["credential_ids"] = json!([]),
        |v| v["machine_identity"]["credential_ids"] = json!([Uuid::nil()]),
        |v| v["machine_identity"]["credential_ids"] = json!(["not-an-id"]),
        |v| {
            v["machine_identity"]["credential_ids"] = json!([
                "0c53f847-e5f4-4209-916d-eb944a9d7802",
                "0c53f847-e5f4-4209-916d-eb944a9d7802"
            ])
        },
        |v| {
            v["machine_identity"]["credential_ids"] =
                json!((0..33).map(|_| Uuid::new_v4()).collect::<Vec<_>>())
        },
    ];
    for mutation in mutations {
        let mut value = source();
        mutation(&mut value);
        assert!(qualify(&value, &policy()).is_err());
    }
}

#[test]
fn policy_cannot_be_selected_before_its_recorded_update() {
    let mut value = policy();
    value["updated_at"] = json!((now() + Duration::nanoseconds(1)).to_rfc3339());
    assert_eq!(
        qualify(&source(), &value),
        Err(MachinePolicyError::FutureSourceState)
    );
    value["updated_at"] = json!(now().to_rfc3339());
    assert!(qualify(&source(), &value).is_ok());
}

#[test]
fn digest_is_stable_for_object_order_and_binds_all_policy_requirements() {
    let original = policy();
    let canonical = parse(&original).unwrap();
    let pretty = serde_json::to_vec_pretty(&original).unwrap();
    assert_eq!(
        canonical.digest(),
        MachineAuthenticationPolicy::from_trusted_document(&pretty)
            .unwrap()
            .digest()
    );
    for field in [
        "name",
        "required_credential_types",
        "authorization_policy_set_id",
    ] {
        let mut changed = original.clone();
        changed[field] = match field {
            "name" => json!("Different policy name"),
            "required_credential_types" => json!(["MachineCredential", "AdditionalCredential"]),
            _ => json!(Uuid::new_v4()),
        };
        assert_ne!(canonical.digest(), parse(&changed).unwrap().digest());
    }
}
