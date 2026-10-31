use super::*;
use crate::installer_compose::{BoundFile, ContainerIdentity, ProjectResources, SetupExecution};
use std::{collections::BTreeSet, path::PathBuf};

#[test]
fn registration_failure_still_revokes_and_revocation_failure_blocks_completion() {
    let mut calls = Vec::new();
    let result = with_revocation(
        &mut calls,
        |calls| {
            calls.push("register");
            Err::<(), _>("public API rejected registration".into())
        },
        |calls| {
            calls.push("revoke");
            Ok(())
        },
    );
    assert_eq!(calls, ["register", "revoke"]);
    assert_eq!(result.unwrap_err(), "public API rejected registration");
    let mut calls = Vec::new();
    let result = with_revocation(
        &mut calls,
        |calls| {
            calls.push("register");
            Ok(())
        },
        |calls| {
            calls.push("revoke");
            Err("unverified cleanup".into())
        },
    );
    assert_eq!(calls, ["register", "revoke"]);
    assert_eq!(result.unwrap_err(), REVOCATION_UNCERTAIN);
}

#[test]
fn credential_receipt_binds_scope_lifetime_and_every_owner_identity() {
    let installation = Uuid::new_v4();
    let organization = Uuid::new_v4();
    let request = Uuid::new_v4();
    let key = Uuid::new_v4();
    let intent = json!({"schema":"elevenid.installer-organization-bootstrap-intent/v1",
        "context":{"installation_id":installation,"organization_id":organization,"request_id":request},
        "created_at":"2026-10-31T10:00:00Z","expires_at":"2026-10-31T10:15:00Z"});
    let intent_bytes = encode(&intent).unwrap();
    let receipt = json!({"schema":"elevenid.installer-organization-bootstrap-receipt/v1",
        "operation":"issued","installation_id":installation,"organization_id":organization,
        "request_id":request,"api_key_id":key,"intent_sha256":hash(&intent_bytes),
        "scopes":["keys:write"],"expires_at":"2026-10-31T10:15:00Z",
        "revoked":false,"automatic_replay_allowed":false});
    assert_eq!(
        validate_key_receipt(
            &receipt,
            &intent_bytes,
            request,
            installation,
            organization,
            false
        )
        .unwrap(),
        key
    );
    for (field, replacement) in [
        ("installation_id", json!(Uuid::new_v4())),
        ("organization_id", json!(Uuid::new_v4())),
        ("request_id", json!(Uuid::new_v4())),
        ("scopes", json!(["keys:write", "admin"])),
        ("intent_sha256", json!("0".repeat(64))),
        ("revoked", json!(true)),
        ("automatic_replay_allowed", json!(true)),
        ("expires_at", json!("2026-11-01T10:15:00Z")),
    ] {
        let mut changed = receipt.clone();
        changed[field] = replacement;
        assert!(
            validate_key_receipt(
                &changed,
                &intent_bytes,
                request,
                installation,
                organization,
                false
            )
            .is_err(),
            "{field}"
        );
    }
    let mut changed_intent = intent;
    changed_intent["expires_at"] = json!("2026-10-31T11:00:00Z");
    let changed_bytes = encode(&changed_intent).unwrap();
    let mut changed = receipt;
    changed["intent_sha256"] = json!(hash(&changed_bytes));
    changed["expires_at"] = changed_intent["expires_at"].clone();
    assert!(validate_key_receipt(
        &changed,
        &changed_bytes,
        request,
        installation,
        organization,
        false
    )
    .is_err());
}

fn identity(service: &str, setup: bool) -> ContainerIdentity {
    ContainerIdentity {
        id: if setup { "b" } else { "a" }.repeat(64),
        service: service.into(),
        image: format!("ghcr.io/elevenid/services@sha256:{}", "c".repeat(64)),
        config_hash: "d".repeat(64),
        setup,
        setup_execution: setup.then(|| SetupExecution {
            started_at: "2026-10-31T10:00:01Z".into(),
            finished_at: "2026-10-31T10:00:02Z".into(),
            completed_without_restart: true,
        }),
        health_required: false,
        cap_add: BTreeSet::new(),
        cap_drop: BTreeSet::from(["ALL".into()]),
        read_only: true,
        memory_limit: 536_870_912,
    }
}

fn session_fixture() -> (Vec<u8>, SavedSession, SessionExtension, Vec<u8>) {
    let installation = PathBuf::from("/private/installation");
    let image = identity("organization", false).image;
    let files = vec![BoundFile {
        path: installation.join("bundle/docker-compose.yml"),
        sha256: "1".repeat(64),
    }];
    let environment = BoundFile {
        path: installation.join("evidence/application.env"),
        sha256: "2".repeat(64),
    };
    let mut inputs = ComposeInputs {
        installation: installation.clone(),
        project: "marty-install-example".into(),
        files,
        bound_inputs: vec![],
        environment,
        profiles: vec!["setup".into(), "installer-init".into()],
        services: vec![],
        approved_images: BTreeSet::from([image.clone()]),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots: BTreeSet::from([installation.join("state")]),
        readonly_bind_roots: BTreeSet::from([
            installation.join("bundle"),
            installation.join("evidence"),
        ]),
        allowed_loopback_ports: BTreeSet::from([8443]),
        prior: None,
    };
    let model = json!({"name":inputs.project,"services":{"organization":{"image":image}}});
    let receipt = ComposeReceipt {
        schema: "elevenid.installer-compose-operation/v1".into(),
        project: inputs.project.clone(),
        engine_id: "engine".into(),
        operation: "maintenance-checkpoint".into(),
        configuration_sha256: crate::installer_compose::model_sha256(&model).unwrap(),
        input_files: inputs
            .files
            .iter()
            .chain([&inputs.environment])
            .map(|file| (file.path.clone(), file.sha256.clone()))
            .collect(),
        command_succeeded: true,
        client_exit_code: Some(0),
        failure_class: None,
        observation_validated: true,
        resources: Some(ProjectResources {
            containers: BTreeMap::from([("organization".into(), identity("organization", false))]),
            networks: BTreeMap::from([("marty-install-example_default".into(), "f".repeat(64))]),
            volumes: BTreeSet::new(),
        }),
        status: vec![json!({"Service":"organization","ID":"a".repeat(64),"State":"running"})],
        installation_ready: false,
    };
    inputs.prior = Some(receipt.clone());
    let previous = SavedSession {
        schema: "elevenid.installer-compose-session/v1".into(),
        installation_id: Uuid::new_v4().to_string(),
        inputs,
        model,
        configuration_sha256: receipt.configuration_sha256.clone(),
        receipt,
    };
    let original = encode(&previous).unwrap();
    let mut current = previous.clone();
    current.inputs.files.push(BoundFile {
        path: installation.join("bundle").join(LAYER),
        sha256: "3".repeat(64),
    });
    current
        .inputs
        .writable_bind_roots
        .insert(installation.join(OUTPUT));
    current.model["services"][ISSUE] = json!({"image":image,"command":["issue"]});
    current.model["services"][REVOKE] = json!({"image":image,"command":["revoke"]});
    current.configuration_sha256 = crate::installer_compose::model_sha256(&current.model).unwrap();
    current.receipt.configuration_sha256 = current.configuration_sha256.clone();
    current.receipt.operation = format!("setup-{ISSUE}");
    current
        .receipt
        .resources
        .as_mut()
        .unwrap()
        .containers
        .insert(ISSUE.into(), identity(ISSUE, true));
    current
        .receipt
        .status
        .push(json!({"Service":ISSUE,"ID":"b".repeat(64),"State":"exited","ExitCode":0}));
    current.inputs.prior = Some(current.receipt.clone());
    let result = encode(&current.receipt).unwrap();
    let extension = SessionExtension {
        schema: "elevenid.installer-organization-session/v1".into(),
        original_session_sha256: hash(&original),
        predecessor_sha256: hash(&original),
        service: ISSUE.into(),
        compose_result_sha256: hash(&result),
        session: current,
    };
    (original, previous, extension, result)
}

#[test]
fn session_extension_preserves_original_runtime_and_exact_setup_result() {
    let (original, previous, extension, result) = session_fixture();
    validate_extension(&extension, &original, &original, &previous, &result, ISSUE).unwrap();
    let value = serde_json::to_value(&extension).unwrap();
    for pointer in [
        "/original_session_sha256",
        "/predecessor_sha256",
        "/compose_result_sha256",
        "/session/inputs/project",
        "/session/inputs/environment/sha256",
        "/session/receipt/resources/containers/organization/id",
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("changed");
        let changed: SessionExtension = serde_json::from_value(changed).unwrap();
        assert!(
            validate_extension(&changed, &original, &original, &previous, &result, ISSUE).is_err(),
            "{pointer}"
        );
    }
    let mut changed: SessionExtension = serde_json::from_value(value).unwrap();
    changed
        .session
        .inputs
        .writable_bind_roots
        .insert(PathBuf::from("/private/foreign"));
    assert!(validate_extension(&changed, &original, &original, &previous, &result, ISSUE).is_err());
    assert!(
        validate_extension(&extension, &original, &original, &previous, &result, REVOKE).is_err()
    );
    let mut reordered: SessionExtension = decode(&encode(&extension).unwrap()).unwrap();
    reordered.session.inputs.files.swap(0, 1);
    assert!(
        validate_extension(&reordered, &original, &original, &previous, &result, ISSUE).is_err()
    );
    let mut relocated: SessionExtension = decode(&encode(&extension).unwrap()).unwrap();
    relocated.session.inputs.files[1].path = PathBuf::from("/private/foreign").join(LAYER);
    assert!(
        validate_extension(&relocated, &original, &original, &previous, &result, ISSUE).is_err()
    );
}
