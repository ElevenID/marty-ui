//! Count/projection regression, not a substitute for authenticated admission.
//! The fixture uses the actual typed selection, fixed bundle layers and binding
//! methods. Its evidence bytes are deliberately inert and grant no authority.
use super::*;
use crate::{installer_application, installer_features as features};
use std::os::unix::fs::PermissionsExt;

fn private(path: &Path) -> BoundFile {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path, path.file_name().unwrap().as_encoded_bytes()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    installer_application::bound(path.to_owned()).unwrap()
}

fn evidence(inputs: &mut ComposeInputs, name: &str) {
    inputs
        .bound_inputs
        .push(private(&inputs.installation.join(name)));
}

fn layer(bundle: &Path, name: &str) -> BoundFile {
    let path = bundle.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    // The prepared bundle renames the production source to docker-compose.yml.
    let source_name = if name == "docker-compose.yml" {
        "docker-compose.selfhost.prod.yml"
    } else {
        name
    };
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(source_name);
    fs::copy(&source, &path)
        .unwrap_or_else(|error| panic!("fixture layer {}: {error}", source.display()));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    installer_application::bundle_bound(bundle, name).unwrap()
}

fn complete_selection(installation: &Path) -> features::Selection {
    let configuration = json!({
        "schema":"elevenid.installer-feature-profile/v1",
        "agent_trust":{
            "organization_id":"00000000-0000-4000-8000-000000000001",
            "enrollment":{"audience":"https://api.example.test","policy_profile":"urn:marty:managed-key-enrollment-policy:v1","policy_revision":1},
            "approval":{"profile":"urn:marty:organization-approval:v1","version":"1.0.0","status_ref":"https://api.example.test/v1/delegation/status"},
            "delegated_use":{"activation":"configured","configuration":{
                "deployment_profile_id":"00000000-0000-4000-8000-000000000002",
                "delegation_policy_id":"00000000-0000-4000-8000-000000000003",
                "flow_definition_id":"verification","flow_definition_version":1,
                "public_base_url":"https://api.example.test","public_caller":true,
                "verifier_did":"did:web:api.example.test","verifier_display_name":"Fixture",
                "receipt_issuer_did":"did:web:api.example.test","receipt_algorithm":"ES256",
                "receipt_key_id":"did:web:api.example.test#receipt","receipt_key_reference":"fixture-receipt",
                "receipt_public_jwk_file":installation.join("owner-inputs/receipt.json"),
                "workload_bindings_file":installation.join("owner-inputs/workloads.json")
            }}
        },
        "workflows":{
            "public_verification":{"activation":"configured","application_origin":"https://console.example.test","catalog_file":installation.join("owner-inputs/catalog.json")},
            "wallet_governance":{"flow_producer_id":"flow"},
            "verification_prerequisite":true,"application_ownership":true,
            "external_associations":true,"external_observations":true
        }
    });
    serde_json::from_value(json!({
        "schema":"elevenid.installer-feature-profile-selection/v1",
        "installation_id":"00000000-0000-4000-8000-000000000001",
        "source_sha256":sha256(&serde_json::to_vec(&configuration).unwrap()),
        "configuration":configuration,"imports":{}
    }))
    .unwrap()
}

fn complete_profile(installation: &Path, cloudflare: bool) -> ComposeInputs {
    let bundle = installation.join("bundle");
    let mut inputs = ComposeInputs {
        installation: installation.into(),
        project: format!("marty-install-{}", "a".repeat(32)),
        files: Vec::new(),
        bound_inputs: Vec::new(),
        environment: private(&installation.join("evidence/application.env")),
        profiles: vec!["setup".into()],
        services: vec!["installer-feature-identities".into()],
        approved_images: BTreeSet::new(),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots: BTreeSet::new(),
        readonly_bind_roots: BTreeSet::new(),
        allowed_loopback_ports: BTreeSet::new(),
        ingress_listener: None,
        prior: None,
    };
    for name in [
        "docker-compose.yml",
        "docker-compose.selfhost.openbao.yml",
        "deploy-config/compose/selfhost-installer/compose.bootstrap.yml",
        "deploy-config/compose/selfhost-installer/compose.installer.yml",
        "deploy-config/compose/selfhost-installer/compose.runtime.yml",
        crate::installer_hosting::EXTERNAL_OIDC_APPLICATION_LAYER,
        crate::installer_oidc::LAYER,
    ] {
        inputs.files.push(layer(&bundle, name));
    }
    // ACME and the connector are mutually exclusive hosting selections.
    if cloudflare {
        inputs.files.push(private(
            &installation.join("downloads/hosting-cloudflare/runtime/compose.cloudflare.yml"),
        ));
    } else {
        for name in ["compose.acme.yml", "compose.acme-runtime.yml"] {
            inputs.files.push(layer(
                &bundle,
                &format!("deploy-config/compose/selfhost-installer/{name}"),
            ));
        }
    }
    let base_layer = if cloudflare {
        "compose.generation-managed.yml"
    } else {
        "compose.generation.yml"
    };
    inputs.files.push(layer(
        &bundle,
        &format!("deploy-config/compose/selfhost-installer/{base_layer}"),
    ));
    inputs.files.push(layer(
        &bundle,
        &format!("{}compose.identities-renew.yml", features::LAYER_ROOT),
    ));
    // The real feature layer projection must preserve this mandatory final
    // override; it cannot silently append a signed/default image after it.
    let development_layer =
        private(&installation.join("evidence/development-signing-image.compose.json"));
    inputs.files.push(development_layer.clone());

    for name in [
        "external-oidc-selection.json",
        "hosting-input.json",
        "hosting-selection.json",
        "application-settings-input.json",
        "application-settings-selection.json",
        "development-signing-image-artifact.json",
        "development-signing-image-binding.json",
    ] {
        evidence(&mut inputs, &format!("evidence/{name}"));
    }
    if cloudflare {
        evidence(&mut inputs, "secrets/cloudflare_tunnel_token");
        evidence(&mut inputs, "evidence/hosting-cloudflare-addon.json");
        for name in [
            "selfhost-cloudflare-images.json",
            "selfhost-cloudflare-addon.zip",
        ] {
            evidence(&mut inputs, &format!("downloads/hosting-cloudflare/{name}"));
        }
        // The SBOM bytes are covered by the receipt; its two attestations are
        // still individual inputs, exactly as the existing add-on binder does.
        for name in [
            "selfhost-cloudflare-images.json",
            "selfhost-cloudflare-addon.zip",
            "cloudflared_wrapper.sbom.cdx.json",
        ] {
            for suffix in [".sigstore.json", ".provenance.jsonl"] {
                evidence(
                    &mut inputs,
                    &format!("downloads/hosting-cloudflare/{name}{suffix}"),
                );
            }
        }
        evidence(
            &mut inputs,
            "downloads/hosting-cloudflare/runtime/scripts/cloudflared-selfhost.sh",
        );
    }
    assert_eq!(inputs.bound_inputs.len(), if cloudflare { 18 } else { 7 });

    let selection = complete_selection(installation);
    let feature_layers = selection.layers();
    assert_eq!(feature_layers.len(), 12);
    for name in feature_layers.into_iter().chain([
        "deploy-config/compose/selfhost-installer/feature-profile/compose.runtime.yml",
        "deploy-config/compose/selfhost-installer/feature-profile/compose.agent-runtime.yml",
        "deploy-config/compose/selfhost-installer/feature-profile/compose.delegated-use-runtime.yml",
    ]) {
        layer(&bundle, name);
    }
    selection.append_layers(&mut inputs, &bundle).unwrap();
    assert_eq!(inputs.files.last().unwrap().path, development_layer.path);
    for name in [
        features::SOURCE,
        features::RECORD,
        features::CREDENTIALS,
        features::TRANSPORT,
        features::ACTIVATION,
        features::IDENTITY_SELECTION,
        features::generations::RECORD,
    ] {
        private(&installation.join("evidence").join(name));
    }
    let before = inputs.bound_inputs.len();
    selection.bind_inputs(&mut inputs).unwrap();
    assert_eq!(inputs.bound_inputs.len(), before + 7);
    selection.bind_inputs(&mut inputs).unwrap();
    assert_eq!(inputs.bound_inputs.len(), before + 7);

    evidence(
        &mut inputs,
        "evidence/generation-feature-000001-binding.json",
    );
    let scope = crate::installer_generation_maintenance::attempt::Attempt::new(2, 1);
    let plan = scope.record(if cloudflare {
        "managed-renewal-plan"
    } else {
        "public-ingress-plan"
    });
    evidence(&mut inputs, &format!("evidence/{plan}"));
    if !cloudflare {
        evidence(
            &mut inputs,
            &format!(
                "evidence/{}",
                crate::installer_public_ingress::PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD
            ),
        );
    }
    evidence(
        &mut inputs,
        &format!("evidence/{}", scope.record("feature-renewal")),
    );
    evidence(
        &mut inputs,
        "evidence/generation-feature-000002-preparation.json",
    );
    for name in crate::installer_feature_identity::renewal_input_names() {
        evidence(
            &mut inputs,
            &format!("feature-profile-generations/000002/input/{name}"),
        );
    }
    inputs
}

#[test]
fn complete_feature_profile_fits_closed_layer_and_evidence_boundaries() {
    for (cloudflare, file_count, input_count) in [(true, 26, 34), (false, 27, 24)] {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let inputs = complete_profile(root.path(), cloudflare);
        assert_eq!(inputs.files.len(), file_count);
        assert_eq!(inputs.bound_inputs.len(), input_count);
        assert_eq!(
            inputs
                .files
                .iter()
                .map(|f| &f.path)
                .collect::<BTreeSet<_>>()
                .len(),
            file_count
        );
        assert_eq!(
            inputs
                .bound_inputs
                .iter()
                .map(|f| &f.path)
                .collect::<BTreeSet<_>>()
                .len(),
            input_count
        );
        assert!(input_counts_allowed(file_count, input_count, true));
        assert!(!input_counts_allowed(file_count, input_count, false));
    }
    assert!(input_counts_allowed(
        MAX_FEATURE_COMPOSE_FILES,
        MAX_FEATURE_BOUND_INPUTS,
        true
    ));
    assert!(!input_counts_allowed(
        MAX_FEATURE_COMPOSE_FILES + 1,
        0,
        true
    ));
    assert!(!input_counts_allowed(1, MAX_FEATURE_BOUND_INPUTS + 1, true));
    assert!(input_counts_allowed(10, 24, false));
    assert!(!input_counts_allowed(11, 24, false));
    assert!(!input_counts_allowed(10, 25, false));
    assert!(!input_counts_allowed(0, 0, true));
}
