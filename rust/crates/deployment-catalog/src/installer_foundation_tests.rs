use super::*;
use crate::installer_state::{Identity, RuntimeBinding, RuntimeProfile};
use serde_json::json;
use std::{fs as files, os::unix::fs::PermissionsExt, process::Command};

fn arn(index: usize) -> String {
    format!("arn:aws:kms:us-east-2:123456789012:key/10000000-0000-4000-8000-{index:012}")
}
fn private(path: &Path) {
    files::create_dir(path).unwrap();
    files::set_permissions(path, files::Permissions::from_mode(0o700)).unwrap();
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    files::write(path, bytes).unwrap();
    files::set_permissions(path, files::Permissions::from_mode(mode)).unwrap();
}
fn configuration(root: &Path) -> Configuration {
    let tls = SELFHOST_ROLES
        .iter()
        .map(|role| role.name)
        .chain(["installer-ingress"])
        .enumerate()
        .map(|(index, name)| {
            (
                name.into(),
                TlsInput {
                    region: "us-east-2".into(),
                    key_arn: arn(index + 1),
                    certificate_file: root.join("leaf.pem"),
                },
            )
        })
        .collect();
    let workload_identities = WORKLOADS
        .iter()
        .map(|name| {
            (
                name.to_string(),
                IdentityInput {
                    role_arn: format!("arn:aws:iam::123456789012:role/{name}"),
                    directory: root.join("identities").join(name),
                },
            )
        })
        .collect();
    Configuration {
        schema: "elevenid.installer-foundation/v1".into(),
        foundation: "aws-kms".into(),
        public_origin: "https://localhost:18443".into(),
        external_oidc: ExternalOidc {
            issuer_url: "https://identity.example.invalid".into(),
            client_id: "marty-fixture".into(),
            admin_email: "operator@example.invalid".into(),
            client_secret_file: None,
            trusted_endpoint_origins: vec!["https://keys.example.invalid".into()],
            allowed_algorithms: vec!["RS256".into()],
        },
        workload_ca_file: root.join("ca.pem"),
        ingress_ca_file: root.join("ca.pem"),
        tls,
        signing_grant_authorities_file: root.join("grants.json"),
        integration_secret: KeyReference {
            region: "us-east-2".into(),
            key_arn: arn(30),
        },
        notification_secret: KeyReference {
            region: "us-east-2".into(),
            key_arn: arn(31),
        },
        workload_identities,
        registration_file: root.join("registration.json"),
    }
}

#[test]
fn foundation_configuration_is_closed_and_reuses_aws_reference_validation() {
    let original = configuration(Path::new("/private/inputs"));
    original.validate().unwrap();
    for change in 0..12 {
        let mut config = original.clone();
        match change {
            0 => config.public_origin = "https://localhost:443".into(),
            1 => config.public_origin.push_str("/path"),
            2 => config.external_oidc.issuer_url = "http://identity.example.invalid".into(),
            3 => config.external_oidc.trusted_endpoint_origins[0].push_str("/jwks"),
            4 => config.external_oidc.allowed_algorithms = vec!["none".into()],
            5 => config.external_oidc.allowed_algorithms = vec!["RS256".into(), "RS256".into()],
            6 => config.integration_secret.key_arn = "alias/mutable".into(),
            7 => config.notification_secret.region = "us-west-2".into(),
            8 => {
                config.tls.get_mut("gateway-client").unwrap().key_arn =
                    config.integration_secret.key_arn.clone()
            }
            9 => {
                config
                    .workload_identities
                    .get_mut("gateway")
                    .unwrap()
                    .role_arn = config.workload_identities["auth"].role_arn.clone()
            }
            10 => {
                config.workload_identities.remove("db-migrate");
            }
            11 => {
                config
                    .workload_identities
                    .get_mut("gateway")
                    .unwrap()
                    .role_arn = "arn:foreign:iam::123456789012:role/gateway".into()
            }
            _ => unreachable!(),
        }
        assert!(config.validate().is_err(), "accepted invalid case {change}");
    }
    let mut value = serde_json::to_value(&original).unwrap();
    value["access_key_id"] = json!("not-a-supported-authority");
    assert!(decode::<Configuration>(&serde_json::to_vec(&value).unwrap()).is_err());
}

fn openssl(root: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "public certificate fixture creation failed"
    );
}
fn inputs(root: &Path) -> (PathBuf, Configuration) {
    // Test-only certificate producer; production accepts public preprovisioned
    // certificates and never creates or imports local private signing keys.
    openssl(
        root,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=fixture-root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
        ],
    );
    openssl(
        root,
        &[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
        ],
    );
    write(&root.join("extensions.cnf"), b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n", 0o600);
    openssl(
        root,
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "extensions.cnf",
            "-out",
            "leaf.pem",
        ],
    );
    for name in ["ca.pem", "leaf.pem"] {
        files::set_permissions(root.join(name), files::Permissions::from_mode(0o600)).unwrap();
    }
    let config = configuration(root);
    let mut keys = serde_json::Map::new();
    for (index, origin) in [
        "gateway_service",
        "gateway_issuer_did",
        "flow_wallet_request",
        "issuance_credential",
        "issuance_canvas",
        "issuance_readiness",
        "issuance_passport",
    ]
    .into_iter()
    .enumerate()
    {
        keys.insert(origin.into(), json!(arn(100 + index)));
    }
    write(&config.signing_grant_authorities_file, &serde_json::to_vec(&json!({"schema":"marty.aws-signing-grant-authorities/v1","region":"us-east-2","keys":keys})).unwrap(), 0o600);
    write(&config.registration_file, &serde_json::to_vec(&json!({"services":[{"id":"tenant-aws", "name":"Existing AWS key", "service_type":"aws-kms", "region":"us-east-2", "auth_mode":"iam_role", "key_reference":arn(200), "algorithms":["ES256"], "key_purposes":["vc_jwt_issuer"]}]})).unwrap(), 0o600);
    private(&root.join("identities"));
    for identity in config.workload_identities.values() {
        files::create_dir(&identity.directory).unwrap();
        files::set_permissions(&identity.directory, files::Permissions::from_mode(0o755)).unwrap();
        write(
            &identity.directory.join("token"),
            b"private-external-web-identity-sentinel",
            0o444,
        );
    }
    let path = root.join("foundation.json");
    write(&path, &serde_json::to_vec(&config).unwrap(), 0o600);
    (path, config)
}
fn fresh(root: &Path) -> (PathBuf, InstallerState) {
    let installation = root.join("installation");
    let mut state = InstallerState::create_with_runtime(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "fixture-engine".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootful,
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.create_private_directory("downloads").unwrap();
    state
        .persist_initial_creation_receipt(&installation)
        .unwrap();
    state.advance(Phase::Verified).unwrap();
    (installation, state)
}

#[test]
fn imported_generation_is_immutable_without_fabricated_network_or_local_operator() {
    let temp = tempfile::tempdir().unwrap();
    files::set_permissions(temp.path(), files::Permissions::from_mode(0o700)).unwrap();
    let (input, config) = inputs(temp.path());
    let (installation, mut state) = fresh(temp.path());
    select(&input, &installation, &mut state).unwrap();
    let selected = state.with_inspection(load).unwrap().unwrap();
    let selection_bytes = state.with_inspection(|s| s.read_evidence(RECORD)).unwrap();
    assert!(!std::str::from_utf8(&selection_bytes)
        .unwrap()
        .contains("private-external-web-identity-sentinel"));
    assert_eq!(
        selected.registration_sha256,
        digest(&files::read(&config.registration_file).unwrap())
    );
    state.advance(Phase::Provisioning).unwrap();
    state.generate_external_auth_credentials().unwrap();
    state
        .persist_credential_creation_receipt(&installation)
        .unwrap();
    selected.import_inputs(&mut state).unwrap();
    assert!(!installation.join("operator-password").exists());
    assert!(!installation.join("openbao-state").exists());
    let names: Vec<_> = files::read_dir(installation.join("secrets"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(!names.iter().any(|name| name.contains("openbao")
        || name.contains("keycloak")
        || name.contains("_tls_kms_token")));
    let model = |root: &str| {
        let declarations: serde_json::Map<String, Value> = names
            .iter()
            .map(|name| {
                (
                    name.clone(),
                    json!({"file":installation.join(root).join(name)}),
                )
            })
            .collect();
        json!({"name":state.journal().compose_project(),"services":{"fixture":{"secrets":names.iter().map(|name| json!({"source":name})).collect::<Vec<_>>() }},"secrets":declarations})
    };
    let source_model = model("secrets");
    let selected_model = model("application-generation");
    let source_env = format!(
        "SELFHOST_SECRET_DIR='{}'\n",
        installation.join("secrets").display()
    )
    .into_bytes();
    state
        .write_evidence("application-source.env", &source_env)
        .unwrap();
    let generation =
        crate::installer_generation_binding::stage(&installation, &mut state, &source_model, None)
            .unwrap();
    assert!(generation.imported_foundation() && generation.network_id.is_none());
    assert!(
        generation
            .files
            .values()
            .all(|file| file.source
                == crate::installer_generation_binding::GenerationSource::Original)
    );
    state
        .write_evidence(
            "application.env",
            &crate::installer_application_env::select_generation(&source_env, &installation)
                .unwrap(),
        )
        .unwrap();
    state
        .write_evidence(
            "application-native-model.json",
            &serde_json::to_vec(&selected_model).unwrap(),
        )
        .unwrap();
    crate::installer_generation_binding::publish_selection(&installation, &mut state, &generation)
        .unwrap();
    let id = state.journal().installation_id().to_string();
    assert_eq!(
        crate::installer_generation_binding::load_verified(&installation, &id, "fixture-engine")
            .unwrap(),
        Some(generation.clone())
    );
    let gateway = &config.workload_identities["gateway"].directory;
    write(
        &temp.path().join("new-token"),
        b"refreshed-external-web-identity-sentinel",
        0o444,
    );
    files::rename(temp.path().join("new-token"), gateway.join("token")).unwrap();
    crate::installer_generation_binding::verify(&installation, &generation).unwrap();
    assert!(select(&input, &installation, &mut state).is_err());
    let changed = installation.join("secrets/signing_grant_authorities");
    files::set_permissions(&changed, files::Permissions::from_mode(0o600)).unwrap();
    write(&changed, b"changed", 0o444);
    assert!(crate::installer_generation_binding::verify(&installation, &generation).is_err());
}

#[test]
fn invalid_grant_configuration_is_refused_before_provisioning_or_selection_receipt() {
    let temp = tempfile::tempdir().unwrap();
    files::set_permissions(temp.path(), files::Permissions::from_mode(0o700)).unwrap();
    let (input, config) = inputs(temp.path());
    let (installation, mut state) = fresh(temp.path());
    write(&config.signing_grant_authorities_file, b"{\"schema\":\"marty.aws-signing-grant-authorities/v1\",\"region\":\"us-east-2\",\"keys\":{}}", 0o600);
    assert!(select(&input, &installation, &mut state).is_err());
    assert_eq!(state.journal().phase(), Phase::Verified);
    assert!(!installation.join("evidence").join(RECORD).exists());
    assert!(!installation.join("secrets").exists());
}

#[test]
fn workload_projection_refuses_parent_child_and_foreign_credential_mounts() {
    let temp = tempfile::tempdir().unwrap();
    files::set_permissions(temp.path(), files::Permissions::from_mode(0o700)).unwrap();
    let (input, config) = inputs(temp.path());
    let (installation, mut state) = fresh(temp.path());
    select(&input, &installation, &mut state).unwrap();
    let selected = state.with_inspection(load).unwrap().unwrap();
    let gateway = &config.workload_identities["gateway"];
    let model = json!({"services":{"gateway":{
        "environment":{
            "AWS_EC2_METADATA_DISABLED":"true",
            "AWS_ROLE_ARN":gateway.role_arn,
            "AWS_WEB_IDENTITY_TOKEN_FILE":"/run/aws-identity/token"
        },
        "volumes":[{"type":"bind","source":gateway.directory,
            "target":"/run/aws-identity","read_only":true}]
    }}});
    selected.validate_model(&model).unwrap();
    for source in [
        gateway.directory.parent().unwrap().to_path_buf(),
        temp.path().to_path_buf(),
        gateway.directory.join("token"),
        config.workload_identities["auth"].directory.clone(),
    ] {
        let mut leaked = model.clone();
        leaked["services"]["gateway"]["volumes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"bind","source":source,"target":"/extra","read_only":true}));
        assert!(selected.validate_model(&leaked).is_err());
    }
    let mut foreign = model;
    let gateway = foreign["services"]
        .as_object_mut()
        .unwrap()
        .remove("gateway")
        .unwrap();
    foreign["services"]["ui"] = gateway;
    assert!(selected.validate_model(&foreign).is_err());
}
