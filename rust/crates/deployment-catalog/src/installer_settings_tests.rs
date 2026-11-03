use super::*;
use crate::installer_state::{Identity, RuntimeBinding, RuntimeProfile};
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};

const SECRET: &[u8] = b"synthetic-private-credential-0123456789abcdef\n";

fn public_modulus() -> String {
    use base64::Engine as _;
    let mut bytes = vec![0x80; 256];
    bytes[255] = 0x81;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn write(path: &Path, bytes: &[u8], mode: u32) {
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn configuration(values: Value, secret_files: Value) -> Configuration {
    serde_json::from_value(json!({"schema":SCHEMA,"values":values,"secret_files":secret_files}))
        .unwrap()
}

fn source(root: &Path, config: &Configuration) -> PathBuf {
    let path = root.join("application.json");
    write(&path, &serde_json::to_vec(config).unwrap(), 0o600);
    path
}

fn smtp(root: &Path) -> Configuration {
    let secret = root.join("smtp-password");
    write(&secret, SECRET, 0o600);
    configuration(
        json!({"KEYCLOAK_SMTP_HOST":"smtp.mail.test","KEYCLOAK_SMTP_FROM":"noreply@mail.test",
        "KEYCLOAK_SMTP_USERNAME":"mailer","KEYCLOAK_VERIFY_EMAIL":true,"KEYCLOAK_RESET_PASSWORD_ENABLED":true}),
        json!({"smtp_password":secret}),
    )
}

fn state(root: &Path) -> (PathBuf, InstallerState) {
    let installation = root.join("installation");
    let mut state = InstallerState::create(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    (installation, state)
}

fn provision(state: &mut InstallerState) {
    state.advance(Phase::Provisioning).unwrap();
    state
        .generate_local_credentials(
            &json!({"passwordPolicy":crate::installer_state::PASSWORD_POLICY}),
        )
        .unwrap();
    state.prepare_application_storage().unwrap();
}

#[test]
fn defaults_restore_registration_without_advertising_unconfigured_mail() {
    let prepared = prepare(None, true).unwrap();
    let env = prepared.configuration.environment(true).unwrap();
    assert_eq!(env["KEYCLOAK_USER_REGISTRATION_ENABLED"], "true");
    for key in [
        "KEYCLOAK_VERIFY_EMAIL",
        "KEYCLOAK_RESET_PASSWORD_ENABLED",
        "KEYCLOAK_SOCIAL_LOGIN_ENABLED",
        "ORGANIZATION_CREATION_ENABLED",
        "CANVAS_PORTABLE_INTEGRATION_ENABLED",
        "CANVAS_MIRROR_WORKER_ENABLED",
    ] {
        assert_eq!(env[key], "false");
    }
    assert_eq!(prepared.secrets.len(), OPTIONAL_INTEGRATION_SECRETS.len());
    assert!(prepared.secrets.values().all(|v| v == &fingerprint(&[])));
}

#[test]
fn legacy_journal_remains_readable_but_a_partial_new_selection_is_not_adopted() {
    let root = private_root();
    let (installation, mut state) = state(root.path());
    let original = std::fs::read(installation.join("installation.json")).unwrap();
    assert!(state.with_inspection(load).unwrap().is_none());
    verify_generation(&installation, &BTreeMap::new()).unwrap();
    assert_eq!(
        std::fs::read(installation.join("installation.json")).unwrap(),
        original
    );
    let prepared = prepare(None, true).unwrap();
    let mut secrets = prepared.secrets;
    for name in [
        "passport_tenant_api_keys",
        "personalization_bureau_api_key",
        "canvas_credentials_api_token",
    ] {
        secrets.remove(name);
    }
    assert_eq!(secrets.len(), 6);
    let record = Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        source_sha256: digest(&prepared.raw),
        configuration: prepared.configuration,
        managed_keycloak: true,
        secrets,
    };
    let raw = serde_json::to_vec(&record).unwrap();
    state.write_evidence(SOURCE, &prepared.raw).unwrap();
    state.write_evidence(RECORD, &raw).unwrap();
    state.bind_application_settings(&digest(&raw)).unwrap();
    assert!(state.with_inspection(load).is_err());
    assert!(verify_generation(&installation, &BTreeMap::new()).is_err());
}

#[test]
fn selected_public_values_reach_canonical_environment_and_survive_generation_selection() {
    use crate::installer_application_env::{render_selected, ApplicationParameters};
    let root = private_root();
    let config = configuration(
        json!({"ORGANIZATION_CREATION_ENABLED":true,
        "KEYCLOAK_USER_REGISTRATION_ENABLED":false,"RATE_LIMIT_RPM":420,
        "UI_ADDITIONAL_BASE_URLS":["https://secondary.test"],"MARTY_ORG_NAME":"Independent Operator"}),
        json!({}),
    );
    let (installation, mut state) = state(root.path());
    select(
        prepare(Some(&source(root.path(), &config)), true).unwrap(),
        &mut state,
    )
    .unwrap();
    let selected = state.with_inspection(load).unwrap().unwrap();
    let example = include_str!("../../../../.env.selfhost.production.example");
    let tls: String = example
        .lines()
        .filter(|line| line.contains("_TLS_KMS_KEY_"))
        .map(|line| format!("{line}\n"))
        .collect();
    let images = [
        ("gateway", "services"),
        ("signing-keys", "services"),
        ("issuance", "services"),
        ("issuance-native", "services"),
        ("keycloak", "keycloak"),
        ("keycloak-configurator", "keycloak"),
        ("openbao_didcomm_image", "openbao-didcomm"),
    ]
    .into_iter()
    .map(|(role, repository)| {
        (
            role.to_owned(),
            format!(
                "ghcr.io/elevenid/marty-ui-oss/{repository}@sha256:{}",
                "a".repeat(64)
            ),
        )
    })
    .collect();
    let runtime = RuntimeBinding {
        docker_host: "unix:///var/run/docker.sock".into(),
        engine_id: "fixture-engine".into(),
        openbao_port: 18200,
        profile: RuntimeProfile::Rootful,
    };
    let parameters = ApplicationParameters {
        installation: installation.clone(),
        applicant_container_group: crate::installer_state::applicant_container_group(&runtime)
            .unwrap(),
        version: "v1.2.3".into(),
        origin: "https://primary.test".into(),
        https_listener_port: 18443,
        gateway_port: 18000,
        keycloak_port: 18180,
        edge_port: 19080,
        openbao_port: 18200,
    };
    let result = render_selected(
        example,
        include_str!("../../../../docker-compose.selfhost.prod.yml"),
        &tls,
        &parameters,
        &images,
        None,
        None,
        Some(&selected),
    )
    .unwrap();
    let text = String::from_utf8(result.env_bytes.clone()).unwrap();
    for line in [
        "KEYCLOAK_USER_REGISTRATION_ENABLED='false'",
        "ORGANIZATION_CREATION_ENABLED='true'",
        "RATE_LIMIT_RPM='420'",
        "MARTY_ORG_NAME='Independent Operator'",
        "CORS_ORIGINS='https://primary.test,https://secondary.test'",
        "GRPC_INSECURE_ALLOWED='false'",
        "PUBLIC_DOMAIN='primary.test'",
        "GATEWAY_OBSERVE_CLIENT_IP='false'",
        "CANVAS_OAUTH_COMPLETION_REDIRECT_URL='https://primary.test/console/org/deploy/canvas'",
    ] {
        assert!(text.lines().any(|value| value == line), "missing {line}");
    }
    let generation =
        crate::installer_application_env::select_generation(&result.env_bytes, &installation)
            .unwrap();
    let expected = text.replace(
        &format!("SELFHOST_SECRET_DIR='{}/secrets'", installation.display()),
        &format!(
            "SELFHOST_SECRET_DIR='{}/application-generation'",
            installation.display()
        ),
    );
    assert_eq!(generation, expected.as_bytes());
}

#[test]
fn rejects_generated_identity_paths_raw_secrets_unknown_and_weakly_typed_values() {
    for values in [
        json!({"PUBLIC_DOMAIN":"other.test"}),
        json!({"SELFHOST_SECRET_DIR":"/tmp"}),
        json!({"GRPC_INSECURE_ALLOWED":true}),
        json!({"GATEWAY_OBSERVE_CLIENT_IP":true}),
        json!({"MARTY_ORG_ID":"00000000-0000-0000-0000-000000000009"}),
        json!({"MARTY_ISSUANCE_IMAGE":"mutable:latest"}),
        json!({"PASSPORT_TENANT_API_KEYS":"secret"}),
        json!({"PERSONALIZATION_BUREAU_API_KEY":"secret"}),
        json!({"KEYCLOAK_ADMIN_PASSWORD":"secret"}),
        json!({"UNREVIEWED_SETTING":"x"}),
        json!({"ORGANIZATION_CREATION_ENABLED":"true"}),
        json!({"KEYCLOAK_SMTP_PORT":-1}),
        json!({"KEYCLOAK_SMTP_PORT":65536}),
        json!({"RATE_LIMIT_RPM":0}),
        json!({"UI_ADDITIONAL_BASE_URLS":"https://second.test"}),
        json!({"UI_ADDITIONAL_BASE_URLS":["https://second.test","https://second.test"]}),
        json!({"UI_ADDITIONAL_BASE_URLS":["http://second.test"]}),
        json!({"CANVAS_CREDENTIALS_API_BASE_URL":"https://user:secret@api.test"}),
        json!({"CANVAS_CREDENTIALS_API_BASE_URL":"https://api.test/#fragment"}),
        json!({"KEYCLOAK_SMTP_FROM_DISPLAY_NAME":"bad\nname"}),
        json!({"CANVAS_LTI_TOOL_PUBLIC_JWKS":{"keys":[{"kty":"RSA","alg":"RS256","kid":"x","n":"x","e":"AQAB","d":"private"}]}}),
        json!({"DIDCOMM_ALLOW_PRIVATE_IPS":true}),
        json!({"CANVAS_LEGACY_EVENT_INGEST_ENABLED":true}),
        json!({"CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS":true}),
        json!({"PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED":true}),
        json!({"SMTP_HOST":"smtp.test"}),
    ] {
        assert!(
            configuration(values.clone(), json!({}))
                .environment(true)
                .is_err(),
            "accepted {values}"
        );
    }
}

#[test]
fn rejects_duplicate_json_fields_before_any_import() {
    let root = private_root();
    for raw in [
        r#"{"schema":"elevenid.installer-application-settings/v1","values":{"ORGANIZATION_CREATION_ENABLED":true,"ORGANIZATION_CREATION_ENABLED":false}}"#,
        r#"{"schema":"elevenid.installer-application-settings/v1","secret_files":{},"secret_files":{}}"#,
        r#"{"schema":"elevenid.installer-application-settings/v1","extra":true}"#,
    ] {
        let path = root.path().join("input.json");
        write(&path, raw.as_bytes(), 0o600);
        assert!(prepare(Some(&path), true).is_err());
    }
}

#[test]
fn keycloak_mail_requires_complete_transport_and_matching_authentication() {
    let root = private_root();
    let config = smtp(root.path());
    let path = source(root.path(), &config);
    let prepared = prepare(Some(&path), true).unwrap();
    let env = prepared.configuration.environment(true).unwrap();
    assert_eq!(env["KEYCLOAK_VERIFY_EMAIL"], "true");
    assert_eq!(env["KEYCLOAK_SMTP_STARTTLS"], "true");
    assert!(!serde_json::to_vec(&env)
        .unwrap()
        .windows(SECRET.len())
        .any(|v| v == SECRET));
    for mutation in [
        "host",
        "from",
        "username",
        "password",
        "both-tls",
        "neither-tls",
    ] {
        let mut bad = config.clone();
        match mutation {
            "host" => {
                bad.values.remove("KEYCLOAK_SMTP_HOST");
            }
            "from" => {
                bad.values.remove("KEYCLOAK_SMTP_FROM");
            }
            "username" => {
                bad.values.remove("KEYCLOAK_SMTP_USERNAME");
            }
            "password" => {
                bad.secret_files.remove("smtp_password");
            }
            "both-tls" => {
                bad.values.insert("KEYCLOAK_SMTP_SSL".into(), json!(true));
            }
            _ => {
                bad.values
                    .insert("KEYCLOAK_SMTP_STARTTLS".into(), json!(false));
            }
        }
        assert!(bad.environment(true).is_err(), "accepted {mutation}");
    }
    for key in ["KEYCLOAK_VERIFY_EMAIL", "KEYCLOAK_RESET_PASSWORD_ENABLED"] {
        assert!(configuration(json!({key:true}), json!({}))
            .environment(true)
            .is_err());
    }
}

#[test]
fn social_pair_and_external_provider_ownership_are_explicit() {
    let root = private_root();
    let id = root.path().join("google-id");
    let secret = root.path().join("google-secret");
    write(&id, b"synthetic.apps.googleusercontent.com", 0o600);
    write(&secret, SECRET, 0o600);
    let good = configuration(
        json!({"KEYCLOAK_SOCIAL_LOGIN_ENABLED":true}),
        json!({"google_client_id":id,"google_client_secret":secret}),
    );
    assert!(prepare(Some(&source(root.path(), &good)), true).is_ok());
    assert!(good.environment(false).is_err());
    let mut bad = good.clone();
    bad.secret_files.remove("google_client_secret");
    assert!(bad.environment(true).is_err());
    assert!(
        configuration(json!({"KEYCLOAK_SOCIAL_LOGIN_ENABLED":true}), json!({}))
            .environment(true)
            .is_err()
    );
    assert!(configuration(
        json!({"KEYCLOAK_USER_REGISTRATION_ENABLED":true}),
        json!({})
    )
    .environment(false)
    .is_err());
    assert!(
        configuration(json!({"ORGANIZATION_CREATION_ENABLED":true}), json!({}))
            .environment(false)
            .is_ok()
    );
}

#[test]
fn analytics_identifier_is_checked_before_provisioning() {
    let root = private_root();
    let id = root.path().join("ga4-id");
    let config = configuration(json!({}), json!({"google_analytics_measurement_id":id}));
    let path = source(root.path(), &config);
    write(&id, b"G-A1B2C3D4E5\n", 0o600);
    assert!(prepare(Some(&path), true).is_ok());
    for bytes in [
        b"UA-1234".as_slice(),
        b"G-",
        b"G-lowercase",
        b"G-ABC\nOTHER",
        b"G-ABC\"injection",
    ] {
        write(&id, bytes, 0o600);
        assert!(prepare(Some(&path), true).is_err());
    }
    assert!(!root.path().join("installation").exists());
}

#[test]
fn canvas_and_did_capabilities_require_their_specific_dependencies() {
    for values in [
        json!({"DID_PUBLIC_FALLBACK_ENABLED":true}),
        json!({"CANVAS_ALLOW_PRIVATE_BASE_URLS":true}),
        json!({"CANVAS_PORTABLE_INTEGRATION_ENABLED":true}),
        json!({"CANVAS_MIRROR_WORKER_ENABLED":true}),
    ] {
        assert!(configuration(values, json!({})).environment(true).is_err());
    }
    let public = configuration(
        json!({"DID_PUBLIC_FALLBACK_ENABLED":true,"DID_WEB_ALLOWED_HOSTS":["issuer.test"],
        "CANVAS_ALLOW_PRIVATE_BASE_URLS":true,"CANVAS_PRIVATE_ORIGIN_ALLOWLIST":["https://canvas.internal.test"]}),
        json!({}),
    );
    assert!(public.environment(true).is_ok());
    let mut portable = configuration(
        json!({"CANVAS_PORTABLE_INTEGRATION_ENABLED":true,
        "CANVAS_CREDENTIALS_PROVIDER":"badgr_api", "CANVAS_LTI_EXPERIENCE_BASE_URL":"https://app.test",
        "CANVAS_PILOT_ORGANIZATION_IDS":["00000000-0000-0000-0000-000000000001"],
        "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS":["00000000-0000-0000-0000-000000000002"],
        "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID":"00000000-0000-0000-0000-000000000001",
        "CANVAS_LTI_TOOL_ISSUER_DID":"did:web:issuer.test", "CANVAS_LTI_TOOL_ACTIVE_KID":"did:web:issuer.test#lti",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS":{"keys":[{"kty":"RSA","alg":"RS256","kid":"did:web:issuer.test#lti","n":public_modulus(),"e":"AQAB"}]}}),
        json!({}),
    );
    assert!(portable.environment(true).is_ok());
    portable.values.insert(
        "CANVAS_LTI_TOOL_ACTIVE_KID".into(),
        json!("did:web:issuer.test#missing"),
    );
    assert!(portable.environment(true).is_err());
    portable.values.insert(
        "CANVAS_LTI_TOOL_ACTIVE_KID".into(),
        json!("did:web:issuer.test#lti"),
    );
    portable
        .values
        .insert("CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS".into(), json!(601));
    assert!(portable.environment(true).is_err());
}

#[test]
fn canvas_api_token_is_distinct_required_and_retained_as_an_original_input() {
    use crate::installer_generation_binding::{GenerationFile, GenerationSource};
    let root = private_root();
    let path = root.path().join("canvas-api-token");
    write(&path, SECRET, 0o600);
    let config = configuration(
        json!({"CANVAS_MIRROR_WORKER_ENABLED":true,
        "CANVAS_MIRROR_WORKER_ORGANIZATION_ID":"org-production", "CANVAS_CREDENTIALS_PROVIDER":"badgr_api",
        "CANVAS_CREDENTIALS_ISSUER_ID":"issuer-production", "CANVAS_CREDENTIALS_BADGECLASS_ID":"badge-production"}),
        json!({"canvas_credentials_api_token":path}),
    );
    let prepared = prepare(Some(&source(root.path(), &config)), true).unwrap();
    assert_eq!(
        prepared.configuration.environment(true).unwrap()["CANVAS_CREDENTIALS_API_TOKEN_FILE"],
        "/run/secrets/canvas_credentials_api_token"
    );
    assert_eq!(
        prepared.secrets["canvas_credentials_api_token"],
        fingerprint(SECRET)
    );
    assert_eq!(
        prepared.secrets["canvas_credentials_shared_secret"],
        fingerprint(&[])
    );
    let mut missing = config.clone();
    missing.secret_files.clear();
    missing
        .secret_files
        .insert("canvas_credentials_shared_secret".into(), path);
    assert!(missing.environment(true).is_err());
    assert!(configuration(
        json!({"CANVAS_CREDENTIALS_API_TOKEN":"raw-secret"}),
        json!({})
    )
    .environment(true)
    .is_err());
    let (installation, mut state) = state(root.path());
    select(prepared, &mut state).unwrap();
    state.advance(Phase::Provisioning).unwrap();
    state
        .generate_local_credentials(
            &json!({"passwordPolicy":crate::installer_state::PASSWORD_POLICY}),
        )
        .unwrap();
    let selected = state.with_inspection(load).unwrap().unwrap();
    for (name, bytes) in selected.initial_secrets().unwrap() {
        write(&installation.join("secrets").join(name), &bytes, 0o444);
    }
    let files = BTreeMap::from([(
        "canvas_credentials_api_token".into(),
        GenerationFile {
            source: GenerationSource::Original,
            sha256: digest(SECRET),
            size: SECRET.len() as u64,
            source_mode: 0o444,
            mode: 0o444,
        },
    )]);
    verify_generation(&installation, &files).unwrap();
    write(
        &installation.join("secrets/canvas_credentials_api_token"),
        b"changed-api-token",
        0o444,
    );
    assert!(verify_generation(&installation, &files).is_err());
}

#[test]
fn passport_uses_validated_file_only_credentials_and_exclusive_authentication_modes() {
    let root = private_root();
    let keyring = root.path().join("tenant-keys.json");
    write(
        &keyring,
        &serde_json::to_vec(&json!({"org-1":"0123456789abcdef0123456789abcdef"})).unwrap(),
        0o600,
    );
    let config = configuration(
        json!({"PASSPORT_NATIVE_HTTP_ENABLED":true,"PASSPORT_NATIVE_GATEWAY_ENABLED":true,
        "PASSPORT_NATIVE_FLOW_ENABLED":true}),
        json!({"passport_tenant_api_keys":keyring}),
    );
    let prepared = prepare(Some(&source(root.path(), &config)), true).unwrap();
    let env = prepared.configuration.environment(true).unwrap();
    assert_eq!(
        env["PASSPORT_TENANT_API_KEYS_FILE"],
        "/run/secrets/passport_tenant_api_keys"
    );
    assert_eq!(env["PASSPORT_TENANT_API_KEYS"], "");
    let mut internal = config.clone();
    internal
        .values
        .insert("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED".into(), json!(true));
    assert!(internal.environment(true).is_err());
    internal.secret_files.clear();
    assert_eq!(
        internal.environment(true).unwrap()["PASSPORT_TENANT_API_KEYS_FILE"],
        ""
    );
    for values in [
        json!({"PASSPORT_NATIVE_HTTP_ENABLED":true}),
        json!({"PASSPORT_NATIVE_GATEWAY_ENABLED":true}),
        json!({"PERSONALIZATION_BUREAU_URL":"https://bureau.test"}),
    ] {
        assert!(configuration(values, json!({})).environment(true).is_err());
    }
    write(&keyring, br#"{"org-1":"too-short"}"#, 0o600);
    assert!(prepare(Some(&source(root.path(), &config)), true).is_err());
}

#[test]
fn selected_credentials_are_imported_once_without_entering_public_records() {
    let root = private_root();
    let config = smtp(root.path());
    let prepared = prepare(Some(&source(root.path(), &config)), true).unwrap();
    let (installation, mut state) = state(root.path());
    select(prepared, &mut state).unwrap();
    assert!(select(prepare(None, true).unwrap(), &mut state).is_err());
    // The refused second selection must not replace any retained record.
    provision(&mut state);
    let selected = state.with_inspection(load).unwrap().unwrap();
    state
        .with_inspection(|v| selected.verify_secrets(v.installation_directory()))
        .unwrap();
    let imported = installation.join("secrets/smtp_password");
    assert_eq!(std::fs::read(&imported).unwrap(), SECRET);
    assert_eq!(std::fs::metadata(&imported).unwrap().mode() & 0o7777, 0o444);
    assert_eq!(std::fs::metadata(&imported).unwrap().nlink(), 1);
    for name in [SOURCE, RECORD] {
        let bytes = std::fs::read(installation.join("evidence").join(name)).unwrap();
        assert!(!bytes.windows(SECRET.len()).any(|v| v == SECRET));
    }
    std::fs::remove_file(config.secret_files["smtp_password"].clone()).unwrap();
    // Reuse authenticates retained bytes, not a now-unneeded source path.
    state
        .with_inspection(|v| {
            load(v)?
                .ok_or(REFUSED)?
                .verify_secrets(v.installation_directory())
        })
        .unwrap();
    write(
        &imported,
        b"different-private-credential-0123456789abc\n",
        0o444,
    );
    assert!(state
        .with_inspection(|v| load(v)?
            .ok_or(REFUSED)?
            .verify_secrets(v.installation_directory()))
        .is_err());
}

#[test]
fn source_drift_links_modes_and_retained_selection_drift_fail_closed() {
    let root = private_root();
    let config = smtp(root.path());
    let path = source(root.path(), &config);
    let prepared = prepare(Some(&path), true).unwrap();
    let (installation, mut state) = state(root.path());
    select(prepared, &mut state).unwrap();
    write(
        &config.secret_files["smtp_password"],
        b"changed-source",
        0o600,
    );
    state.advance(Phase::Provisioning).unwrap();
    state
        .generate_local_credentials(
            &json!({"passwordPolicy":crate::installer_state::PASSWORD_POLICY}),
        )
        .unwrap();
    assert!(state.prepare_application_storage().is_err());
    assert!(!installation.join("state").exists());
    let alias = root.path().join("alias.json");
    symlink(&path, &alias).unwrap();
    assert!(prepare(Some(&alias), true).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(prepare(Some(&path), true).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(prepare(Some(&path), true).is_err());
    write(&installation.join("evidence").join(SOURCE), b"{}", 0o600);
    assert!(state.with_inspection(load).is_err());
}

#[test]
fn generation_files_keep_selected_optional_credentials_original_and_hash_bound() {
    use crate::installer_generation_binding::{GenerationFile, GenerationSource};
    let root = private_root();
    let config = smtp(root.path());
    let (installation, mut state) = state(root.path());
    select(
        prepare(Some(&source(root.path(), &config)), true).unwrap(),
        &mut state,
    )
    .unwrap();
    state.advance(Phase::Provisioning).unwrap();
    state
        .generate_local_credentials(
            &json!({"passwordPolicy":crate::installer_state::PASSWORD_POLICY}),
        )
        .unwrap();
    let selected = state.with_inspection(load).unwrap().unwrap();
    // This retained-input reader fixture is independent of applicant GID
    // provisioning. The storage-owner test covers exclusive import itself.
    for (name, bytes) in selected.initial_secrets().unwrap() {
        write(&installation.join("secrets").join(name), &bytes, 0o444);
    }
    let mut files: BTreeMap<_, _> = selected
        .secrets
        .iter()
        .map(|(name, expected)| {
            (
                name.clone(),
                GenerationFile {
                    source: GenerationSource::Original,
                    sha256: expected.sha256.clone(),
                    size: expected.size_bytes,
                    source_mode: 0o444,
                    mode: 0o444,
                },
            )
        })
        .collect();
    verify_generation(&installation, &files).unwrap();
    files.get_mut("smtp_password").unwrap().source = GenerationSource::Candidate;
    assert!(verify_generation(&installation, &files).is_err());
    files.get_mut("smtp_password").unwrap().source = GenerationSource::Original;
    files.get_mut("smtp_password").unwrap().sha256 = digest(b"other");
    assert!(verify_generation(&installation, &files).is_err());
    files.get_mut("smtp_password").unwrap().sha256 = fingerprint(SECRET).sha256;
    let secret = installation.join("secrets/smtp_password");
    std::fs::remove_file(&secret).unwrap();
    symlink(&config.secret_files["smtp_password"], &secret).unwrap();
    assert!(verify_generation(&installation, &files).is_err());
}

#[test]
fn acme_preparation_binds_nonempty_optional_inputs_and_refuses_later_changes() {
    let root = private_root();
    let config = smtp(root.path());
    let installation = root.path().join("installation");
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
    let hosting = root.path().join("hosting.json");
    write(&hosting, &serde_json::to_vec(&json!({"schema":"elevenid.installation-hosting/v1","mode":"direct",
        "public_origin":"https://installer.test","listener":{"bind_address":"0.0.0.0","port":18443},
        "tls":{"termination":"marty-keyless","certificate_source":"acme","http01_host_port":18080,
            "acme":{"environment":"production","directory_url":"https://acme-v02.api.letsencrypt.org/directory",
                "profile":"shortlived","terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf","terms_agreed":true}}})).unwrap(), 0o600);
    crate::installer_hosting::select(
        crate::installer_hosting::prepare(Some(&hosting), None).unwrap(),
        &mut state,
    )
    .unwrap();
    select(
        prepare(Some(&source(root.path(), &config)), true).unwrap(),
        &mut state,
    )
    .unwrap();
    state.advance(Phase::Provisioning).unwrap();
    state
        .generate_local_credentials(
            &json!({"passwordPolicy":crate::installer_state::PASSWORD_POLICY}),
        )
        .unwrap();
    state
        .persist_credential_creation_receipt(&installation)
        .unwrap();
    crate::installer_acme_preparation::prepare(&mut state, &installation).unwrap();
    let prepared: Value = serde_json::from_slice(
        &std::fs::read(installation.join("evidence/acme-application-prepared.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        prepared["entries"]["secrets/smtp_password"]["length"],
        SECRET.len()
    );
    assert_eq!(
        prepared["application_settings_sha256"],
        state.journal().application_settings_sha256().unwrap()
    );
    state
        .with_inspection(|v| crate::installer_acme_preparation::verify(v, &installation))
        .unwrap();
    state
        .with_inspection(|v| {
            crate::installer_acme_preparation::verify_retained_provenance(v, &installation)
        })
        .unwrap();
    write(
        &installation.join("secrets/smtp_password"),
        &vec![b'x'; SECRET.len()],
        0o444,
    );
    assert!(state
        .with_inspection(|v| crate::installer_acme_preparation::verify(v, &installation))
        .is_err());
    assert!(state
        .with_inspection(
            |v| crate::installer_acme_preparation::verify_retained_provenance(v, &installation)
        )
        .is_err());
}
