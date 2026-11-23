//! Explicit credential barriers around native Compose-managed OpenBao phases.
//! Fresh installations retain a separate static seal and initialize once. There is no
//! per-service scheduler or host health-polling loop here.
#![cfg(target_os = "linux")]
use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt, ComposeSession},
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase, LOCAL_AUTH_SCALAR_SECRETS, SCALAR_SECRETS},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenBaoInventory {
    pub installation_id: String,
    pub engine_id: String,
    pub project: String,
    pub image: String,
    pub host_port: u16,
    pub network_name: String,
    pub network_id: String,
    pub container_ids: BTreeMap<String, String>,
    pub pending_receipt: PathBuf,
}
fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "OpenBao intent exists or cannot be saved")?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| "OpenBao evidence write failed")?;
    File::open(path.parent().ok_or("OpenBao evidence parent absent")?)
        .and_then(|p| p.sync_all())
        .map_err(|_| "OpenBao evidence directory sync failed".into())
}
/// Identity only; the shared Compose driver re-observes cumulative exact runtime
/// resources. This function must not create or adopt any Docker resource.
pub(crate) fn require_binding(state: &InstallerState, bao: &OpenBaoInventory) -> Result<()> {
    let journal = state.journal();
    let binding = journal.runtime().ok_or("OpenBao runtime absent")?;
    require(
        bao.installation_id == journal.installation_id().to_string()
            && bao.engine_id == binding.engine_id
            && bao.project == journal.compose_project()
            && bao.host_port == binding.openbao_port
            && bao.network_name == format!("{}_default", journal.compose_project()),
        "OpenBao observation differs from installation binding",
    )
}

/// Check the exact fresh credential set before creating any OpenBao state or
/// contacting Docker. Admit only the imported credentials selected by the
/// locked journal, with their original custody and fingerprint checks.
fn validate_initial_credentials(installation: &Path, state: &InstallerState) -> Result<()> {
    const REFUSED: &str = "fresh OpenBao credential custody differs";
    const OIDC_SECRET: &str = "external_oidc_client_secret";
    use crate::installer_host_fs as host_fs;

    state.require_live_phase(Phase::Provisioning)?;
    state.with_inspection(|view| {
        view.require_path_binding(installation)?;
        require(crate::installer_foundation::load(view)?.is_none(), REFUSED)?;
        let selected = crate::installer_oidc::load(view)?;
        let postgres = crate::installer_postgres::load(view)?;
        let hosting = crate::installer_hosting::load(view)?;
        let scalars: BTreeSet<_> = SCALAR_SECRETS
            .into_iter()
            .filter(|name| selected.is_none() || !LOCAL_AUTH_SCALAR_SECRETS.contains(name))
            .collect();
        let mut expected: BTreeSet<String> = scalars.iter().map(|name| (*name).into()).collect();
        let mut imported = BTreeSet::new();
        if selected.is_some() {
            imported.insert(OIDC_SECRET);
        }
        if postgres.is_some() {
            imported.insert(crate::installer_postgres::SECRET);
        }
        if hosting
            .as_ref()
            .is_some_and(|value| value.connector().is_some())
        {
            imported.insert(crate::installer_hosting::CONNECTOR_TOKEN);
        }
        expected.extend(imported.iter().map(|name| (*name).to_owned()));
        let path = installation.join("secrets");
        let secrets = host_fs::directory(&path, REFUSED)?;
        require(
            host_fs::file_names(&secrets, REFUSED)? == expected,
            "fresh scalar secret set differs",
        )?;
        for name in scalars {
            let file = host_fs::open_child(&secrets, name, libc::O_PATH, REFUSED)?;
            let metadata = file.metadata().map_err(|_| REFUSED)?;
            require(
                metadata.is_file()
                    && metadata.nlink() == 1
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.mode() & 0o7777 == 0o444
                    && metadata.len() == 64,
                "scalar credential custody differs",
            )?;
        }
        let mut values = BTreeMap::new();
        for name in imported {
            let file =
                host_fs::open_child(&secrets, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
            let before = file.metadata().map_err(|_| REFUSED)?;
            require(
                before.is_file()
                    && before.nlink() == 1
                    && before.uid() == unsafe { libc::geteuid() }
                    && before.mode() & 0o7777 == 0o444
                    && before.len() <= 65536,
                REFUSED,
            )?;
            let mut bytes = Vec::new();
            (&file)
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(|_| REFUSED)?;
            let after = file.metadata().map_err(|_| REFUSED)?;
            require(
                bytes.len() as u64 == before.len()
                    && before.dev() == after.dev()
                    && before.ino() == after.ino()
                    && before.uid() == after.uid()
                    && before.nlink() == after.nlink()
                    && before.mode() == after.mode()
                    && before.len() == after.len()
                    && before.mtime() == after.mtime()
                    && before.mtime_nsec() == after.mtime_nsec()
                    && before.ctime() == after.ctime()
                    && before.ctime_nsec() == after.ctime_nsec(),
                REFUSED,
            )?;
            values.insert(name.to_owned(), bytes);
        }
        if let Some(selected) = selected {
            selected.verify_imported(&values)?;
        }
        if let Some(postgres) = postgres {
            postgres.verify_imported(&values)?;
        }
        if let Some(hosting) = hosting {
            hosting.verify_imported_connector(&values)?;
        }
        host_fs::require_directory_binding(&path, &secrets, REFUSED)?;
        view.require_path_binding(installation)
    })
}

pub fn start_openbao(
    docker_path: &Path,
    installation: &Path,
    state: &mut InstallerState,
    plugin_image: &str,
    mut inputs: ComposeInputs,
) -> Result<(OpenBaoInventory, ComposeReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    let journal = state.journal().clone();
    require(
        InstallerState::inspect(installation)? == journal,
        "OpenBao journal changed",
    )?;
    let binding = journal.runtime().ok_or("OpenBao runtime absent")?;
    require(
        inputs.prior.is_none()
            && inputs.project == journal.compose_project()
            && inputs.approved_images.contains(plugin_image),
        "OpenBao requires fresh admitted project",
    )?;
    validate_initial_credentials(installation, state)?;
    let secrets = installation.join("secrets");
    state.create_private_directory("openbao-state")?;
    state.persist_openbao_state_creation_receipt(installation)?;
    state.prepare_openbao_control()?;
    crate::installer_openbao_seal::prepare_for_install(state, installation)?;
    let state_before = fs::symlink_metadata(installation.join("openbao-state"))
        .map_err(|_| "OpenBao initial directory identity unavailable")?;
    let pending = installation.join("openbao-pending.json");
    exclusive(&pending, &serde_json::to_vec(&json!({"schema":"elevenid.installer-openbao-intent/v2",
        "installation_id":journal.installation_id(),"engine_id":binding.engine_id,"project":inputs.project,
        "image":plugin_image,"automatic_retry":false})).map_err(|_| "OpenBao intent encode failed")?)?;
    inputs.services = vec!["openbao-tls-init".into()];
    let tls = ComposeSession::new(docker_path, binding, inputs.clone())?;
    tls.pull()?;
    let mut receipt = tls.run_setup_job(state, "openbao-tls-init")?;
    let resources = receipt
        .resources
        .as_ref()
        .ok_or("OpenBao TLS resources absent")?;
    let initialized = resources
        .containers
        .get("openbao-tls-init")
        .ok_or("TLS initializer absent")?;
    let completed = serde_json::to_vec(
        &json!({"role":"openbao-tls-init","container_id":initialized.id,"exit_code":0}),
    )
    .map_err(|_| "TLS completion encode failed")?;
    exclusive(
        &installation.join("openbao-completed-openbao-tls-init.json"),
        &completed,
    )?;
    let docker = DockerRunner::from_binding(docker_path, binding, installation)?;
    let local: Vec<serde_json::Value> =
        serde_json::from_str(&docker.run_checked(&["image", "inspect", plugin_image])?)
            .map_err(|_| "OpenBao image metadata invalid")?;
    require(local.len() == 1, "OpenBao image identity ambiguous")?;
    state.persist_openbao_owner_transition_receipt(
        installation,
        &binding.engine_id,
        plugin_image,
        local[0]["Id"].as_str().ok_or("OpenBao image ID absent")?,
        &initialized.id,
        &completed,
    )?;
    inputs
        .bound_inputs
        .push(crate::installer_compose::record_openbao_custody(
            installation,
            state,
            &receipt,
            &state_before,
        )?);
    inputs.prior = Some(receipt);
    inputs.services = vec!["openbao".into()];
    state.with_inspection(|view| crate::installer_openbao_seal::verify(view, installation))?;
    let api = ComposeSession::new(docker_path, binding, inputs.clone())?;
    receipt = api.up_wait(state, "openbao-api", Duration::from_secs(180))?;
    inputs.prior = Some(receipt);
    inputs.services = vec!["openbao-bootstrap".into()];
    let bootstrap = ComposeSession::new(docker_path, binding, inputs.clone())?;
    receipt = bootstrap.run_setup_job(state, "openbao-bootstrap")?;
    crate::installer_openbao_seal::record_initialization(
        installation,
        state,
        &bootstrap,
        &receipt,
    )?;
    inputs.prior = Some(receipt);
    inputs.services = vec!["openbao-unseal".into()];
    let ready = ComposeSession::new(docker_path, binding, inputs.clone())?;
    receipt = ready.up_wait(state, "openbao-ready", Duration::from_secs(180))?;
    inputs.prior = Some(receipt);
    inputs.services = vec!["installer-control-enroll".into()];
    let control = ComposeSession::new(docker_path, binding, inputs)?;
    receipt = control.run_setup_job(state, "installer-control-enroll")?;
    crate::installer_openbao_control::record_enrollment(installation, state, &control, &receipt)?;
    for name in [
        "openbao_service_token",
        "openbao_bootstrap_token",
        "signing_keys_openbao_token",
        "didcomm_issuance_openbao_token",
        "notification_openbao_token",
        "haip_kms_token",
        "openbao_tls_ca_cert",
    ] {
        let m = fs::symlink_metadata(secrets.join(name)).map_err(|_| "OpenBao output absent")?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.len() > 0
                && m.len() <= 65536
                && m.mode() & 0o022 == 0,
            "OpenBao output custody differs",
        )?;
    }
    let observed = receipt
        .resources
        .as_ref()
        .ok_or("OpenBao resources absent")?;
    let network_name = format!("{}_default", journal.compose_project());
    let result = OpenBaoInventory {
        installation_id: journal.installation_id().to_string(),
        engine_id: binding.engine_id.clone(),
        project: journal.compose_project(),
        image: plugin_image.into(),
        host_port: binding.openbao_port,
        network_id: observed
            .networks
            .get(&network_name)
            .ok_or("OpenBao default network absent")?
            .clone(),
        network_name,
        container_ids: observed
            .containers
            .iter()
            .map(|(r, c)| (r.clone(), c.id.clone()))
            .collect(),
        pending_receipt: pending,
    };
    Ok((result, receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_state::{Identity, PASSWORD_POLICY};
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn private_file(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn fixture(external_secret: Option<&[u8]>) -> (tempfile::TempDir, PathBuf, InstallerState) {
        selected_fixture(external_secret, false, false)
    }

    fn selected_fixture(
        external_secret: Option<&[u8]>,
        postgres: bool,
        connector: bool,
    ) -> (tempfile::TempDir, PathBuf, InstallerState) {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("installation");
        let mut state = InstallerState::create(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        state.advance(Phase::Verified).unwrap();
        if let Some(secret) = external_secret {
            let secret_path = temp.path().join("client-secret");
            if !secret.is_empty() {
                private_file(&secret_path, secret, 0o600);
            }
            let configuration = json!({
                "schema": "elevenid.installer-external-oidc/v1",
                "external_oidc": {
                    "issuer_url": "https://identity.example.test/tenant",
                    "client_id": "fixture-client",
                    "admin_email": "operator@example.test",
                    "allowed_algorithms": ["RS256"],
                    "client_secret_file": (!secret.is_empty()).then_some(secret_path)
                }
            });
            let input = temp.path().join("oidc.json");
            private_file(&input, &serde_json::to_vec(&configuration).unwrap(), 0o600);
            crate::installer_oidc::select(
                crate::installer_oidc::prepare(Some(&input), false).unwrap(),
                &mut state,
            )
            .unwrap();
        }
        if postgres {
            let password = temp.path().join("database-password");
            private_file(&password, b"synthetic:database/password", 0o600);
            let input = temp.path().join("postgres.json");
            private_file(
                &input,
                &serde_json::to_vec(&json!({
                    "schema": "elevenid.installer-external-postgres/v1",
                    "external_postgres": {
                        "host": "aws-0-us-west-1.pooler.supabase.com", "port": 5432,
                        "username": "elevenid.projectref", "database": "postgres",
                        "password_file": password
                    }
                }))
                .unwrap(),
                0o600,
            );
            crate::installer_postgres::select(
                crate::installer_postgres::prepare(Some(&input), true, false).unwrap(),
                &mut state,
            )
            .unwrap();
        }
        if connector {
            let token = temp.path().join("tunnel-token");
            private_file(&token, b"synthetic-cloudflare-token-1234567890", 0o600);
            let input = temp.path().join("hosting.json");
            private_file(
                &input,
                &serde_json::to_vec(&json!({
                    "schema": "elevenid.installation-hosting/v1", "mode": "external-proxy",
                    "public_origin": "https://marty.example.test",
                    "listener": {"bind_address": "127.0.0.1", "port": 18443},
                    "tls": {"termination": "marty-keyless", "certificate_source": "managed-ca"},
                    "connector": {"kind": "cloudflare-tunnel", "token_file": token}
                }))
                .unwrap(),
                0o600,
            );
            let prepared = crate::installer_hosting::prepare(Some(&input), None).unwrap();
            crate::installer_hosting::select(prepared, &mut state).unwrap();
        }
        state.advance(Phase::Provisioning).unwrap();
        if external_secret.is_some() {
            state.generate_external_auth_credentials().unwrap();
            state
                .with_inspection(crate::installer_oidc::load)
                .unwrap()
                .unwrap()
                .import_inputs(&mut state)
                .unwrap();
        } else {
            state
                .generate_local_credentials(&json!({"passwordPolicy": PASSWORD_POLICY}))
                .unwrap();
        }
        if postgres {
            state
                .with_inspection(crate::installer_postgres::load)
                .unwrap()
                .unwrap()
                .import_inputs(&mut state)
                .unwrap();
        }
        if connector {
            state
                .with_inspection(crate::installer_hosting::load)
                .unwrap()
                .unwrap()
                .import_connector(&mut state)
                .unwrap();
        }
        (temp, path, state)
    }

    #[test]
    fn fresh_preflight_accepts_exact_selected_database_and_connector_without_mutation() {
        for secret in [b"".as_slice(), b"synthetic-confidential-client-secret"] {
            for (postgres, connector) in [(true, false), (false, true), (true, true)] {
                let (_temp, path, state) = selected_fixture(Some(secret), postgres, connector);
                let journal = fs::read(path.join("installation.json")).unwrap();
                let before: BTreeMap<_, _> = fs::read_dir(path.join("secrets"))
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        (entry.file_name(), fs::read(entry.path()).unwrap())
                    })
                    .collect();
                validate_initial_credentials(&path, &state).unwrap();
                assert_eq!(fs::read(path.join("installation.json")).unwrap(), journal);
                for (name, value) in before {
                    assert_eq!(fs::read(path.join("secrets").join(name)).unwrap(), value);
                }
                assert!(!path.join("openbao-state").exists());
            }
        }
        let (_temp, path, state) = selected_fixture(None, false, true);
        validate_initial_credentials(&path, &state).unwrap();
        assert!(!path.join("openbao-state").exists());
    }

    #[test]
    fn fresh_preflight_refuses_changed_selected_inputs_before_docker_or_kms_state() {
        for name in [
            crate::installer_postgres::SECRET,
            crate::installer_hosting::CONNECTOR_TOKEN,
        ] {
            for mutation in ["missing", "changed", "mode", "symlink", "hardlink"] {
                let (temp, path, state) = selected_fixture(Some(b"client-secret"), true, true);
                let target = path.join("secrets").join(name);
                match mutation {
                    "missing" => fs::remove_file(&target).unwrap(),
                    "changed" => {
                        fs::remove_file(&target).unwrap();
                        private_file(&target, b"changed-selected-input", 0o444);
                    }
                    "mode" => {
                        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap()
                    }
                    "symlink" => {
                        let outside = temp.path().join("substitute");
                        private_file(&outside, &fs::read(&target).unwrap(), 0o444);
                        fs::remove_file(&target).unwrap();
                        symlink(outside, &target).unwrap();
                    }
                    "hardlink" => fs::hard_link(&target, temp.path().join("extra-link")).unwrap(),
                    _ => unreachable!(),
                }
                assert!(
                    validate_initial_credentials(&path, &state).is_err(),
                    "{name}/{mutation}"
                );
                assert!(!path.join("openbao-state").exists());
            }
        }
    }

    #[test]
    fn fresh_preflight_refuses_unselected_imports_and_missing_selection_records() {
        for (postgres, connector, extra) in [
            (false, true, crate::installer_postgres::SECRET),
            (true, false, crate::installer_hosting::CONNECTOR_TOKEN),
        ] {
            let (_temp, path, state) =
                selected_fixture(Some(b"client-secret"), postgres, connector);
            private_file(
                &path.join("secrets").join(extra),
                b"unselected-import",
                0o444,
            );
            assert!(validate_initial_credentials(&path, &state).is_err());
            assert!(!path.join("openbao-state").exists());
        }
        for record in [
            crate::installer_postgres::RECORD,
            crate::installer_hosting::RECORD,
        ] {
            let (_temp, path, state) = selected_fixture(Some(b"client-secret"), true, true);
            fs::remove_file(path.join("evidence").join(record)).unwrap();
            assert!(validate_initial_credentials(&path, &state).is_err());
            assert!(!path.join("openbao-state").exists());
        }
    }

    #[test]
    fn fresh_credential_preflight_preserves_managed_inventory() {
        for mutation in ["none", "missing", "extra", "mode", "length"] {
            let (_temp, path, state) = fixture(None);
            let scalar = path.join("secrets/postgres_password");
            match mutation {
                "none" => {}
                "missing" => fs::remove_file(scalar).unwrap(),
                "extra" => private_file(
                    &path.join("secrets/external_oidc_client_secret"),
                    b"",
                    0o444,
                ),
                "mode" => fs::set_permissions(scalar, fs::Permissions::from_mode(0o600)).unwrap(),
                "length" => {
                    fs::remove_file(&scalar).unwrap();
                    private_file(&scalar, b"too-short", 0o444);
                }
                _ => unreachable!(),
            }
            assert_eq!(
                validate_initial_credentials(&path, &state).is_ok(),
                mutation == "none",
                "{mutation}"
            );
            assert!(!path.join("openbao-state").exists());
        }
    }

    #[test]
    fn fresh_external_preflight_accepts_exact_public_and_confidential_inputs_without_mutation() {
        for secret in [b"".as_slice(), b"synthetic-confidential-client-secret"] {
            let (_temp, path, state) = fixture(Some(secret));
            let journal = fs::read(path.join("installation.json")).unwrap();
            validate_initial_credentials(&path, &state).unwrap();
            assert_eq!(fs::read(path.join("installation.json")).unwrap(), journal);
            assert!(!path.join("operator-password").exists());
            assert!(!path.join("openbao-state").exists());
            assert_eq!(
                fs::read(path.join("secrets/external_oidc_client_secret")).unwrap(),
                secret
            );
        }
    }

    #[test]
    fn fresh_external_preflight_rejects_missing_extra_and_changed_credentials() {
        for secret in [b"".as_slice(), b"synthetic-confidential-client-secret"] {
            for mutation in [
                "missing-scalar",
                "local-auth",
                "extra",
                "missing-secret",
                "changed-secret",
                "mode",
                "symlink",
                "hardlink",
                "missing-selection",
            ] {
                let (temp, path, state) = fixture(Some(secret));
                let target = path.join("secrets/external_oidc_client_secret");
                match mutation {
                    "missing-scalar" => {
                        fs::remove_file(path.join("secrets/postgres_password")).unwrap()
                    }
                    "local-auth" => private_file(
                        &path.join("secrets/keycloak_db_password"),
                        &[b'x'; 64],
                        0o444,
                    ),
                    "extra" => private_file(&path.join("secrets/unselected"), &[b'x'; 64], 0o444),
                    "missing-secret" => fs::remove_file(target).unwrap(),
                    "changed-secret" => {
                        fs::remove_file(&target).unwrap();
                        private_file(&target, b"changed", 0o444);
                    }
                    "mode" => {
                        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap()
                    }
                    "symlink" => {
                        let outside = temp.path().join("replacement");
                        private_file(&outside, secret, 0o444);
                        fs::remove_file(&target).unwrap();
                        symlink(outside, target).unwrap();
                    }
                    "hardlink" => fs::hard_link(target, temp.path().join("extra-link")).unwrap(),
                    "missing-selection" => {
                        fs::remove_file(path.join("evidence").join(crate::installer_oidc::RECORD))
                            .unwrap()
                    }
                    _ => unreachable!(),
                }
                assert!(
                    validate_initial_credentials(&path, &state).is_err(),
                    "accepted {mutation}"
                );
                assert!(!path.join("openbao-state").exists());
                assert!(!path.join("openbao-pending.json").exists());
            }
        }
    }
}
