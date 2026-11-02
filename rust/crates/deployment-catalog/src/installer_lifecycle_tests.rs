use super::*;
use crate::installer_state::InstallerState;
use std::os::unix::fs::{symlink, PermissionsExt};

fn fixture() -> (tempfile::TempDir, PathBuf, InstallerState, Configuration) {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("Marty %n $HOME workspace");
    let identity = Identity {
        source_sha: "a".repeat(40),
        release_tag: "v0.0.0".into(),
        inventory_sha256: format!("sha256:{}", "b".repeat(64)),
    };
    let runtime = RuntimeBinding {
        docker_host: "unix:///var/run/docker.sock".into(),
        engine_id: "fixture-engine".into(),
        openbao_port: 18443,
        profile: RuntimeProfile::Rootful,
    };
    let mut state =
        InstallerState::create_with_runtime(&path, identity.clone(), runtime.clone()).unwrap();
    state.create_private_directory("evidence").unwrap();
    let mut configuration = Configuration {
        schema: CONFIGURATION_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        installation: path.clone(),
        owner_uid: unsafe { libc::geteuid() },
        release: identity,
        runtime,
        compose_project: state.journal().compose_project(),
        compose_configuration_sha256: "c".repeat(64),
        operator_sha256: "d".repeat(64),
        docker: "/usr/bin/docker".into(),
        units: BTreeMap::new(),
    };
    configuration.units = render_units(&configuration)
        .unwrap()
        .into_iter()
        .map(|(name, text)| (name, installer_release::sha256(text.as_bytes())))
        .collect();
    (parent, path, state, configuration)
}

fn seed(state: &mut InstallerState, configuration: &Configuration) -> String {
    let bytes = serde_json::to_vec(configuration).unwrap();
    state.write_evidence(CONFIGURATION, &bytes).unwrap();
    for (name, text) in render_units(configuration).unwrap() {
        state.write_evidence(&name, text.as_bytes()).unwrap();
    }
    installer_release::sha256(&bytes)
}

fn load_intent(
    state: &LockedMaintenance,
    configuration: &Configuration,
    digest: &str,
) -> (Intent, String) {
    intent_chain(
        state.inspection(),
        configuration,
        digest,
        &record_names(state.inspection()).unwrap(),
    )
    .unwrap()
    .unwrap()
}

#[test]
fn unconfigured_status_distinguishes_renewal_owners_from_installed_support() {
    let (_parent, path, state, _configuration) = fixture();
    drop(state);
    let report: Value = serde_json::from_str(
        &run(&[
            "status".into(),
            "--install-dir".into(),
            path.to_str().unwrap().into(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(report["configured"], false);
    for capability in [
        "public_generation_credentials",
        "private_generation_renewal",
    ] {
        assert_eq!(
            report["maintenance_capabilities"][capability],
            "selected_generation_owner"
        );
    }
    assert_eq!(
        report["maintenance_capabilities"]["imported_foundation_credentials"],
        "customer_managed"
    );
    assert!(report["automatic_renewal_supported"].is_null());
    assert_eq!(report["installation_ready"], false);
    assert_eq!(report["boot_recovery_qualification"], "not_assessed");
}

#[test]
fn arguments_are_closed_and_paths_cannot_inject_unit_directives() {
    let valid = vec![
        "install".into(),
        "--install-dir".into(),
        "/private/Marty %n $HOME".into(),
    ];
    assert!(arguments(&valid).is_ok());
    for extra in [
        ["--force", "true"],
        ["--enable", "true"],
        ["--user-unit-dir", "/etc/systemd/system"],
        ["--install-dir", "/another"],
        ["--docker-bin", "relative"],
    ] {
        let mut args = valid.clone();
        args.extend(extra.map(String::from));
        assert!(arguments(&args).is_err(), "{extra:?}");
    }
    for path in [
        "relative",
        "/",
        "/tmp/../other",
        "/tmp/./other",
        "/tmp//other",
        "/tmp/other/",
        "/tmp/a\nExecStart=evil",
        "/tmp/a\r",
        "/tmp/a\0b",
        "/tmp/a'quoted",
        "/tmp/a\"quoted",
        "/tmp/a\\path",
    ] {
        assert!(
            arguments(&["install".into(), "--install-dir".into(), path.into()]).is_err(),
            "{path:?}"
        );
    }
    assert!(arguments(&[
        "renew".into(),
        "--install-dir".into(),
        "/private/install".into()
    ])
    .is_err());
    assert!(arguments(&["install".into(), "--install-dir".into()]).is_err());
}

#[test]
fn scheduled_mode_is_explicit_and_only_available_to_periodic_actions() {
    for action in [
        "export",
        "install",
        "status",
        "boot",
        "shutdown",
        "check",
        "maintain",
        "pause",
        "resume",
        "security-seal",
    ] {
        let mut args = vec![
            action.into(),
            "--install-dir".into(),
            "/private/install".into(),
        ];
        assert!(!arguments(&args).unwrap().scheduled);
        args.push("--scheduled".into());
        if ["check", "maintain"].contains(&action) {
            assert!(arguments(&args).unwrap().scheduled);
            args.push("--scheduled".into());
            assert!(arguments(&args).is_err());
        } else {
            assert!(arguments(&args).is_err(), "{action}");
        }
    }
}

#[test]
fn scheduled_defer_has_no_unguarded_observation_or_operation() {
    let (_parent, path, owner, _configuration) = fixture();
    let before = std::fs::read(path.join("installation.json")).unwrap();
    let evidence_before: Vec<_> = std::fs::read_dir(path.join("evidence"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    for action in ["check", "maintain"] {
        let mut args = vec![
            action.into(),
            "--install-dir".into(),
            path.to_str().unwrap().into(),
            "--docker-bin".into(),
            "/definitely-not-an-executable".into(),
        ];
        // Ordinary invocations still fail immediately, even when the test's
        // scheduled budget is nonzero.
        assert!(run_with_lock_wait(&args, Duration::from_secs(1))
            .err()
            .unwrap()
            .starts_with("installation is locked:"));
        args.push("--scheduled".into());
        let result: Value =
            serde_json::from_str(&run_with_lock_wait(&args, Duration::ZERO).unwrap()).unwrap();
        assert_eq!(result["operation"], action);
        assert_eq!(result["result"]["outcome"], "deferred");
        assert_eq!(result["result"]["operation_performed"], false);
        assert_eq!(result["result"]["docker_invoked"], false);
        assert_eq!(result["result"]["intent_modified"], false);
        assert_eq!(result["runtime_observed"], false);
        assert_eq!(result["installation_ready"], false);
        assert!(result.get("installation_id").is_none());
        assert!(result.get("desired_state").is_none());
    }
    assert_eq!(
        std::fs::read(path.join("installation.json")).unwrap(),
        before
    );
    let evidence_after: Vec<_> = std::fs::read_dir(path.join("evidence"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(evidence_after, evidence_before);
    drop(owner);
    std::fs::write(path.join("installation.json"), b"invalid journal").unwrap();
    assert!(run_with_lock_wait(
        &[
            "check".into(),
            "--install-dir".into(),
            path.to_str().unwrap().into(),
            "--scheduled".into(),
        ],
        Duration::ZERO
    )
    .is_err());
}

#[test]
fn generated_units_bind_exact_retained_argv_and_escape_systemd_expansions() {
    let (_parent, _path, _state, configuration) = fixture();
    let units = render_units(&configuration).unwrap();
    let [boot_name, check_name, timer_name, maintenance_name, maintenance_timer_name] =
        unit_names(configuration.installation_id);
    let boot = &units[&boot_name];
    let check = &units[&check_name];
    let timer = &units[&timer_name];
    let maintenance = &units[&maintenance_name];
    let maintenance_timer = &units[&maintenance_timer_name];
    assert!(boot.contains(&format!(
        "ExecStart={}\n",
        command(&configuration, "boot").unwrap()
    )));
    assert!(boot.contains(&format!(
        "ExecStop={}\n",
        command(&configuration, "shutdown").unwrap()
    )));
    assert!(boot.contains("ExecStart=:\"/"));
    assert!(boot.contains("Marty %%n $HOME workspace/marty-deploy\""));
    assert!(boot.contains("\"lifecycle\" \"boot\" \"--install-dir\""));
    assert!(boot.contains("Wants=docker.service\nAfter=docker.service\n"));
    assert!(boot.contains("Type=oneshot\nRemainAfterExit=yes\nNoNewPrivileges=yes\nUMask=0077"));
    assert!(boot.contains("Restart=on-failure\nRestartSec=15"));
    assert!(!boot.contains("Requires=docker.service"));
    assert!(!boot.contains("PartOf=docker.service"));
    assert!(check.contains(&format!(
        "ExecStart={} \"--scheduled\"\n",
        command(&configuration, "check").unwrap()
    )));
    assert!(check.contains("TimeoutStartSec=180\n"));
    assert!(check.contains(&format!("After=docker.service {boot_name}\n")));
    assert!(!check.contains("Requires="));
    assert!(!check.contains("PartOf="));
    assert!(!check.contains("Restart="));
    assert!(timer.contains("OnCalendar=*-*-* *:00/5:00\nPersistent=true\n"));
    assert!(timer.contains(&format!("Unit={check_name}\n")));
    assert!(maintenance.contains(&format!(
        "ExecStart={} \"--scheduled\"\n",
        command(&configuration, "maintain").unwrap()
    )));
    assert!(maintenance.contains(&format!("After=docker.service {boot_name}\n")));
    assert!(
        maintenance.contains("Type=oneshot\nNoNewPrivileges=yes\nUMask=0077\nTimeoutStartSec=1830")
    );
    assert!(!maintenance.contains("RemainAfterExit="));
    assert!(!maintenance.contains("Restart="));
    assert!(maintenance_timer.contains("OnCalendar=*-*-* *:00/5:00\nPersistent=true\n"));
    assert!(maintenance_timer.contains(&format!("Unit={maintenance_name}\n")));
    assert!(!boot.contains("--scheduled"));
    assert!(!timer.contains("--scheduled"));
    assert!(!maintenance_timer.contains("--scheduled"));
    for text in units.values() {
        for absent in ["EnvironmentFile=", "TOKEN=", "PASSWORD="] {
            assert!(!text.contains(absent), "unexpected {absent}");
        }
        for line in text.lines().filter(|line| line.starts_with("Exec")) {
            for absent in [
                "/bin/sh",
                "\"sudo\"",
                "\"compose\" \"up\"",
                "\"init\"",
                "\"renew\"",
            ] {
                assert!(!line.contains(absent), "unexpected command {absent}");
            }
        }
    }
    let mut foreign = configuration.clone();
    foreign.installation_id = uuid::Uuid::new_v4();
    assert!(render_units(&foreign)
        .unwrap()
        .keys()
        .all(|name| !units.contains_key(name)));
    let mut quoted_argument = configuration.clone();
    quoted_argument.docker = "/private/docker \"quoted\" \\ tool".into();
    assert!(command(&quoted_argument, "boot")
        .unwrap()
        .ends_with("\"/private/docker \\\"quoted\\\" \\\\ tool\""));
    for path in [
        "/private/quote\"",
        "/private/apostrophe'",
        "/private/back\\slash",
    ] {
        let mut invalid = configuration.clone();
        invalid.installation = path.into();
        assert!(render_units(&invalid).is_err());
    }
}

#[test]
fn systemd_argument_rejects_control_and_single_command_separator() {
    assert_eq!(
        systemd_argument("/a space/%n/${HOME}/\"quote\"/\\").unwrap(),
        "\"/a space/%%n/${HOME}/\\\"quote\\\"/\\\\\""
    );
    for value in ["", ";", "line\nnext", "tab\tvalue", "nul\0", "\u{0085}"] {
        assert!(systemd_argument(value).is_err());
    }
}

#[test]
fn customer_commands_link_check_unit_and_never_run_privileged_management() {
    let (_parent, _path, _state, mut configuration) = fixture();
    configuration.owner_uid = 1000;
    let actions = next_actions(&configuration, &observed_prerequisites());
    assert_eq!(actions["unattended_eligible"], true);
    assert_eq!(actions["commands_executed"], false);
    assert_eq!(actions["prerequisite_remediation"], json!([]));
    assert_eq!(actions["manual_recovery_command"], actions["commands"][0]);
    assert_eq!(actions["commands"][0][1], "lifecycle");
    assert_eq!(actions["commands"][0][2], "resume");
    assert_eq!(actions["commands"][1][2], "link");
    let [boot, check, timer, maintenance, maintenance_timer] =
        unit_names(configuration.installation_id);
    for (index, name) in [
        boot.clone(),
        check,
        timer.clone(),
        maintenance,
        maintenance_timer.clone(),
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            actions["commands"][1][index + 3],
            configuration
                .installation
                .join("evidence")
                .join(name)
                .to_str()
                .unwrap()
        );
    }
    assert_eq!(
        actions["commands"][3],
        json!([
            "systemctl",
            "--user",
            "enable",
            "--now",
            boot,
            timer,
            maintenance_timer
        ])
    );
    assert!(!actions["commands"].to_string().contains("sudo"));
    assert!(!actions["commands"].to_string().contains("loginctl"));
}

fn observed_prerequisites() -> installer_runtime::UserSystemdPrerequisites {
    installer_runtime::UserSystemdPrerequisites {
        schema: "elevenid.installer-user-systemd-prerequisites/v1",
        uid: 1000,
        linger_enabled: Some(true),
        docker_unit_loaded: Some(true),
        docker_unit_enabled: Some(true),
        docker_unit_active: Some(true),
        automatically_startable: true,
    }
}

#[test]
fn unattended_commands_require_every_known_prerequisite_but_keep_manual_recovery() {
    let (_parent, _path, _state, mut configuration) = fixture();
    configuration.owner_uid = 1000;
    for (index, name) in [
        "linger_enabled",
        "docker_unit_loaded",
        "docker_unit_enabled",
        "docker_unit_active",
    ]
    .into_iter()
    .enumerate()
    {
        for observed in [Some(false), None] {
            let mut prerequisites = observed_prerequisites();
            match index {
                0 => prerequisites.linger_enabled = observed,
                1 => prerequisites.docker_unit_loaded = observed,
                2 => prerequisites.docker_unit_enabled = observed,
                3 => prerequisites.docker_unit_active = observed,
                _ => unreachable!(),
            }
            prerequisites.automatically_startable = false;
            let actions = next_actions(&configuration, &prerequisites);
            assert_eq!(actions["unattended_eligible"], json!(observed), "{name}");
            assert_eq!(actions["commands"], json!([]), "{name}");
            assert_eq!(actions["commands_executed"], false);
            assert_eq!(
                actions["prerequisite_remediation"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(actions["prerequisite_remediation"][0]["prerequisite"], name);
            assert_eq!(
                actions["prerequisite_remediation"][0]["observed"],
                json!(observed)
            );
            assert!(!actions["prerequisite_remediation"][0]["customer_action"]
                .as_str()
                .unwrap()
                .is_empty());
            assert_eq!(
                actions["manual_recovery_command"],
                json!([
                    configuration.installation.join("marty-deploy"),
                    "lifecycle",
                    "resume",
                    "--install-dir",
                    configuration.installation,
                    "--docker-bin",
                    configuration.docker
                ])
            );
        }
    }
}

#[test]
fn unavailable_user_manager_is_unknown_and_known_failures_are_false() {
    let (_parent, _path, _state, mut configuration) = fixture();
    configuration.owner_uid = 1000;
    let mut prerequisites = observed_prerequisites();
    prerequisites.linger_enabled = None;
    prerequisites.docker_unit_loaded = None;
    prerequisites.docker_unit_enabled = None;
    prerequisites.docker_unit_active = None;
    prerequisites.automatically_startable = false;
    let actions = next_actions(&configuration, &prerequisites);
    assert!(actions["unattended_eligible"].is_null());
    assert_eq!(
        actions["prerequisite_remediation"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(actions["commands"], json!([]));
    assert_eq!(
        actions["prerequisite_verification_commands"][0],
        json!([
            "/usr/bin/loginctl",
            "show-user",
            "1000",
            "--property=Linger",
            "--value"
        ])
    );
    prerequisites.linger_enabled = Some(false);
    assert_eq!(
        next_actions(&configuration, &prerequisites)["unattended_eligible"],
        false
    );
    prerequisites.linger_enabled = None;
    prerequisites.docker_unit_enabled = Some(false);
    assert_eq!(
        next_actions(&configuration, &prerequisites)["unattended_eligible"],
        false
    );
}

#[test]
fn root_or_another_users_observation_cannot_authorize_unit_enablement() {
    let (_parent, _path, _state, mut configuration) = fixture();
    for (owner_uid, observed_uid) in [(0, 0), (1000, 1001), (1000, 0)] {
        configuration.owner_uid = owner_uid;
        let mut prerequisites = observed_prerequisites();
        prerequisites.uid = observed_uid;
        let actions = next_actions(&configuration, &prerequisites);
        assert_eq!(actions["unattended_eligible"], false);
        assert_eq!(actions["commands"], json!([]));
        assert_eq!(
            actions["prerequisite_remediation"][0]["prerequisite"],
            "installation_owner_user_manager"
        );
        assert_eq!(actions["commands_executed"], false);
    }
}

#[test]
fn append_only_intent_survives_reopen_and_never_overwrites_pause() {
    let (_parent, path, mut initial, configuration) = fixture();
    let digest = seed(&mut initial, &configuration);
    drop(initial);
    let mut state = LockedMaintenance::open(&path).unwrap();
    append_intent(
        &mut state,
        &configuration,
        &digest,
        None,
        IntentReason::Installed,
    )
    .unwrap();
    let (paused, hash) = load_intent(&state, &configuration, &digest);
    assert_eq!(paused.desired_state, DesiredState::Paused);
    append_intent(
        &mut state,
        &configuration,
        &digest,
        Some((&paused, &hash)),
        IntentReason::ManualStart,
    )
    .unwrap();
    let (running, hash) = load_intent(&state, &configuration, &digest);
    assert_eq!(running.desired_state, DesiredState::Running);
    append_intent(
        &mut state,
        &configuration,
        &digest,
        Some((&running, &hash)),
        IntentReason::ManualStop,
    )
    .unwrap();
    let stop_bytes = state.read_evidence(&intent_name(3)).unwrap().unwrap();
    drop(state);
    let mut state = LockedMaintenance::open(&path).unwrap();
    let (paused, hash) = load_intent(&state, &configuration, &digest);
    assert_eq!(paused.sequence, 3);
    assert_eq!(paused.desired_state, DesiredState::Paused);
    assert_eq!(paused.reason, IntentReason::ManualStop);
    append_intent(
        &mut state,
        &configuration,
        &digest,
        Some((&paused, &hash)),
        IntentReason::Uninstall,
    )
    .unwrap();
    assert_eq!(
        state.read_evidence(&intent_name(3)).unwrap().unwrap(),
        stop_bytes
    );
    assert_eq!(
        load_intent(&state, &configuration, &digest).0.reason,
        IntentReason::Uninstall
    );
    assert!(state
        .write_evidence_exclusive(&intent_name(3), b"overwrite")
        .is_err());
}

#[test]
fn paused_scheduled_commands_do_not_open_docker_or_append_intent() {
    let (_parent, path, mut initial, configuration) = fixture();
    let digest = seed(&mut initial, &configuration);
    drop(initial);
    let mut state = LockedMaintenance::open(&path).unwrap();
    append_intent(
        &mut state,
        &configuration,
        &digest,
        None,
        IntentReason::Installed,
    )
    .unwrap();
    let (intent, intent_sha256) = load_intent(&state, &configuration, &digest);
    let loaded = Loaded {
        configuration,
        configuration_sha256: digest,
        intent,
        intent_sha256,
    };
    let before = record_names(state.inspection()).unwrap();
    for action in [
        Action::Boot,
        Action::Check,
        Action::Shutdown,
        Action::Maintain,
    ] {
        let report = scheduled(
            &mut state,
            &path,
            Path::new("/does/not/exist/docker"),
            action,
            &loaded,
        )
        .unwrap();
        assert_eq!(
            report,
            json!({"outcome":"paused", "docker_invoked":false, "intent_preserved":true})
        );
        assert_eq!(record_names(state.inspection()).unwrap(), before);
    }
}

#[test]
fn shutdown_preserves_running_intent_even_when_native_operation_is_refused() {
    let (_parent, path, mut initial, configuration) = fixture();
    let digest = seed(&mut initial, &configuration);
    drop(initial);
    let mut state = LockedMaintenance::open(&path).unwrap();
    append_intent(
        &mut state,
        &configuration,
        &digest,
        None,
        IntentReason::Installed,
    )
    .unwrap();
    let (paused, hash) = load_intent(&state, &configuration, &digest);
    append_intent(
        &mut state,
        &configuration,
        &digest,
        Some((&paused, &hash)),
        IntentReason::ManualStart,
    )
    .unwrap();
    let (intent, intent_sha256) = load_intent(&state, &configuration, &digest);
    let loaded = Loaded {
        configuration,
        configuration_sha256: digest,
        intent,
        intent_sha256,
    };
    assert_eq!(
        scheduled_operation(Action::Boot, DesiredState::Running).unwrap(),
        Some("start")
    );
    assert_eq!(
        scheduled_operation(Action::Shutdown, DesiredState::Running).unwrap(),
        Some("stop")
    );
    assert_eq!(
        scheduled_operation(Action::Check, DesiredState::Running).unwrap(),
        Some("validate")
    );
    let before = record_names(state.inspection()).unwrap();
    // No authenticated saved Compose session exists: the actual native executor
    // must refuse, leaving the boot intent intact rather than manufacturing pause.
    assert!(scheduled(
        &mut state,
        &path,
        Path::new("/does/not/exist/docker"),
        Action::Shutdown,
        &loaded
    )
    .is_err());
    assert_eq!(record_names(state.inspection()).unwrap(), before);
    assert_eq!(
        load_intent(&state, &loaded.configuration, &loaded.configuration_sha256)
            .0
            .desired_state,
        DesiredState::Running
    );
}

#[test]
fn missing_foreign_or_edited_intent_chain_fails_closed() {
    for corruption in [
        "gap",
        "foreign",
        "digest",
        "reason",
        "previous",
        "unknown",
        "duplicate",
    ] {
        let (_parent, path, mut initial, configuration) = fixture();
        let digest = seed(&mut initial, &configuration);
        drop(initial);
        let mut state = LockedMaintenance::open(&path).unwrap();
        let intent = append_intent(
            &mut state,
            &configuration,
            &digest,
            None,
            IntentReason::Installed,
        )
        .unwrap();
        let hash = installer_release::sha256(&serde_json::to_vec(&intent).unwrap());
        append_intent(
            &mut state,
            &configuration,
            &digest,
            Some((&intent, &hash)),
            IntentReason::ManualStart,
        )
        .unwrap();
        let mut edited = serde_json::to_value(&intent).unwrap();
        let evidence = path.join("evidence");
        match corruption {
            "gap" => std::fs::remove_file(evidence.join(intent_name(1))).unwrap(),
            "foreign" => {
                edited["installation_id"] = json!(uuid::Uuid::new_v4());
            }
            "digest" => {
                edited["configuration_sha256"] = json!("0".repeat(64));
            }
            "reason" => {
                edited["desired_state"] = json!("running");
            }
            "previous" => {
                edited["previous_sha256"] = json!("0".repeat(64));
            }
            "unknown" => {
                state
                    .write_evidence_exclusive("lifecycle-unexpected.json", b"{}")
                    .unwrap();
            }
            "duplicate" => {
                std::fs::write(
                    evidence.join(intent_name(1)),
                    b"{\"schema\":\"x\",\"schema\":\"y\"}",
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        if ["foreign", "digest", "reason", "previous"].contains(&corruption) {
            std::fs::write(
                evidence.join(intent_name(1)),
                serde_json::to_vec(&edited).unwrap(),
            )
            .unwrap();
        }
        assert!(
            intent_chain(
                state.inspection(),
                &configuration,
                &digest,
                &record_names(state.inspection()).unwrap()
            )
            .is_err(),
            "{corruption}"
        );
    }
}

#[test]
fn unit_artifacts_cannot_be_replaced_or_adopt_symlinks() {
    let (_parent, path, mut initial, configuration) = fixture();
    seed(&mut initial, &configuration);
    drop(initial);
    let mut state = LockedMaintenance::open(&path).unwrap();
    let [boot, _, _, _, _] = unit_names(configuration.installation_id);
    let exact = state.read_evidence(&boot).unwrap().unwrap();
    persist_exact(&mut state, &boot, &exact).unwrap();
    assert!(persist_exact(&mut state, &boot, b"replacement").is_err());
    assert_eq!(state.read_evidence(&boot).unwrap().unwrap(), exact);
    assert_eq!(
        std::fs::metadata(path.join("evidence").join(&boot))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    let target = path.join("outside");
    std::fs::write(&target, b"outside").unwrap();
    std::fs::remove_file(path.join("evidence").join(&boot)).unwrap();
    symlink(&target, path.join("evidence").join(&boot)).unwrap();
    assert!(persist_exact(&mut state, &boot, b"replacement").is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"outside");
}

#[test]
fn security_seal_survives_reopen_and_only_explicit_resume_clears_it() {
    let (_parent, path, mut initial, configuration) = fixture();
    let digest = seed(&mut initial, &configuration);
    drop(initial);
    let mut state = LockedMaintenance::open(&path).unwrap();
    append_intent(
        &mut state,
        &configuration,
        &digest,
        None,
        IntentReason::Installed,
    )
    .unwrap();
    let (paused, hash) = load_intent(&state, &configuration, &digest);
    append_intent(
        &mut state,
        &configuration,
        &digest,
        Some((&paused, &hash)),
        IntentReason::SecuritySeal,
    )
    .unwrap();
    drop(state);
    let mut state = LockedMaintenance::open(&path).unwrap();
    let (sealed, hash) = load_intent(&state, &configuration, &digest);
    assert_eq!(sealed.desired_state, DesiredState::SecuritySealed);
    let before = record_names(state.inspection()).unwrap();
    for reason in [
        IntentReason::ManualStart,
        IntentReason::ManualStop,
        IntentReason::Pause,
        IntentReason::Uninstall,
    ] {
        assert!(append_intent(
            &mut state,
            &configuration,
            &digest,
            Some((&sealed, &hash)),
            reason
        )
        .is_err());
        assert_eq!(record_names(state.inspection()).unwrap(), before);
    }
    for action in [
        Action::Boot,
        Action::Check,
        Action::Maintain,
        Action::Shutdown,
    ] {
        assert_eq!(
            scheduled_operation(action, DesiredState::SecuritySealed).unwrap(),
            None
        );
    }
    let loaded = Loaded {
        configuration: configuration.clone(),
        configuration_sha256: digest.clone(),
        intent: sealed.clone(),
        intent_sha256: hash.clone(),
    };
    let report = scheduled(
        &mut state,
        &path,
        Path::new("/does/not/exist/docker"),
        Action::Check,
        &loaded,
    )
    .unwrap();
    assert_eq!(report["outcome"], "security_sealed");
    assert_eq!(report["docker_invoked"], false);
    // A failed attempt to converge the stopped runtime preserves the seal.
    assert!(scheduled(
        &mut state,
        &path,
        Path::new("/does/not/exist/docker"),
        Action::Maintain,
        &loaded
    )
    .is_err());
    assert_eq!(record_names(state.inspection()).unwrap(), before);
    append_intent(
        &mut state,
        &configuration,
        &digest,
        Some((&sealed, &hash)),
        IntentReason::Resume,
    )
    .unwrap();
    assert_eq!(
        load_intent(&state, &configuration, &digest).0.desired_state,
        DesiredState::Running
    );
}

#[test]
fn a_failed_manual_pause_is_durable_before_the_first_docker_mutation() {
    let (_parent, path, mut initial, configuration) = fixture();
    let digest = seed(&mut initial, &configuration);
    drop(initial);
    let mut state = LockedMaintenance::open(&path).unwrap();
    append_intent(
        &mut state,
        &configuration,
        &digest,
        None,
        IntentReason::Installed,
    )
    .unwrap();
    let (paused, hash) = load_intent(&state, &configuration, &digest);
    append_intent(
        &mut state,
        &configuration,
        &digest,
        Some((&paused, &hash)),
        IntentReason::Resume,
    )
    .unwrap();
    let (running, hash) = load_intent(&state, &configuration, &digest);
    let loaded = Loaded {
        configuration: configuration.clone(),
        configuration_sha256: digest.clone(),
        intent: running,
        intent_sha256: hash,
    };
    assert!(manual_control(
        &mut state,
        &path,
        Path::new("/does/not/exist/docker"),
        Action::Pause,
        &loaded
    )
    .is_err());
    let (paused, _) = load_intent(&state, &configuration, &digest);
    assert_eq!(paused.reason, IntentReason::Pause);
    assert_eq!(paused.desired_state, DesiredState::Paused);
    assert_eq!(paused.sequence, 3);
}

#[test]
fn usable_retained_runtime_serves_before_provider_failure_and_errors_remain_errors() {
    for failure in ["provider unavailable", "maintenance evidence differs"] {
        let mut serving = false;
        let mut repairs = 0;
        let mut validations = 0;
        let mut operations = Vec::new();
        let result = recover_application_in_order(true, |step| {
            operations.push(step);
            match step {
                ApplicationRecoveryStep::RepairHealth => repairs += 1,
                ApplicationRecoveryStep::StartRetained => serving = true,
                ApplicationRecoveryStep::ValidateSelected => {
                    assert!(serving);
                    validations += 1;
                }
                ApplicationRecoveryStep::MaintainGeneration => {
                    assert!(serving, "provider work must not gate a usable cold start");
                    assert_eq!(validations, 1);
                    return Err(failure.into());
                }
            }
            Ok(Value::Null)
        });
        assert_eq!(result.err().unwrap(), failure);
        assert!(serving);
        assert_eq!(repairs, 1);
        assert_eq!(validations, 1);
        assert_eq!(
            operations,
            [
                ApplicationRecoveryStep::RepairHealth,
                ApplicationRecoveryStep::StartRetained,
                ApplicationRecoveryStep::ValidateSelected,
                ApplicationRecoveryStep::MaintainGeneration,
            ]
        );
    }
}

#[test]
fn required_generation_failure_cannot_start_or_repair_a_stale_selected_runtime() {
    let mut operations = Vec::new();
    let result = recover_application_in_order(false, |step| {
        operations.push(step);
        if step == ApplicationRecoveryStep::MaintainGeneration {
            Err("replacement authority unavailable".into())
        } else {
            panic!("application recovery ran before the required replacement")
        }
    });
    assert_eq!(result.err().unwrap(), "replacement authority unavailable");
    assert_eq!(operations, [ApplicationRecoveryStep::MaintainGeneration]);
}

#[test]
fn failed_early_health_start_or_validation_stops_before_optional_maintenance() {
    for failure in [
        ApplicationRecoveryStep::RepairHealth,
        ApplicationRecoveryStep::StartRetained,
        ApplicationRecoveryStep::ValidateSelected,
    ] {
        let mut operations = Vec::new();
        let result = recover_application_in_order(true, |step| {
            operations.push(step);
            if step == failure {
                Err("retained runtime did not validate".into())
            } else {
                Ok(Value::Null)
            }
        });
        assert_eq!(result.err().unwrap(), "retained runtime did not validate");
        assert_eq!(operations.last(), Some(&failure));
        assert!(!operations.contains(&ApplicationRecoveryStep::MaintainGeneration));
        assert_eq!(
            operations
                .iter()
                .filter(|step| **step == ApplicationRecoveryStep::RepairHealth)
                .count(),
            1
        );
    }
}

#[test]
fn successful_maintenance_revalidates_the_successor_without_a_second_health_or_start_pass() {
    for fail_final_validation in [false, true] {
        let mut selected = "parent";
        let mut repairs = 0;
        let mut starts = 0;
        let mut validated = Vec::new();
        let result = recover_application_in_order(true, |step| {
            match step {
                ApplicationRecoveryStep::RepairHealth => {
                    repairs += 1;
                    return Ok(json!({"repair":"bounded"}));
                }
                ApplicationRecoveryStep::StartRetained => {
                    starts += 1;
                    return Ok(json!({"started_generation":selected}));
                }
                ApplicationRecoveryStep::MaintainGeneration => {
                    selected = "successor";
                    return Ok(json!({"activation_performed":true}));
                }
                ApplicationRecoveryStep::ValidateSelected => {
                    validated.push(selected);
                    if selected == "successor" && fail_final_validation {
                        return Err("successor validation failed".into());
                    }
                }
            }
            Ok(Value::Null)
        });
        assert_eq!(repairs, 1);
        assert_eq!(starts, 1);
        assert_eq!(validated, ["parent", "successor"]);
        if fail_final_validation {
            assert_eq!(result.err().unwrap(), "successor validation failed");
        } else {
            let report = result.unwrap();
            assert_eq!(report.health, json!({"repair":"bounded"}));
            assert_eq!(report.application["started_generation"], "parent");
            assert_eq!(report.generation["activation_performed"], true);
        }
    }
}

#[test]
fn stale_runtime_recovery_starts_the_replacement_after_required_maintenance() {
    let mut replaced = false;
    let mut serving = false;
    let mut repairs = 0;
    let mut validations = 0;
    let report = recover_application_in_order(false, |step| {
        match step {
            ApplicationRecoveryStep::MaintainGeneration => {
                replaced = true;
                return Ok(json!({"activation_performed":true}));
            }
            ApplicationRecoveryStep::RepairHealth => {
                assert!(replaced);
                repairs += 1;
            }
            ApplicationRecoveryStep::StartRetained => {
                assert!(replaced);
                serving = true;
            }
            ApplicationRecoveryStep::ValidateSelected => {
                assert!(serving);
                validations += 1;
            }
        }
        Ok(Value::Null)
    })
    .unwrap();
    assert!(serving);
    assert_eq!(repairs, 1);
    assert_eq!(validations, 1);
    assert_eq!(report.generation["activation_performed"], true);
}
