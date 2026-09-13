//! Validated fixture environments only. This does not resolve deployment inputs.
use std::{
    collections::BTreeMap,
    path::Path,
    process::{Command, Stdio},
};

#[derive(Clone, Copy)]
pub(super) enum Isolation {
    Base,
    Kubernetes,
}

pub(super) struct ResolvedRuntime {
    pub(super) native_environment: BTreeMap<String, String>,
    pub(super) gateway_environment: BTreeMap<String, String>,
    pub(super) isolation: Isolation,
}

impl ResolvedRuntime {
    pub(super) fn native_command(&self) -> Command {
        exact_environment_command(
            Path::new(env!("CARGO_BIN_EXE_marty-issuance-service")),
            &self.native_environment,
        )
    }

    pub(super) fn gateway_command(&self) -> Command {
        assert_eq!(
            std::env::consts::OS,
            "linux",
            "gateway requires owned Linux namespace isolation"
        );
        assert_eq!(
            std::env::var("MARTY_BASE_RUNTIME_CHILD").as_deref(),
            Ok("1")
        );
        if matches!(self.isolation, Isolation::Kubernetes) {
            assert_eq!(
                std::env::var("MARTY_KUBERNETES_RUNTIME_CHILD").as_deref(),
                Ok("1")
            );
        }
        exact_environment_command(
            &Path::new(env!("CARGO_BIN_EXE_marty-issuance-service"))
                .with_file_name("marty-gateway"),
            &self.gateway_environment,
        )
    }
}

fn exact_environment_command(binary: &Path, environment: &BTreeMap<String, String>) -> Command {
    assert!(binary.is_file(), "required exact test binary is built");
    let mut command = Command::new(binary);
    command
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    command
}
