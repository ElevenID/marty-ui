//! Exact actual-Compose environment -> native process boundary. No smoke
//! defaults are injected after rendering; only the Windows loader root survives.
use std::{
    collections::BTreeMap,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::Value;

const MODEL_LIMIT: u64 = 262144;

fn bounded_render(
    command: &mut Command,
    input: &[u8],
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    use super::bounded_fixture_command::{run, CommandFailure};
    let output = run(command, Some(input), timeout, MODEL_LIMIT).map_err(|error| match error {
        CommandFailure::Io(error) => error,
        CommandFailure::TimedOut => std::io::Error::other("Compose rendering exceeded deadline"),
        CommandFailure::OutputTooLarge => std::io::Error::other("rendered model exceeds limit"),
        CommandFailure::TerminationFailed => {
            std::io::Error::other("owned renderer did not exit after kill")
        }
    })?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let diagnostic = String::from_utf8(output.stderr)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        Err(std::io::Error::other(format!(
            "read-only synthetic Compose fixture rendering failed: {diagnostic}"
        )))
    }
}

pub(super) fn assert_renderer_deadlines() {
    let python = std::env::var_os("MARTY_DIDCOMM_TEST_PYTHON")
        .expect("configured renderer qualification requires explicit Python");
    for (program, expected) in [
        (
            "import os,time; os.close(1); time.sleep(30)",
            "Compose rendering exceeded deadline",
        ),
        (
            "import sys,time; sys.stdout.write('x'*262145); sys.stdout.flush(); time.sleep(30)",
            "rendered model exceeds limit",
        ),
    ] {
        let started = Instant::now();
        let error = bounded_render(
            Command::new(&python).args(["-c", program]),
            b"{}",
            Duration::from_millis(400),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert!(started.elapsed() < Duration::from_secs(10));
    }
    assert_eq!(
        bounded_render(
            Command::new(python).args(["-c", "import sys; sys.stdout.write(sys.stdin.read())"]),
            b"{}",
            Duration::from_secs(10),
        )
        .unwrap(),
        b"{}"
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RenderedBase {
    schema: String,
    pub(super) native_environment: BTreeMap<String, String>,
    pub(super) gateway_environment: BTreeMap<String, String>,
    overlay: Value,
    base_files: Vec<String>,
    native_entrypoint: Vec<String>,
    native_command: Vec<String>,
    scope: String,
}

impl RenderedBase {
    pub(super) fn render(spec: &Value) -> Self {
        let python =
            std::env::var_os("MARTY_DIDCOMM_TEST_PYTHON").unwrap_or_else(|| "python3".into());
        let mut command = Command::new(python);
        command.env_clear();
        for name in ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.env("PYTHONUTF8", "1").arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../scripts/render_base_native_runtime_fixture.py"),
        );
        if let Some(renderer) = std::env::var_os("MARTY_BASE_COMPOSE_BINARY") {
            assert!(
                Path::new(&renderer).is_file(),
                "configured Compose renderer exists"
            );
            command.arg("--compose-command").arg(renderer);
        }
        let bytes = bounded_render(
            &mut command,
            &serde_json::to_vec(spec).unwrap(),
            Duration::from_secs(100),
        )
        .expect("bounded complete Compose model and owned renderer lifetime");
        let rendered: Self = serde_json::from_slice(&bytes).expect("typed rendered fixture model");
        assert_eq!(rendered.schema, "marty.base-native-process-fixture/v1");
        assert_eq!(rendered.native_entrypoint, ["/app/services/entrypoint.sh"]);
        assert!(rendered.native_command.is_empty());
        assert_eq!(
            rendered.native_environment["SERVICE_NAME"],
            "issuance_native"
        );
        assert_eq!(rendered.native_environment["ISSUANCE_GRPC_ENABLED"], "true");
        assert_eq!(rendered.gateway_environment["REDIS_DB_GATEWAY"], "2");
        assert_eq!(rendered.base_files[0], "docker-compose.base.yml");
        assert_eq!(
            rendered.base_files[1],
            "docker-compose.profile.issuance-native.yml"
        );
        assert_eq!(rendered.overlay["services"].as_object().unwrap().len(), 2);
        assert!(rendered
            .scope
            .contains("not container networking or release-image proof"));
        rendered
    }

    pub(super) fn resolved(self) -> super::resolved_runtime::ResolvedRuntime {
        super::resolved_runtime::ResolvedRuntime {
            native_environment: self.native_environment,
            gateway_environment: self.gateway_environment,
            isolation: super::resolved_runtime::Isolation::Base,
        }
    }
}
