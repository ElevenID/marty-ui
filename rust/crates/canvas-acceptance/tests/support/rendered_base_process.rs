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
            super::canvas_published_database::repository_root()
                .join("scripts/render_base_native_runtime_fixture.py"),
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

#[cfg(target_os = "linux")]
#[test]
fn rendered_base_renewal_config_crosses_encryption_and_private_address_policy() {
    use serde_json::json;

    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Rendered base configuration requires the configured Linux Canvas gate");
        return;
    }
    // This is a renderer/component proof, not a substitute for the owned
    // database, ingress, process, wallet, and cleanup acceptance cases.
    let directory = tempfile::tempdir().expect("owned synthetic policy directory");
    let ca = directory.path().join("ca.pem");
    let policy = directory.path().join("didcomm-encryption-policy.json");
    let token = directory.path().join("openbao-token");
    std::fs::write(&ca, b"synthetic CA fixture").unwrap();
    std::fs::write(&policy, b"{}").unwrap();
    std::fs::write(&token, b"synthetic token fixture").unwrap();
    let ca = ca.to_str().unwrap();
    let policy = policy.to_str().unwrap();

    for (authenticated, allow_private_ips, expected_private_ips) in [
        (false, false, "false"),
        (true, false, "false"),
        (false, true, "true"),
        (true, true, "true"),
    ] {
        let spec = json!({
            "inputs": {
                "ISSUANCE_API_KEY": super::issuance_named_peers::API_KEY,
                "GRPC_SERVICE_TOKEN": super::issuance_named_peers::TOKEN,
                "SIGNING_KEYS_INTERNAL_API_KEY": super::issuance_named_peers::SIGNING_KEY,
                "TOKEN_HMAC_KEY": "synthetic-fresh-main-hmac",
                "PUBLIC_API_URL": "https://issuer.example",
                "UI_BASE_URL": "http://localhost:3000",
                "ISSUANCE_OFFER_TTL_MINUTES": "10080",
                "TOKEN_RATE_LIMIT": "30",
                "CANVAS_PORTABLE_INTEGRATION_ENABLED": "false",
                "CANVAS_PILOT_ORGANIZATION_IDS": ""
            },
            "http_port": 18005,
            "grpc_port": 19005,
            "gateway_port": 18000,
            "database_url": "postgresql://oracle:synthetic-local-only@127.0.0.1:15432/canvas_published_schema_test",
            "redis_url": "redis://127.0.0.1:16379",
            "peer_origin": "http://127.0.0.1:18001",
            "legacy_origin": "http://127.0.0.1:18002",
            "ca_file": ca,
            "policy_directory": directory.path(),
            "kms_url": "http://127.0.0.1:18200",
            "kms_token_file": token,
            "integration_secret_kms_url": "https://127.0.0.1:18201/internal",
            "integration_secret_kms_ca_file": ca,
            "authcrypt": authenticated,
            "allow_private_ips": allow_private_ips
        });
        let rendered = RenderedBase::render(&spec);
        let native = &rendered.native_environment;
        let gateway = &rendered.gateway_environment;
        assert_eq!(
            native.get("DIDCOMM_ALLOW_PRIVATE_IPS").map(String::as_str),
            Some(expected_private_ips)
        );
        assert_eq!(
            native.get("DIDCOMM_TLS_CA_FILE").map(String::as_str),
            Some(ca)
        );
        assert_eq!(
            native.get("DIDCOMM_KMS_ADDR").map(String::as_str),
            Some("http://127.0.0.1:18200")
        );
        assert_eq!(
            native.get("DIDCOMM_KMS_TOKEN_FILE").map(String::as_str),
            Some(token.to_str().unwrap())
        );
        assert_eq!(
            native.get("INTEGRATION_SECRET_KMS_URL").map(String::as_str),
            Some("https://127.0.0.1:18201/internal")
        );
        assert_eq!(
            native
                .get("INTEGRATION_SECRET_KMS_CA_FILE")
                .map(String::as_str),
            Some(ca)
        );
        assert_eq!(
            native
                .get("DIDCOMM_ENCRYPTION_POLICY_FILE")
                .map(String::as_str),
            if authenticated { Some(policy) } else { None }
        );
        assert_eq!(
            native
                .get("DIDCOMM_DID_WEB_INTERNAL_BASE_URL")
                .map(String::as_str),
            Some("http://127.0.0.1:18001")
        );
        assert_eq!(
            native.get("ISSUANCE_SERVICE_PORT").map(String::as_str),
            Some("18005")
        );
        assert_eq!(
            native.get("ISSUANCE_GRPC_PORT").map(String::as_str),
            Some("19005")
        );
        assert_eq!(
            gateway.get("ISSUANCE_SERVICE_URL").map(String::as_str),
            Some("http://127.0.0.1:18002")
        );
        assert_eq!(
            gateway
                .get("ISSUANCE_NATIVE_SERVICE_URL")
                .map(String::as_str),
            Some("http://127.0.0.1:18005")
        );
        assert_eq!(
            gateway.get("REDIS_URL").map(String::as_str),
            Some("redis://127.0.0.1:16379")
        );
    }
    println!("\nRENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1");
}
