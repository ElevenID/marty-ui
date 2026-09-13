//! Actual rendered Flow settings -> canonical file loader -> real configuration
//! and provider factory. This is NOT full Flow startup/public authorization or
//! container DNS/TLS handshakes. Other lazy provider channels are never called.
use super::super::super::bounded_fixture_command;
use super::{physical, server_with_rejection, snapshot, Ports, Seeds, TOKEN};
use marty_flow::{
    FlowConfigError, FlowGrpcChannelFactories, FlowProviderError, FlowServiceConfig,
    HttpPhysicalDocumentProvider, IssuanceInitiationRequest, IssuanceInitiationResult,
    IssuanceProvider,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
};

const PREFIX: &str = "MARTY_FLOW_RENDERED_RESULT_V1=";
const KEY: &str = "synthetic-legacy-physical-api-key";
const FILES: &[&str] = &[
    "grpc_service_token",
    "issuance_api_key",
    "marty_db_password",
    "flow_webhook_secret",
    "flow_application_event_hmac_key",
    "flow_workload_client_cert",
    "flow_workload_client_key",
    "flow_workload_server_cert",
    "flow_workload_server_key",
    "workload_identity_ca_cert",
    "ca.pem",
    "server.key",
    "loader.sh",
    "flow.stdout",
    "flow.stderr",
];

pub(super) struct Directory(pub(super) PathBuf);
impl Directory {
    pub(super) fn new() -> Self {
        // Verify canonical ownership without passing Windows verbatim paths
        // to Git OpenSSL, matching the existing owned wallet fixture.
        let root = std::env::temp_dir();
        assert!(root.is_absolute());
        let resolved = root.canonicalize().unwrap();
        let path = root.join(format!("flow-rendered-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        let owned = Self(path);
        assert_eq!(
            owned.0.canonicalize().unwrap().parent(),
            Some(resolved.as_path())
        );
        owned
    }
    pub(super) fn close(self) {
        self.remove().unwrap();
        assert!(!self.0.exists());
    }
    fn remove(&self) -> std::io::Result<()> {
        if !self.0.exists() {
            return Ok(());
        }
        for name in FILES {
            match std::fs::remove_file(self.0.join(name)) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
        }
        // No recursive deletion; unknown content makes explicit cleanup fail.
        std::fs::remove_dir(&self.0)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if self.remove().is_err() {
            eprintln!("owned Flow fixture cleanup failed");
        }
    }
}

pub(super) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn capture(command: &mut Command, input: Option<&[u8]>) -> Vec<u8> {
    let output = bounded_fixture_command::run(command, input, Duration::from_secs(120), 262144)
        .expect("owned Flow fixture command must finish within bounded capture");
    assert!(
        output.status.success(),
        "owned synthetic Flow fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

pub(super) fn render(spec: &Value) -> Value {
    let mut command = Command::new(
        std::env::var_os("MARTY_DIDCOMM_TEST_PYTHON").expect("explicit Python fixture required"),
    );
    command.env_clear();
    for name in [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "PATHEXT",
        "COMSPEC",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .arg(root().join("scripts/render_flow_native_runtime_fixture.py"))
        .arg("--compose-command")
        .arg(
            std::env::var_os("MARTY_BASE_COMPOSE_BINARY")
                .expect("explicit pinned Compose required"),
        )
        .env("PYTHONDONTWRITEBYTECODE", "1");
    serde_json::from_slice(&capture(
        &mut command,
        Some(&serde_json::to_vec(spec).unwrap()),
    ))
    .unwrap()
}

fn child_command(
    environment: &BTreeMap<String, String>,
    directory: &Path,
    action: &str,
    deployed: bool,
) -> Command {
    let shell = if cfg!(windows) {
        PathBuf::from("C:/Program Files/Git/usr/bin/sh.exe")
    } else {
        PathBuf::from("/bin/sh")
    };
    assert!(shell.is_file());
    let mut command = Command::new(&shell);
    command.env_clear().envs(environment)
        .env("PATH", shell.parent().unwrap())
        .env("MARTY_FLOW_RENDERED_CHILD", "1")
        .env("MARTY_FLOW_RENDERED_ACTION", action)
        .env("MARTY_FLOW_RENDERED_DEPLOYED", if deployed { "1" } else { "0" })
        .args(["-c", ". \"$1\"; exec \"$2\" --exact flow_rendered_provider_child --nocapture --test-threads=1", "flow-rendered-loader"])
        .arg(directory.join("loader.sh"))
        .arg(std::env::current_exe().unwrap());
    #[cfg(windows)]
    command.env("SystemRoot", std::env::var_os("SystemRoot").unwrap());
    command
}

async fn execute(
    environment: &BTreeMap<String, String>,
    directory: &Path,
    action: &str,
    deployed: bool,
) -> Value {
    let mut command = child_command(environment, directory, action, deployed);
    let output = tokio::task::spawn_blocking(move || capture(&mut command, None))
        .await
        .unwrap();
    let text = String::from_utf8(output).unwrap();
    let matches: Vec<_> = text
        .lines()
        .filter_map(|line| line.find(PREFIX).map(|index| &line[index + PREFIX.len()..]))
        .collect();
    assert_eq!(matches.len(), 1, "exact unique child completion report");
    serde_json::from_str(matches[0]).unwrap()
}

fn request(conflict: bool, deployed: bool) -> IssuanceInitiationRequest {
    let profile = if deployed { "selfhost" } else { "base_native" };
    IssuanceInitiationRequest {
        organization_id: "org-1".into(),
        flow_instance_id: format!("rendered-{profile}-flow-instance"),
        credential_template_id: "template-1".into(),
        applicant_id: Some("applicant-1".into()),
        subject_did: Some("did:key:z6MkHolder".into()),
        holder_did: None,
        authorized_client_id: None,
        application_id: None,
        issuer_did: "did:web:issuer.example".into(),
        delivery_mode: Some("wallet_only".into()),
        idempotency_key: Some(format!("rendered-{profile}-flow-key-attempt-1")),
        claims: BTreeMap::from([("profile".into(), json!({"level":if conflict {3} else {2}}))]),
    }
}

pub(super) async fn child() {
    assert_eq!(
        std::env::var("MARTY_FLOW_RENDERED_CHILD").as_deref(),
        Ok("1")
    );
    let action = std::env::var("MARTY_FLOW_RENDERED_ACTION").unwrap();
    let config = FlowServiceConfig::from_env();
    if let Some(name) = action.strip_prefix("missing:") {
        assert!(matches!(config, Err(FlowConfigError::Missing { name: actual }) if actual == name));
        println!("{PREFIX}{}", json!({"kind":"config-missing"}));
        return;
    }
    let config = config.unwrap();
    let deployed = std::env::var("MARTY_FLOW_RENDERED_DEPLOYED").as_deref() == Ok("1");
    assert_eq!(config.workload_client_tls.is_some(), deployed);
    assert_eq!(config.workload_server_tls.is_some(), deployed);
    assert_eq!(config.redis_database, 3);
    assert_eq!(config.organization_grpc_target, "http://organization:9002");
    assert_eq!(
        config.credential_template_grpc_target,
        "http://credential-template:9003"
    );
    assert_eq!(
        config.presentation_policy_grpc_target,
        "http://presentation-policy:9009"
    );
    assert_eq!(config.signing_keys_url, "http://signing-keys:8017/internal");
    assert_eq!(config.issuance_api_key.as_deref(), Some(KEY));
    assert_eq!(config.signing_keys_api_key.as_deref(), Some(KEY));
    assert!(config.database_url.starts_with("postgresql://"));
    assert!(!config.database_url.contains("${"));
    // Do not connect unrelated provider owners. All issuance calls below use
    // the actual factory and its rendered target/authentication decisions.
    let factories = FlowGrpcChannelFactories::from_config(&config).unwrap();
    let providers = factories
        .connect_lazy()
        .unwrap()
        .providers(config.service_token.as_deref())
        .unwrap();
    let result = if action == "physical" {
        HttpPhysicalDocumentProvider::new(
            &config.issuance_url,
            config.issuance_api_key.as_deref().unwrap(),
        )
        .unwrap()
        .health_check()
        .await
        .unwrap();
        json!({"kind":"physical"})
    } else {
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            providers
                .issuance
                .initiate(&request(action == "conflict", deployed)),
        )
        .await
        .unwrap();
        match result {
            Ok(result) => json!({"kind":"success","result":result}),
            Err(FlowProviderError::Unavailable { .. }) => json!({"kind":"unavailable"}),
            Err(FlowProviderError::Rejected { .. }) => json!({"kind":"rejected"}),
            Err(FlowProviderError::Conflict { .. }) => json!({"kind":"conflict"}),
            Err(error) => panic!("unexpected actual Flow provider error: {error}"),
        }
    };
    println!("{PREFIX}{result}");
}

pub(super) async fn run(database_url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .unwrap();
    // Existing complete snapshot includes Flow tables; no orchestration proof
    // is duplicated here, but unexpected Flow writes remain visible.
    marty_flow::migrate_flow_schema(&pool).await.unwrap();
    let ports = Arc::new(Ports::default());
    let seeds = Arc::new(Seeds {
        next: AtomicUsize::new(0),
        ports: ports.clone(),
    });
    let native = server_with_rejection(&pool, ports.clone(), seeds.clone(), None).await;
    let legacy = server_with_rejection(&pool, ports.clone(), seeds, Some(TOKEN)).await;
    let physical = physical::Legacy::start().await;
    let directory = Directory::new();
    let spec = json!({"native_rpc":native.origin(),"legacy_rpc":legacy.origin(),"legacy_http":physical.origin(),"directory":directory.0});
    let model = tokio::task::spawn_blocking(move || render(&spec))
        .await
        .unwrap();
    assert_eq!(model["schema"], "marty.flow-rendered-selection/v1");
    let source = std::fs::read_to_string(root().join("scripts/load-secrets-env.sh")).unwrap();
    // Same LF normalization as packaged POSIX shell assets, no logic changes.
    std::fs::write(directory.0.join("loader.sh"), source.replace("\r\n", "\n")).unwrap();
    let profiles: BTreeMap<String, Value> =
        serde_json::from_value(model["profiles"].clone()).unwrap();
    assert_eq!(
        profiles.keys().map(String::as_str).collect::<Vec<_>>(),
        ["base", "base_native", "selfhost"]
    );
    let before = snapshot(&pool).await;
    let base: BTreeMap<String, String> =
        serde_json::from_value(profiles["base"]["environment"].clone()).unwrap();
    assert_eq!(
        execute(&base, &directory.0, "normal", false).await["kind"],
        "rejected"
    );
    // Standalone base intentionally has no forwarded service token. A second
    // controlled baseline token proves the listener is a live authenticated
    // RPC trap, not merely an unresolvable address.
    let mut authenticated_base = base.clone();
    authenticated_base.insert("GRPC_SERVICE_TOKEN".into(), TOKEN.into());
    assert_eq!(
        execute(&authenticated_base, &directory.0, "normal", false).await["kind"],
        "unavailable"
    );
    assert_eq!(legacy.attempts(), 2);
    assert_eq!(native.attempts(), 0);
    assert_eq!(snapshot(&pool).await, before);
    for (index, name) in ["base_native", "selfhost"].into_iter().enumerate() {
        let environment: BTreeMap<String, String> =
            serde_json::from_value(profiles[name]["environment"].clone()).unwrap();
        let deployed = name == "selfhost";
        let before_config = snapshot(&pool).await;
        let before_config_attempts = native.attempts();
        for missing in [
            "ISSUANCE_API_KEY",
            "SIGNING_KEYS_INTERNAL_API_KEY",
            "GRPC_SERVICE_TOKEN",
        ] {
            if deployed {
                let mut invalid = environment.clone();
                assert!(invalid.remove(&format!("{missing}_FILE")).is_some());
                assert_eq!(
                    execute(
                        &invalid,
                        &directory.0,
                        &format!("missing:{missing}"),
                        deployed
                    )
                    .await["kind"],
                    "config-missing"
                );
                assert_eq!(legacy.attempts(), 2);
                assert_eq!(native.attempts(), before_config_attempts);
                assert_eq!(snapshot(&pool).await, before_config);
            }
        }
        let before_auth = snapshot(&pool).await;
        let previous_attempts = native.attempts();
        if !deployed {
            let mut missing = environment.clone();
            assert!(missing.remove("GRPC_SERVICE_TOKEN").is_some());
            assert_eq!(
                execute(&missing, &directory.0, "normal", false).await["kind"],
                "rejected"
            );
            assert_eq!(native.attempts(), previous_attempts + 1);
            assert_eq!(legacy.attempts(), 2);
            assert_eq!(snapshot(&pool).await, before_auth);
        }
        let missing_attempt = usize::from(!deployed);
        let mut wrong = environment.clone();
        wrong.remove("GRPC_SERVICE_TOKEN_FILE");
        wrong.insert(
            "GRPC_SERVICE_TOKEN".into(),
            "synthetic-wrong-service-token-long-enough".into(),
        );
        assert_eq!(
            execute(&wrong, &directory.0, "normal", deployed).await["kind"],
            "rejected"
        );
        assert_eq!(native.attempts(), previous_attempts + missing_attempt + 1);
        assert_eq!(snapshot(&pool).await, before_auth);
        let created = execute(&environment, &directory.0, "normal", deployed).await;
        assert_eq!(created["kind"], "success");
        let result: IssuanceInitiationResult =
            serde_json::from_value(created["result"].clone()).unwrap();
        assert_eq!(
            result.transaction_id,
            format!("flow-composed-transaction-{}", index + 1)
        );
        assert_eq!(
            result.pre_authorized_code.as_deref(),
            Some(format!("synthetic-flow-composed-code-{}", index + 1).as_str())
        );
        assert_eq!(result.status, "pending");
        assert_eq!(result.expires_at_ms, Some(1_788_093_900_000));
        assert_eq!(
            result
                .credential_offer_uris
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["ordinary"]
        );
        assert_eq!(
            result.credential_offer_uri.as_ref(),
            result.credential_offer_uris.get("ordinary")
        );
        assert_eq!(
            result.credential_offer_labels,
            BTreeMap::from([("ordinary".into(), "Ordinary Wallet".into())])
        );
        let offer = url::Url::parse(result.credential_offer_uri.as_deref().unwrap()).unwrap();
        assert_eq!(offer.scheme(), "openid-credential-offer");
        let pairs: Vec<_> = offer.query_pairs().collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "credential_offer");
        assert_eq!(
            serde_json::from_str::<Value>(&pairs[0].1).unwrap(),
            json!({
                "credential_issuer":"https://issuer.example/org/org-1",
                "credential_configuration_ids":["EmployeeCredential#sd-jwt"],
                "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":result.pre_authorized_code}}
            })
        );
        assert_eq!(created["result"].as_object().unwrap().len(), 7);
        let stored = snapshot(&pool).await;
        assert_eq!(
            execute(&environment, &directory.0, "normal", deployed).await,
            created
        );
        assert_eq!(
            execute(&environment, &directory.0, "conflict", deployed).await["kind"],
            "conflict"
        );
        assert_eq!(snapshot(&pool).await, stored);
        assert_eq!(
            execute(&environment, &directory.0, "physical", deployed).await["kind"],
            "physical"
        );
        assert_eq!(native.attempts(), previous_attempts + missing_attempt + 4);
        assert_eq!(legacy.attempts(), 2, "no configured RPC fallback");
    }
    physical.assert_health_requests(2);
    let stored = snapshot(&pool).await;
    native.close().await;
    for name in ["base_native", "selfhost"] {
        let environment = serde_json::from_value(profiles[name]["environment"].clone()).unwrap();
        assert_eq!(
            execute(&environment, &directory.0, "normal", name == "selfhost").await["kind"],
            "unavailable"
        );
        assert_eq!(legacy.attempts(), 2);
        assert_eq!(snapshot(&pool).await, stored);
    }
    physical.assert_health_requests(2);
    physical.close().await;
    legacy.close().await;
    pool.close().await;
    directory.close();
}
