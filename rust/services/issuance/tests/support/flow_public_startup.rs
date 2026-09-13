//! Actual same-build Flow main and public service handlers with rendered base
//! configuration. Not a production image, gateway JWT, selfhost TLS or callback
//! delivery qualification. No application listener or operator config is used.
#[path = "flow_public_startup_peers.rs"]
mod peers;
use super::super::super::{
    bounded_fixture_command::{self, stop_owned_child},
    issuance_process::reserve_port,
};
use super::{
    assert_native_result, definition, key_hash, rendered, server_with_rejection, snapshot, Ports,
    Seeds, TOKEN,
};
use marty_flow::{
    flow_proto::{flow_service_client::FlowServiceClient, HealthCheckRequest},
    ArtifactStatus, FlowArtifactRecord, IssuanceInitiationResult, PostgresFlowRepository,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

struct Process {
    child: Arc<Mutex<Child>>,
    directory: PathBuf,
    stopped: bool,
    output_failed: Arc<AtomicBool>,
    monitor: tokio::task::JoinHandle<()>,
    #[cfg(windows)]
    binary: Option<PathBuf>,
}
impl Process {
    fn start(environment: &BTreeMap<String, String>, directory: &Path) -> Self {
        let binary = Path::new(env!("CARGO_BIN_EXE_marty-issuance-service")).with_file_name(
            if cfg!(windows) {
                "marty-flow.exe"
            } else {
                "marty-flow"
            },
        );
        assert!(
            binary.is_file(),
            "Required same-build Flow binary must be built by the gate"
        );
        let loaded = load_environment(environment, directory);
        // Git sh's exec on Windows can retain a separate native child. Start
        // the actual binary directly after the bounded loader has exited.
        let mut command = Command::new(&binary);
        command.env_clear().envs(loaded);
        #[cfg(windows)]
        command.env("SystemRoot", std::env::var_os("SystemRoot").unwrap());
        assert_eq!(command.get_program(), binary.as_os_str());
        assert_eq!(
            command.get_args().count(),
            0,
            "Actual Flow child must not be a wrapper shell"
        );
        let process = Self::spawn(command, directory);
        #[cfg(windows)]
        let process = {
            let mut process = process;
            process.binary = Some(binary);
            process
        };
        eprintln!(
            "Exact-owned Flow main process: {}",
            process.child.lock().unwrap().id()
        );
        process
    }
    fn spawn(mut command: Command, directory: &Path) -> Self {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                std::fs::File::create(directory.join("flow.stdout")).unwrap(),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(directory.join("flow.stderr")).unwrap(),
            ));
        let child = Arc::new(Mutex::new(command.spawn().unwrap()));
        let output_failed = Arc::new(AtomicBool::new(false));
        let monitored_child = child.clone();
        let monitored_failure = output_failed.clone();
        let monitored_directory = directory.to_owned();
        let monitor = tokio::spawn(async move {
            loop {
                if !output_within_limit(&monitored_directory) {
                    monitored_failure.store(true, Ordering::SeqCst);
                    if stop_owned_child(&mut monitored_child.lock().unwrap()).is_err() {
                        eprintln!("Owned Flow output-limit cleanup failed");
                    }
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        });
        Self {
            child,
            directory: directory.to_owned(),
            stopped: false,
            output_failed,
            monitor,
            #[cfg(windows)]
            binary: None,
        }
    }
    fn check_output(&self) {
        assert!(!self.output_failed.load(Ordering::SeqCst));
        assert!(
            output_within_limit(&self.directory),
            "Closed process output bound"
        );
    }
    async fn ready(&mut self, client: &reqwest::Client, url: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            self.check_output();
            assert!(
                self.child.lock().unwrap().try_wait().unwrap().is_none(),
                "Flow exited before readiness"
            );
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("Owned Flow readiness deadline");
            if let Ok(response) = client
                .get(format!("{url}/ready"))
                .timeout(remaining.min(Duration::from_secs(3)))
                .send()
                .await
            {
                if response.status().is_success() {
                    return response.json().await.unwrap();
                }
            }
            assert!(Instant::now() < deadline, "Owned Flow readiness deadline");
            tokio::time::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(25)),
            )
            .await;
        }
    }
    async fn rejected(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            self.check_output();
            if let Some(status) = self.child.lock().unwrap().try_wait().unwrap() {
                assert!(!status.success());
                return;
            }
            assert!(Instant::now() < deadline, "Owned failed startup deadline");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    async fn terminate(&mut self) {
        stop_owned_child(&mut self.child.lock().unwrap()).unwrap();
        assert!(self.child.lock().unwrap().try_wait().unwrap().is_some());
        self.stopped = true;
        self.monitor.abort();
        if let Err(error) = (&mut self.monitor).await {
            assert!(error.is_cancelled());
        }
        assert!(
            self.monitor.is_finished(),
            "No output-monitor task remains after verified cleanup"
        );
    }
    async fn close(mut self) {
        self.terminate().await;
        self.check_output();
        #[cfg(windows)]
        if let Some(binary) = &self.binary {
            // Read-only diagnostic: open without truncate and never write. A
            // surviving Windows executable mapping denies this access, as the
            // original shell-child leak did during the following Cargo build.
            drop(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(binary)
                    .expect("Owned native Flow executable must have no surviving image lock"),
            );
        }
    }
}

fn load_environment(
    environment: &BTreeMap<String, String>,
    directory: &Path,
) -> BTreeMap<String, String> {
    let (shell, env_binary) = if cfg!(windows) {
        (
            "C:/Program Files/Git/usr/bin/sh.exe",
            "C:/Program Files/Git/usr/bin/env.exe",
        )
    } else {
        ("/bin/sh", "/usr/bin/env")
    };
    let mut command = Command::new(shell);
    command
        .env_clear()
        .envs(environment)
        .env("PATH", Path::new(shell).parent().unwrap())
        .args(["-c", ". \"$1\"; exec \"$2\" -0", "flow-owned-environment"])
        .arg(directory.join("loader.sh"))
        .arg(env_binary);
    #[cfg(windows)]
    command.env("SystemRoot", std::env::var_os("SystemRoot").unwrap());
    let output = bounded_fixture_command::run(&mut command, None, Duration::from_secs(10), 262144)
        .expect("Closed loader capture must finish within deadline");
    assert!(
        output.status.success() && output.stderr.is_empty(),
        "Closed loader refused synthetic input"
    );
    let mut allowed: BTreeSet<_> = environment.keys().cloned().collect();
    for name in environment.keys() {
        for suffix in ["_FILE", "_TEMPLATE"] {
            if let Some(base) = name.strip_suffix(suffix) {
                allowed.insert(base.into());
            }
        }
    }
    let mut loaded = BTreeMap::new();
    assert_eq!(output.stdout.last(), Some(&0));
    for entry in output.stdout[..output.stdout.len() - 1].split(|byte| *byte == 0) {
        let text = std::str::from_utf8(entry).expect("Closed loader encoding");
        let (name, value) = text.split_once('=').expect("Closed loader entry");
        if matches!(
            name,
            "PATH" | "PWD" | "SHLVL" | "_" | "SystemRoot" | "SYSTEMROOT"
        ) {
            continue;
        }
        // An env-cleared Git sh synthesizes these process defaults on Windows.
        // They are not loader settings and must never reach the Flow child.
        #[cfg(windows)]
        if matches!(name, "HOME" | "TERM" | "WINDIR") {
            continue;
        }
        assert!(
            allowed.contains(name),
            "Loader must not introduce undeclared environment"
        );
        assert!(
            loaded.insert(name.to_owned(), value.to_owned()).is_none(),
            "Unambiguous loaded environment"
        );
    }
    loaded
}
impl Drop for Process {
    fn drop(&mut self) {
        self.monitor.abort();
        if !self.stopped && stop_owned_child(&mut self.child.lock().unwrap()).is_err() {
            eprintln!("Owned Flow process cleanup failed");
        }
    }
}

fn output_within_limit(directory: &Path) -> bool {
    ["flow.stdout", "flow.stderr"]
        .into_iter()
        .all(|name| std::fs::metadata(directory.join(name)).is_ok_and(|value| value.len() < 262144))
}

async fn assert_artifact(
    pool: &sqlx::PgPool,
    instance: &str,
    artifact: &FlowArtifactRecord,
    attempt: u32,
) {
    let result = IssuanceInitiationResult {
        transaction_id: artifact.issuance_transaction_id.clone().unwrap(),
        credential_offer_uri: artifact.credential_offer_uri.clone(),
        credential_offer_uris: artifact.credential_offer_uris.clone(),
        credential_offer_labels: artifact.credential_offer_labels.clone(),
        pre_authorized_code: artifact.pre_authorized_code.clone(),
        expires_at_ms: artifact
            .expires_at
            .map(|value| u64::try_from(value.timestamp_millis()).unwrap()),
        status: artifact.issuance_status.clone().unwrap(),
    };
    let uri = assert_native_result(&result, attempt as usize);
    assert_eq!(artifact.flow_instance_id, instance);
    assert_eq!(artifact.attempt_number, attempt);
    assert_eq!(artifact.status, ArtifactStatus::Active);
    assert_eq!(artifact.state, Some(result.transaction_id.clone()));
    assert!(artifact.qr_payload.is_none() && artifact.scanned_at.is_none());
    assert_eq!(artifact.wallet_metadata, json!({}));
    assert_eq!(artifact.created_at, artifact.updated_at);
    assert_eq!(artifact.credential_offer_uri, Some(uri));
    let transaction: Value = sqlx::query_scalar(
        "SELECT to_jsonb(t) FROM issuance_service.issuance_transactions t WHERE id=$1",
    )
    .bind(&result.transaction_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(transaction["organization_id"], "org-1");
    assert_eq!(
        transaction["idempotency_key_hash"],
        key_hash(&if attempt == 1 {
            format!("flow-instance-offer-v1:{instance}")
        } else {
            format!("flow-instance-offer-v1:{instance}:{attempt}")
        })
    );
}

async fn http(
    client: &reqwest::Client,
    url: &str,
    path: &str,
    user: Option<&str>,
    body: Option<&Value>,
) -> (u16, Value) {
    let mut request = if body.is_some() {
        client.post(format!("{url}{path}"))
    } else {
        client.get(format!("{url}{path}"))
    };
    if let Some(user) = user {
        request = request.header("x-user-id", user);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    assert!(response.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    (status, response.json().await.unwrap())
}

pub(super) async fn run(database_url: &str, redis_url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .unwrap();
    let exists: bool = sqlx::query_scalar("SELECT to_regnamespace('flow_service') IS NOT NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !exists,
        "Actual main, not fixture setup, must perform Flow migrations"
    );
    let ports = Arc::new(Ports::default());
    let seeds = Arc::new(Seeds {
        next: AtomicUsize::new(0),
        ports: ports.clone(),
    });
    let native = server_with_rejection(&pool, ports.clone(), seeds.clone(), None).await;
    let legacy = server_with_rejection(&pool, ports.clone(), seeds.clone(), Some(TOKEN)).await;
    let peers = peers::Peers::start().await;
    let directory = rendered::Directory::new();
    let spec = json!({"native_rpc":native.origin(),"legacy_rpc":legacy.origin(),"legacy_http":peers.url("legacy"),"directory":directory.0});
    let model = tokio::task::spawn_blocking(move || rendered::render(&spec))
        .await
        .unwrap();
    assert_eq!(model["schema"], "marty.flow-rendered-selection/v1");
    let mut environment: BTreeMap<String, String> =
        serde_json::from_value(model["profiles"]["base_native"]["environment"].clone()).unwrap();
    assert_eq!(environment["ENVIRONMENT"], "development");
    assert_eq!(environment["ISSUANCE_GRPC_TARGET"], native.origin());
    assert_eq!(environment["ISSUANCE_SERVICE_URL"], peers.url("legacy"));
    // Closed test endpoint rebinding; every original configured owner is checked.
    for (name, original, role) in [
        ("ORG_GRPC_TARGET", "organization:9002", "organization"),
        (
            "CT_GRPC_TARGET",
            "credential-template:9003",
            "credential-grpc",
        ),
        ("PP_GRPC_TARGET", "presentation-policy:9009", "policy"),
        (
            "SIGNING_KEYS_INTERNAL_URL",
            "http://signing-keys:8017/internal",
            "signing",
        ),
        (
            "CREDENTIAL_TEMPLATE_SERVICE_URL",
            "http://credential-template:8003",
            "template",
        ),
        (
            "TRUST_PROFILE_SERVICE_URL",
            "http://trust-profile:8004",
            "trust",
        ),
        (
            "DEPLOYMENT_PROFILE_SERVICE_URL",
            "http://deployment-profile:8010",
            "deployment",
        ),
    ] {
        assert_eq!(environment[name], original);
        environment.insert(name.into(), peers.url(role));
    }
    assert_eq!(environment["REDIS_URL"], "redis://redis:6379");
    assert_eq!(environment["REDIS_DB_FLOW"], "3");
    assert!(environment["DATABASE_URL"].ends_with("@postgres:5432/marty"));
    environment.insert("DATABASE_URL".into(), database_url.into());
    environment.insert("REDIS_URL".into(), redis_url.into());
    let (http_reservation, http_port) = reserve_port();
    let (grpc_reservation, grpc_port) = reserve_port();
    environment.insert("FLOW_HTTP_ADDR".into(), format!("127.0.0.1:{http_port}"));
    environment.insert("FLOW_GRPC_ADDR".into(), format!("127.0.0.1:{grpc_port}"));
    let source =
        std::fs::read_to_string(rendered::root().join("scripts/load-secrets-env.sh")).unwrap();
    std::fs::write(directory.0.join("loader.sh"), source.replace("\r\n", "\n")).unwrap();
    drop((http_reservation, grpc_reservation));
    let mut process = Process::start(&environment, &directory.0);
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{http_port}");
    let ready = process.ready(&client, &url).await;
    assert_eq!(
        ready,
        json!({"ready":true,"lifecycle":"active","health":"healthy","required_components_healthy":true})
    );
    let (status, health) = http(&client, &url, "/health", None, None).await;
    assert_eq!(status, 200);
    let components = health["components"].as_object().unwrap();
    let expected = [
        "database",
        "nonce_store",
        "organization_grpc",
        "credential_template_grpc",
        "presentation_policy_grpc",
        "issuance_grpc",
        "signing_keys_http",
        "physical_issuance_http",
        "reference_catalog_http",
        "callback_delivery",
        "http_listener",
        "grpc_listener",
    ];
    assert_eq!(
        marty_flow::FlowDependency::all()
            .map(|v| v.name())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(components.len(), expected.len());
    for name in expected {
        assert_eq!(components[name], json!({"status":"healthy"}));
    }
    marty_flow::validate_flow_schema(&pool).await.unwrap();
    peers.assert_health();
    let repository = PostgresFlowRepository::new(pool.clone());
    let definition = definition("oid4vci_pre_authorized");
    repository.save_definition(&definition).await.unwrap();
    let body = json!({"organization_id":"org-1","flow_definition_id":definition.id,"subject_id":"applicant-1","initial_context":{"subject_did":"did:key:z6MkHolder","claims":{"profile":{"level":2}}}});
    let before = snapshot(&pool).await;
    let (status, denied) = http(&client, &url, "/v1/flows/instances", None, Some(&body)).await;
    assert_eq!(
        (status, denied),
        (
            401,
            json!({"error":"authentication_required","detail":"X-User-ID header required"})
        )
    );
    let (status, denied) = http(
        &client,
        &url,
        "/v1/flows/instances",
        Some("foreign-user"),
        Some(&body),
    )
    .await;
    assert_eq!(
        (status, denied),
        (
            403,
            json!({"error":"flow_authorization_failed","detail":"FLOW.PROVIDER_REJECTED: tenant_membership: membership missing"})
        )
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(seeds.next.load(Ordering::SeqCst), 0);
    let (status, started) = http(
        &client,
        &url,
        "/v1/flows/instances",
        Some("synthetic-user"),
        Some(&body),
    )
    .await;
    assert_eq!(status, 200);
    let id = started["id"].as_str().unwrap();
    let stored = repository.instance(id).await.unwrap().unwrap();
    assert_eq!(
        started,
        serde_json::to_value(stored.projection().unwrap()).unwrap()
    );
    let artifacts = repository.artifacts_for_instance(id).await.unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_artifact(&pool, id, &artifacts[0], 1).await;
    let expected: Vec<_> = artifacts.iter().map(|v| v.projection().unwrap()).collect();
    assert_eq!(
        http(
            &client,
            &url,
            &format!("/v1/flows/instances/{id}/artifacts"),
            Some("synthetic-user"),
            None
        )
        .await,
        (200, serde_json::to_value(expected).unwrap())
    );
    let (status, retry) = http(
        &client,
        &url,
        &format!("/v1/flows/instances/{id}/generate-qr"),
        Some("synthetic-user"),
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, 200);
    let artifacts = repository.artifacts_for_instance(id).await.unwrap();
    assert_eq!(artifacts.len(), 2);
    let second = artifacts.iter().find(|v| v.attempt_number == 2).unwrap();
    assert_artifact(&pool, id, second, 2).await;
    let first = artifacts.iter().find(|v| v.attempt_number == 1).unwrap();
    assert_eq!(first.status, ArtifactStatus::Expired);
    assert_eq!(
        retry,
        serde_json::to_value(second.projection().unwrap()).unwrap()
    );
    assert_eq!(seeds.next.load(Ordering::SeqCst), 2);
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{grpc_port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(3));
    let channel = tokio::time::timeout(Duration::from_secs(3), endpoint.connect())
        .await
        .unwrap()
        .unwrap();
    let mut grpc = FlowServiceClient::new(channel);
    for token in [None, Some("synthetic-wrong-token")] {
        let mut request = tonic::Request::new(HealthCheckRequest {});
        if let Some(token) = token {
            request
                .metadata_mut()
                .insert("x-service-token", token.parse().unwrap());
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), grpc.health_check(request))
                .await
                .unwrap()
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }
    let mut request = tonic::Request::new(HealthCheckRequest {});
    request
        .metadata_mut()
        .insert("x-service-token", TOKEN.parse().unwrap());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), grpc.health_check(request))
            .await
            .unwrap()
            .unwrap()
            .into_inner()
            .status,
        "serving"
    );
    process.close().await;
    let before = snapshot(&pool).await;
    let prior_seeds = seeds.next.load(Ordering::SeqCst);
    let prior_effects = ports.take();
    native.close().await;
    let mut rejected = Process::start(&environment, &directory.0);
    rejected.rejected().await;
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", http_port))
        .await
        .is_err());
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", grpc_port))
        .await
        .is_err());
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(seeds.next.load(Ordering::SeqCst), prior_seeds);
    assert!(ports.take().is_empty());
    assert!(
        !prior_effects.is_empty(),
        "Successful admission exercised real native ports"
    );
    rejected.close().await;
    assert_eq!(
        legacy.attempts(),
        0,
        "Rendered native selection never falls back to counted legacy RPC"
    );
    peers.assert_health();
    peers.close().await;
    legacy.close().await;
    pool.close().await;
    directory.close();
}

#[test]
fn owned_output_child() {
    use std::io::Write;
    let Ok(mode) = std::env::var("MARTY_FLOW_OUTPUT_CONTROL") else {
        return;
    };
    match mode.as_str() {
        "early-exit" => std::process::exit(17),
        "stdout" => {
            std::io::stdout().write_all(&vec![b'x'; 300000]).unwrap();
            std::io::stdout().flush().unwrap();
        }
        "stderr" => {
            std::io::stderr().write_all(&vec![b'x'; 300000]).unwrap();
            std::io::stderr().flush().unwrap();
        }
        _ => panic!("Unknown closed process-control case"),
    }
    std::thread::sleep(Duration::from_secs(30));
    panic!("Output-limit monitor must terminate the owned child first");
}

#[tokio::test]
async fn owned_process_output_and_early_exit_cleanup_are_verified() {
    for mode in ["stdout", "stderr", "early-exit"] {
        let directory = rendered::Directory::new();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env("MARTY_FLOW_OUTPUT_CONTROL", mode)
            .args([
                "--exact",
                "didcomm_admission_recovery::flow_consumer::public_startup::owned_output_child",
                "--nocapture",
            ]);
        #[cfg(windows)]
        command.env("SystemRoot", std::env::var_os("SystemRoot").unwrap());
        let mut process = Process::spawn(command, &directory.0);
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = process.child.lock().unwrap().try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "Output monitor must finish the owned child within deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert!(!status.success());
        assert_eq!(
            process.output_failed.load(Ordering::SeqCst),
            mode != "early-exit"
        );
        if mode == "early-exit" {
            assert_eq!(status.code(), Some(17));
        }
        process.terminate().await;
        assert!(process.stopped && process.monitor.is_finished());
        assert!(process.child.lock().unwrap().try_wait().unwrap().is_some());
        drop(process);
        directory.close();
    }
}

#[test]
fn loader_capture_preserves_values_and_removes_file_alias_before_direct_spawn() {
    let directory = rendered::Directory::new();
    let source =
        std::fs::read_to_string(rendered::root().join("scripts/load-secrets-env.sh")).unwrap();
    std::fs::write(directory.0.join("loader.sh"), source.replace("\r\n", "\n")).unwrap();
    std::fs::write(
        directory.0.join("grpc_service_token"),
        b"synthetic-loaded-service-token\r\n",
    )
    .unwrap();
    let values = BTreeMap::from([
        (
            "GRPC_SERVICE_TOKEN_FILE".into(),
            directory
                .0
                .join("grpc_service_token")
                .to_str()
                .unwrap()
                .into(),
        ),
        (
            "FLOW_SYNTHETIC_LITERAL".into(),
            " spaces = quotes \" preserved\nsecond line".into(),
        ),
    ]);
    let loaded = load_environment(&values, &directory.0);
    assert_eq!(
        loaded,
        BTreeMap::from([
            (
                "GRPC_SERVICE_TOKEN".into(),
                "synthetic-loaded-service-token".into()
            ),
            (
                "FLOW_SYNTHETIC_LITERAL".into(),
                values["FLOW_SYNTHETIC_LITERAL"].clone()
            ),
        ])
    );
    directory.close();
}
