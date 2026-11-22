//! Shared mechanics for the single bounded actual-executable qualification.
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, process::Stdio, time::Duration};

use axum::Router;
use marty_service_runtime::{
    https::{BoundKeylessHttpsServer, ManagedAuthorityHttpsConfig},
    RemoteTlsIdentityFiles, TlsIdentityNames,
};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::watch,
    task::JoinHandle,
};

use crate::support::{
    database::Database,
    owned::{Owned, PUBLIC_BASE},
    TestResult,
};

pub const SERVICE_TOKEN: &str = "disposable-host-wire-service-token-00000001";
pub const ISSUANCE_KEY: &str = "disposable-host-issuance-api-key-0000000001";
pub const READ_KEY: &str = "disposable-host-signing-read-key-000000001";
pub const SIGN_KEY: &str = "disposable-host-issuer-sign-key-0000000001";

pub fn setting(name: &str) -> String {
    std::env::var(name).expect("owned live fixture setting")
}

pub fn identity(prefix: &str, certificate: Option<String>) -> TestResult<RemoteTlsIdentityFiles> {
    let mut values: BTreeMap<String, String> = std::env::vars()
        .filter(|(name, _)| name.starts_with(prefix))
        .collect();
    if let Some(certificate) = certificate {
        values.insert(format!("{prefix}_CERT_FILE"), certificate);
    }
    Ok(RemoteTlsIdentityFiles::from_values(
        |name| values.get(name).map(String::as_str),
        TlsIdentityNames::files(prefix),
        Duration::from_secs(5),
        8,
    )?
    .ok_or("fixture TLS identity missing")?)
}

pub struct Server {
    pub address: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<Result<(), String>>,
}
impl Server {
    pub fn new(
        address: SocketAddr,
        stop: watch::Sender<bool>,
        task: JoinHandle<Result<(), String>>,
    ) -> Self {
        Self {
            address,
            stop,
            task,
        }
    }
    pub fn origin(&self) -> String {
        format!("https://{}", self.address)
    }
    pub async fn https(router: Router) -> TestResult<Self> {
        let server = BoundKeylessHttpsServer::bind(
            &ManagedAuthorityHttpsConfig {
                address: "127.0.0.1:0".parse()?,
                identity: identity("MARTY_TEST_POLICY_OWNER_TLS", None)?,
            },
            router,
        )
        .await
        .map_err(|_| "fixture keyless HTTPS bind failed")?;
        let address = server.local_addr()?;
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            server
                .serve(receiver)
                .await
                .map_err(|_| "fixture HTTPS serve failed".into())
        });
        Ok(Self::new(address, stop, task))
    }
    pub async fn close(&mut self) -> TestResult<()> {
        let _ = self.stop.send(true);
        tokio::time::timeout(Duration::from_secs(20), &mut self.task).await???;
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

pub async fn caller(certificate: Option<String>) -> TestResult<reqwest::Client> {
    let identity = identity("MARTY_TEST_USE_CALLER_TLS", certificate)?
        .connect()
        .await?;
    let ca = std::fs::read(setting("MARTY_TEST_USE_CA_DER_FILE"))?;
    let mut tls = (*mmf_platform::keyless_grpc_client_config(&identity, vec![ca])?).clone();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .http1_only()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?)
}

pub fn available_address() -> TestResult<SocketAddr> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}

pub fn environment(
    owned: &Owned,
    db: &Database,
    keys: &super::live_signing::SigningKeys,
    template: &Server,
    policy: &Server,
    references: &Server,
) -> TestResult<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for name in ["BAO_ADDR", "BAO_CACERT", "SSL_CERT_FILE", "SSL_CERT_DIR"] {
        env.insert(name.into(), setting(name));
    }
    env.insert("MARTY_DELEGATED_USE_ENABLED".into(), "true".into());
    for (name, value) in [
        ("LISTEN_ADDR", available_address()?.to_string()),
        ("ORGANIZATION_ID", owned.organization.to_string()),
        ("DEPLOYMENT_PROFILE_ID", owned.deployment.to_string()),
        ("DELEGATION_POLICY_ID", owned.delegated_policy.to_string()),
        (
            "APPROVAL_PROFILE",
            owned.approval.consent_profile().pin.profile,
        ),
        (
            "APPROVAL_VERSION",
            owned.approval.consent_profile().pin.version,
        ),
        (
            "APPROVAL_ARTIFACT_DIGEST",
            owned.approval.consent_profile().pin.artifact_digest,
        ),
        ("STATUS_REF", owned.authority.status_ref.clone()),
        (
            "FLOW_DEFINITION_ID",
            owned.flow.definition.definition_id.clone(),
        ),
        (
            "FLOW_DEFINITION_VERSION",
            owned.flow.definition.version.to_string(),
        ),
        ("PUBLIC_BASE_URL", PUBLIC_BASE.into()),
        ("VERIFIER_DID", "did:web:delegated-host.example.test".into()),
        (
            "VERIFIER_DISPLAY_NAME",
            "Disposable live startup gate".into(),
        ),
        ("CREDENTIAL_TEMPLATE_GRPC_TARGET", template.origin()),
        ("PRESENTATION_POLICY_GRPC_TARGET", policy.origin()),
        (
            "WORKLOAD_TLS_CA_CERT_FILE",
            setting("MARTY_TEST_POLICY_WORKLOAD_CA_CERT"),
        ),
        ("SERVICE_TOKEN", SERVICE_TOKEN.into()),
        ("ISSUANCE_API_KEY", ISSUANCE_KEY.into()),
        ("RECEIPT_ISSUER_DID", keys.issuer.clone()),
        ("RECEIPT_ALGORITHM", "ES256".into()),
        ("RECEIPT_KEY_ID", keys.kid.clone()),
        ("RECEIPT_KEY_REFERENCE", keys.key.clone()),
        ("RECEIPT_PUBLIC_JWK", serde_json::to_string(&keys.jwk)?),
        (
            "REQUEST_MINT_TOKEN_FILE",
            setting("MARTY_TEST_USE_REQUEST_MINT_TOKEN_FILE"),
        ),
        (
            "RECEIPT_MINT_TOKEN_FILE",
            setting("MARTY_TEST_RECEIPT_MINT_TOKEN_FILE"),
        ),
        (
            "CLIENT_CA_FILES",
            serde_json::to_string(&[setting("MARTY_TEST_USE_CA_DER_FILE")])?,
        ),
        (
            "WORKLOAD_BINDINGS",
            serde_json::json!([{
                "workload_uri": setting("MARTY_TEST_USE_CALLER_URI"),
                "leaf_sha256": setting("MARTY_TEST_USE_CALLER_LEAF_SHA256"),
                "principal_id": owned.principal.id,
            }])
            .to_string(),
        ),
    ] {
        env.insert(format!("DELEGATED_USE_{name}"), value);
    }
    for name in [
        "ISSUANCE_NATIVE_URL",
        "CREDENTIAL_TEMPLATE_URL",
        "TRUST_PROFILE_URL",
        "DEPLOYMENT_PROFILE_URL",
    ] {
        env.insert(format!("DELEGATED_USE_{name}"), references.origin());
    }
    for prefix in ["REQUEST", "RECEIPT"] {
        for (name, value) in [
            ("SIGNING_ORIGIN", keys.server.origin()),
            ("READ_CREDENTIAL", READ_KEY.into()),
            ("SIGN_CREDENTIAL", SIGN_KEY.into()),
            ("GRANT_OPENBAO_ORIGIN", setting("BAO_ADDR")),
        ] {
            env.insert(format!("DELEGATED_USE_{prefix}_{name}"), value);
        }
    }
    for (target, source) in [
        ("TLS", "MARTY_TEST_USE_SERVER_TLS"),
        ("WORKLOAD_TLS", "MARTY_TEST_POLICY_FLOW_CLIENT_TLS"),
    ] {
        for suffix in [
            "CERT_FILE",
            "KMS_PROVIDER",
            "KMS_ADDR",
            "KMS_CA_CERT_FILE",
            "KMS_TOKEN_FILE",
            "KMS_KEY_NAME",
            "KMS_KEY_VERSION",
        ] {
            env.insert(
                format!("DELEGATED_USE_{target}_{suffix}"),
                setting(&format!("{source}_{suffix}")),
            );
        }
    }
    for (name, value) in [
        ("USE_WRITER", &db.urls.use_writer),
        ("RUNTIME_READER", &db.urls.runtime_reader),
        ("ORGANIZATION_AUTHORITY", &db.urls.organization_authority),
        ("REGISTRY_SOURCE", &db.urls.registry_source),
        ("ACCESS_SOURCE", &db.urls.access_source),
        ("MACHINE_POLICY_SOURCE", &db.urls.machine_policy_source),
        ("MACHINE_POLICY_EVIDENCE", &db.urls.machine_policy_evidence),
        (
            "DELEGATION_POLICY_SOURCE",
            &db.urls.delegation_policy_source,
        ),
        ("MACHINE_AUDIT", &db.urls.machine_audit),
        ("FLOW_READER", &db.urls.flow_reader),
        ("FLOW_INGRESS", &db.urls.flow_ingress),
        ("CREDENTIAL_TRUST", &db.urls.credential_trust),
        ("CREDENTIAL_STATUS", &db.urls.credential_status),
        ("CREDENTIAL_EVIDENCE", &db.urls.credential_evidence),
    ] {
        env.insert(format!("DELEGATED_USE_{name}_DATABASE_URL"), value.clone());
    }
    Ok(env)
}

fn command(env: &BTreeMap<String, String>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_marty-delegated-use"));
    command
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

pub struct Executable {
    child: Child,
}
impl Executable {
    pub async fn start(env: &BTreeMap<String, String>) -> TestResult<Self> {
        let mut child = command(env).spawn()?;
        let mut stderr = BufReader::new(child.stderr.take().ok_or("child stderr missing")?).lines();
        let line = tokio::time::timeout(Duration::from_secs(45), stderr.next_line())
            .await??
            .ok_or("host exited without startup diagnostic")?;
        if line
            != format!(
                "internal delegated use listening on {}",
                env["DELEGATED_USE_LISTEN_ADDR"]
            )
        {
            return Err(format!("actual host startup failed: {line}").into());
        }
        Ok(Self { child })
    }
    pub async fn close(&mut self) -> TestResult<()> {
        self.child.kill().await?;
        self.child.wait().await?;
        Ok(())
    }
}

pub async fn rejected_before_listen(
    env: &BTreeMap<String, String>,
    expected: &str,
) -> TestResult<()> {
    let output = tokio::time::timeout(Duration::from_secs(45), command(env).output()).await??;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr)?;
    assert!(
        diagnostic.contains(expected),
        "unexpected sanitized startup failure: {diagnostic}"
    );
    assert!(!diagnostic.contains("listening on"));
    for credential in [READ_KEY, SIGN_KEY, SERVICE_TOKEN, ISSUANCE_KEY] {
        assert!(!diagnostic.contains(credential));
    }
    assert!(
        tokio::net::TcpStream::connect(&env["DELEGATED_USE_LISTEN_ADDR"])
            .await
            .is_err()
    );
    Ok(())
}

pub fn provider_calls(path: &str) -> TestResult<usize> {
    let content = std::fs::read_to_string(PathBuf::from(setting("MARTY_TEST_RECEIPT_AUDIT_FILE")))?;
    let mut count = 0;
    for line in content.lines() {
        let record: Value = serde_json::from_str(line)?;
        if record["type"] == "request" && record["request"]["path"] == path {
            count += 1;
        }
    }
    Ok(count)
}
