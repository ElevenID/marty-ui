//! Run-owned beta migration rehearsal. Never stops live beta writers.
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

pub const REFUSAL: &str = "Beta migration rehearsal failed";
pub const RECOVERY: &str = "Beta rehearsal cleanup requires inspection";
const NETWORK: &str = "elevenid-beta-network";
const OWNER: &str = "marty.beta-rehearsal.owner";
const ROLE: &str = "marty.beta-rehearsal.role";
const BAO: &str = "quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878";
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    repo_root: PathBuf,
    artifact_dir: PathBuf,
    backup_dir: PathBuf,
    logs_dir: PathBuf,
    source_id: String,
    migration_image: String,
    verification_image: String,
    env_files: Vec<PathBuf>,
    compose_files: Vec<PathBuf>,
    migration_admin_email: String,
    pilot_organization_id: String,
    beta_origin: String,
}
#[derive(Default, Debug)]
struct Request {
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    input: Option<Vec<u8>>,
    log: Option<PathBuf>,
    redactions: Vec<String>,
}
impl Request {
    fn new(args: &[&str]) -> Self {
        Self {
            args: args.iter().map(|v| (*v).into()).collect(),
            ..Self::default()
        }
    }
    fn env(&mut self, name: &str, value: &str) {
        self.args.extend(["--env".into(), name.into()]);
        self.environment.insert(name.into(), value.into());
    }
    fn tail(&mut self, args: &[&str]) {
        self.args.extend(args.iter().map(|v| (*v).to_owned()));
    }
}
struct Output {
    success: bool,
    text: String,
}
trait Docker {
    fn execute(&mut self, request: Request) -> Result<Output>;
    fn sleep(&mut self) {
        std::thread::sleep(Duration::from_secs(2));
    }
}
struct LocalDocker;
impl Docker for LocalDocker {
    fn execute(&mut self, request: Request) -> Result<Output> {
        let mut child = Command::new("docker")
            .args(&request.args)
            .envs(&request.environment)
            .stdin(if request.input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| REFUSAL)?;
        let input_result = match request.input {
            Some(bytes) => child.stdin.take().ok_or(REFUSAL)?.write_all(&bytes),
            None => Ok(()),
        };
        let output = child.wait_with_output().map_err(|_| REFUSAL)?;
        if input_result.is_err() {
            return Err(REFUSAL);
        }
        if let Some(path) = request.log {
            let mut bytes = String::from_utf8_lossy(&output.stdout).into_owned();
            bytes.push_str(&String::from_utf8_lossy(&output.stderr));
            for value in request.redactions {
                if !value.is_empty() {
                    bytes = bytes.replace(&value, "[redacted]");
                }
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|_| REFUSAL)?;
            file.write_all(bytes.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| REFUSAL)?;
        }
        Ok(Output {
            success: output.status.success(),
            text: String::from_utf8(output.stdout).map_err(|_| REFUSAL)?,
        })
    }
}
fn checked(docker: &mut impl Docker, request: Request) -> Result<String> {
    let output = docker.execute(request)?;
    if output.success {
        Ok(output.text)
    } else {
        Err(REFUSAL)
    }
}
fn immutable(value: &str) -> bool {
    regex::Regex::new(r"\A(?:sha256:|[^@\s]+@sha256:)[0-9a-f]{64}\z")
        .unwrap()
        .is_match(value)
}
fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate(context: &mut Context) -> Result<()> {
    if context.source_id.len() != 40
        || !context
            .source_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || context.beta_origin != "https://beta.elevenidllc.com"
        || !immutable(&context.migration_image)
        || !immutable(&context.verification_image)
        || uuid::Uuid::parse_str(&context.pilot_organization_id).is_err()
        || context.migration_admin_email.is_empty()
        || context.migration_admin_email.len() > 320
        || context.migration_admin_email.contains(['\0', '\r', '\n'])
    {
        return Err(REFUSAL);
    }
    context.repo_root = context.repo_root.canonicalize().map_err(|_| REFUSAL)?;
    let root = context
        .repo_root
        .join("tests/artifacts")
        .canonicalize()
        .map_err(|_| REFUSAL)?;
    context.artifact_dir = context.artifact_dir.canonicalize().map_err(|_| REFUSAL)?;
    context.backup_dir = context.backup_dir.canonicalize().map_err(|_| REFUSAL)?;
    context.logs_dir = context.logs_dir.canonicalize().map_err(|_| REFUSAL)?;
    if !context.artifact_dir.starts_with(&root)
        || context.artifact_dir == root
        || !context.backup_dir.starts_with(&context.artifact_dir)
        || !context.logs_dir.starts_with(&context.artifact_dir)
        || !context.backup_dir.join("postgres-marty.dump").is_file()
        || !context.repo_root.join("docker/openbao-init.sh").is_file()
        || context.env_files.is_empty()
        || context.compose_files.is_empty()
        || context
            .env_files
            .iter()
            .chain(&context.compose_files)
            .any(|p| !p.is_absolute() || !p.is_file())
    {
        return Err(REFUSAL);
    }
    for name in [
        "openbao-copy-public-ca.crt",
        "revocation-migration-rehearsal.log",
        "migration-rehearsal.log",
        "migration-rehearsal-verify.log",
        "issuance-migration-rehearsal.log",
        "issuance-migration-rehearsal-verify.log",
        "verification-migration-rehearsal-1.log",
        "verification-migration-rehearsal-2.log",
    ] {
        if fs::symlink_metadata(context.logs_dir.join(name)).is_ok() {
            return Err(REFUSAL);
        }
    }
    Ok(())
}
fn image(docker: &mut impl Docker, reference: &str) -> Result<String> {
    let request = || Request::new(&["image", "inspect", reference, "--format", "{{.Id}}"]);
    let result = docker.execute(request())?;
    let value = if result.success {
        result.text
    } else {
        checked(docker, Request::new(&["pull", reference]))?;
        checked(docker, request())?
    };
    let value = value.trim().to_owned();
    if immutable(&value) {
        Ok(value)
    } else {
        Err(REFUSAL)
    }
}
fn compose(context: &Context) -> Request {
    let mut request = Request::new(&["compose", "--project-name", "elevenid-beta"]);
    for path in &context.env_files {
        request.tail(&["--env-file", path.to_str().unwrap()]);
    }
    for path in &context.compose_files {
        request.tail(&["-f", path.to_str().unwrap()]);
    }
    request
}
fn tag_helper(request: &mut Request, owner: &str, names: &BTreeMap<String, String>) {
    request.tail(&[
        "--name",
        &names["helper"],
        "--label",
        &format!("{OWNER}={owner}"),
        "--label",
        &format!("{ROLE}=helper"),
    ]);
}
fn migration(
    docker: &mut impl Docker,
    mut request: Request,
    context: &Context,
    name: &str,
    redactions: &[String],
) -> Result<()> {
    request.log = Some(context.logs_dir.join(name));
    request.redactions = redactions.to_vec();
    checked(docker, request).map(|_| ())
}
fn cleanup(docker: &mut impl Docker, owner: &str, names: &BTreeMap<String, String>) -> Result<()> {
    let filter = format!("label={OWNER}={owner}");
    let list = || {
        Request::new(&[
            "ps",
            "-a",
            "--no-trunc",
            "--filter",
            &filter,
            "--format",
            "{{.ID}}",
        ])
    };
    let ids = checked(docker, list()).map_err(|_| RECOVERY)?;
    let mut failed = false;
    for id in ids.lines().filter(|id| !id.is_empty()) {
        if !identifier(id) {
            failed = true;
            continue;
        }
        let result = (|| {
            let labels = checked(
                docker,
                Request::new(&["inspect", "--format", "{{json .Config.Labels}}", id]),
            )?;
            let labels: Value = serde_json::from_str(&labels).map_err(|_| RECOVERY)?;
            let name = checked(
                docker,
                Request::new(&["inspect", "--format", "{{.Name}}", id]),
            )?;
            let role = labels[ROLE].as_str().ok_or(RECOVERY)?;
            if labels[OWNER] != owner
                || names.get(role).map(String::as_str) != Some(name.trim().trim_start_matches('/'))
            {
                return Err(RECOVERY);
            }
            checked(docker, Request::new(&["rm", "--force", id])).map(|_| ())
        })();
        if result.is_err() {
            failed = true;
        }
    }
    if !checked(docker, list())
        .map_err(|_| RECOVERY)?
        .trim()
        .is_empty()
    {
        failed = true;
    }
    if failed {
        Err(RECOVERY)
    } else {
        Ok(())
    }
}
fn perform(
    context: &Context,
    docker: &mut impl Docker,
    owner: &str,
    names: &BTreeMap<String, String>,
    attempted: &mut bool,
) -> Result<()> {
    let password = uuid::Uuid::new_v4().simple().to_string();
    let redis_password = uuid::Uuid::new_v4().simple().to_string();
    let bao_token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let mut redactions = vec![password.clone(), redis_password.clone(), bao_token.clone()];
    let pg = &names["postgres"];
    let redis = &names["redis"];
    let bao = &names["openbao"];
    let pg_image = image(docker, "postgres:15-alpine")?;
    let redis_image = image(docker, "redis:7-alpine")?;
    for (role, reference) in [
        ("postgres", pg_image.as_str()),
        ("openbao", BAO),
        ("redis", redis_image.as_str()),
    ] {
        let mut request = Request::new(&[
            "run",
            "--detach",
            "--name",
            &names[role],
            "--network",
            NETWORK,
            "--label",
            &format!("{OWNER}={owner}"),
            "--label",
            &format!("{ROLE}={role}"),
        ]);
        match role {
            "postgres" => request.env("POSTGRES_PASSWORD", &password),
            "openbao" => {
                request.tail(&["--tmpfs", "/tmp/bao-tls:rw,mode=1777"]);
                request.env("BAO_DEV_ROOT_TOKEN_ID", &bao_token);
                request.env("BAO_DEV_LISTEN_ADDRESS", "0.0.0.0:8200");
            }
            _ => request.env("REDIS_PASSWORD", &redis_password),
        }
        request.tail(&[reference]);
        match role {
            "openbao" => request.tail(&[
                "server",
                "-dev",
                "-dev-tls",
                "-dev-tls-cert-dir=/tmp/bao-tls",
            ]),
            "redis" => request.tail(&[
                "sh",
                "-ec",
                "exec redis-server --requirepass \"$REDIS_PASSWORD\"",
            ]),
            _ => (),
        }
        *attempted = true;
        let id = checked(docker, request)?;
        if !identifier(id.trim()) {
            return Err(REFUSAL);
        }
    }
    let mut ready = false;
    for _ in 0..60 {
        if docker
            .execute(Request::new(&["exec", pg, "pg_isready", "-U", "postgres"]))?
            .success
        {
            ready = true;
            break;
        }
        docker.sleep();
    }
    if !ready {
        return Err(REFUSAL);
    }
    let (mut redis_ready, mut bao_ready) = (false, false);
    for _ in 0..60 {
        let mut request = Request::new(&["exec"]);
        request.env("REDISCLI_AUTH", &redis_password);
        request.tail(&[redis, "redis-cli", "ping"]);
        let result = docker.execute(request)?;
        if result.success && result.text.lines().any(|s| s == "PONG") {
            redis_ready = true;
        }
        if docker
            .execute(Request::new(&[
                "exec",
                bao,
                "bao",
                "status",
                "-address=https://127.0.0.1:8200",
                "-ca-cert=/tmp/bao-tls/vault-ca.pem",
            ]))?
            .success
        {
            bao_ready = true;
        }
        if redis_ready && bao_ready {
            break;
        }
        docker.sleep();
    }
    if !redis_ready || !bao_ready {
        return Err(REFUSAL);
    }
    let certificate = checked(
        docker,
        Request::new(&["exec", bao, "cat", "/tmp/bao-tls/vault-ca.pem"]),
    )?;
    let certificate = format!("{}\n", certificate.trim_end_matches(['\r', '\n']));
    if !regex::Regex::new(
        r"\A-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----\n\z",
    )
    .unwrap()
    .is_match(&certificate)
    {
        return Err(REFUSAL);
    }
    let ca = context.logs_dir.join("openbao-copy-public-ca.crt");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ca)
        .map_err(|_| REFUSAL)?
        .write_all(certificate.as_bytes())
        .map_err(|_| REFUSAL)?;
    let ca_mount = format!(
        "type=bind,src={},dst=/bao-public-ca/ca.crt,readonly",
        ca.display()
    );
    let network = format!("container:{bao}");
    let bao_request = |operator: bool| {
        let mut request =
            Request::new(&["run", "--rm", "--network", &network, "--mount", &ca_mount]);
        tag_helper(&mut request, owner, names);
        request.env("BAO_ADDR", "https://localhost:8200");
        request.env("BAO_CACERT", "/bao-public-ca/ca.crt");
        if operator {
            request.env("BAO_TOKEN", &bao_token);
        }
        request
    };
    let mut request = bao_request(true);
    request.tail(&[
        "--mount",
        &format!(
            "type=bind,src={},dst=/scripts/openbao-init.sh,readonly",
            context.repo_root.join("docker/openbao-init.sh").display()
        ),
        "--entrypoint",
        "/bin/sh",
        BAO,
        "/scripts/openbao-init.sh",
    ]);
    checked(docker, request)?;
    let mut request = bao_request(true);
    request.tail(&[
        BAO,
        "bao",
        "token",
        "create",
        "-policy=notification-webhook-service",
        "-no-default-policy",
        "-orphan",
        "-ttl=2h",
        "-renewable=false",
        "-field=token",
    ]);
    let notification = checked(docker, request)?.trim().to_owned();
    if notification.is_empty() || notification.contains(char::is_whitespace) {
        return Err(REFUSAL);
    }
    redactions.push(notification.clone());
    let mut request = Request::new(&[
        "exec",
        "-i",
        pg,
        "psql",
        "-U",
        "postgres",
        "-d",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
    ]);
    request.input = Some(format!("CREATE ROLE marty LOGIN PASSWORD '{password}';\n").into_bytes());
    checked(docker, request)?;
    checked(
        docker,
        Request::new(&[
            "exec", pg, "createdb", "-U", "postgres", "-O", "marty", "marty",
        ]),
    )?;
    checked(
        docker,
        Request::new(&[
            "cp",
            context
                .backup_dir
                .join("postgres-marty.dump")
                .to_str()
                .ok_or(REFUSAL)?,
            &format!("{pg}:/tmp/marty.dump"),
        ]),
    )?;
    checked(
        docker,
        Request::new(&[
            "exec",
            pg,
            "pg_restore",
            "-U",
            "postgres",
            "-d",
            "marty",
            "--no-owner",
            "--role=marty",
            "/tmp/marty.dump",
        ]),
    )?;
    let url = format!("postgresql://marty:{password}@{pg}:5432/marty");
    let mut request = compose(context);
    request.tail(&["run", "--rm", "--no-deps"]);
    tag_helper(&mut request, owner, names);
    request.env("DATABASE_URL", &url);
    request.tail(&["revocation-profile-migrate"]);
    migration(
        docker,
        request,
        context,
        "revocation-migration-rehearsal.log",
        &redactions,
    )?;
    let mut request = bao_request(false);
    for (name, value) in [
        ("DATABASE_URL", url.as_str()),
        ("MARTY_DB_PASSWORD", password.as_str()),
        ("MARTY_ORG_ADMIN_EMAIL", &context.migration_admin_email),
        ("PUBLIC_API_URL", &context.beta_origin),
        ("MARTY_MIGRATION_PROFILE", "beta"),
        ("MARTY_KMS_BOOTSTRAP_ENABLED", "false"),
        ("NOTIFICATION_OPENBAO_CA_CERT_FILE", "/bao-public-ca/ca.crt"),
        ("NOTIFICATION_OPENBAO_TOKEN", notification.as_str()),
        (
            "REDIS_URL",
            &format!("redis://:{redis_password}@{redis}:6379"),
        ),
        ("MARTY_ORG_ID", &context.pilot_organization_id),
    ] {
        request.env(name, value);
    }
    request.tail(&[&context.migration_image]);
    migration(
        docker,
        request,
        context,
        "migration-rehearsal.log",
        &redactions,
    )?;
    let mut request = bao_request(false);
    for (name, value) in [
        ("DATABASE_URL", url.as_str()),
        ("PUBLIC_API_URL", &context.beta_origin),
        ("MARTY_MIGRATION_PROFILE", "beta"),
        ("MARTY_KMS_BOOTSTRAP_ENABLED", "false"),
    ] {
        request.env(name, value);
    }
    request.tail(&[
        &context.migration_image,
        "/usr/local/bin/marty-migration-bootstrap",
        "--verify-only",
    ]);
    migration(
        docker,
        request,
        context,
        "migration-rehearsal-verify.log",
        &redactions,
    )?;
    for log in [
        "issuance-migration-rehearsal.log",
        "issuance-migration-rehearsal-verify.log",
    ] {
        let mut request = compose(context);
        request.tail(&["run", "--rm", "--no-deps"]);
        tag_helper(&mut request, owner, names);
        request.env("DATABASE_URL", &url);
        request.tail(&["issuance-migrations"]);
        migration(docker, request, context, log, &redactions)?;
    }
    for pass in 1..=2 {
        let mut request = Request::new(&[
            "run",
            "--rm",
            "--network",
            NETWORK,
            "--entrypoint",
            "/usr/local/bin/marty-verification-service",
        ]);
        tag_helper(&mut request, owner, names);
        request.env("DATABASE_URL", &url);
        request.tail(&[&context.verification_image, "migrate"]);
        migration(
            docker,
            request,
            context,
            &format!("verification-migration-rehearsal-{pass}.log"),
            &redactions,
        )?;
    }
    Ok(())
}
fn run_with(input: Value, docker: &mut impl Docker) -> Result<Value> {
    let mut context: Context = serde_json::from_value(input).map_err(|_| REFUSAL)?;
    validate(&mut context)?;
    let owner = uuid::Uuid::new_v4().simple().to_string();
    let suffix = format!("{}-{}", &context.source_id[..12], &owner[..12]);
    let names = BTreeMap::from([
        ("postgres".into(), format!("elevenid-beta-copy-{suffix}")),
        (
            "openbao".into(),
            format!("elevenid-beta-copy-openbao-{suffix}"),
        ),
        ("redis".into(), format!("elevenid-beta-copy-redis-{suffix}")),
        (
            "helper".into(),
            format!("elevenid-beta-copy-helper-{suffix}"),
        ),
    ]);
    let mut attempted = false;
    let result = perform(&context, docker, &owner, &names, &mut attempted);
    if attempted {
        cleanup(docker, &owner, &names)?;
    }
    result?;
    Ok(json!({"completed":true}))
}
pub fn run(input: Value) -> Result<Value> {
    run_with(input, &mut LocalDocker)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct MockDocker {
        calls: Vec<Request>,
        containers: BTreeMap<String, (String, Value)>,
        fail_at: Option<usize>,
        never_ready: Option<&'static str>,
        foreign: bool,
        sleeps: usize,
    }
    fn argument<'a>(request: &'a Request, flag: &str) -> Option<&'a str> {
        request
            .args
            .windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].as_str())
    }
    impl Docker for MockDocker {
        fn execute(&mut self, request: Request) -> Result<Output> {
            let index = self.calls.len() + 1;
            let fail = self.fail_at == Some(index);
            let mut text = String::new();
            let args = &request.args;
            let run = args.first().is_some_and(|s| s == "run")
                || (args.first().is_some_and(|s| s == "compose")
                    && args.iter().any(|s| s == "run"));
            if run {
                let labels: serde_json::Map<String, Value> = args
                    .windows(2)
                    .filter(|pair| pair[0] == "--label")
                    .map(|pair| {
                        let (name, value) = pair[1].split_once('=').unwrap();
                        (name.into(), Value::String(value.into()))
                    })
                    .collect();
                let id = format!("{index:064x}");
                let name =
                    argument(&request, "--name").expect("every rehearsal run has an owned name");
                self.containers
                    .insert(id.clone(), (name.into(), Value::Object(labels.clone())));
                if self.foreign {
                    let mut labels = labels;
                    labels.insert(ROLE.into(), "foreign".into());
                    self.containers.insert(
                        "f".repeat(64),
                        ("marty-selfhost-prod".into(), Value::Object(labels)),
                    );
                }
                if args.iter().any(|s| s == "--detach") {
                    text = format!("{id}\n");
                } else if !fail {
                    self.containers.remove(&id);
                }
                if args.iter().any(|s| s == "-field=token") {
                    text = "synthetic-notification-credential\n".into();
                }
            } else if args.first().is_some_and(|s| s == "ps") {
                text = self.containers.keys().map(|s| format!("{s}\n")).collect();
            } else if args.first().is_some_and(|s| s == "inspect") {
                let (name, labels) = self.containers.get(args.last().unwrap()).ok_or(REFUSAL)?;
                text = if args.iter().any(|s| s == "{{.Name}}") {
                    format!("/{name}\n")
                } else {
                    serde_json::to_string(labels).unwrap()
                };
            } else if args.first().is_some_and(|s| s == "rm") {
                if !fail {
                    self.containers.remove(args.last().unwrap());
                }
            } else if args.first().is_some_and(|s| s == "image") {
                text = format!("sha256:{}\n", "1".repeat(64));
            } else if args.iter().any(|s| s == "ping") {
                text = "PONG\n".into();
            } else if args.iter().any(|s| s == "cat") {
                text = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n".into();
            }
            let not_ready = self
                .never_ready
                .is_some_and(|probe| args.iter().any(|s| s == probe));
            self.calls.push(request);
            Ok(Output {
                success: !fail && !not_ready,
                text,
            })
        }
        fn sleep(&mut self) {
            self.sleeps += 1;
        }
    }
    fn context() -> (tempfile::TempDir, Value) {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let artifact = repo.join("tests/artifacts/owned-rehearsal");
        let backup = artifact.join("preflight-backup");
        let logs = artifact.join("logs");
        fs::create_dir_all(&backup).unwrap();
        fs::create_dir_all(&logs).unwrap();
        fs::create_dir_all(repo.join("docker")).unwrap();
        fs::write(backup.join("postgres-marty.dump"), b"synthetic dump").unwrap();
        fs::write(repo.join("docker/openbao-init.sh"), b"synthetic init").unwrap();
        let env = repo.join("operator.env");
        fs::write(&env, b"synthetic config").unwrap();
        let compose = repo.join("compose.yml");
        fs::write(&compose, b"services: {}\n").unwrap();
        let value = json!({"repo_root":repo,"artifact_dir":artifact,"backup_dir":backup,"logs_dir":logs,
            "source_id":"a".repeat(40),"migration_image":format!("sha256:{}","2".repeat(64)),"verification_image":format!("sha256:{}","3".repeat(64)),
            "env_files":[env],"compose_files":[compose],"migration_admin_email":"synthetic@example.invalid",
            "pilot_organization_id":"00000000-0000-0000-0000-000000000001","beta_origin":"https://beta.elevenidllc.com"});
        (temp, value)
    }
    #[test]
    fn all_migration_passes_use_existing_compose_and_private_credentials() {
        let (_temp, input) = context();
        let mut docker = MockDocker::default();
        assert_eq!(
            run_with(input.clone(), &mut docker).unwrap(),
            json!({"completed":true})
        );
        assert!(docker.containers.is_empty());
        let logs: Vec<_> = docker
            .calls
            .iter()
            .filter_map(|r| {
                r.log
                    .as_ref()
                    .map(|p| p.file_name().unwrap().to_str().unwrap())
            })
            .collect();
        assert_eq!(
            logs,
            [
                "revocation-migration-rehearsal.log",
                "migration-rehearsal.log",
                "migration-rehearsal-verify.log",
                "issuance-migration-rehearsal.log",
                "issuance-migration-rehearsal-verify.log",
                "verification-migration-rehearsal-1.log",
                "verification-migration-rehearsal-2.log"
            ]
        );
        for request in &docker.calls {
            for key in [
                "POSTGRES_PASSWORD",
                "REDIS_PASSWORD",
                "BAO_DEV_ROOT_TOKEN_ID",
                "REDISCLI_AUTH",
                "BAO_TOKEN",
                "DATABASE_URL",
                "MARTY_DB_PASSWORD",
                "NOTIFICATION_OPENBAO_TOKEN",
            ] {
                if let Some(value) = request.environment.get(key) {
                    assert!(
                        !request.args.iter().any(|s| s.contains(value)),
                        "credential entered host argv"
                    );
                }
            }
            if request.args.first().is_some_and(|s| s == "compose") {
                assert_eq!(argument(request, "--project-name"), Some("elevenid-beta"));
                assert_eq!(
                    argument(request, "--env-file"),
                    input["env_files"][0].as_str()
                );
                assert_eq!(argument(request, "-f"), input["compose_files"][0].as_str());
                assert!(request.args.iter().any(|s| s == "--no-deps"));
            }
            if request.args.iter().any(|s| {
                s.ends_with("marty-migration-bootstrap")
                    || s == input["migration_image"].as_str().unwrap()
            }) {
                assert!(
                    !request.environment.contains_key("BAO_TOKEN"),
                    "migration must not inherit root authority"
                );
                assert!(!request.environment.contains_key("OPENBAO_SERVICE_TOKEN"));
                assert_eq!(
                    request
                        .environment
                        .get("MARTY_KMS_BOOTSTRAP_ENABLED")
                        .map(String::as_str),
                    Some("false")
                );
            }
            if request.args.first().is_some_and(|s| s == "rm") {
                assert!(identifier(request.args.last().unwrap()));
            }
        }
        assert_eq!(
            docker
                .calls
                .iter()
                .filter(|r| r
                    .args
                    .iter()
                    .any(|s| s == "/usr/local/bin/marty-verification-service"))
                .count(),
            2
        );
        assert_eq!(
            docker
                .calls
                .iter()
                .filter(|r| r.args.last().is_some_and(|s| s == "issuance-migrations"))
                .count(),
            2
        );
    }
    #[test]
    fn failures_at_every_command_keep_cleanup_owned_and_fail_closed_when_uncertain() {
        let (_temp, input) = context();
        let mut baseline = MockDocker::default();
        run_with(input, &mut baseline).unwrap();
        for index in 1..=baseline.calls.len() {
            let (_temp, input) = context();
            let mut docker = MockDocker {
                fail_at: Some(index),
                ..MockDocker::default()
            };
            let result = run_with(input, &mut docker);
            assert!(
                docker.containers.is_empty() || result == Err(RECOVERY),
                "unconfirmed cleanup must not report success"
            );
            assert!(docker
                .calls
                .iter()
                .filter(|r| r.args.first().is_some_and(|s| s == "rm"))
                .all(|r| identifier(r.args.last().unwrap())));
        }
    }
    #[test]
    fn unknown_container_identity_is_never_removed() {
        let (_temp, input) = context();
        let mut docker = MockDocker {
            foreign: true,
            ..MockDocker::default()
        };
        assert_eq!(run_with(input, &mut docker), Err(RECOVERY));
        assert!(docker.containers.contains_key(&"f".repeat(64)));
        assert!(!docker
            .calls
            .iter()
            .any(|r| r.args.first().is_some_and(|s| s == "rm")
                && r.args.last() == Some(&"f".repeat(64))));
    }
    #[test]
    fn readiness_is_bounded_and_cleans_all_owned_resources() {
        for probe in ["pg_isready", "ping", "status"] {
            let (_temp, input) = context();
            let mut docker = MockDocker {
                never_ready: Some(probe),
                ..MockDocker::default()
            };
            assert_eq!(run_with(input, &mut docker), Err(REFUSAL));
            assert_eq!(docker.sleeps, 60);
            assert!(docker.containers.is_empty());
        }
    }
    #[test]
    fn invalid_or_reused_artifact_inputs_do_not_start_docker() {
        let (_temp, mut input) = context();
        input["beta_origin"] = "https://foreign.invalid".into();
        let mut docker = MockDocker::default();
        assert_eq!(run_with(input, &mut docker), Err(REFUSAL));
        assert!(docker.calls.is_empty());
        let (_temp, input) = context();
        fs::write(
            PathBuf::from(input["logs_dir"].as_str().unwrap()).join("migration-rehearsal.log"),
            b"preserved evidence",
        )
        .unwrap();
        assert_eq!(run_with(input, &mut docker), Err(REFUSAL));
        assert!(docker.calls.is_empty());
    }
}

#[cfg(test)]
mod docker_contract {
    use super::*;
    use sha2::{Digest, Sha256};
    const IMAGE: &str =
        "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";
    struct Owned {
        owner: String,
        names: BTreeMap<String, String>,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = cleanup(&mut LocalDocker, &self.owner, &self.names);
        }
    }
    struct Uncertain;
    impl Docker for Uncertain {
        fn execute(&mut self, request: Request) -> Result<Output> {
            let mut output = LocalDocker.execute(request)?;
            if output.success {
                output.success = false;
            }
            Ok(output)
        }
    }
    #[test]
    #[ignore = "explicit disposable local Docker/Compose contract; cached immutable Alpine only"]
    fn real_docker_labels_environment_and_uncertain_creation() {
        assert!(
            std::env::var_os("DOCKER_HOST").is_none(),
            "explicit remote Docker endpoint is not permitted"
        );
        let mut docker = LocalDocker;
        let contexts = checked(&mut docker, Request::new(&["context", "inspect"])).unwrap();
        let contexts: Value = serde_json::from_str(&contexts).unwrap();
        let endpoint = contexts[0]["Endpoints"]["docker"]["Host"].as_str().unwrap();
        assert!(
            endpoint.starts_with("npipe://") || endpoint.starts_with("unix://"),
            "local Docker endpoint required"
        );
        checked(&mut docker, Request::new(&["image", "inspect", IMAGE]))
            .expect("cached pinned image required; this test never pulls");
        let owner = uuid::Uuid::new_v4().simple().to_string();
        let names = BTreeMap::from([
            (
                "postgres".into(),
                format!("marty-rehearsal-contract-pg-{owner}"),
            ),
            (
                "helper".into(),
                format!("marty-rehearsal-contract-helper-{owner}"),
            ),
        ]);
        let guard = Owned {
            owner: owner.clone(),
            names: names.clone(),
        };
        let mut parent = Request::new(&[
            "run",
            "--detach",
            "--network",
            "none",
            "--name",
            &names["postgres"],
            "--label",
            &format!("{OWNER}={owner}"),
            "--label",
            &format!("{ROLE}=postgres"),
            IMAGE,
            "sh",
            "-ec",
            "while :; do sleep 1; done",
        ]);
        parent.redactions = Vec::new();
        // Model loss of a successful creation response with a real created object.
        assert!(checked(&mut Uncertain, parent).is_err());
        let scope = tempfile::tempdir().unwrap();
        let file = scope.path().join("compose.json");
        fs::write(&file,serde_json::to_vec(&json!({"services":{"helper":{"image":IMAGE,"network_mode":"none","entrypoint":["/bin/sh","-ec"],"command":["while :; do sleep 1; done"]}}})).unwrap()).unwrap();
        let project = format!("marty-rehearsal-contract-{}", &owner[..12]);
        let mut request = Request::new(&[
            "compose",
            "--project-name",
            &project,
            "-f",
            file.to_str().unwrap(),
            "run",
            "--detach",
            "--rm",
            "--no-deps",
            "--pull",
            "never",
        ]);
        tag_helper(&mut request, &owner, &names);
        let secret = uuid::Uuid::new_v4().simple().to_string();
        request.env("TEST_REHEARSAL_SECRET", &secret);
        request.tail(&["helper"]);
        assert!(!request.args.iter().any(|arg| arg.contains(&secret)));
        let id = checked(&mut docker, request).unwrap();
        let id = id.trim();
        assert!(identifier(id));
        let digest = checked(
            &mut docker,
            Request::new(&[
                "exec",
                id,
                "sh",
                "-ec",
                "printf '%s' \"$TEST_REHEARSAL_SECRET\" | sha256sum",
            ]),
        )
        .unwrap();
        assert!(digest.starts_with(&format!("{:x}", Sha256::digest(secret.as_bytes()))));
        assert!(!digest.contains(&secret));
        // Both the detached uncertain object and the Compose helper must be
        // discovered by exact owner/name/role and removed by immutable ID.
        cleanup(&mut docker, &owner, &names).unwrap();
        drop(guard);
    }
}
