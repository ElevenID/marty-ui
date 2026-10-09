// Exact-owned base-profile Redis dependency, never an operator Redis URL.
// Uses the existing Docker fixture command/inspection boundary. The base image
// tag is resolved locally to an immutable image ID before container creation;
// this is runtime evidence, not authenticated release provenance.

use super::canvas_published_database::{docker, docker_with_timeout, inspect, PublishedDatabase};
use mmf_security::RedisRateLimiter;
use serde_json::Value;
use std::time::{Duration, Instant};
use uuid::Uuid;

const LABEL: &str = "com.elevenid.test.base-native-redis";
const IMAGE: &str = "redis:7-alpine";
const TMPFS: &str = "rw,mode=1777";
const COMMAND: &[&str] = &["--save", "", "--appendonly", "no", "--dir", "/data"];

enum Network {
    Loopback,
    PublishedNamespace { descriptor: String, id: String },
}

impl Network {
    fn published(owned: &PublishedDatabase) -> Result<Self, String> {
        let descriptor = owned.borrow_descriptor()?;
        let value: Value = serde_json::from_str(&descriptor)
            .map_err(|_| "Invalid verified database descriptor")?;
        let id = value["postgres_id"]
            .as_str()
            .ok_or("Missing verified database ID")?
            .to_owned();
        exact_id(&id)?;
        Ok(Self::PublishedNamespace { descriptor, id })
    }

    fn mode(&self) -> String {
        match self {
            Self::Loopback => "bridge".into(),
            Self::PublishedNamespace { id, .. } => format!("container:{id}"),
        }
    }

    fn verify_parent(&self) -> Result<(), String> {
        if let Self::PublishedNamespace { descriptor, .. } = self {
            PublishedDatabase::borrowed_url(descriptor)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Readiness {
    Actual,
    ControlledTimeout,
}

fn ping_ready(result: Result<String, String>) -> Result<bool, String> {
    match result {
        Ok(response) => Ok(response == "PONG"),
        // A failed reap is not a retryable Redis-not-ready response.
        Err(error) if error == "Docker command cleanup failed" => Err(error),
        Err(_) => Ok(false),
    }
}

fn exact_id(id: &str) -> Result<(), String> {
    if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("Owned Redis requires an exact container ID".into())
    }
}

fn image_identity(id: &str) -> Result<(), String> {
    id.strip_prefix("sha256:")
        .ok_or_else(|| "Owned Redis requires an immutable local image ID".to_owned())
        .and_then(exact_id)
}

fn checked_identity(
    info: &Value,
    id: &str,
    scope: &str,
    image: &str,
    network: &Network,
) -> Result<(), String> {
    exact_id(id)?;
    image_identity(image)?;
    if info["Id"] != id
        || info["Config"]["Labels"][LABEL] != scope
        || info["Image"] != image
        || info["Config"]["Image"] != image
        || info["Config"]["User"] != "redis"
        || info["Config"]["Entrypoint"] != serde_json::json!(["redis-server"])
        || info["Config"]["Cmd"] != serde_json::json!(COMMAND)
        || info["Mounts"]
            .as_array()
            .is_none_or(|items| !items.is_empty())
        || info["HostConfig"]["Tmpfs"] != serde_json::json!({"/data": TMPFS})
        || info["HostConfig"]["ReadonlyRootfs"] != true
        || info["HostConfig"]["CapDrop"] != serde_json::json!(["ALL"])
        || info["HostConfig"]["SecurityOpt"] != serde_json::json!(["no-new-privileges"])
        || info["HostConfig"]["NetworkMode"] != network.mode()
    {
        return Err("Refusing Redis access or cleanup: identity/storage mismatch".into());
    }
    Ok(())
}

fn checked_url(
    info: &Value,
    id: &str,
    scope: &str,
    image: &str,
    network: &Network,
) -> Result<String, String> {
    checked_identity(info, id, scope, image, network)?;
    if info["State"]["Running"] != true {
        return Err("Owned Redis is not running".into());
    }
    let ports = info["NetworkSettings"]["Ports"]
        .as_object()
        .ok_or("Owned Redis has no port map")?;
    if matches!(network, Network::PublishedNamespace { .. }) {
        if !ports.is_empty()
            || info["HostConfig"]["PortBindings"]
                .as_object()
                .is_none_or(|bindings| !bindings.is_empty())
        {
            return Err("Namespace Redis must not publish ports".into());
        }
        return Ok("redis://127.0.0.1:6379".into());
    }
    let bindings = ports
        .get("6379/tcp")
        .and_then(Value::as_array)
        .ok_or("Owned Redis has no loopback binding")?;
    if ports.len() != 1 || bindings.len() != 1 || bindings[0]["HostIp"] != "127.0.0.1" {
        return Err("Owned Redis requires exactly one loopback binding".into());
    }
    let port = bindings[0]["HostPort"]
        .as_str()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or("Invalid owned Redis port")?;
    // Deliberately no database suffix: the actual rendered gateway environment
    // retains REDIS_DB_GATEWAY selection, rather than this helper overriding it.
    Ok(format!("redis://127.0.0.1:{port}"))
}

pub(super) struct OwnedRedis {
    scope: String,
    image: String,
    id: Option<String>,
    creation_attempted: bool,
    url: String,
    network: Network,
}

impl OwnedRedis {
    pub(super) async fn start() -> Result<Self, String> {
        Self::start_owned(Network::Loopback, Uuid::new_v4(), Readiness::Actual).await
    }

    pub(super) async fn start_in_published_namespace(
        owned: &PublishedDatabase,
    ) -> Result<Self, String> {
        Self::start_owned(
            Network::published(owned)?,
            Uuid::new_v4(),
            Readiness::Actual,
        )
        .await
    }

    async fn start_owned(
        network: Network,
        scope: Uuid,
        readiness: Readiness,
    ) -> Result<Self, String> {
        network.verify_parent()?;
        let image = docker(&["image", "inspect", "--format", "{{.Id}}", IMAGE])?;
        image_identity(&image)?;
        let mut owned = Self {
            scope: scope.to_string(),
            image,
            id: None,
            creation_attempted: false,
            url: String::new(),
            network,
        };
        if let Err(error) = owned.initialize(readiness).await {
            // A logged Drop error is never accepted as verified cleanup. Return
            // the cleanup failure explicitly; Drop remains only a panic fallback.
            owned.cleanup()?;
            return Err(error);
        }
        Ok(owned)
    }

    async fn initialize(&mut self, readiness: Readiness) -> Result<(), String> {
        let label = format!("{LABEL}={}", self.scope);
        let tmpfs = format!("/data:{TMPFS}");
        let network = self.network.mode();
        let mut arguments = vec![
            "create",
            "--pull=never",
            "--label",
            &label,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "redis",
            "--tmpfs",
            &tmpfs,
            "--network",
            &network,
        ];
        if matches!(self.network, Network::Loopback) {
            arguments.extend(["--publish", "127.0.0.1::6379"]);
        }
        arguments.extend(["--entrypoint", "redis-server", &self.image]);
        arguments.extend(COMMAND);
        self.creation_attempted = true;
        let id = docker(&arguments)?;
        exact_id(&id)?;
        self.id = Some(id.clone());
        checked_identity(&inspect(&id)?, &id, &self.scope, &self.image, &self.network)?;
        eprintln!("Created exact-owned base runtime Redis: container={id}");
        docker(&["start", &id])?;
        self.url = checked_url(&inspect(&id)?, &id, &self.scope, &self.image, &self.network)?;
        let duration = if matches!(readiness, Readiness::ControlledTimeout) {
            Duration::from_millis(1)
        } else {
            Duration::from_secs(30)
        };
        let deadline = Instant::now() + duration;
        tokio::time::timeout(duration, async {
            if matches!(readiness, Readiness::ControlledTimeout) {
                std::future::pending::<()>().await;
            }
            loop {
                // Reuse the production Redis client's actual PING health check;
                // do not substitute TCP acceptance or add a second RESP client.
                match &self.network {
                    Network::Loopback => {
                        if let Ok(client) =
                            RedisRateLimiter::connect(&self.url, label.clone()).await
                        {
                            if client.health_check().await.is_ok() {
                                break;
                            }
                        }
                    }
                    Network::PublishedNamespace { .. } => {
                        // The host cannot reach the unpublished namespace port.
                        // Use the image's real Redis client in that same namespace.
                        if ping_ready(docker_with_timeout(
                            &["exec", &id, "redis-cli", "PING"],
                            deadline.saturating_duration_since(Instant::now()),
                        ))? {
                            break;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "Owned Redis PING readiness timed out".to_owned())??;
        self.network.verify_parent()?;
        if checked_url(&inspect(&id)?, &id, &self.scope, &self.image, &self.network)? != self.url {
            return Err("Owned Redis binding changed during readiness".into());
        }
        eprintln!(
            "Owned base runtime Redis: container={id}, image={}",
            self.image
        );
        Ok(())
    }

    pub(super) fn verify_published_namespace(
        &self,
        owned: &PublishedDatabase,
    ) -> Result<(), String> {
        let expected = Network::published(owned)?;
        if self.network.mode() != expected.mode() {
            return Err("Redis is not in the verified database namespace".into());
        }
        let id = self.id.as_deref().ok_or("Missing owned Redis")?;
        if checked_url(&inspect(id)?, id, &self.scope, &self.image, &expected)? != self.url {
            return Err("Owned Redis URL changed".into());
        }
        Ok(())
    }

    pub(super) async fn assert_constructor_timeout_cleanup(
        owned: &PublishedDatabase,
    ) -> Result<(), String> {
        let scope = Uuid::new_v4();
        let result = Self::start_owned(
            Network::published(owned)?,
            scope,
            Readiness::ControlledTimeout,
        )
        .await;
        match result {
            Err(error) if error == "Owned Redis PING readiness timed out" => {}
            Ok(value) => {
                value.close_verified()?;
                return Err("Controlled Redis timeout unexpectedly succeeded".into());
            }
            Err(_) => {
                return Err("Controlled Redis failure did not reach its readiness boundary".into())
            }
        }
        let filter = format!("label={LABEL}={scope}");
        if !docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?.is_empty() {
            return Err("Constructor failure left an owned Redis resource".into());
        }
        Ok(())
    }

    pub(super) fn url(&self) -> &str {
        &self.url
    }

    fn owned_ids(&self) -> Result<Vec<String>, String> {
        if !self.creation_attempted {
            return Ok(Vec::new());
        }
        let filter = format!("label={LABEL}={}", self.scope);
        let result = docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?;
        let ids: Vec<_> = result.lines().map(str::to_owned).collect();
        if ids.len() > 1
            || self
                .id
                .as_ref()
                .is_some_and(|id| ids.as_slice() != std::slice::from_ref(id))
        {
            return Err("Owned Redis resource identity is missing or ambiguous".into());
        }
        for id in &ids {
            checked_identity(&inspect(id)?, id, &self.scope, &self.image, &self.network)?;
        }
        Ok(ids)
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let ids = self.owned_ids()?;
        for id in &ids {
            docker(&["rm", "--force", id])?;
            let filter = format!("id={id}");
            if !docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?.is_empty() {
                return Err("Exact owned Redis resource remained after cleanup".into());
            }
        }
        self.id = None;
        self.creation_attempted = false;
        Ok(())
    }

    pub(super) fn close_verified(mut self) -> Result<(), String> {
        self.cleanup()
    }
}

impl Drop for OwnedRedis {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Owned Redis cleanup requires inspection: {error}");
        }
    }
}
