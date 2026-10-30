//! Common owned-container invariants. Stage capabilities, scratch and mounts stay local.
#![cfg(target_os = "linux")]
use crate::installer_runtime::DockerRunner;
use serde_json::{json, Value};
use std::collections::BTreeMap;
type Result<T> = std::result::Result<T, String>;
fn require(condition: bool, refusal: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(refusal.into())
    }
}
pub(crate) struct ExpectedContainer<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub owner: &'a str,
    pub image: &'a str,
    pub image_id: &'a str,
    pub network_id: &'a str,
    pub stage: &'static str,
    pub entrypoint: Value,
    pub command: Value,
}
pub(crate) fn validate_identity_and_security(
    c: &Value,
    expected: &ExpectedContainer<'_>,
    refusal: &str,
) -> Result<()> {
    let host = &c["HostConfig"];
    let config = &c["Config"];
    require(
        c["Id"] == expected.id
            && c["Image"] == expected.image_id
            && c["Name"] == format!("/{}", expected.name)
            && config["Image"] == expected.image
            && config["User"] == "0:0"
            && config["Entrypoint"] == expected.entrypoint
            && config["Cmd"] == expected.command
            && config["Labels"]["com.elevenid.installer.id"] == expected.owner
            && config["Labels"]["com.elevenid.installer.stage"] == expected.stage
            && host["ReadonlyRootfs"] == true
            && host["Privileged"] == false
            && host["CapDrop"] == json!(["ALL"])
            && (host["SecurityOpt"] == json!(["no-new-privileges"])
                || host["SecurityOpt"] == json!(["no-new-privileges:true"]))
            && host["NetworkMode"] == expected.network_id
            && host["AutoRemove"] == false
            && host["RestartPolicy"]["Name"] == "no"
            && host["PidMode"].as_str().is_some_and(str::is_empty)
            && host["UsernsMode"].as_str().is_some_and(str::is_empty)
            && matches!(host["IpcMode"].as_str(), Some("private" | ""))
            && empty_or_null(&host["PortBindings"])
            && empty_or_null(&host["Devices"])
            && empty_or_null(&host["DeviceRequests"])
            && empty_or_null(&host["Binds"]),
        refusal,
    )
}
pub(crate) fn validate_stopped_state(c: &Value, terminal: bool, refusal: &str) -> Result<()> {
    require(c["State"]["Running"] == false, refusal)?;
    if terminal {
        require(
            c["State"]["Status"] == "exited"
                && c["State"]["ExitCode"] == 0
                && c["State"]["OOMKilled"] == false,
            refusal,
        )
    } else {
        require(c["State"]["Status"] == "created", refusal)
    }
}

pub(crate) fn inspect(docker: &DockerRunner, container: &str, refusal: &str) -> Result<Value> {
    let result: Value =
        serde_json::from_str(&docker.run_checked(&["inspect", container])?).map_err(|_| refusal)?;
    let list = result.as_array().ok_or(refusal)?;
    require(list.len() == 1, refusal)?;
    Ok(list[0].clone())
}

pub(crate) fn empty_or_null(value: &Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}

pub(crate) fn environment_map(value: &Value, refusal: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for item in value.as_array().ok_or(refusal)? {
        let (key, value) = item
            .as_str()
            .ok_or(refusal)?
            .split_once('=')
            .ok_or(refusal)?;
        require(
            !key.is_empty()
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !value.chars().any(char::is_control)
                && result.insert(key.to_owned(), value.to_owned()).is_none(),
            refusal,
        )?;
    }
    Ok(result)
}

pub(crate) fn bootstrap_environment(
    inherited: &Value,
    refusal: &str,
) -> Result<BTreeMap<String, String>> {
    let environment = environment_map(inherited, refusal)?;
    require(
        !environment.keys().any(|key| {
            key.starts_with("BAO_")
                || key.starts_with("MARTY_TLS_")
                || key.starts_with("SELFHOST_")
                || [
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                    "NO_PROXY",
                    "LD_PRELOAD",
                    "LD_LIBRARY_PATH",
                ]
                .contains(&key.to_ascii_uppercase().as_str())
        }),
        refusal,
    )?;
    Ok(environment)
}
