//! Deterministic provisioning and recovery decisions over caller-owned observations.
//! Filesystem, release attestations, Docker mutation and database fences remain
//! with their existing protected owners. This module performs no I/O.
use crate::passport_model::{require, PolicyResult};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn pattern(value: &Value, regex: &str) -> bool {
    value
        .as_str()
        .is_some_and(|s| regex::Regex::new(regex).unwrap().is_match(s))
}
fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .map(|v| v.keys().map(String::as_str).collect())
        .unwrap_or_default()
}
fn strings(value: &Value) -> Option<BTreeSet<&str>> {
    value.as_array()?.iter().map(Value::as_str).collect()
}
fn optional_strings<'a>(record: &'a Value, key: &str) -> Result<BTreeSet<&'a str>, String> {
    match record.get(key) {
        None => Ok(BTreeSet::new()),
        Some(value) => {
            strings(value).ok_or_else(|| "Aggregate resume recreation set is invalid".into())
        }
    }
}
fn stage(input: &Value) -> PolicyResult {
    let plan = &input["plan"];
    let project = plan["project"].as_str().unwrap_or("");
    let surface = plan["surface"].as_str().unwrap_or("");
    require(
        pattern(
            &plan["project"],
            r"\Amarty-passport-acceptance-(base|selfhost)-[a-z0-9]{6,32}\z",
        ) && project.starts_with(&format!("marty-passport-acceptance-{surface}-")),
        "Disposable input project is invalid",
    )?;
    require(
        input["gateway_port"]
            .as_u64()
            .is_some_and(|v| (1024..=65535).contains(&v)),
        "Disposable Gateway port is invalid",
    )?;
    let run = match &plan["run_id"] {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    require(
        plan["schema"] == "marty.passport-supported-provisioning-plan/v1"
            && plan["status"] == "blocked"
            && matches!(surface, "base" | "selfhost")
            && regex::Regex::new(r"\A[1-9][0-9]{0,19}\z")
                .unwrap()
                .is_match(&run)
            && pattern(&plan["source_commit"], r"\A[0-9a-f]{40}\z"),
        "Disposable input plan is invalid",
    )?;
    require(
        plan["owner_labels"]
            == json!({
                "com.marty.passport.acceptance.owner":"supported-consumer",
                "com.marty.passport.acceptance.run-id":run,
                "com.marty.passport.acceptance.source-commit":plan["source_commit"],
                "com.marty.passport.acceptance.services-image":plan["services_reference"]
            }),
        "Disposable input owner labels are invalid",
    )?;
    let images = &plan["infra_images"];
    require(
        images.is_object() && keys(images) == BTreeSet::from(["postgres", "redis", "openbao"]),
        "Disposable infrastructure image set is invalid",
    )?;
    let mut references = json!({"MARTY_SERVICES_IMAGE":plan["services_reference"],"PASSPORT_ACCEPTANCE_MIGRATIONS_IMAGE":plan["migrations_reference"]});
    for (name, value) in images.as_object().unwrap() {
        references[format!("PASSPORT_ACCEPTANCE_{}_IMAGE", name.to_uppercase())] = value.clone();
    }
    require(
        references
            .as_object()
            .unwrap()
            .values()
            .all(|v| pattern(v, r"\A[^\s]+@sha256:[0-9a-f]{64}\z")),
        "Disposable image reference is invalid",
    )?;
    require(
        plan["expires_at"]
            .as_str()
            .is_some_and(|s| !s.contains(['\r', '\n'])),
        "Disposable expiry is invalid",
    )?;
    Ok(references)
}
fn preserved_kms(input: &Value) -> PolicyResult {
    let bao = &input["observed"];
    let id = &input["container_id"];
    require(
        pattern(id, r"\A[0-9a-f]{64}\z"),
        "Preserved OpenBao identity is invalid",
    )?;
    let config = &bao["Config"];
    let env = config["Env"].as_array();
    require(
        bao["Id"] == *id
            && config.is_object()
            && env.is_some_and(|a| {
                a.iter()
                    .all(|s| s.as_str().is_some_and(|s| s.contains('=')))
            }),
        "Preserved OpenBao environment is invalid",
    )?;
    let services = &input["rendered"]["services"];
    require(
        services.is_object(),
        "Rendered beta service graph is invalid",
    )?;
    let signer = &services["passport-callback-signer"];
    let bootstrap = &services["openbao-init"];
    require(
        signer.is_object() && bootstrap.is_object(),
        "Rendered beta KMS roles are incomplete",
    )?;
    // The rendered-model environment adapter has already normalized both roles.
    let s = &input["signer_environment"];
    let b = &input["bootstrap_environment"];
    require(
        env.unwrap().iter().all(|v| {
            !["BAO_DEV_ROOT_TOKEN_ID=", "BAO_TOKEN=", "VAULT_TOKEN="]
                .iter()
                .any(|p| v.as_str().unwrap().starts_with(p))
        }) && config["Cmd"] == json!(["server", "-config=/bao/config/openbao.hcl"])
            && bao["Mounts"].as_array().is_some_and(|mounts| {
                mounts.iter().any(|m| {
                    m.is_object()
                        && m["Type"] == "volume"
                        && m["Destination"] == "/bao/data"
                        && m["Name"] == "elevenid-beta_openbao_data"
                })
            })
            && s["BAO_ADDR"] == "https://openbao:8200"
            && s["BAO_CACERT"] == "/bao/public-ca/ca.crt"
            && s["BAO_TOKEN_FILE"] == "/bao/passport-callback/token"
            && !crate::python_truthy(&s["BAO_TOKEN"])
            && b["BAO_PASSPORT_CALLBACK_TOKEN_FILE"] == "/bao/passport-callback/token",
        "Preserved OpenBao is not the scoped Raft callback KMS",
    )?;
    Ok(Value::Null)
}
fn resume(input: &Value) -> PolicyResult {
    let record = &input["record"];
    let old = &record["old_container_ids_by_service"];
    let observed = input["observed"]
        .as_object()
        .ok_or("Aggregate resume beta service inventory changed")?;
    require(
        observed
            .values()
            .all(|v| v.as_array().is_some_and(|a| a.len() <= 2)),
        "Aggregate resume beta service is duplicated",
    )?;
    let recreated = optional_strings(record, "recreate_applications")?
        .union(&optional_strings(record, "recreate_ingress_last")?)
        .copied()
        .collect::<BTreeSet<_>>();
    let rendered = &input["rendered_services"];
    require(
        rendered.is_object(),
        "Aggregate resume rendered services are invalid",
    )?;
    let signed = strings(&input["signed_applications"])
        .ok_or("Aggregate resume signed service set is invalid")?;
    let selectors = input["selectors"]
        .as_object()
        .ok_or("Aggregate resume runtime selectors are invalid")?;
    for (service, containers) in observed {
        let containers = containers
            .as_array()
            .ok_or("Aggregate resume beta state is invalid")?;
        require(
            containers
                .iter()
                .filter(|v| v["Id"] != old[service])
                .count()
                <= 1,
            "Aggregate resume beta service has duplicate replacements",
        )?;
        for container in containers {
            let state = &container["State"];
            require(state.is_object(), "Aggregate resume beta state is invalid")?;
            let networks = &container["NetworkSettings"]["Networks"];
            let expected = &record["expected_networks_by_service"];
            require(
                networks.is_object()
                    && expected.is_object()
                    && strings(&expected[service]).is_some_and(|v| keys(networks).is_subset(&v)),
                "Aggregate resume beta service joined an unexpected network",
            )?;
            if !recreated.contains(service.as_str()) {
                require(
                    container["Id"] == old[service],
                    "Aggregate resume infrastructure identity changed",
                )?;
            } else if container["Id"] == old[service] {
                require(
                    state["Running"] == false,
                    "Stopped old beta application restarted during resume",
                )?;
            } else {
                let config = &container["Config"];
                require(
                    config.is_object() && config["Image"] == record["services_image"],
                    "Aggregate resume application image differs",
                )?;
                let labels = &config["Labels"];
                let hashes = &record["service_config_hashes"];
                require(
                    labels.is_object()
                        && hashes.is_object()
                        && pattern(&hashes[service], r"\A[0-9a-f]{64}\z")
                        && labels["com.docker.compose.config-hash"] == hashes[service],
                    "Aggregate resume Compose service config differs",
                )?;
                if signed.contains(service.as_str()) {
                    let raw = config["Env"]
                        .as_array()
                        .ok_or("Aggregate resume application environment is invalid")?;
                    require(
                        raw.iter()
                            .all(|v| v.as_str().is_some_and(|v| v.contains('='))),
                        "Aggregate resume application environment is invalid",
                    )?;
                    let selected = raw
                        .iter()
                        .map(|v| v.as_str().unwrap().split_once('=').unwrap())
                        .collect::<std::collections::BTreeMap<_, _>>();
                    require(
                        selected.len() == raw.len()
                            && selected.get("SERVICE_NAME").copied()
                                == Some(service.replace('-', "_").as_str())
                            && selectors.get(service).is_none_or(|wanted| {
                                wanted.as_object().is_some_and(|m| {
                                    m.iter().all(|(k, v)| {
                                        v.as_str() == selected.get(k.as_str()).copied()
                                    })
                                })
                            }),
                        "Aggregate resume Rust runtime selector differs",
                    )?;
                }
                let wanted = &rendered[service];
                require(
                    wanted.is_object(),
                    "Aggregate resume rendered application is absent",
                )?;
                for (field, docker) in [("entrypoint", "Entrypoint"), ("command", "Cmd")] {
                    if let Some(value) = wanted.get(field) {
                        require(
                            config.get(docker) == Some(value),
                            "Aggregate resume application process differs",
                        )?;
                    }
                }
                if service == "passport-callback-signer" {
                    require(
                        networks.is_object()
                            && keys(networks)
                                == BTreeSet::from(["elevenid-beta-passport-callback-signing"]),
                        "Aggregate resume callback signer network differs",
                    )?;
                }
            }
        }
    }
    let mut ready = Vec::new();
    for service in recreated {
        let Some(containers) = observed.get(service).and_then(Value::as_array) else {
            continue;
        };
        if containers.len() != 1 || containers[0]["Id"] == old[service] {
            continue;
        }
        let state = &containers[0]["State"];
        let networks = &containers[0]["NetworkSettings"]["Networks"];
        if state["Running"] == true
            && state["Status"] == "running"
            && networks.is_object()
            && strings(&record["expected_networks_by_service"][service])
                .is_some_and(|v| keys(networks) == v)
            && (state["Health"].is_null()
                || (state["Health"].is_object() && state["Health"]["Status"] == "healthy"))
        {
            ready.push(service);
        }
    }
    Ok(json!(ready))
}
pub(crate) fn evaluate(operation: &str, input: &Value) -> PolicyResult {
    match operation {
        "lifecycle-stage-input" => stage(input),
        "lifecycle-preserved-kms" => preserved_kms(input),
        "lifecycle-resume-runtime" => resume(input),
        _ => Err("Deployment lifecycle operation is invalid".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_present_recreation_sets_cannot_become_an_empty_generation() {
        for value in [Value::Null, json!(false), json!(["flow", 7]), json!("flow")] {
            assert!(optional_strings(
                &json!({"recreate_applications":value}),
                "recreate_applications"
            )
            .is_err());
        }
        assert!(optional_strings(&json!({}), "recreate_applications")
            .unwrap()
            .is_empty());
    }
}
