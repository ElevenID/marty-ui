//! Startup ordering for the already admitted application model. The explicit
//! KMS initialization barrier is stronger than the ordinary Compose graph.
#![cfg(target_os = "linux")]
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "application startup dependency contract differs from the reviewed model";
const INITIALIZERS: [&str; 5] = [
    "revocation-profile-migrate",
    "db-migrate",
    "kms-initialize",
    "keycloak-configurator",
    "issuance-migrations",
];
const MIGRATIONS: [&str; 4] = [
    "postgres",
    "redis",
    "revocation-profile-migrate",
    "db-migrate",
];
const EXCLUDED: [&str; 4] = [
    "cloudflared",
    "cloudflared-beta",
    "tunnel-nginx-proxy",
    "kms-initialize",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Healthy,
    ExitedZero,
    Running,
}

pub fn completion(model: &Value, role: &str) -> Result<Completion> {
    let service = model["services"]
        .get(role)
        .filter(|s| s.is_object())
        .ok_or(REFUSED)?;
    if INITIALIZERS.contains(&role) {
        if service["restart"] != "no" {
            return Err(REFUSED.into());
        }
        return Ok(Completion::ExitedZero);
    }
    let health = &service["healthcheck"];
    // This background worker deliberately has no health endpoint. Record only
    // process observation; business-journey qualification is a separate gate.
    if role == "canvas-sync-worker" && health["disable"] == true {
        return Ok(Completion::Running);
    }
    let test = health["test"].as_array().ok_or(REFUSED)?;
    if health["disable"] == true
        || test.len() < 2
        || !matches!(test[0].as_str(), Some("CMD" | "CMD-SHELL"))
        || !test
            .iter()
            .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
    {
        return Err(REFUSED.into());
    }
    Ok(Completion::Healthy)
}

pub fn startup_order(model: &Value, selected: &[String]) -> Result<Vec<String>> {
    let services = model["services"].as_object().ok_or(REFUSED)?;
    let chosen: BTreeSet<&str> = selected.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = services
        .keys()
        .map(String::as_str)
        .filter(|s| !EXCLUDED.contains(s))
        .collect();
    let canonical = services.len() == 33 && EXCLUDED.iter().all(|s| services.contains_key(*s));
    let generation_selected = services.len() == 30
        && services.contains_key("kms-initialize")
        && EXCLUDED[..3].iter().all(|s| !services.contains_key(*s));
    if !(canonical || generation_selected)
        || chosen.len() != 29
        || chosen.len() != selected.len()
        || chosen != expected
    {
        return Err(REFUSED.into());
    }
    let mut all = chosen;
    all.insert("kms-initialize");
    let mut graph = BTreeMap::<String, BTreeSet<String>>::new();
    for role in &all {
        completion(model, role).map_err(|e| format!("{e}: completion for {role}"))?;
        let mut deps = BTreeSet::new();
        if let Some(value) = services[*role].get("depends_on") {
            for (peer, spec) in value.as_object().ok_or(REFUSED)? {
                if !all.contains(peer.as_str()) || spec["required"] == false {
                    return Err(format!("{REFUSED}: dependency {role} -> {peer}"));
                }
                let condition = match completion(model, peer)? {
                    Completion::Healthy => "service_healthy",
                    Completion::ExitedZero => "service_completed_successfully",
                    Completion::Running => return Err(REFUSED.into()),
                };
                if spec["condition"] != condition {
                    return Err(REFUSED.into());
                }
                deps.insert(peer.clone());
            }
        }
        graph.insert((*role).to_owned(), deps);
    }
    // The initialization closure must be precisely the reviewed database and
    // Redis stage; application dependencies may not move ahead of this barrier.
    let mut closure = BTreeSet::new();
    let mut pending: Vec<_> = graph["kms-initialize"].iter().cloned().collect();
    while let Some(role) = pending.pop() {
        if closure.insert(role.clone()) {
            pending.extend(graph[&role].iter().cloned());
        }
    }
    if closure != MIGRATIONS.iter().map(|s| (*s).to_owned()).collect() {
        return Err(REFUSED.into());
    }
    for (role, deps) in &mut graph {
        if role != "kms-initialize" && !closure.contains(role) {
            deps.insert("kms-initialize".into());
        }
    }
    let mut order = Vec::new();
    while !graph.is_empty() {
        let next = graph
            .iter()
            .find(|(_, deps)| deps.is_empty())
            .map(|(role, _)| role.clone())
            .ok_or(REFUSED)?;
        graph.remove(&next);
        for deps in graph.values_mut() {
            deps.remove(&next);
        }
        order.push(next);
    }
    Ok(order)
}
