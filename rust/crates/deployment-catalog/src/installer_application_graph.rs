//! Startup ordering for the already admitted application model. The explicit
//! KMS initialization barrier and eager workload prerequisites are stronger
//! than the ordinary Compose graph. The admitted model remains unchanged.
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

/// Dependencies checked both when ordering starts and immediately before each
/// start. The published compliance-profile service connects to organization
/// before exposing its health listener, although the older signed Compose
/// model declares only its database dependency. Serial installer startup must
/// establish that prerequisite without changing the authenticated model.
pub(crate) fn required_dependencies(model: &Value, role: &str) -> Result<BTreeSet<String>> {
    let service = model["services"]
        .get(role)
        .filter(|s| s.is_object())
        .ok_or(REFUSED)?;
    let mut dependencies = BTreeSet::new();
    if let Some(value) = service.get("depends_on") {
        for (peer, spec) in value.as_object().ok_or(REFUSED)? {
            if spec["required"] == false {
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
            dependencies.insert(peer.clone());
        }
    }
    if role == "compliance-profile" {
        if completion(model, "organization")? != Completion::Healthy {
            return Err(REFUSED.into());
        }
        dependencies.insert("organization".into());
    }
    Ok(dependencies)
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
        let deps = required_dependencies(model, role)?;
        for peer in &deps {
            if !all.contains(peer.as_str()) {
                return Err(format!("{REFUSED}: dependency {role} -> {peer}"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn model() -> (Value, Vec<String>) {
        let mut services = serde_json::Map::new();
        for role in INITIALIZERS
            .iter()
            .copied()
            .chain(["postgres", "redis", "organization", "compliance-profile"])
            .map(str::to_owned)
            .chain((0..21).map(|index| format!("fixture-{index:02}")))
        {
            services.insert(role.clone(), json!({
                "restart": if INITIALIZERS.contains(&role.as_str()) { "no" } else { "unless-stopped" },
                "healthcheck": {"test": ["CMD", "true"]},
                "depends_on": {}
            }));
        }
        let mut model = json!({"services": services});
        for role in ["db-migrate", "revocation-profile-migrate"] {
            model["services"][role]["depends_on"] =
                json!({"postgres": {"condition": "service_healthy"}});
        }
        model["services"]["kms-initialize"]["depends_on"] = json!({
            "db-migrate": {"condition": "service_completed_successfully"},
            "revocation-profile-migrate": {"condition": "service_completed_successfully"},
            "redis": {"condition": "service_healthy"}
        });
        model["services"]["organization"]["depends_on"] = json!({
            "db-migrate": {"condition": "service_completed_successfully"},
            "redis": {"condition": "service_healthy"}
        });
        model["services"]["compliance-profile"]["depends_on"] =
            json!({"db-migrate": {"condition": "service_completed_successfully"}});
        let selected = model["services"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|role| role.as_str() != "kms-initialize")
            .cloned()
            .collect();
        (model, selected)
    }

    #[test]
    fn compliance_prerequisite_orders_and_checks_organization_without_changing_model() {
        let (model, selected) = model();
        let before = model.clone();
        assert_eq!(
            required_dependencies(&model, "compliance-profile").unwrap(),
            BTreeSet::from(["db-migrate".into(), "organization".into()])
        );
        assert!(required_dependencies(&model, "fixture-00")
            .unwrap()
            .is_empty());
        let order = startup_order(&model, &selected).unwrap();
        assert_eq!(order.len(), 30);
        assert_eq!(order[4], "kms-initialize");
        assert_eq!(
            order[..4]
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            MIGRATIONS.into_iter().collect::<BTreeSet<_>>()
        );
        let position = |role| order.iter().position(|value| value == role).unwrap();
        assert!(position("kms-initialize") < position("organization"));
        assert!(position("organization") < position("compliance-profile"));
        assert_eq!(model, before);
        assert!(model["services"]["compliance-profile"]["depends_on"]
            .get("organization")
            .is_none());
    }

    #[test]
    fn compliance_prerequisite_requires_health_and_preserves_declared_dependency_checks() {
        let (model, selected) = model();
        for invalid in [
            json!({"condition": "service_started"}),
            json!({"condition": "service_healthy", "required": false}),
        ] {
            let mut changed = model.clone();
            changed["services"]["compliance-profile"]["depends_on"]["organization"] = invalid;
            assert!(required_dependencies(&changed, "compliance-profile").is_err());
            assert!(startup_order(&changed, &selected).is_err());
        }
        let mut changed = model.clone();
        changed["services"]["organization"]["healthcheck"]["disable"] = json!(true);
        assert!(required_dependencies(&changed, "compliance-profile").is_err());
        assert!(startup_order(&changed, &selected).is_err());
        let mut changed = model;
        let organization = changed["services"]
            .as_object_mut()
            .unwrap()
            .remove("organization")
            .unwrap();
        changed["services"]["replacement"] = organization;
        let selected: Vec<_> = selected
            .into_iter()
            .map(|role| {
                if role == "organization" {
                    "replacement".into()
                } else {
                    role
                }
            })
            .collect();
        assert!(required_dependencies(&changed, "compliance-profile").is_err());
        assert!(startup_order(&changed, &selected).is_err());
    }

    #[test]
    fn compliance_prerequisite_refuses_dependency_cycle() {
        let (mut model, selected) = model();
        model["services"]["organization"]["depends_on"]["compliance-profile"] =
            json!({"condition": "service_healthy"});
        assert!(startup_order(&model, &selected).is_err());
    }
}
