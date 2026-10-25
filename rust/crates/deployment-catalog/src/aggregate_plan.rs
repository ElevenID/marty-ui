//! Read-only aggregate generation planning. Release proofs and mutations stay
//! with the deployment owner; results contain resource names and IDs only.
use crate::passport_model::{beta_origin, environment, private_gateway, require, PolicyResult};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

fn strings(value: &Value) -> Result<BTreeSet<&str>, String> {
    value
        .as_array()
        .and_then(|a| a.iter().map(Value::as_str).collect())
        .ok_or_else(|| "Aggregate service metadata is invalid".into())
}
fn names(value: &Value) -> BTreeSet<&str> {
    if let Some(o) = value.as_object() {
        o.keys().map(String::as_str).collect()
    } else {
        value
            .as_array()
            .and_then(|a| a.iter().map(Value::as_str).collect())
            .unwrap_or_default()
    }
}
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::String(v) => !v.is_empty(),
        Value::Array(v) => !v.is_empty(),
        Value::Object(v) => !v.is_empty(),
        Value::Number(v) => v.as_f64() != Some(0.0),
    }
}
pub(crate) fn prepare(input: &Value) -> PolicyResult {
    let rendered = &input["rendered"];
    let services = &rendered["services"];
    let signed = strings(&input["signed_applications"])?;
    let new = strings(&input["new_services"])?;
    let ingress = strings(&input["ingress"])?;
    let generation = input["generation"]
        .as_array()
        .filter(|g| !g.is_empty())
        .ok_or("Beta maintenance generation is invalid")?;
    let mut previous = Map::new();
    for item in generation {
        let service = item["service"].as_str();
        require(
            item.is_object()
                && service.is_some()
                && item["container_id"].as_str().is_some_and(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                })
                && !previous.contains_key(service.unwrap_or("")),
            "Beta maintenance generation has ambiguous services",
        )?;
        previous.insert(service.unwrap().to_owned(), item["container_id"].clone());
    }
    let old: BTreeSet<&str> = previous.keys().map(String::as_str).collect();
    require(
        !old.contains("issuance-canvas-localhost-bridge"),
        "Optional Canvas localhost bridge cannot enter signed aggregate beta generation",
    )?;
    let required: BTreeSet<_> = signed
        .difference(&new)
        .copied()
        .chain(["issuance"])
        .collect();
    require(
        old.contains("postgres") && required.is_subset(&old) && new.is_disjoint(&old),
        "Beta generation or simulator service state is unexpected",
    )?;
    require(
        services.is_object()
            && old.is_subset(&names(services))
            && signed.is_subset(&names(services)),
        "Rendered beta Compose omits required services",
    )?;
    beta_origin(services)?;
    private_gateway(services)?;
    for name in &signed {
        let service = &services[*name];
        require(
            service.is_object(),
            format!("Rendered beta service is invalid: {name}"),
        )?;
        require(
            service["image"] == input["services_image"],
            format!("Rendered beta service image differs from signed release: {name}"),
        )?;
        let env = environment(service)?;
        require(
            env.get("SERVICE_NAME") == Some(&json!(name.replace('-', "_"))),
            format!("Rendered beta service dispatch differs: {name}"),
        )?;
        if *name == "issuance-native" {
            for key in [
                "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
                "PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE",
                "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED",
                "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
                "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE",
            ] {
                require(
                    !env.contains_key(key),
                    format!("Rendered beta Rust selector differs: {name}.{key}"),
                )?;
            }
        }
        if let Some(selectors) = input["selectors"][*name].as_object() {
            for (key, expected) in selectors {
                require(
                    env.get(key) == Some(expected),
                    format!("Rendered beta Rust selector differs: {name}.{key}"),
                )?;
            }
        }
        if new.contains(name) {
            require(
                !truthy(&service["ports"]),
                format!("Synthetic passport service publishes a port: {name}"),
            )?;
        }
    }
    let callback = &services["passport-callback-signer"];
    require(
        names(&callback["networks"]) == BTreeSet::from(["passport-callback-signing"])
            && !truthy(&callback["volumes"])
            && !truthy(&callback["secrets"]),
        "Passport callback signer isolation differs",
    )?;
    require(
        names(&services["passport-beta-bureau"]["networks"])
            == BTreeSet::from(["marty-network", "passport-callback-signing"]),
        "Passport synthetic bureau networks differ",
    )?;
    let network = &rendered["networks"]["passport-callback-signing"];
    require(
        network.is_object()
            && network["name"] == "elevenid-beta-passport-callback-signing"
            && network["internal"] == true,
        "Passport callback signing network is not isolated",
    )?;
    for name in &signed {
        if !["issuance-native", "canvas-sync-worker", "canvas-sandbox"].contains(name) {
            require(
                !truthy(&services[*name]["entrypoint"]) && !truthy(&services[*name]["command"]),
                format!("Rendered beta service overrides signed dispatch: {name}"),
            )?;
        }
    }
    require(
        services["issuance-native"]["entrypoint"] == json!(["/app/services/entrypoint.sh"])
            && services["issuance-native"]["command"] == json!([]),
        "Native issuance entrypoint differs",
    )?;
    require(
        services["canvas-sync-worker"]["command"]
            == json!(["/usr/local/bin/marty-canvas-sync-worker"])
            && !truthy(&services["canvas-sync-worker"]["entrypoint"]),
        "Canvas worker command differs",
    )?;
    let sandbox = &services["canvas-sandbox"];
    require(
        sandbox["entrypoint"] == json!(["/usr/local/bin/marty-canvas-sandbox"])
            && sandbox["command"] == json!([])
            && !truthy(&sandbox["build"])
            && sandbox["healthcheck"]["test"]
                == json!(["CMD", "curl", "-fsS", "http://localhost:8017/health"]),
        "Rendered beta Canvas sandbox is not the signed Rust runtime",
    )?;
    let issuance = &services["issuance"];
    let issuance_env = environment(issuance)?;
    require(
        issuance.is_object()
            && issuance["image"] == input["services_image"]
            && issuance["entrypoint"] == json!(["/usr/local/bin/marty-issuance-service"])
            && issuance["command"] == json!([])
            && issuance_env.get("SERVICE_NAME") == Some(&json!("issuance_native"))
            && issuance_env.get("MARTY_SCHEMA_STARTUP_MODE") == Some(&json!("validate"))
            && issuance_env.get("CANVAS_MIRROR_WORKER_ENABLED") == Some(&json!("false")),
        "Rendered beta issuance image differs from signed Rust release",
    )?;
    let migrations = &services["issuance-migrations"];
    let migrations_env = environment(migrations)?;
    require(
        migrations.is_object()
            && migrations["image"] == input["services_image"]
            && migrations["entrypoint"] == json!(["/usr/local/bin/marty-issuance-service"])
            && migrations["command"] == json!(["verify-owned-schema"])
            && migrations_env.get("SERVICE_NAME") == Some(&json!("issuance_native"))
            && migrations_env
                .get("DATABASE_URL")
                .and_then(Value::as_str)
                .is_some_and(|s| s.starts_with("postgresql://"))
            && migrations["depends_on"]["organization"]["condition"] == "service_healthy"
            && migrations["depends_on"]["credential-template"]["condition"] == "service_healthy",
        "Rendered beta issuance migrator differs from signed Rust release",
    )?;
    for name in [
        "passport-provider-ingress",
        "passport-callback-signer-supported",
    ] {
        require(
            services.get(name).is_none(),
            "External physical provider profile entered synthetic beta Compose",
        )?;
    }
    require(
        rendered["name"] == "elevenid-beta",
        "Rendered Compose project is not the beta project",
    )?;
    let ui = &input["ui_rendered"];
    require(
        ui["name"] == "elevenid-beta-ui"
            && ui["services"].is_object()
            && names(&ui["services"]) == BTreeSet::from(["ui-prod"])
            && ui["services"]["ui-prod"].is_object()
            && ui["services"]["ui-prod"]["image"] == input["ui_image"],
        "Rendered beta UI differs from signed release",
    )?;
    require(
        ui["networks"].is_object()
            && ui["networks"]["default"].is_object()
            && ui["networks"]["default"]["external"] == true
            && ui["networks"]["default"]["name"] == "elevenid-beta-network",
        "Rendered beta UI network differs",
    )?;
    let old_services: BTreeSet<_> = old.iter().copied().filter(|n| *n != "postgres").collect();
    require(
        old_services.contains("openbao")
            && input["stop_container_ids"]
                .as_array()
                .is_some_and(|stops| !stops.contains(&previous["openbao"])),
        "Beta OpenBao was not preserved through maintenance",
    )?;
    let replaceable: BTreeSet<_> = signed.iter().copied().chain(["issuance"]).collect();
    let replacement: BTreeSet<_> = old_services
        .intersection(&replaceable)
        .copied()
        .chain(new.iter().copied())
        .collect();
    let restart: BTreeSet<_> = old_services
        .difference(&replacement)
        .copied()
        .filter(|n| *n != "openbao")
        .collect();
    require(
        rendered["networks"].is_object(),
        "Rendered beta networks are invalid",
    )?;
    let mut expected_networks = Map::new();
    for name in old.union(&new) {
        let default = json!({"marty-network":null});
        let configured = services[*name].get("networks").unwrap_or(&default);
        let network_keys: Vec<&str> = if let Some(map) = configured.as_object() {
            map.keys().map(String::as_str).collect()
        } else {
            configured
                .as_array()
                .and_then(|a| a.iter().map(Value::as_str).collect())
                .ok_or("Rendered beta service network configuration is invalid")?
        };
        let mut resolved = BTreeSet::new();
        for key in &network_keys {
            let definition = &rendered["networks"][*key];
            require(
                definition.is_object() && definition["name"].is_string(),
                "Rendered beta network name is invalid",
            )?;
            resolved.insert(definition["name"].as_str().unwrap());
        }
        require(
            !resolved.is_empty() && resolved.len() == network_keys.len(),
            "Rendered beta service networks are ambiguous",
        )?;
        expected_networks.insert((*name).to_owned(), json!(resolved));
    }
    Ok(json!({
        "postgres_container_id": previous["postgres"],
        "restart_infrastructure": restart.difference(&ingress).collect::<Vec<_>>(),
        "preserved_infrastructure": ["openbao"],
        "recreate_applications": replacement.difference(&ingress).collect::<Vec<_>>(),
        "restart_ingress_last": restart.intersection(&ingress).collect::<Vec<_>>(),
        "recreate_ingress_last": replacement.intersection(&ingress).collect::<Vec<_>>(),
        "target_services": old_services.union(&new).collect::<Vec<_>>(),
        "old_container_ids_by_service": previous,
        "expected_networks_by_service": expected_networks
    }))
}
