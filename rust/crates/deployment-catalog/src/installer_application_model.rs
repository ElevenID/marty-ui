//! Pure overlay over authenticated, isolated-env, all-profile Compose JSON.
//! Filesystem ownership/symlink checks and exact Docker network ID observation
//! remain mandatory caller duties immediately before startup. Commands and env
//! originate in the authenticated release: this is resource/DAG admission, not
//! independent validation of every executable or application setting.
#![cfg(target_os = "linux")]
use crate::installer_state::ApplicantContainerGroup;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "application Compose model differs from the reviewed installer contract";
pub struct ApplicationModelParameters {
    pub installation: PathBuf,
    pub applicant_container_group: ApplicantContainerGroup,
    pub bundle: PathBuf,
    pub compose_project: String,
    pub openbao_network_name: String,
    pub openbao_network_id: String,
    pub origin: String,
}
#[derive(Serialize)]
pub struct ApplicationModelPlan {
    pub model: Value,
    pub selected_services: Vec<String>,
    pub expected_network_id: String,
    pub installation_ready: bool,
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
// Compose versions normalize byte sizes as either a JSON number or decimal
// string. Admit only finite positive limits, never Docker's unlimited sentinel.
pub(crate) fn memory_limit(value: &Value) -> Result<u64> {
    let bytes = value.as_u64().or_else(|| {
        value.as_str().and_then(|s| {
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse::<u64>().ok())
                .flatten()
        })
    });
    bytes
        .filter(|n| (6 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(n))
        .ok_or_else(|| REFUSED.into())
}
fn object(v: &Value) -> Result<&Map<String, Value>> {
    v.as_object().ok_or_else(|| REFUSED.into())
}
fn string(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| REFUSED.into())
}
fn keys(v: &Value) -> Result<BTreeSet<&str>> {
    Ok(object(v)?.keys().map(String::as_str).collect())
}
fn subset(v: &Value, allowed: &[&str]) -> Result<()> {
    require(keys(v)?.iter().all(|key| allowed.contains(key)))
}
fn array(v: &Value) -> Result<&[Value]> {
    if v.is_null() {
        Ok(&[])
    } else {
        v.as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| REFUSED.into())
    }
}
fn safe_path(path: &Path) -> Result<&str> {
    let s = path.to_str().ok_or(REFUSED)?;
    require(
        s.starts_with('/')
            && s != "/"
            && !s.ends_with('/')
            && s.split('/')
                .skip(1)
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && !s.chars().any(|c| c.is_control() || c == '\\'),
    )?;
    Ok(s)
}
fn digest(s: &str) -> bool {
    s.rsplit_once("@sha256:").is_some_and(|(repo, h)| {
        !repo.is_empty()
            && h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
// Compose config JSON is a re-loadable document: literal dollars are doubled
// even in filesystem paths. Compare/insert that encoding here. Runtime Docker
// inspection must compare against raw owned filesystem paths, not these strings.
fn compose_path(path: &Path) -> Result<String> {
    Ok(path.to_str().ok_or(REFUSED)?.replace('$', "$$"))
}
fn expected_mount(source: &str, p: &ApplicationModelParameters) -> PathBuf {
    if let Some(s) = source.strip_prefix("bundle/") {
        p.bundle.join(s)
    } else if let Some(s) = source.strip_prefix("state/") {
        p.installation.join("state").join(s)
    } else {
        PathBuf::from(source)
    }
}
fn admit_mounts(service: &Value, contract: &Value, p: &ApplicationModelParameters) -> Result<()> {
    let volumes = array(&service["volumes"])?;
    let expected = array(&contract["mounts"])?;
    require(volumes.len() == expected.len())?;
    let mut seen = BTreeSet::new();
    for v in volumes {
        subset(
            v,
            &["type", "source", "target", "read_only", "bind", "volume"],
        )?;
        require(v.get("read_only").is_none_or(Value::is_boolean))?;
        let target = string(&v["target"])?;
        require(seen.insert(target))?;
        let e = expected
            .iter()
            .find(|e| e["target"] == target)
            .ok_or(REFUSED)?;
        require(
            v["type"] == e["type"]
                && v["read_only"].as_bool().unwrap_or(false)
                    == e["read_only"].as_bool().unwrap_or(false),
        )?;
        let source = string(&e["source"])?;
        require(v["source"].as_str() == Some(compose_path(&expected_mount(source, p))?.as_str()))?;
        if e["type"] == "bind" {
            require(v["volume"].is_null())?;
            let bind = &v["bind"];
            require(
                bind.is_null()
                    || *bind == json!({})
                    || *bind == json!({"create_host_path":false})
                    || (source.starts_with("bundle/") && *bind == json!({"create_host_path":true})),
            )?;
        } else {
            require(v["bind"].is_null() && (v["volume"].is_null() || v["volume"] == json!({})))?;
        }
    }
    Ok(())
}
fn admit_ports(name: &str, service: &Value) -> Result<()> {
    let ports = array(&service["ports"])?;
    let target: Option<u64> = match name {
        "gateway" => Some(8000),
        "keycloak" => Some(8080),
        "edge" => Some(80),
        _ => None,
    };
    require(ports.len() == usize::from(target.is_some()))?;
    for binding in ports {
        subset(
            binding,
            &["target", "published", "host_ip", "protocol", "mode"],
        )?;
        let published = string(&binding["published"])?;
        let number: u16 = published.parse().map_err(|_| REFUSED)?;
        require(
            binding["target"].as_u64() == target
                && binding["host_ip"] == "127.0.0.1"
                && binding["protocol"] == "tcp"
                && binding["mode"] == "ingress"
                && number >= 1024
                && number.to_string() == published,
        )?;
    }
    Ok(())
}
/// Full authenticated inventory contains 32 application images and the Bao image.
/// Accept original models only. Persist the result and mutation intent; startup
/// must use selected_services, never an unqualified `compose up`.
pub fn prepare(
    model: &Value,
    images: &BTreeMap<String, String>,
    p: &ApplicationModelParameters,
) -> Result<ApplicationModelPlan> {
    safe_path(&p.installation)?;
    safe_path(&p.bundle)?;
    require(
        p.bundle.starts_with(&p.installation)
            && p.bundle != p.installation
            && !p.bundle.starts_with(p.installation.join("state"))
            && !p.bundle.starts_with(p.installation.join("secrets")),
    )?;
    let project = &p.compose_project;
    require(
        regex::Regex::new(r"\Amarty-install-[0-9a-f]{32}\z")
            .unwrap()
            .is_match(project),
    )?;
    require(
        p.openbao_network_name == format!("{project}-bao_default")
            && p.openbao_network_id.len() == 64
            && p.openbao_network_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    let port = p.origin.strip_prefix("https://localhost:").ok_or(REFUSED)?;
    let number: u16 = port.parse().map_err(|_| REFUSED)?;
    require(number >= 1024 && port == number.to_string())?;
    let contract: Value = serde_json::from_str(CONTRACT).map_err(|_| REFUSED)?;
    subset(
        model,
        &[
            "name",
            "services",
            "networks",
            "volumes",
            "secrets",
            "configs",
            "x-database-url-sync-template",
            "x-database-url-template",
            "x-issuance-application-env",
            "x-redis-socket-mount",
            "x-runtime-env",
            "x-selfhost-service-image",
        ],
    )?;
    require(model["name"] == *project && keys(&model["services"])? == keys(&contract)?)?;
    require(
        images.len() == 33
            && images.contains_key("openbao_didcomm_image")
            && images.values().all(|s| digest(s)),
    )?;
    let mut image_names: BTreeSet<&str> = images.keys().map(String::as_str).collect();
    image_names.remove("openbao_didcomm_image");
    require(image_names == keys(&contract)?)?;
    require(model["configs"].is_null() || model["configs"] == json!({}))?;
    require(keys(&model["networks"])? == BTreeSet::from(["default"]))?;
    let network = &model["networks"]["default"];
    subset(network, &["name", "ipam"])?;
    require(
        network["name"] == format!("{project}_default")
            && (network.get("ipam").is_none() || network["ipam"] == json!({}))
            && model["volumes"]
                == json!({"redis-socket":{"name":format!("{project}_redis-socket")}}),
    )?;
    let secret_names: BTreeSet<&str> = object(&contract)?
        .values()
        .flat_map(|c| c["secrets"].as_object().unwrap().keys().map(String::as_str))
        .collect();
    require(keys(&model["secrets"])? == secret_names)?;
    for name in &secret_names {
        require(
            model["secrets"][name]
                == json!({"name":format!("marty-selfhost-prod_{name}"),"file":compose_path(&p.installation.join("secrets").join(name))?}),
        )?;
    }
    let excluded = [
        "cloudflared",
        "cloudflared-beta",
        "tunnel-nginx-proxy",
        "kms-initialize",
    ];
    let services = object(&model["services"])?;
    for (name, service) in services {
        let c = &contract[name];
        subset(
            service,
            &[
                "image",
                "command",
                "entrypoint",
                "environment",
                "healthcheck",
                "restart",
                "user",
                "group_add",
                "volumes",
                "secrets",
                "depends_on",
                "profiles",
                "ports",
                "networks",
                "expose",
                "labels",
                "working_dir",
                "stop_grace_period",
                "pull_policy",
                "mem_limit",
            ],
        )?;
        require(service["image"].as_str() == images.get(name).map(String::as_str))?;
        memory_limit(&service["mem_limit"])?;
        if name == "applicant" {
            require(service.get("user").is_none())?;
            require(
                service["group_add"]
                    == json!([p.applicant_container_group.container_gid().to_string()]),
            )?;
        } else {
            require(service.get("group_add").is_none())?;
        }
        require(service.get("pull_policy").is_none() || service["pull_policy"] == "always")?;
        require(service["networks"] == json!({"default":null}))?;
        require(array(&service["profiles"])? == array(&c["profiles"])?)?;
        let dependencies = service.get("depends_on").cloned().unwrap_or(json!({}));
        require(keys(&dependencies)? == keys(&c["dependencies"])?)?;
        for (peer, d) in object(&dependencies)? {
            require(d == &json!({"condition":c["dependencies"][peer],"required":true}))?;
            require(excluded.contains(&name.as_str()) || !excluded.contains(&peer.as_str()))?;
            if c["dependencies"][peer] == "service_healthy" {
                let health = &services[peer]["healthcheck"];
                let test = array(&health["test"])?;
                require(
                    test.len() >= 2
                        && ["CMD", "CMD-SHELL"].contains(&test[0].as_str().unwrap_or(""))
                        && test
                            .iter()
                            .all(|s| s.as_str().is_some_and(|s| !s.trim().is_empty()))
                        && health["disable"] != true,
                )?;
            } else {
                require(services[peer]["restart"] == "no")?;
            }
        }
        let mut refs = BTreeMap::new();
        for r in array(&service["secrets"])? {
            require(keys(r)? == BTreeSet::from(["source", "target"]))?;
            require(
                refs.insert(string(&r["source"])?, string(&r["target"])?)
                    .is_none(),
            )?;
        }
        require(serde_json::to_value(refs).map_err(|_| REFUSED)? == c["secrets"])?;
        admit_mounts(service, c, p)?;
        admit_ports(name, service)?;
    }
    require(model["services"]["keycloak"]["environment"]["KC_HOSTNAME"] == p.origin)?;
    for name in ["keycloak", "issuance", "flow", "gateway"] {
        require(model["services"][name]["environment"]["BAO_ADDR"] == "https://openbao:8200")?;
    }
    require(
        model["services"]["db-migrate"]["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"] == "false"
            && model["services"]["db-migrate"]["environment"]
                .get("BAO_TOKEN_FILE")
                .is_none()
            && model["services"]["kms-initialize"]["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"]
                == "true"
            && model["services"]["kms-initialize"]["environment"]["BAO_TOKEN_FILE"]
                == "/run/secrets/openbao_bootstrap_token",
    )?;
    let mut output = model.clone();
    // The reviewed packager preserves canonical file-secret display names.
    // They are not external Docker secrets; rebind every exact declaration to
    // this installation before serializing the execution artifact.
    for (name, declaration) in output["secrets"].as_object_mut().ok_or(REFUSED)? {
        declaration["name"] = json!(format!("{project}_{name}"));
    }
    // Compose has already expanded these exact source extension anchors. They
    // are inert metadata, not runtime resources; omit them from the execution
    // artifact to avoid a second interpolation of unused placeholder values.
    output
        .as_object_mut()
        .ok_or(REFUSED)?
        .retain(|key, _| !key.starts_with("x-"));
    for s in output["services"]
        .as_object_mut()
        .ok_or(REFUSED)?
        .values_mut()
    {
        s.as_object_mut().ok_or(REFUSED)?.remove("ports");
    }
    output["networks"] = json!({"default":{"name":p.openbao_network_name,"external":true}});
    let env = output["services"]["keycloak-configurator"]["environment"]
        .as_object_mut()
        .ok_or(REFUSED)?;
    require(
        !env.contains_key("MARTY_ORG_ADMIN_PASSWORD")
            && !env.contains_key("MARTY_ORG_ADMIN_PASSWORD_FILE")
            && env.get("MARTY_ORG_ADMIN_EMAIL") == Some(&json!("operator@localhost")),
    )?;
    for (key, value) in [
        ("KEYCLOAK_SETUP_STRICT", "true"),
        ("CANVAS_DEMO_ADMIN_ENABLED", "false"),
        ("MARTY_ORG_ADMIN_EMAIL", "operator@localhost"),
        (
            "MARTY_ORG_ADMIN_PASSWORD_FILE",
            "/run/secrets/operator_bootstrap_password",
        ),
    ] {
        env.insert(key.into(), json!(value));
    }
    output["secrets"]["operator_bootstrap_password"] = json!({"name":format!("{project}_operator_bootstrap_password"),"file":compose_path(&p.installation.join("secrets/operator_bootstrap_password"))?});
    output["services"]["keycloak-configurator"]["secrets"].as_array_mut().ok_or(REFUSED)?.push(json!({"source":"operator_bootstrap_password","target":"/run/secrets/operator_bootstrap_password"}));
    for v in output["services"]["edge"]["volumes"]
        .as_array_mut()
        .ok_or(REFUSED)?
    {
        if v["target"] == "/etc/nginx/conf.d/default.conf.template" {
            v["source"] = json!(compose_path(
                &p.installation.join("evidence/installer-nginx.conf")
            )?);
            v["bind"] = json!({"create_host_path":false});
        }
    }
    Ok(ApplicationModelPlan {
        model: output,
        selected_services: services
            .keys()
            .filter(|n| !excluded.contains(&n.as_str()))
            .cloned()
            .collect(),
        expected_network_id: p.openbao_network_id.clone(),
        installation_ready: false,
    })
}

// Reviewed installed-runtime DAG/secret contract plus canonical mount table.
const CONTRACT: &str = r#"{
  "applicant": {
    "dependencies": {
      "db-migrate": "service_completed_successfully"
    },
    "mounts": [
      {
        "read_only": false,
        "source": "state/applicant",
        "target": "/app/data",
        "type": "bind"
      }
    ],
    "profiles": [],
    "secrets": {
      "flow_application_event_hmac_key": "/run/secrets/flow_application_event_hmac_key",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "marty_db_password": "/run/secrets/marty_db_password",
      "notification_applicant_event_token": "/run/secrets/notification_applicant_event_token",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "auth": {
    "dependencies": {
      "db-migrate": "service_completed_successfully",
      "flow": "service_healthy",
      "keycloak-configurator": "service_completed_successfully",
      "redis": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "auth_server_tls_kms_token": "/run/secrets/auth_server_tls_kms_token",
      "auth_tls_kms_token": "/run/secrets/auth_tls_kms_token",
      "auth_workload_client_cert": "/run/secrets/auth_workload_client_cert",
      "auth_workload_server_cert": "/run/secrets/auth_workload_server_cert",
      "flow_webhook_secret": "/run/secrets/flow_webhook_secret",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "marty_api_client_secret": "/run/secrets/marty_api_client_secret",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "canvas-sync-worker": {
    "dependencies": {
      "db-migrate": "service_completed_successfully",
      "issuance-migrations": "service_completed_successfully"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "sign_grant_mint_issuance_canvas_token": "/run/secrets/sign_grant_mint_issuance_canvas_token",
      "signing_keys_integration_secret_key": "/run/secrets/signing_keys_integration_secret_key",
      "signing_keys_issuer_sign_key": "/run/secrets/signing_keys_issuer_sign_key",
      "token_hmac_key": "/run/secrets/token_hmac_key",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "cloudflared": {
    "dependencies": {
      "edge": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "bundle/scripts/cloudflared-selfhost.sh",
        "target": "/scripts/cloudflared-selfhost.sh",
        "type": "bind"
      }
    ],
    "profiles": [],
    "secrets": {
      "cloudflare_tunnel_token": "/run/secrets/cloudflare_tunnel_token"
    }
  },
  "cloudflared-beta": {
    "dependencies": {
      "tunnel-nginx-proxy": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "bundle/scripts/cloudflared-selfhost.sh",
        "target": "/scripts/cloudflared-selfhost.sh",
        "type": "bind"
      }
    ],
    "profiles": [
      "beta-tunnel"
    ],
    "secrets": {
      "cloudflare_beta_tunnel_token": "/run/secrets/cloudflare_beta_tunnel_token"
    }
  },
  "compliance-profile": {
    "dependencies": {
      "db-migrate": "service_completed_successfully"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "compliance_profile_tls_kms_token": "/run/secrets/compliance_profile_tls_kms_token",
      "compliance_profile_workload_client_cert": "/run/secrets/compliance_profile_workload_client_cert",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "credential-template": {
    "dependencies": {
      "db-migrate": "service_completed_successfully"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "ct_tls_kms_token": "/run/secrets/ct_tls_kms_token",
      "ct_workload_server_cert": "/run/secrets/ct_workload_server_cert",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "db-migrate": {
    "dependencies": {
      "postgres": "service_healthy",
      "redis": "service_healthy",
      "revocation-profile-migrate": "service_completed_successfully"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "marty_db_password": "/run/secrets/marty_db_password",
      "notification_openbao_token": "/run/secrets/notification_openbao_token",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert"
    }
  },
  "deployment-profile": {
    "dependencies": {
      "db-migrate": "service_completed_successfully"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "deployment_profile_tls_kms_token": "/run/secrets/deployment_profile_tls_kms_token",
      "deployment_profile_workload_client_cert": "/run/secrets/deployment_profile_workload_client_cert",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "device-registration": {
    "dependencies": {
      "db-migrate": "service_completed_successfully",
      "redis": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "device_registration_gateway_key": "/run/secrets/device_registration_gateway_key",
      "device_registration_signing_keys_key": "/run/secrets/device_registration_signing_keys_key",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "marty_db_password": "/run/secrets/marty_db_password",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "edge": {
    "dependencies": {
      "flow": "service_healthy",
      "gateway": "service_healthy",
      "keycloak": "service_healthy",
      "ui": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "bundle/docker/nginx-selfhost.prod.conf.template",
        "target": "/etc/nginx/conf.d/default.conf.template",
        "type": "bind"
      },
      {
        "read_only": true,
        "source": "bundle/scripts/nginx-entrypoint-selfhost.sh",
        "target": "/docker-entrypoint.d/40-render-selfhost.sh",
        "type": "bind"
      }
    ],
    "profiles": [],
    "secrets": {}
  },
  "event-stream": {
    "dependencies": {},
    "mounts": [],
    "profiles": [],
    "secrets": {
      "es_tls_kms_token": "/run/secrets/es_tls_kms_token",
      "es_workload_server_cert": "/run/secrets/es_workload_server_cert",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert"
    }
  },
  "flow": {
    "dependencies": {
      "credential-template": "service_healthy",
      "db-migrate": "service_completed_successfully",
      "issuance": "service_healthy",
      "issuance-native": "service_healthy",
      "organization": "service_healthy",
      "presentation-policy": "service_healthy",
      "redis": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "flow_application_event_hmac_key": "/run/secrets/flow_application_event_hmac_key",
      "flow_client_tls_kms_token": "/run/secrets/flow_client_tls_kms_token",
      "flow_server_tls_kms_token": "/run/secrets/flow_server_tls_kms_token",
      "flow_webhook_secret": "/run/secrets/flow_webhook_secret",
      "flow_workload_client_cert": "/run/secrets/flow_workload_client_cert",
      "flow_workload_server_cert": "/run/secrets/flow_workload_server_cert",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "sign_grant_mint_flow_wallet_token": "/run/secrets/sign_grant_mint_flow_wallet_token",
      "signing_keys_issuer_sign_key": "/run/secrets/signing_keys_issuer_sign_key",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "gateway": {
    "dependencies": {
      "applicant": "service_healthy",
      "auth": "service_healthy",
      "compliance-profile": "service_healthy",
      "credential-template": "service_healthy",
      "deployment-profile": "service_healthy",
      "event-stream": "service_healthy",
      "flow": "service_healthy",
      "issuance": "service_healthy",
      "issuance-native": "service_healthy",
      "notification": "service_healthy",
      "organization": "service_healthy",
      "presentation-policy": "service_healthy",
      "revocation-profile": "service_healthy",
      "trust-profile": "service_healthy",
      "verification": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "device_registration_gateway_key": "/run/secrets/device_registration_gateway_key",
      "gateway_tls_kms_token": "/run/secrets/gateway_tls_kms_token",
      "gateway_workload_client_cert": "/run/secrets/gateway_workload_client_cert",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "sign_grant_mint_gateway_issuer_did_token": "/run/secrets/sign_grant_mint_gateway_issuer_did_token",
      "sign_grant_mint_gateway_service_token": "/run/secrets/sign_grant_mint_gateway_service_token",
      "signing_keys_issuer_sign_key": "/run/secrets/signing_keys_issuer_sign_key",
      "signing_keys_service_sign_gateway_key": "/run/secrets/signing_keys_service_sign_gateway_key",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "issuance": {
    "dependencies": {
      "db-migrate": "service_completed_successfully",
      "issuance-migrations": "service_completed_successfully",
      "issuance-native": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "bundle/scripts/load-openbao-token-and-start.sh",
        "target": "/app/load-openbao-token-and-start.sh",
        "type": "bind"
      }
    ],
    "profiles": [],
    "secrets": {
      "canvas_credentials_shared_secret": "/run/secrets/canvas_credentials_shared_secret",
      "didcomm_issuance_openbao_token": "/run/secrets/didcomm_issuance_openbao_token",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_service_token": "/run/secrets/openbao_service_token",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "sign_grant_mint_issuance_canvas_token": "/run/secrets/sign_grant_mint_issuance_canvas_token",
      "sign_grant_mint_issuance_credential_token": "/run/secrets/sign_grant_mint_issuance_credential_token",
      "sign_grant_mint_issuance_passport_token": "/run/secrets/sign_grant_mint_issuance_passport_token",
      "sign_grant_mint_issuance_readiness_token": "/run/secrets/sign_grant_mint_issuance_readiness_token",
      "signing_keys_integration_secret_key": "/run/secrets/signing_keys_integration_secret_key",
      "signing_keys_issuer_sign_key": "/run/secrets/signing_keys_issuer_sign_key",
      "token_hmac_key": "/run/secrets/token_hmac_key",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "issuance-migrations": {
    "dependencies": {
      "credential-template": "service_healthy",
      "db-migrate": "service_completed_successfully",
      "organization": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "bundle/scripts/load-secrets-env.sh",
        "target": "/app/load-secrets-env.sh",
        "type": "bind"
      }
    ],
    "profiles": [],
    "secrets": {
      "marty_db_password": "/run/secrets/marty_db_password"
    }
  },
  "issuance-native": {
    "dependencies": {
      "db-migrate": "service_completed_successfully",
      "issuance-migrations": "service_completed_successfully",
      "postgres": "service_healthy",
      "revocation-profile": "service_healthy",
      "signing-keys": "service_healthy"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "canvas_credentials_shared_secret": "/run/secrets/canvas_credentials_shared_secret",
      "didcomm_issuance_openbao_token": "/run/secrets/didcomm_issuance_openbao_token",
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "issuance_tls_kms_token": "/run/secrets/issuance_tls_kms_token",
      "issuance_workload_server_cert": "/run/secrets/issuance_workload_server_cert",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "sign_grant_mint_issuance_canvas_token": "/run/secrets/sign_grant_mint_issuance_canvas_token",
      "sign_grant_mint_issuance_credential_token": "/run/secrets/sign_grant_mint_issuance_credential_token",
      "sign_grant_mint_issuance_passport_token": "/run/secrets/sign_grant_mint_issuance_passport_token",
      "sign_grant_mint_issuance_readiness_token": "/run/secrets/sign_grant_mint_issuance_readiness_token",
      "signing_keys_integration_secret_key": "/run/secrets/signing_keys_integration_secret_key",
      "signing_keys_issuer_sign_key": "/run/secrets/signing_keys_issuer_sign_key",
      "token_hmac_key": "/run/secrets/token_hmac_key",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "keycloak": {
    "dependencies": {
      "postgres": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "bundle/config/keycloak",
        "target": "/opt/keycloak/data/import",
        "type": "bind"
      },
      {
        "read_only": true,
        "source": "bundle/config/keycloak/themes",
        "target": "/opt/keycloak/themes",
        "type": "bind"
      },
      {
        "read_only": true,
        "source": "bundle/scripts/load-secrets-env.sh",
        "target": "/scripts/load-secrets-env.sh",
        "type": "bind"
      },
      {
        "read_only": true,
        "source": "bundle/scripts/keycloak-selfhost-start.sh",
        "target": "/scripts/keycloak-selfhost-start.sh",
        "type": "bind"
      }
    ],
    "profiles": [],
    "secrets": {
      "google_client_id": "/run/secrets/google_client_id",
      "google_client_secret": "/run/secrets/google_client_secret",
      "keycloak_11id_ciba_token": "/run/secrets/11id-ciba.token",
      "keycloak_11id_cookie_token": "/run/secrets/11id-cookie.token",
      "keycloak_11id_rs256_cert": "/run/secrets/keycloak-11id-rs256.crt",
      "keycloak_admin_password": "/run/secrets/keycloak_admin_password",
      "keycloak_db_password": "/run/secrets/keycloak_db_password",
      "keycloak_master_ciba_token": "/run/secrets/master-ciba.token",
      "keycloak_master_cookie_token": "/run/secrets/master-cookie.token",
      "keycloak_master_rs256_cert": "/run/secrets/keycloak-master-rs256.crt",
      "keycloak_signing_kms_token": "/run/secrets/keycloak_signing_kms_token",
      "marty_api_client_secret": "/run/secrets/marty_api_client_secret",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert"
    }
  },
  "keycloak-configurator": {
    "dependencies": {
      "keycloak": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "bundle/scripts/setup-keycloak.sh",
        "target": "/scripts/setup-keycloak.sh",
        "type": "bind"
      },
      {
        "read_only": true,
        "source": "bundle/scripts/setup-keycloak-selfhost-production.sh",
        "target": "/scripts/setup-keycloak-selfhost-production.sh",
        "type": "bind"
      },
      {
        "read_only": true,
        "source": "bundle/scripts/load-secrets-env.sh",
        "target": "/scripts/load-secrets-env.sh",
        "type": "bind"
      }
    ],
    "profiles": [],
    "secrets": {
      "google_client_id": "/run/secrets/google_client_id",
      "google_client_secret": "/run/secrets/google_client_secret",
      "keycloak_admin_password": "/run/secrets/keycloak_admin_password",
      "marty_api_client_secret": "/run/secrets/marty_api_client_secret",
      "smtp_password": "/run/secrets/smtp_password"
    }
  },
  "kms-initialize": {
    "dependencies": {
      "db-migrate": "service_completed_successfully"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [
      "kms-init"
    ],
    "secrets": {
      "marty_db_password": "/run/secrets/marty_db_password",
      "notification_openbao_token": "/run/secrets/notification_openbao_token",
      "openbao_bootstrap_token": "/run/secrets/openbao_bootstrap_token",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert"
    }
  },
  "notification": {
    "dependencies": {
      "db-migrate": "service_completed_successfully"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "marty_db_password": "/run/secrets/marty_db_password",
      "notification_applicant_event_token": "/run/secrets/notification_applicant_event_token",
      "notification_openbao_token": "/run/secrets/notification_openbao_token",
      "notification_tls_kms_token": "/run/secrets/notification_tls_kms_token",
      "notification_webhook_secret": "/run/secrets/notification_webhook_secret",
      "notification_workload_server_cert": "/run/secrets/notification_workload_server_cert",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "smtp_password": "/run/secrets/smtp_password"
    }
  },
  "organization": {
    "dependencies": {
      "db-migrate": "service_completed_successfully",
      "redis": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "org_tls_kms_token": "/run/secrets/org_tls_kms_token",
      "org_workload_server_cert": "/run/secrets/org_workload_server_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "postgres": {
    "dependencies": {},
    "mounts": [
      {
        "read_only": false,
        "source": "state/postgres",
        "target": "/var/lib/postgresql/data",
        "type": "bind"
      },
      {
        "read_only": true,
        "source": "bundle/docker/init-databases.sh",
        "target": "/docker-entrypoint-initdb.d/init-databases.sh",
        "type": "bind"
      }
    ],
    "profiles": [],
    "secrets": {
      "keycloak_db_password": "/run/secrets/keycloak_db_password",
      "marty_db_password": "/run/secrets/marty_db_password",
      "postgres_password": "/run/secrets/postgres_password"
    }
  },
  "presentation-policy": {
    "dependencies": {
      "db-migrate": "service_completed_successfully"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "pp_tls_kms_token": "/run/secrets/pp_tls_kms_token",
      "pp_workload_server_cert": "/run/secrets/pp_workload_server_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "redis": {
    "dependencies": {},
    "mounts": [
      {
        "read_only": false,
        "source": "state/redis",
        "target": "/data",
        "type": "bind"
      },
      {
        "read_only": false,
        "source": "redis-socket",
        "target": "/data/run",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {}
  },
  "revocation-profile": {
    "dependencies": {
      "db-migrate": "service_completed_successfully",
      "redis": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "marty_db_password": "/run/secrets/marty_db_password",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "rp_tls_kms_token": "/run/secrets/rp_tls_kms_token",
      "rp_workload_server_cert": "/run/secrets/rp_workload_server_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "revocation-profile-migrate": {
    "dependencies": {
      "postgres": "service_healthy"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "marty_db_password": "/run/secrets/marty_db_password"
    }
  },
  "signing-keys": {
    "dependencies": {
      "db-migrate": "service_completed_successfully",
      "redis": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "device_registration_signing_keys_key": "/run/secrets/device_registration_signing_keys_key",
      "haip_kms_token": "/run/secrets/haip_kms_token",
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "sign_grant_verify_token": "/run/secrets/sign_grant_verify_token",
      "signing_keys_integration_secret_key": "/run/secrets/signing_keys_integration_secret_key",
      "signing_keys_issuer_sign_key": "/run/secrets/signing_keys_issuer_sign_key",
      "signing_keys_openbao_token": "/run/secrets/signing_keys_openbao_token",
      "signing_keys_service_sign_gateway_key": "/run/secrets/signing_keys_service_sign_gateway_key",
      "signing_keys_tls_kms_token": "/run/secrets/signing_keys_tls_kms_token",
      "signing_keys_workload_server_cert": "/run/secrets/signing_keys_workload_server_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "trust-profile": {
    "dependencies": {
      "db-migrate": "service_completed_successfully"
    },
    "mounts": [],
    "profiles": [],
    "secrets": {
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "issuance_api_key": "/run/secrets/issuance_api_key",
      "marty_db_password": "/run/secrets/marty_db_password",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  },
  "tunnel-nginx-proxy": {
    "dependencies": {
      "edge": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "bundle/docker/tunnel-nginx-proxy.edge.conf",
        "target": "/etc/nginx/conf.d/default.conf",
        "type": "bind"
      }
    ],
    "profiles": [
      "beta-tunnel"
    ],
    "secrets": {}
  },
  "ui": {
    "dependencies": {},
    "mounts": [],
    "profiles": [],
    "secrets": {
      "google_analytics_measurement_id": "/run/secrets/google_analytics_measurement_id",
      "google_site_verification": "/run/secrets/google_site_verification"
    }
  },
  "verification": {
    "dependencies": {
      "credential-template": "service_healthy",
      "presentation-policy": "service_healthy",
      "redis": "service_healthy"
    },
    "mounts": [
      {
        "read_only": true,
        "source": "redis-socket",
        "target": "/run/marty-redis",
        "type": "volume"
      }
    ],
    "profiles": [],
    "secrets": {
      "grpc_service_token": "/run/secrets/grpc_service_token",
      "openbao_tls_ca_cert": "/run/secrets/openbao_tls_ca_cert",
      "verification_tls_kms_token": "/run/secrets/verification_tls_kms_token",
      "verification_workload_client_cert": "/run/secrets/verification_workload_client_cert",
      "workload_identity_ca_cert": "/run/secrets/workload_identity_ca_cert"
    }
  }
}"#;
#[cfg(test)]
mod tests {
    use super::*;
    fn rootful_applicant_group() -> crate::installer_state::ApplicantContainerGroup {
        use crate::installer_state::{applicant_container_group, RuntimeBinding, RuntimeProfile};
        applicant_container_group(&RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "fixture-engine".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootful,
        })
        .unwrap()
    }
    fn fixture() -> (Value, BTreeMap<String, String>, ApplicationModelParameters) {
        fixture_at("/private/install")
    }
    fn fixture_at(
        installation: &str,
    ) -> (Value, BTreeMap<String, String>, ApplicationModelParameters) {
        let project = format!("marty-install-{}", "a".repeat(32));
        let p = ApplicationModelParameters {
            installation: installation.into(),
            applicant_container_group: rootful_applicant_group(),
            bundle: Path::new(installation).join("bundle/selfhost-prepared"),
            compose_project: project.clone(),
            openbao_network_name: format!("{project}-bao_default"),
            openbao_network_id: "b".repeat(64),
            origin: "https://localhost:18443".into(),
        };
        let contract: Value = serde_json::from_str(CONTRACT).unwrap();
        let mut model = json!({"name":project,"services":{},"secrets":{},"networks":{"default":{"name":format!("{project}_default")}},"volumes":{"redis-socket":{"name":format!("{project}_redis-socket")}}});
        model["x-runtime-env"] = json!({"PUBLIC_DOMAIN":"localhost:18443"});
        let mut images = BTreeMap::new();
        for (name, c) in object(&contract).unwrap() {
            let image = format!("ghcr.io/elevenid/test/{name}@sha256:{}", "c".repeat(64));
            images.insert(name.clone(), image.clone());
            let mut deps = json!({});
            for (peer, condition) in object(&c["dependencies"]).unwrap() {
                deps[peer] = json!({"condition":condition,"required":true});
            }
            let mut mounts = c["mounts"].clone();
            for m in mounts.as_array_mut().unwrap() {
                m["source"] =
                    json!(
                        compose_path(&expected_mount(m["source"].as_str().unwrap(), &p)).unwrap()
                    );
            }
            let mut secrets = Vec::new();
            for (source, target) in object(&c["secrets"]).unwrap() {
                secrets.push(json!({"source":source,"target":target}));
                model["secrets"][source] = json!({"name":format!("marty-selfhost-prod_{source}"),"file":compose_path(&p.installation.join("secrets").join(source)).unwrap()});
            }
            model["services"][name] = json!({"image":image,"mem_limit":536870912,"networks":{"default":null},"profiles":c["profiles"],"depends_on":deps,"volumes":mounts,"secrets":secrets,"environment":{"BAO_ADDR":"https://openbao:8200"},"healthcheck":{"test":["CMD","true"]},"restart":"no"});
        }
        for (name, target, published) in [
            ("keycloak", 8080, "18180"),
            ("gateway", 8000, "18000"),
            ("edge", 80, "19080"),
        ] {
            model["services"][name]["ports"] = json!([{"host_ip":"127.0.0.1","published":published,"target":target,"protocol":"tcp","mode":"ingress"}]);
        }
        model["services"]["applicant"]["group_add"] =
            json!([p.applicant_container_group.container_gid().to_string()]);
        model["services"]["keycloak"]["environment"]["KC_HOSTNAME"] = json!(p.origin);
        model["services"]["keycloak-configurator"]["environment"]["MARTY_ORG_ADMIN_EMAIL"] =
            json!("operator@localhost");
        model["services"]["db-migrate"]["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"] =
            json!("false");
        model["services"]["kms-initialize"]["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"] =
            json!("true");
        model["services"]["kms-initialize"]["environment"]["BAO_TOKEN_FILE"] =
            json!("/run/secrets/openbao_bootstrap_token");
        images.insert(
            "openbao_didcomm_image".into(),
            format!("ghcr.io/elevenid/bao@sha256:{}", "d".repeat(64)),
        );
        (model, images, p)
    }
    #[test]
    fn exact_resource_overlay_preserves_closed_graph_and_separates_startup() {
        let (model, images, p) = fixture();
        let plan = prepare(&model, &images, &p).unwrap();
        assert!(plan.model.get("x-runtime-env").is_none());
        for (name, declaration) in plan.model["secrets"].as_object().unwrap() {
            assert_eq!(declaration["name"], format!("{}_{name}", p.compose_project));
            assert_eq!(
                declaration["file"],
                json!(p.installation.join("secrets").join(name))
            );
            if name != "operator_bootstrap_password" {
                assert_eq!(declaration["file"], model["secrets"][name]["file"]);
            }
        }
        let mut normalized = model.clone();
        normalized["networks"]["default"]["ipam"] = json!({});
        assert!(prepare(&normalized, &images, &p).is_ok());
        assert_eq!(plan.selected_services.len(), 28);
        assert!(!plan.installation_ready);
        assert_eq!(plan.expected_network_id, p.openbao_network_id);
        assert_eq!(object(&plan.model["services"]).unwrap().len(), 32);
        for (name, s) in object(&plan.model["services"]).unwrap() {
            assert!(s.get("ports").is_none());
            assert_eq!(s["depends_on"], model["services"][name]["depends_on"]);
        }
        for name in [
            "kms-initialize",
            "cloudflared",
            "cloudflared-beta",
            "tunnel-nginx-proxy",
        ] {
            assert!(!plan.selected_services.contains(&name.to_string()));
        }
        assert_eq!(plan.model["networks"]["default"]["external"], true);
        let env = &plan.model["services"]["keycloak-configurator"]["environment"];
        assert_eq!(env["KEYCLOAK_SETUP_STRICT"], "true");
        assert_eq!(env["CANVAS_DEMO_ADMIN_ENABLED"], "false");
        assert_eq!(
            env["MARTY_ORG_ADMIN_PASSWORD_FILE"],
            "/run/secrets/operator_bootstrap_password"
        );
        assert!(env.get("MARTY_ORG_ADMIN_PASSWORD").is_none());
        assert_eq!(
            plan.model["services"]["edge"]["volumes"][0]["source"],
            "/private/install/evidence/installer-nginx.conf"
        );
        // Cannot accidentally apply this plan twice or treat it as fresh input.
        assert!(prepare(&plan.model, &images, &p).is_err());
    }

    #[test]
    fn applicant_requires_image_user_and_exact_runtime_group() {
        let (model, images, p) = fixture();
        assert!(prepare(&model, &images, &p).is_ok());
        let mut root_user = model.clone();
        root_user["services"]["applicant"]["user"] = json!("0:0");
        assert!(prepare(&root_user, &images, &p).is_err());
        let mut root_group = model.clone();
        root_group["services"]["applicant"]["group_add"] = json!(["0"]);
        assert!(prepare(&root_group, &images, &p).is_err());
        let mut missing_group = model.clone();
        missing_group["services"]["applicant"]
            .as_object_mut()
            .unwrap()
            .remove("group_add");
        assert!(prepare(&missing_group, &images, &p).is_err());
        let mut foreign_group = model.clone();
        foreign_group["services"]["postgres"]["group_add"] = json!(["10001"]);
        assert!(prepare(&foreign_group, &images, &p).is_err());
    }
    #[test]
    fn applicant_namespace_group_zero_requires_the_rootless_projection() {
        use crate::installer_state::{applicant_container_group, RuntimeBinding, RuntimeProfile};
        let binding = RuntimeBinding {
            docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
                libc::geteuid()
            }),
            engine_id: "fixture-engine".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootless,
        };
        if unsafe { libc::geteuid() } == 0 {
            assert!(applicant_container_group(&binding).is_err());
            return;
        }
        let (mut model, images, mut p) = fixture();
        let host_gid = p.applicant_container_group.host_gid();
        p.applicant_container_group = applicant_container_group(&binding).unwrap();
        model["services"]["applicant"]["group_add"] = json!(["0"]);
        assert!(prepare(&model, &images, &p).is_ok());
        for group in [
            json!([host_gid.to_string()]),
            json!(["10001"]),
            json!([0]),
            json!(["0", "0"]),
            json!(["0", "1"]),
        ] {
            let mut changed = model.clone();
            changed["services"]["applicant"]["group_add"] = group;
            assert!(prepare(&changed, &images, &p).is_err());
        }
        for user in ["0:0", "10001:0"] {
            let mut changed = model.clone();
            changed["services"]["applicant"]["user"] = json!(user);
            assert!(prepare(&changed, &images, &p).is_err());
        }
        let mut changed = model.clone();
        changed["services"]["postgres"]["group_add"] = json!(["0"]);
        assert!(prepare(&changed, &images, &p).is_err());
        p.applicant_container_group = rootful_applicant_group();
        assert!(prepare(&model, &images, &p).is_err());
    }
    #[test]
    fn memory_caps_are_finite_required_and_compose_version_compatible() {
        let (model, images, p) = fixture();
        for valid in [json!(2147483648u64), json!("2147483648")] {
            let mut changed = model.clone();
            changed["services"]["keycloak"]["mem_limit"] = valid;
            prepare(&changed, &images, &p).unwrap();
        }
        for invalid in [
            Value::Null,
            json!(0),
            json!(-1),
            json!("0"),
            json!("-1"),
            json!(true),
            json!(1.5),
            json!("2g"),
            json!("+2147483648"),
            json!(1),
            json!(64 * 1024 * 1024 * 1024u64 + 1),
            json!("9999999999999999999999999999999999999999"),
        ] {
            let mut changed = model.clone();
            changed["services"]["keycloak"]["mem_limit"] = invalid;
            assert!(prepare(&changed, &images, &p).is_err());
        }
        let mut missing = model;
        missing["services"]["keycloak"]
            .as_object_mut()
            .unwrap()
            .remove("mem_limit");
        assert!(prepare(&missing, &images, &p).is_err());
    }
    #[test]
    fn rejects_resource_and_privilege_drift() {
        let (model, images, p) = fixture();
        for (pointer, value) in [
            ("/services/gateway/build", json!({"context":"/source"})),
            ("/x-unknown", json!({})),
            ("/services/gateway/pull_policy", json!("build")),
            (
                "/services/ui/volumes",
                json!([{"type":"bind","source":"/private/install/bundle/selfhost-prepared/ui","target":"/app","read_only":true}]),
            ),
            ("/services/gateway/privileged", json!(true)),
            ("/services/gateway/network_mode", json!("host")),
            ("/services/keycloak/volumes/0/source", json!("/etc")),
            ("/services/keycloak/volumes/0/read_only", json!(false)),
            (
                "/services/postgres/volumes/0/source",
                json!("/private/install/state/../secrets"),
            ),
            ("/services/redis/volumes/1/source", json!("shared-volume")),
            ("/services/gateway/ports/0/host_ip", json!("0.0.0.0")),
            ("/networks/default/external", json!(true)),
            ("/networks/default/ipam", json!({"driver":"default"})),
            ("/networks/default/driver", json!("host")),
            ("/networks/default/ipam", json!(null)),
            ("/secrets/marty_db_password/file", json!("/etc/shadow")),
            (
                "/secrets/marty_db_password/name",
                json!("anotherproject_marty_db_password"),
            ),
            ("/secrets/marty_db_password/external", json!(true)),
            (
                "/secrets/marty_db_password/environment",
                json!("DATABASE_PASSWORD"),
            ),
            ("/services/gateway/depends_on/auth/required", json!(false)),
            (
                "/services/keycloak-configurator/environment/MARTY_ORG_ADMIN_PASSWORD",
                json!("plaintext"),
            ),
        ] {
            let mut changed = model.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            changed
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), value);
            assert!(
                prepare(&changed, &images, &p).is_err(),
                "accepted {pointer}"
            );
        }
    }
    #[test]
    fn literal_dollar_paths_require_exact_compose_encoding() {
        let (model, images, p) = fixture_at("/private/install $literal #path");
        let plan = prepare(&model, &images, &p).unwrap();
        assert_eq!(
            plan.model["secrets"]["operator_bootstrap_password"]["file"],
            "/private/install $$literal #path/secrets/operator_bootstrap_password"
        );
        for wrong in ["$literal", "$$$$literal"] {
            let mut changed = model.clone();
            let file = changed["secrets"]["marty_db_password"]["file"]
                .as_str()
                .unwrap()
                .replace("$$literal", wrong);
            changed["secrets"]["marty_db_password"]["file"] = json!(file);
            assert!(prepare(&changed, &images, &p).is_err());
        }
    }
    #[test]
    fn rejects_image_and_identity_drift() {
        let (model, mut images, mut p) = fixture();
        images.remove("ui");
        assert!(prepare(&model, &images, &p).is_err());
        let (_, images, _) = fixture();
        p.origin = "https://localhost:18443/".into();
        assert!(prepare(&model, &images, &p).is_err());
        p.origin = "https://localhost:18443".into();
        p.openbao_network_name = "unowned_default".into();
        assert!(prepare(&model, &images, &p).is_err());
    }
}
