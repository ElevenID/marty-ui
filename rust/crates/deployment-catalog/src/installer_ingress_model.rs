//! Add the installer-only HTTPS boundary to an admitted application document.
//! This describes execution; callers still verify files, network identity and
//! provisioning receipts immediately before creating any containers.
#![cfg(target_os = "linux")]
use crate::{installer_application_model::ApplicationModelPlan, installer_ingress_provision};
use serde_json::{json, Value};
use std::path::{Component, Path};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "installer HTTPS boundary differs from owned application contract";
pub const SERVICE: &str = "installer-ingress";
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn mount(installation: &Path, source: &str, target: &str) -> Result<Value> {
    let path = installation.join(source);
    let path = path.to_str().ok_or(REFUSED)?;
    // This is a new string in a normalized Compose document, so encode literal
    // filesystem dollars exactly once. Runtime inspection uses the raw path.
    Ok(
        json!({"type":"bind","source":path.replace('$', "$$"),"target":target,
        "read_only":true,"bind":{"create_host_path":false}}),
    )
}
pub fn add(
    plan: &mut ApplicationModelPlan,
    installation: &Path,
    installation_id: &str,
    origin: &str,
    services_image: &str,
) -> Result<()> {
    let key = installer_ingress_provision::resource_name(installation_id)?;
    let uuid = uuid::Uuid::parse_str(installation_id).map_err(|_| REFUSED)?;
    let project = format!("marty-install-{}", uuid.simple());
    let port_text = origin.strip_prefix("https://localhost:").ok_or(REFUSED)?;
    let port: u16 = port_text.parse().map_err(|_| REFUSED)?;
    require(port >= 1024 && port_text == port.to_string())?;
    require(
        installation.is_absolute()
            && installation
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && installation
                .to_str()
                .is_some_and(|s| !s.chars().any(char::is_control)),
    )?;
    require(
        !plan.installation_ready
            && plan.model["name"] == project
            && plan.model["services"]["gateway"]["image"] == services_image
            && plan.model["services"]["signing-keys"]["image"] == services_image
            && services_image
                .split_once("@sha256:")
                .is_some_and(|(repository, digest)| {
                    !repository.is_empty()
                        && digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            && plan.model["networks"]
                == json!({"default":{"name":format!("{project}-bao_default"),"external":true}})
            && plan.selected_services.iter().any(|s| s == "edge")
            && !plan.selected_services.iter().any(|s| s == SERVICE),
    )?;
    let services = plan.model["services"].as_object().ok_or(REFUSED)?;
    require(
        !services.contains_key(SERVICE)
            && services.values().all(|s| s.get("ports").is_none())
            && plan.model["services"]["edge"]["healthcheck"]["test"].is_array(),
    )?;
    let service = json!({
        "image":services_image,"pull_policy":"always",
        "mem_limit":536870912,
        "entrypoint":["/usr/local/bin/marty-oidf-keyless-edge"],"command":[],
        "user":"10001:10001","read_only":true,"cap_drop":["ALL"],
        "security_opt":["no-new-privileges:true"],"restart":"no",
        "labels":{"com.elevenid.installer.id":installation_id,"com.elevenid.installer.stage":"ingress"},
        "networks":{"default":null},
        "ports":[{"mode":"ingress","host_ip":"127.0.0.1","target":8443,"published":port.to_string(),"protocol":"tcp"}],
        "depends_on":{"edge":{"condition":"service_healthy","required":true}},
        "environment":{
            "OIDF_EDGE_PROFILE":"installer","OIDF_EDGE_PUBLIC_ORIGIN":origin,
            "OIDF_EDGE_BIND":"0.0.0.0:8443",
            "OIDF_EDGE_TLS_CERT_FILE":"/run/installer/tls.crt",
            "OIDF_EDGE_TLS_KMS_CA_CERT_FILE":"/run/installer/openbao-ca.crt",
            "OIDF_EDGE_TLS_KMS_TOKEN_FILE":"/run/installer/signer.token",
            "OIDF_EDGE_TLS_KMS_ADDR":"https://openbao:8200",
            "OIDF_EDGE_TLS_KMS_KEY_NAME":key,"OIDF_EDGE_TLS_KMS_KEY_VERSION":"1"
        },
        "volumes":[
            mount(installation,"secrets/installer_ingress_tls_cert","/run/installer/tls.crt")?,
            mount(installation,"secrets/installer_ingress_ca_cert","/run/installer/ca.crt")?,
            mount(installation,"secrets/installer_ingress_tls_kms_token","/run/installer/signer.token")?,
            mount(installation,"secrets/openbao_tls_ca_cert","/run/installer/openbao-ca.crt")?
        ],
        "healthcheck":{"test":["CMD","curl","--fail","--silent","--show-error",
            "--max-time","10","--noproxy","*","--cacert","/run/installer/ca.crt",
            "--connect-to",format!("localhost:{port}:127.0.0.1:8443"),format!("{origin}/")],
            "interval":"10s","timeout":"12s","start_period":"30s","retries":12}
    });
    plan.model["services"][SERVICE] = service;
    plan.selected_services.push(SERVICE.into());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "12345678-1234-4234-8234-123456789abc";
    fn fixture() -> (ApplicationModelPlan, String) {
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
            "a".repeat(64)
        );
        let plan = ApplicationModelPlan {
            model: json!({"name":"marty-install-12345678123442348234123456789abc",
                "networks":{"default":{"name":"marty-install-12345678123442348234123456789abc-bao_default","external":true}},
                "services":{"gateway":{"image":image},"signing-keys":{"image":image},"edge":{"healthcheck":{"test":["CMD","true"]}}}}),
            selected_services: vec!["edge".into()],
            expected_network_id: "d".repeat(64),
            installation_ready: false,
        };
        (plan, image)
    }
    #[test]
    fn refuses_authority_project_image_and_publication_drift() {
        for origin in [
            "http://localhost:18443",
            "https://elsewhere:18443",
            "https://localhost:443",
            "https://localhost:018443",
            "https://localhost:18443/",
        ] {
            let (mut plan, image) = fixture();
            assert!(add(&mut plan, Path::new("/owned"), ID, origin, &image).is_err());
        }
        for mutation in 0..4 {
            let (mut plan, image) = fixture();
            match mutation {
                0 => plan.model["name"] = json!("unrelated"),
                1 => plan.model["services"]["gateway"]["image"] = json!("unrelated"),
                2 => plan.model["services"]["edge"]["ports"] = json!(["80:80"]),
                _ => plan.model["networks"]["default"]["name"] = json!("unrelated"),
            }
            assert!(add(
                &mut plan,
                Path::new("/owned"),
                ID,
                "https://localhost:18443",
                &image
            )
            .is_err());
        }
    }
    #[test]
    fn only_scoped_inputs_and_verified_https_are_exposed() {
        let (mut plan, image) = fixture();
        add(
            &mut plan,
            Path::new("/owned $path"),
            ID,
            "https://localhost:18443",
            &image,
        )
        .unwrap();
        let service = &plan.model["services"][SERVICE];
        assert_eq!(service["ports"][0]["host_ip"], "127.0.0.1");
        assert_eq!(service["environment"]["OIDF_EDGE_TLS_KMS_KEY_VERSION"], "1");
        for volume in service["volumes"].as_array().unwrap() {
            assert_eq!(volume["read_only"], true);
            assert_eq!(volume["bind"]["create_host_path"], false);
            assert!(volume["source"]
                .as_str()
                .unwrap()
                .starts_with("/owned $$path/"));
            assert!(!volume["source"].as_str().unwrap().contains("root.token"));
        }
        let health = service["healthcheck"]["test"].as_array().unwrap();
        assert!(health.contains(&json!("--cacert")));
        assert!(!health.contains(&json!("--insecure")));
        assert!(add(
            &mut plan,
            Path::new("/owned $path"),
            ID,
            "https://localhost:18443",
            &image
        )
        .is_err());
    }
}
