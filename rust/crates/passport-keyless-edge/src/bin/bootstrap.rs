//! One-shot disposable passport TLS provisioning. Leaf private keys remain
//! non-exportable OpenBao Transit keys; only public certs and scoped tokens
//! are written to the project output directory.

use std::{
    env,
    error::Error,
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

const MAX_RESPONSE: usize = 1024 * 1024;

struct Role {
    name: &'static str,
    file_prefix: &'static str,
    common_name: &'static str,
    alt_names: &'static str,
    uri_sans: &'static str,
    ip_sans: &'static str,
    server: bool,
    client: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Passport,
    Selfhost,
}

struct SelfhostRole {
    name: &'static str,
    key_name: &'static str,
    cert_file: &'static str,
    token_file: &'static str,
}

// Names here are the disposable self-host contract in the production Compose
// catalog. The keys live only in this install's private OpenBao instance.
const SELFHOST_ROLES: &[SelfhostRole] = &[
    SelfhostRole {
        name: "signing-keys-server",
        key_name: "workload-tls-signing-keys-server",
        cert_file: "signing_keys_workload_server_cert",
        token_file: "signing_keys_tls_kms_token",
    },
    SelfhostRole {
        name: "gateway-client",
        key_name: "workload-tls-gateway-auth-client",
        cert_file: "gateway_workload_client_cert",
        token_file: "gateway_tls_kms_token",
    },
    SelfhostRole {
        name: "auth-client",
        key_name: "workload-tls-auth-client",
        cert_file: "auth_workload_client_cert",
        token_file: "auth_tls_kms_token",
    },
    SelfhostRole {
        name: "auth-server",
        key_name: "workload-tls-auth-server",
        cert_file: "auth_workload_server_cert",
        token_file: "auth_server_tls_kms_token",
    },
    SelfhostRole {
        name: "compliance-profile-client",
        key_name: "workload-tls-compliance-profile-client",
        cert_file: "compliance_profile_workload_client_cert",
        token_file: "compliance_profile_tls_kms_token",
    },
    SelfhostRole {
        name: "deployment-profile-client",
        key_name: "workload-tls-deployment-profile-client",
        cert_file: "deployment_profile_workload_client_cert",
        token_file: "deployment_profile_tls_kms_token",
    },
    SelfhostRole {
        name: "organization-server",
        key_name: "workload-tls-organization-server",
        cert_file: "org_workload_server_cert",
        token_file: "org_tls_kms_token",
    },
    SelfhostRole {
        name: "event-stream-server",
        key_name: "workload-tls-event-stream-server",
        cert_file: "es_workload_server_cert",
        token_file: "es_tls_kms_token",
    },
    SelfhostRole {
        name: "notification-server",
        key_name: "workload-tls-notification-server",
        cert_file: "notification_workload_server_cert",
        token_file: "notification_tls_kms_token",
    },
    SelfhostRole {
        name: "revocation-profile-server",
        key_name: "workload-tls-revocation-profile-server",
        cert_file: "rp_workload_server_cert",
        token_file: "rp_tls_kms_token",
    },
    SelfhostRole {
        name: "credential-template-server",
        key_name: "workload-tls-credential-template-server",
        cert_file: "ct_workload_server_cert",
        token_file: "ct_tls_kms_token",
    },
    SelfhostRole {
        name: "issuance-server",
        key_name: "workload-tls-issuance-server",
        cert_file: "issuance_workload_server_cert",
        token_file: "issuance_tls_kms_token",
    },
    SelfhostRole {
        name: "flow-client",
        key_name: "workload-tls-flow-client",
        cert_file: "flow_workload_client_cert",
        token_file: "flow_client_tls_kms_token",
    },
    SelfhostRole {
        name: "flow-server",
        key_name: "workload-tls-flow-server",
        cert_file: "flow_workload_server_cert",
        token_file: "flow_server_tls_kms_token",
    },
    SelfhostRole {
        name: "pp-server",
        key_name: "workload-tls-presentation-policy-server",
        cert_file: "pp_workload_server_cert",
        token_file: "pp_tls_kms_token",
    },
    SelfhostRole {
        name: "verification-client",
        key_name: "workload-tls-verification-client",
        cert_file: "verification_workload_client_cert",
        token_file: "verification_tls_kms_token",
    },
];

const ROLES: &[Role] = &[
    Role {
        name: "passport-edge",
        file_prefix: "passport_edge_tls",
        common_name: "localhost",
        alt_names: "edge,passport-https-edge",
        uri_sans: "",
        ip_sans: "127.0.0.1",
        server: true,
        client: false,
    },
    Role {
        name: "signing-keys-server",
        file_prefix: "signing_keys_workload_server",
        common_name: "signing-keys",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "gateway-client",
        file_prefix: "gateway_workload_client",
        common_name: "gateway",
        alt_names: "",
        uri_sans: "spiffe://marty.internal/service/gateway",
        ip_sans: "",
        server: false,
        client: true,
    },
    Role {
        name: "auth-client",
        file_prefix: "auth_workload_client",
        common_name: "auth",
        alt_names: "",
        uri_sans: "spiffe://marty.internal/service/auth",
        ip_sans: "",
        server: false,
        client: true,
    },
    Role {
        name: "auth-server",
        file_prefix: "auth_workload_server",
        common_name: "auth",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "compliance-profile-client",
        file_prefix: "compliance_profile_workload_client",
        common_name: "compliance-profile",
        alt_names: "",
        uri_sans: "spiffe://marty.internal/service/compliance-profile",
        ip_sans: "",
        server: false,
        client: true,
    },
    Role {
        name: "deployment-profile-client",
        file_prefix: "deployment_profile_workload_client",
        common_name: "deployment-profile",
        alt_names: "",
        uri_sans: "spiffe://marty.internal/service/deployment-profile",
        ip_sans: "",
        server: false,
        client: true,
    },
    Role {
        name: "organization-server",
        file_prefix: "org_workload_server",
        common_name: "organization",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "event-stream-server",
        file_prefix: "es_workload_server",
        common_name: "event-stream",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "notification-server",
        file_prefix: "notification_workload_server",
        common_name: "notification",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "revocation-profile-server",
        file_prefix: "rp_workload_server",
        common_name: "revocation-profile",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "credential-template-server",
        file_prefix: "ct_workload_server",
        common_name: "credential-template",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "issuance-server",
        file_prefix: "issuance_workload_server",
        common_name: "issuance-native",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "flow-client",
        file_prefix: "flow_workload_client",
        common_name: "flow",
        alt_names: "",
        uri_sans: "spiffe://marty.internal/service/flow",
        ip_sans: "",
        server: false,
        client: true,
    },
    Role {
        name: "flow-server",
        file_prefix: "flow_workload_server",
        common_name: "flow",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "pp-server",
        file_prefix: "pp_workload_server",
        common_name: "presentation-policy",
        alt_names: "",
        uri_sans: "",
        ip_sans: "",
        server: true,
        client: false,
    },
    Role {
        name: "verification-client",
        file_prefix: "verification_workload_client",
        common_name: "verification",
        alt_names: "",
        uri_sans: "spiffe://marty.internal/service/verification",
        ip_sans: "",
        server: false,
        client: true,
    },
];

fn selfhost_role(name: &str) -> Option<&'static SelfhostRole> {
    SELFHOST_ROLES.iter().find(|role| role.name == name)
}

fn selected_roles(profile: Profile) -> impl Iterator<Item = &'static Role> {
    ROLES.iter().filter(move |role| match profile {
        Profile::Passport => !matches!(role.name, "verification-client" | "notification-server"),
        Profile::Selfhost => selfhost_role(role.name).is_some(),
    })
}

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.trim().is_empty() || value.contains(['\r', '\n']) {
        return Err(format!("{name} is invalid").into());
    }
    Ok(value)
}

fn data<'a>(response: &'a Value, key: &str) -> Result<&'a Value, Box<dyn Error>> {
    response
        .get("data")
        .and_then(|data| data.get(key))
        .ok_or_else(|| format!("OpenBao {key} response is incomplete").into())
}

fn value<'a>(response: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    data(response, key)?
        .as_str()
        .ok_or_else(|| format!("OpenBao {key} response is invalid").into())
}

fn write_new(path: &Path, contents: &str) -> Result<(), Box<dyn Error>> {
    if contents.contains("PRIVATE KEY") || contents.contains('\0') {
        return Err("OpenBao returned private or invalid material".into());
    }
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(contents.as_bytes())?;
    output.sync_all()?;
    Ok(())
}

struct Bao {
    transport: OpenBaoHttp,
    root_token: String,
}

impl Bao {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> Result<(StatusCode, Value), Box<dyn Error>> {
        let mut request = self
            .transport
            .client()
            .request(method, format!("{}/v1/{path}", self.transport.origin()))
            .header("X-Vault-Token", token.unwrap_or(&self.root_token));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        let mut chunks = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(next) = chunks.next().await {
            let chunk = next?;
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE {
                return Err("OpenBao response exceeded size limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let parsed = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&bytes).map_err(|_| "OpenBao response is invalid JSON")?
        };
        Ok((status, parsed))
    }

    async fn checked(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> Result<Value, Box<dyn Error>> {
        let (status, response) = self.request(method, path, body, token).await?;
        if !status.is_success() {
            return Err(format!("OpenBao {path} request failed with {status}").into());
        }
        Ok(response)
    }
}

async fn provision(
    bao: &Bao,
    output: &Path,
    project: &str,
    profile: Profile,
) -> Result<(), Box<dyn Error>> {
    let pki_mount = match profile {
        Profile::Passport => {
            bao.checked(
                Method::POST,
                "sys/mounts/transit",
                Some(json!({"type":"transit"})),
                None,
            )
            .await?;
            "pki"
        }
        Profile::Selfhost => {
            // The existing self-host OpenBao bootstrap owns Transit. A distinct
            // PKI mount keeps workload TLS separate from its credential PKI.
            bao.checked(Method::GET, "sys/mounts/transit", None, None)
                .await?;
            "workload-pki"
        }
    };
    bao.checked(
        Method::POST,
        &format!("sys/mounts/{pki_mount}"),
        Some(json!({"type":"pki"})),
        None,
    )
    .await?;
    let ca_name = match profile {
        Profile::Passport => "Marty disposable passport workload CA",
        Profile::Selfhost => "Marty disposable self-host workload CA",
    };
    let ca = bao
        .checked(
            Method::POST,
            &format!("{pki_mount}/root/generate/internal"),
            Some(json!({
                "common_name": ca_name, "ttl": "48h",
                "key_type": "ec", "key_bits": 256,
            })),
            None,
        )
        .await?;
    if data(&ca, "private_key").is_ok() {
        return Err("OpenBao exported the CA key".into());
    }
    let ca_pem = value(&ca, "certificate")?;
    if !ca_pem.contains("BEGIN CERTIFICATE") {
        return Err("OpenBao CA certificate is invalid".into());
    }
    write_new(&output.join("workload_identity_ca_cert"), ca_pem)?;

    let mut first_token = None;
    let mut last_key = None;
    for role in selected_roles(profile) {
        let selfhost = selfhost_role(role.name);
        let key = match profile {
            Profile::Passport => format!("{project}-{}", role.name),
            Profile::Selfhost => selfhost
                .ok_or("self-host TLS role is unmapped")?
                .key_name
                .to_owned(),
        };
        bao.checked(
            Method::POST,
            &format!("transit/keys/{key}"),
            Some(json!({
                "type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false,
            })),
            None,
        )
        .await?;
        let metadata = bao
            .checked(Method::GET, &format!("transit/keys/{key}"), None, None)
            .await?;
        if value(&metadata, "type")? != "ecdsa-p256"
            || data(&metadata, "exportable")? != false
            || data(&metadata, "allow_plaintext_backup")? != false
        {
            return Err("disposable Transit key is exportable or wrong type".into());
        }
        bao.checked(
            Method::POST,
            &format!("{pki_mount}/roles/{}", role.name),
            // Transit emits a CSR with its own SAN. Use the explicit, role-scoped
            // names below so the issued certificate covers the Docker peer name.
            Some(json!({
                "allow_any_name": true, "allow_localhost": true, "allow_ip_sans": true,
                "allowed_uri_sans": role.uri_sans,
                "server_flag": role.server, "client_flag": role.client,
                "key_type": "ec", "key_bits": 256, "max_ttl": "24h",
                "use_csr_common_name": false, "use_csr_sans": false,
            })),
            None,
        )
        .await?;
        let csr = bao
            .checked(
                Method::POST,
                &format!("transit/keys/{key}/csr"),
                Some(json!({"version":1})),
                None,
            )
            .await?;
        let ttl = match profile {
            Profile::Passport => "1h",
            Profile::Selfhost => "8h",
        };
        let mut request = json!({"csr":value(&csr, "csr")?,
                                 "common_name":role.common_name,"ttl":ttl});
        if !role.alt_names.is_empty() {
            request["alt_names"] = json!(role.alt_names);
        }
        if !role.uri_sans.is_empty() {
            request["uri_sans"] = json!(role.uri_sans);
        }
        if !role.ip_sans.is_empty() {
            request["ip_sans"] = json!(role.ip_sans);
        }
        let signed = bao
            .checked(
                Method::POST,
                &format!("{pki_mount}/sign/{}", role.name),
                Some(request),
                None,
            )
            .await?;
        if data(&signed, "private_key").is_ok() {
            return Err("OpenBao exported a leaf key".into());
        }
        let cert = value(&signed, "certificate")?;
        if !cert.contains("BEGIN CERTIFICATE") {
            return Err("OpenBao leaf certificate is invalid".into());
        }
        let cert_file = match profile {
            Profile::Passport => format!("{}_cert", role.file_prefix),
            Profile::Selfhost => selfhost
                .ok_or("self-host TLS role is unmapped")?
                .cert_file
                .to_owned(),
        };
        write_new(&output.join(cert_file), cert)?;
        let policy_name = match profile {
            Profile::Passport => key.clone(),
            Profile::Selfhost => format!("{project}-{key}"),
        };
        let policy = format!(
            "path \"transit/keys/{key}\" {{ capabilities = [\"read\"] }}\n\
             path \"transit/sign/{key}\" {{ capabilities = [\"update\"] }}"
        );
        bao.checked(
            Method::PUT,
            &format!("sys/policies/acl/{policy_name}"),
            Some(json!({"policy":policy})),
            None,
        )
        .await?;
        let issued = bao
            .checked(
                Method::POST,
                "auth/token/create",
                Some(json!({
                    "policies":[policy_name], "no_default_policy":true, "ttl":ttl,
                })),
                None,
            )
            .await?;
        let token = issued
            .get("auth")
            .and_then(|auth| auth.get("client_token"))
            .and_then(Value::as_str)
            .ok_or("OpenBao scoped token is missing")?;
        if token == bao.root_token || token.len() < 20 {
            return Err("OpenBao scoped token is invalid".into());
        }
        let token_file = match profile {
            Profile::Passport => format!("{}_kms_token", role.file_prefix),
            Profile::Selfhost => selfhost
                .ok_or("self-host TLS role is unmapped")?
                .token_file
                .to_owned(),
        };
        write_new(&output.join(token_file), token)?;
        if first_token.is_none() {
            first_token = Some(token.to_owned());
        }
        last_key = Some(key);
    }
    let foreign_key = last_key.ok_or("disposable TLS roles are missing")?;
    let (status, _) = bao
        .request(
            Method::POST,
            &format!("transit/sign/{foreign_key}"),
            Some(json!({"input":STANDARD.encode(b"cross-scope-denial")})),
            first_token.as_deref(),
        )
        .await?;
    if status != StatusCode::FORBIDDEN {
        return Err("disposable TLS signer token crossed key scope".into());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let profile = match env::var("MARTY_TLS_BOOTSTRAP_PROFILE").as_deref() {
        Ok("selfhost-disposable") => Profile::Selfhost,
        Ok("passport") | Err(_) => Profile::Passport,
        Ok(_) => return Err("unknown disposable TLS bootstrap profile".into()),
    };
    if profile == Profile::Selfhost
        && env::var("MARTY_SELFHOST_DISPOSABLE_OPENBAO").as_deref() != Ok("1")
    {
        return Err("self-host TLS bootstrap requires disposable OpenBao ownership".into());
    }
    let endpoint = required("BAO_ADDR")?;
    let (project_name, output_name, project_prefix) = match profile {
        Profile::Passport => (
            "PASSPORT_ACCEPTANCE_PROJECT",
            "PASSPORT_TLS_OUTPUT_DIR",
            "marty-passport-acceptance-",
        ),
        Profile::Selfhost => (
            "MARTY_SELFHOST_PROJECT",
            "SELFHOST_TLS_OUTPUT_DIR",
            "marty-selfhost-disposable-",
        ),
    };
    let project = required(project_name)?;
    if !project.starts_with(project_prefix)
        || project.len() > 80
        || !project
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("disposable TLS project is invalid".into());
    }
    let output = PathBuf::from(required(output_name)?);
    let metadata = fs::symlink_metadata(&output)?;
    if !output.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || fs::read_dir(&output)?.next().is_some()
    {
        return Err("disposable TLS output directory must be empty and private".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err("disposable TLS output directory must be private".into());
        }
    }
    let ca_file = required("BAO_CACERT")?;
    let root_token = fs::read_to_string(required("BAO_ROOT_TOKEN_FILE")?)?;
    let root_token = root_token.trim().to_owned();
    let valid_token = match profile {
        Profile::Passport => {
            root_token.len() == 64 && root_token.bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        Profile::Selfhost => {
            root_token.len() >= 20
                && root_token.len() <= 256
                && root_token.bytes().all(|byte| byte.is_ascii_graphic())
        }
    };
    if !valid_token {
        return Err("OpenBao bootstrap token is invalid".into());
    }
    let bao = Bao {
        transport: OpenBaoHttp::connect(
            &endpoint,
            Some(Path::new(&ca_file)),
            std::time::Duration::from_secs(10),
        )?,
        root_token,
    };
    provision(&bao, &output, &project, profile).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn selfhost_tls_outputs_and_keys_match_deployment_inputs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let catalog: Value = serde_json::from_str(
            &fs::read_to_string(root.join("deploy-config/catalog/secrets.json")).unwrap(),
        )
        .unwrap();
        let secrets = catalog["secrets"].as_object().unwrap();
        let expected_files: BTreeSet<_> = secrets
            .keys()
            .filter(|name| {
                name.contains("_workload_") && name.ends_with("_cert")
                    || name.ends_with("_tls_kms_token")
            })
            .map(String::as_str)
            .collect();
        let actual_files: BTreeSet<_> = SELFHOST_ROLES
            .iter()
            .flat_map(|role| [role.cert_file, role.token_file])
            .collect();
        assert_eq!(actual_files.len(), SELFHOST_ROLES.len() * 2);
        assert_eq!(actual_files, expected_files);

        let environment =
            fs::read_to_string(root.join(".env.selfhost.production.example")).unwrap();
        let expected_keys: BTreeSet<_> = environment
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter(|(name, _)| name.ends_with("_TLS_KMS_KEY_NAME"))
            .map(|(_, value)| value)
            .collect();
        let actual_keys: BTreeSet<_> = SELFHOST_ROLES.iter().map(|role| role.key_name).collect();
        assert_eq!(actual_keys.len(), SELFHOST_ROLES.len());
        assert_eq!(actual_keys, expected_keys);

        let selected: BTreeSet<_> = selected_roles(Profile::Selfhost)
            .map(|role| role.name)
            .collect();
        let mapped: BTreeSet<_> = SELFHOST_ROLES.iter().map(|role| role.name).collect();
        assert_eq!(selected, mapped);
        assert_eq!(selected_roles(Profile::Passport).count(), 15);
    }
}
