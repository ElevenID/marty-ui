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
];

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

async fn provision(bao: &Bao, output: &Path, project: &str) -> Result<(), Box<dyn Error>> {
    bao.checked(
        Method::POST,
        "sys/mounts/transit",
        Some(json!({"type":"transit"})),
        None,
    )
    .await?;
    bao.checked(
        Method::POST,
        "sys/mounts/pki",
        Some(json!({"type":"pki"})),
        None,
    )
    .await?;
    let ca = bao
        .checked(
            Method::POST,
            "pki/root/generate/internal",
            Some(json!({
                "common_name": "Marty disposable passport workload CA", "ttl": "48h",
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
    for role in ROLES {
        let key = format!("{project}-{}", role.name);
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
            &format!("pki/roles/{}", role.name),
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
        let mut request = json!({"csr":value(&csr, "csr")?,
                                 "common_name":role.common_name,"ttl":"1h"});
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
                &format!("pki/sign/{}", role.name),
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
        write_new(&output.join(format!("{}_cert", role.file_prefix)), cert)?;
        let policy = format!(
            "path \"transit/keys/{key}\" {{ capabilities = [\"read\"] }}\n\
             path \"transit/sign/{key}\" {{ capabilities = [\"update\"] }}"
        );
        bao.checked(
            Method::PUT,
            &format!("sys/policies/acl/{key}"),
            Some(json!({"policy":policy})),
            None,
        )
        .await?;
        let issued = bao
            .checked(
                Method::POST,
                "auth/token/create",
                Some(json!({
                    "policies":[key], "no_default_policy":true, "ttl":"1h",
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
        write_new(
            &output.join(format!("{}_kms_token", role.file_prefix)),
            token,
        )?;
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
    let endpoint = required("BAO_ADDR")?;
    let project = required("PASSPORT_ACCEPTANCE_PROJECT")?;
    if !project.starts_with("marty-passport-acceptance-")
        || project.len() > 80
        || !project
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("disposable passport project is invalid".into());
    }
    let output = PathBuf::from(required("PASSPORT_TLS_OUTPUT_DIR")?);
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
    if root_token.len() != 64 || !root_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
    provision(&bao, &output, &project).await?;
    Ok(())
}
