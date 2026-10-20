//! One-shot keyless TLS provisioning and isolated renewal staging. Leaf
//! private keys remain non-exportable OpenBao Transit keys; only public
//! certificates and scoped tokens are written to an empty output directory.
//! Renewal output is not activated by this binary.

use std::{
    env,
    error::Error,
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use marty_openbao_http::OpenBaoHttp;
use mmf_platform::OpenBaoTlsIdentityFiles;
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
    SelfhostRenew,
}

impl Profile {
    fn is_selfhost(self) -> bool {
        matches!(self, Self::Selfhost | Self::SelfhostRenew)
    }
}

fn selected_workload_pki_mount(
    profile: Profile,
    requested: Option<&str>,
) -> Result<&str, Box<dyn Error>> {
    match (profile, requested) {
        (Profile::SelfhostRenew, None | Some("workload-pki")) => Ok("workload-pki"),
        (Profile::SelfhostRenew, Some(mount)) => {
            let version = mount
                .strip_prefix("workload-pki-v")
                .ok_or("replacement workload PKI mount is invalid")?;
            let parsed = version
                .parse::<u16>()
                .map_err(|_| "replacement workload PKI version is invalid")?;
            if !(2..=9999).contains(&parsed) || parsed.to_string() != version {
                return Err("replacement workload PKI version is invalid".into());
            }
            Ok(mount)
        }
        (_, None) => Ok("workload-pki"),
        (_, Some(_)) => Err("workload PKI mount selection is renewal-only".into()),
    }
}

fn renewal_authority(mount: &str) -> (&'static str, &'static str, &'static str) {
    if mount == "workload-pki" {
        (
            "selfhost-kms-renewal",
            "auth/selfhost-renew/login",
            "BAO_RENEWAL_TOKEN_FILE",
        )
    } else {
        (
            "selfhost-kms-ca-rotation",
            "auth/selfhost-ca-rotation/login",
            "BAO_CA_ROTATION_TOKEN_FILE",
        )
    }
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

const SELFHOST_KEY_METADATA_FILE: &str = "selfhost-tls-kms-roles.json";

fn checked_transit_key_metadata(metadata: &Value, profile: Profile) -> Result<(), Box<dyn Error>> {
    if value(metadata, "type")? != "ecdsa-p256"
        || data(metadata, "exportable")? != false
        || data(metadata, "allow_plaintext_backup")? != false
    {
        return Err("disposable Transit key is exportable or wrong type".into());
    }
    if profile.is_selfhost() && data(metadata, "latest_version")?.as_u64() != Some(1) {
        return Err("disposable Transit key is not version 1".into());
    }
    Ok(())
}

fn selfhost_key_metadata() -> Value {
    json!({
        "schema": "marty.selfhost-disposable-tls-keys/v1",
        "roles": SELFHOST_ROLES.iter().map(|role| json!({
            "role": role.name,
            "key_name": role.key_name,
            "version": 1,
        })).collect::<Vec<_>>(),
    })
}

fn checked_existing_role(metadata: &Value, role: &Role) -> Result<(), Box<dyn Error>> {
    let fields = metadata
        .get("data")
        .ok_or("existing workload PKI role has no metadata")?;
    let expected_uri_sans: Vec<_> = role
        .uri_sans
        .split(',')
        .filter(|value| !value.is_empty())
        .collect();
    let actual_uri_sans: Vec<_> = fields["allowed_uri_sans"]
        .as_array()
        .ok_or("existing workload PKI role has no URI SAN constraint")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid workload PKI URI SAN"))
        .collect::<Result<_, _>>()?;
    if fields["allow_any_name"] != true
        || fields["allow_localhost"] != true
        || fields["allow_ip_sans"] != true
        || fields["server_flag"] != role.server
        || fields["client_flag"] != role.client
        || fields["key_type"] != "ec"
        || fields["key_bits"] != 256
        || fields["max_ttl"] != 86400
        || fields["use_csr_common_name"] != false
        || fields["use_csr_sans"] != false
        || actual_uri_sans != expected_uri_sans
    {
        return Err("existing workload PKI role differs from the reviewed contract".into());
    }
    Ok(())
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
        Profile::Selfhost | Profile::SelfhostRenew => selfhost_role(role.name).is_some(),
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
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(path)?;
    output.write_all(contents.as_bytes())?;
    output.sync_all()?;
    Ok(())
}

struct Bao {
    transport: OpenBaoHttp,
    authority_token: String,
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
            .header("X-Vault-Token", token.unwrap_or(&self.authority_token));
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
    endpoint: &str,
    ca_file: &Path,
    renewal_pki_mount: &str,
) -> Result<(), Box<dyn Error>> {
    if profile == Profile::SelfhostRenew {
        let (expected_policy, expected_path, _) = renewal_authority(renewal_pki_mount);
        let lookup = bao
            .checked(
                Method::POST,
                "auth/token/lookup",
                Some(json!({"token": bao.authority_token})),
                None,
            )
            .await?;
        let policies = data(&lookup, "policies")?
            .as_array()
            .ok_or("renewal authority policies are invalid")?;
        let remaining = data(&lookup, "ttl")?
            .as_u64()
            .ok_or("renewal authority TTL is invalid")?;
        if policies.len() != 1
            || policies[0] != expected_policy
            || value(&lookup, "path")? != expected_path
            || !(3600..=28800).contains(&remaining)
        {
            return Err("renewal authority is not the scoped AppRole token".into());
        }
    }
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
        Profile::SelfhostRenew => {
            bao.checked(Method::GET, "sys/mounts/transit", None, None)
                .await?;
            let mount = bao
                .checked(
                    Method::GET,
                    &format!("sys/mounts/{renewal_pki_mount}"),
                    None,
                    None,
                )
                .await?;
            if value(&mount, "type")? != "pki" {
                return Err("renewal issuer mount is not PKI".into());
            }
            renewal_pki_mount
        }
    };
    if profile != Profile::SelfhostRenew {
        bao.checked(
            Method::POST,
            &format!("sys/mounts/{pki_mount}"),
            Some(json!({"type":"pki"})),
            None,
        )
        .await?;
    }
    let ca_name = match profile {
        Profile::Passport => "Marty disposable passport workload CA",
        Profile::Selfhost => "Marty disposable self-host workload CA",
        Profile::SelfhostRenew => "",
    };
    let ca = if profile == Profile::SelfhostRenew {
        // Read the exact issuer selected by the validated renewal ceremony.
        // This producer neither creates a CA nor activates a new trust anchor.
        bao.checked(Method::GET, &format!("{pki_mount}/cert/ca"), None, None)
            .await?
    } else {
        bao.checked(
            Method::POST,
            &format!("{pki_mount}/root/generate/internal"),
            Some(json!({
                "common_name": ca_name, "ttl": "48h",
                "key_type": "ec", "key_bits": 256,
            })),
            None,
        )
        .await?
    };
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
            Profile::Selfhost | Profile::SelfhostRenew => selfhost
                .ok_or("self-host TLS role is unmapped")?
                .key_name
                .to_owned(),
        };
        if profile != Profile::SelfhostRenew {
            bao.checked(
                Method::POST,
                &format!("transit/keys/{key}"),
                Some(json!({
                    "type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false,
                })),
                None,
            )
            .await?;
        }
        let metadata = bao
            .checked(Method::GET, &format!("transit/keys/{key}"), None, None)
            .await?;
        checked_transit_key_metadata(&metadata, profile)?;
        if profile == Profile::SelfhostRenew {
            let existing_role = bao
                .checked(
                    Method::GET,
                    &format!("{pki_mount}/roles/{}", role.name),
                    None,
                    None,
                )
                .await?;
            checked_existing_role(&existing_role, role)?;
        } else {
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
        }
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
            Profile::Selfhost | Profile::SelfhostRenew => "8h",
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
            Profile::Selfhost | Profile::SelfhostRenew => selfhost
                .ok_or("self-host TLS role is unmapped")?
                .cert_file
                .to_owned(),
        };
        write_new(&output.join(&cert_file), cert)?;
        let policy_name = match profile {
            Profile::Passport => key.clone(),
            Profile::Selfhost | Profile::SelfhostRenew => format!("{project}-{key}"),
        };
        let policy = format!(
            "path \"transit/keys/{key}\" {{ capabilities = [\"read\"] }}\n\
             path \"transit/sign/{key}\" {{ capabilities = [\"update\"] }}"
        );
        if profile == Profile::SelfhostRenew {
            let current = bao
                .checked(
                    Method::GET,
                    &format!("sys/policies/acl/{policy_name}"),
                    None,
                    None,
                )
                .await?;
            if value(&current, "policy")? != policy {
                return Err("existing TLS signer policy differs from the reviewed scope".into());
            }
        } else {
            bao.checked(
                Method::PUT,
                &format!("sys/policies/acl/{policy_name}"),
                Some(json!({"policy":policy})),
                None,
            )
            .await?;
        }
        let create_path = if profile == Profile::SelfhostRenew {
            "auth/token/create/selfhost-renew-leaf"
        } else {
            "auth/token/create"
        };
        let issued = bao
            .checked(
                Method::POST,
                create_path,
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
        if token == bao.authority_token || token.len() < 20 {
            return Err("OpenBao scoped token is invalid".into());
        }
        let token_file = match profile {
            Profile::Passport => format!("{}_kms_token", role.file_prefix),
            Profile::Selfhost | Profile::SelfhostRenew => selfhost
                .ok_or("self-host TLS role is unmapped")?
                .token_file
                .to_owned(),
        };
        if profile == Profile::SelfhostRenew {
            let lookup = bao
                .checked(
                    Method::POST,
                    "auth/token/lookup",
                    Some(json!({"token": token})),
                    None,
                )
                .await?;
            let scopes = data(&lookup, "policies")?
                .as_array()
                .ok_or("renewed TLS token policies are invalid")?;
            let remaining = data(&lookup, "ttl")?
                .as_u64()
                .ok_or("renewed TLS token TTL is invalid")?;
            if scopes.len() != 1
                || scopes[0] != policy_name
                || !(3600..=28800).contains(&remaining)
                || data(&lookup, "orphan")?.as_bool() != Some(true)
                || value(&lookup, "path")? != "auth/token/create/selfhost-renew-leaf"
            {
                return Err("renewed TLS token has unexpected authority or lifetime".into());
            }
            let proof = bao
                .checked(
                    Method::POST,
                    &format!("transit/sign/{key}"),
                    Some(json!({"input": STANDARD.encode(b"renewal-key-scope"),
                                "key_version": 1})),
                    Some(token),
                )
                .await?;
            if !value(&proof, "signature")?.starts_with("vault:v1:") {
                return Err("renewed TLS token used a different signer version".into());
            }
            write_new(&output.join(&token_file), token)?;
            OpenBaoTlsIdentityFiles {
                certificate_chain_file: output.join(&cert_file),
                kms_ca_cert_file: ca_file.to_owned(),
                kms_endpoint: endpoint.to_owned(),
                kms_token_file: output.join(&token_file),
                kms_key_name: key.clone(),
                kms_key_version: 1,
                request_timeout: Duration::from_secs(5),
                max_concurrent_signs: 1,
            }
            .connect()
            .await?;
        } else {
            write_new(&output.join(&token_file), token)?;
        }
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
    if profile.is_selfhost() {
        write_new(
            &output.join(SELFHOST_KEY_METADATA_FILE),
            &selfhost_key_metadata().to_string(),
        )?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let profile = match env::var("MARTY_TLS_BOOTSTRAP_PROFILE").as_deref() {
        Ok("selfhost-disposable") => Profile::Selfhost,
        Ok("selfhost-renew") => Profile::SelfhostRenew,
        Ok("passport") | Err(_) => Profile::Passport,
        Ok(_) => return Err("unknown TLS bootstrap profile".into()),
    };
    let requested_mount = match env::var("MARTY_SELFHOST_WORKLOAD_PKI_MOUNT") {
        Ok(mount) => Some(mount),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    let renewal_pki_mount = selected_workload_pki_mount(profile, requested_mount.as_deref())?;
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
        Profile::SelfhostRenew => (
            "MARTY_SELFHOST_PROJECT",
            "SELFHOST_TLS_OUTPUT_DIR",
            "marty-selfhost-",
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
    let token_variable = match profile {
        Profile::SelfhostRenew => renewal_authority(renewal_pki_mount).2,
        Profile::Passport | Profile::Selfhost => "BAO_ROOT_TOKEN_FILE",
    };
    let authority_token = fs::read_to_string(required(token_variable)?)?;
    let authority_token = authority_token.trim().to_owned();
    let valid_token = match profile {
        Profile::Passport => {
            authority_token.len() == 64
                && authority_token.bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        Profile::Selfhost | Profile::SelfhostRenew => {
            authority_token.len() >= 20
                && authority_token.len() <= 256
                && authority_token.bytes().all(|byte| byte.is_ascii_graphic())
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
        authority_token,
    };
    provision(
        &bao,
        &output,
        &project,
        profile,
        &endpoint,
        Path::new(&ca_file),
        renewal_pki_mount,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn replacement_workload_issuer_mount_is_explicit_and_versioned() {
        assert_eq!(
            selected_workload_pki_mount(Profile::SelfhostRenew, None).unwrap(),
            "workload-pki"
        );
        assert_eq!(
            selected_workload_pki_mount(Profile::SelfhostRenew, Some("workload-pki-v2")).unwrap(),
            "workload-pki-v2"
        );
        assert_eq!(
            selected_workload_pki_mount(Profile::SelfhostRenew, Some("workload-pki-v9999"))
                .unwrap(),
            "workload-pki-v9999"
        );
        assert_eq!(renewal_authority("workload-pki").0, "selfhost-kms-renewal");
        assert_eq!(
            renewal_authority("workload-pki-v2").0,
            "selfhost-kms-ca-rotation"
        );
        for invalid in [
            "",
            "workload-pki-next",
            "workload-pki-v1",
            "workload-pki-v02",
            "workload-pki-v10000",
            "workload-pki-v2/roles/admin",
        ] {
            assert!(selected_workload_pki_mount(Profile::SelfhostRenew, Some(invalid)).is_err());
        }
        assert!(selected_workload_pki_mount(Profile::Selfhost, Some("workload-pki-v2")).is_err());
        assert!(selected_workload_pki_mount(Profile::Passport, Some("workload-pki-v2")).is_err());
    }

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

    #[test]
    fn selfhost_key_metadata_requires_version_one_and_has_no_secret_values() {
        let valid = json!({"data": {
            "type": "ecdsa-p256", "exportable": false,
            "allow_plaintext_backup": false, "latest_version": 1,
        }});
        assert!(checked_transit_key_metadata(&valid, Profile::Selfhost).is_ok());
        for version in [json!(0), json!(2), json!("1"), json!(true)] {
            let mut invalid = valid.clone();
            invalid["data"]["latest_version"] = version;
            assert!(checked_transit_key_metadata(&invalid, Profile::Selfhost).is_err());
            assert!(checked_transit_key_metadata(&invalid, Profile::Passport).is_ok());
        }
        let manifest = selfhost_key_metadata();
        assert_eq!(manifest["schema"], "marty.selfhost-disposable-tls-keys/v1");
        assert_eq!(manifest["roles"].as_array().unwrap().len(), 16);
        assert!(!manifest.to_string().contains("token"));
        assert!(!manifest.to_string().contains("PRIVATE KEY"));
    }

    #[test]
    fn renewal_refuses_broadened_or_changed_existing_role() {
        let role = ROLES
            .iter()
            .find(|role| role.name == "flow-client")
            .unwrap();
        let original = json!({"data": {
            "allow_any_name": true, "allow_localhost": true,
            "allow_ip_sans": true,
            "allowed_uri_sans": ["spiffe://marty.internal/service/flow"],
            "server_flag": false, "client_flag": true,
            "key_type": "ec", "key_bits": 256, "max_ttl": 86400,
            "use_csr_common_name": false, "use_csr_sans": false,
        }});
        assert!(checked_existing_role(&original, role).is_ok());
        for (field, changed) in [
            ("allowed_uri_sans", json!(["*"])),
            ("server_flag", json!(true)),
            ("key_bits", json!(384)),
            ("max_ttl", json!(2592000)),
            ("use_csr_sans", json!(true)),
        ] {
            let mut altered = original.clone();
            altered["data"][field] = changed;
            assert!(checked_existing_role(&altered, role).is_err(), "{field}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn scoped_token_output_is_private_from_creation() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "marty-tls-output-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        write_new(&path, "synthetic scoped token").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(path).unwrap();
    }
}
