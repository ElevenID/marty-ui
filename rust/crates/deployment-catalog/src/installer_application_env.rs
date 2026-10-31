//! Nonsecret inputs for the authenticated canonical application Compose file.
//! Does not create accounts, directories, containers, or claim readiness. Caller
//! authenticates example/Compose bytes and persists parameters before execution.
#![cfg(target_os = "linux")]
use crate::installer_state::ApplicantContainerGroup;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "application environment differs from the reviewed installation contract";
const EXAMPLE: &str = include_str!("../../../../.env.selfhost.production.example");
pub const OPERATOR_EMAIL: &str = "operator@localhost";
pub const OPTIONAL_EMPTY_SECRETS: [&str; 6] = [
    "google_client_id",
    "google_client_secret",
    "google_analytics_measurement_id",
    "google_site_verification",
    "smtp_password",
    "canvas_credentials_shared_secret",
];

pub struct ApplicationParameters {
    pub installation: PathBuf,
    pub applicant_container_group: ApplicantContainerGroup,
    pub version: String,
    pub origin: String,
    pub gateway_port: u16,
    pub keycloak_port: u16,
    pub edge_port: u16,
    pub openbao_port: u16,
}
#[derive(Serialize)]
pub struct ApplicationEnvironment {
    pub env_bytes: Vec<u8>,
    pub required_private_directories: Vec<PathBuf>,
    pub optional_empty_secrets: Vec<String>,
    pub operator_account_created: bool,
    pub installation_ready: bool,
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn parse(text: &str) -> Result<BTreeMap<String, String>> {
    require(text.len() <= 65536 && text.is_ascii())?;
    let key = regex::Regex::new(r"\A[A-Z][A-Z0-9_]*\z").unwrap();
    let mut values = BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').ok_or(REFUSED)?;
        require(
            key.is_match(name)
                && !value
                    .chars()
                    .any(|c| c.is_control() || c == '\'' || c == '\\')
                && values.insert(name.into(), value.into()).is_none(),
        )?;
    }
    Ok(values)
}
fn safe_path(path: &std::path::Path) -> Result<String> {
    let value = path.to_str().ok_or(REFUSED)?;
    require(
        path.is_absolute()
            && value.starts_with('/')
            && value != "/"
            && !value.ends_with('/')
            && !value
                .chars()
                .any(|c| c.is_control() || c == '\'' || c == '\\')
            && value
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != ".."),
    )?;
    Ok(value.into())
}
pub(crate) fn origin_port(origin: &str) -> Result<u16> {
    let port = origin.strip_prefix("https://localhost:").ok_or(REFUSED)?;
    let number = port.parse::<u16>().map_err(|_| REFUSED)?;
    require(number >= 1024 && port == number.to_string())?;
    Ok(number)
}
fn required_variables(compose: &str, values: &BTreeMap<String, String>) -> Result<()> {
    require(compose.len() <= 256 * 1024)?;
    let expression = regex::Regex::new(r"\$\{([A-Z][A-Z0-9_]*)(?::\?|\?)[^}]*\}").unwrap();
    for captured in expression.captures_iter(compose) {
        let start = captured.get(0).unwrap().start();
        // Escaped container-side references are not Compose interpolation.
        if start > 0 && compose.as_bytes()[start - 1] == b'$' {
            continue;
        }
        require(
            values
                .get(&captured[1])
                .is_some_and(|value| !value.is_empty()),
        )?;
    }
    Ok(())
}
/// `images` is the authenticated inventory map, including openbao_didcomm_image.
/// Networking/ingress overlays must preserve this exact public authority and
/// provide the already-owned OpenBao network alias. Nginx server_name needs the
/// separate host-only literal localhost; PUBLIC_DOMAIN also feeds KC_HOSTNAME.
pub fn render(
    example: &str,
    compose: &str,
    tls_fragment: &str,
    p: &ApplicationParameters,
    images: &BTreeMap<String, String>,
) -> Result<ApplicationEnvironment> {
    render_selected(example, compose, tls_fragment, p, images, None)
}

pub(crate) fn render_selected(
    example: &str,
    compose: &str,
    tls_fragment: &str,
    p: &ApplicationParameters,
    images: &BTreeMap<String, String>,
    foundation: Option<&crate::installer_foundation::Selection>,
) -> Result<ApplicationEnvironment> {
    let baseline = parse(EXAMPLE)?;
    let mut values = parse(example)?;
    require(values == baseline)?;
    let expected_tls: BTreeMap<_, _> = baseline
        .iter()
        .filter(|(key, _)| key.contains("_TLS_KMS_KEY_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    require(
        expected_tls.len() == 32
            && if foundation.is_some() {
                tls_fragment.is_empty()
            } else {
                parse(tls_fragment)? == expected_tls
            },
    )?;
    crate::installer_release::release_tier(&p.version)?;
    safe_path(&p.installation)?;
    let https_port = origin_port(&p.origin)?;
    let ports = [
        https_port,
        p.gateway_port,
        p.keycloak_port,
        p.edge_port,
        p.openbao_port,
    ];
    require(
        ports.iter().all(|port| *port >= 1024)
            && ports.into_iter().collect::<BTreeSet<_>>().len() == 5,
    )?;
    let image_pattern=regex::Regex::new(r"\Aghcr\.io/elevenid/marty-ui-oss/(services|keycloak|openbao-didcomm)@sha256:[0-9a-f]{64}\z").unwrap();
    let selected = |role: &str, repository: &str| -> Result<String> {
        let image = images.get(role).ok_or(REFUSED)?;
        require(
            image_pattern.is_match(image)
                && image.starts_with(&format!("ghcr.io/elevenid/marty-ui-oss/{repository}@")),
        )?;
        Ok(image.clone())
    };
    let services = selected("gateway", "services")?;
    require(images.get("signing-keys") == Some(&services))?;
    let managed_identity_images = if foundation.is_none() {
        let keycloak = selected("keycloak", "keycloak")?;
        require(images.get("keycloak-configurator") == Some(&keycloak))?;
        Some((
            keycloak,
            selected("openbao_didcomm_image", "openbao-didcomm")?,
        ))
    } else {
        None
    };
    let issuance = selected("issuance", "services")?;
    require(images.get("issuance-native") == Some(&issuance))?;
    for (key, relative) in [
        ("SELFHOST_SECRET_DIR", "secrets"),
        ("SELFHOST_STATE_DIR", "state"),
        ("SELFHOST_BACKUP_DIR", "backups"),
        ("SELFHOST_OPENBAO_STATE_DIR", "openbao-state"),
        ("SELFHOST_OPENBAO_EXPORT_DIR", "openbao-exports"),
        (
            "SELFHOST_OPENBAO_SNAPSHOT_IDENTITY_DIR",
            "openbao-snapshot-identity",
        ),
    ] {
        values.insert(key.into(), safe_path(&p.installation.join(relative))?);
    }
    values.insert(
        "APPLICANT_STATE_GID".into(),
        p.applicant_container_group.container_gid().to_string(),
    );
    for (key, value) in [
        ("SELFHOST_IMAGE_PREFIX", "ghcr.io/elevenid/marty-ui-oss"),
        ("BAO_ADDR", "https://openbao:8200"),
        ("KEYCLOAK_KMS_ADDR", "https://openbao:8200"),
        ("GRPC_INSECURE_ALLOWED", "false"),
        ("MARTY_ORG_DOMAIN", "localhost"),
        ("MARTY_ORG_ADMIN_EMAIL", OPERATOR_EMAIL),
        ("KEYCLOAK_SMTP_FROM", "noreply@localhost"),
        ("MARTY_MIGRATION_PROFILE", "selfhost-production"),
    ] {
        values.insert(key.into(), value.into());
    }
    for key in baseline.keys().filter(|key| key.ends_with("_TLS_KMS_ADDR")) {
        values.insert(key.clone(), "https://openbao:8200".into());
    }
    for (key, value) in [
        (
            "SELFHOST_IMAGE_TAG",
            p.version.strip_prefix('v').ok_or(REFUSED)?.to_owned(),
        ),
        ("MARTY_ISSUANCE_IMAGE", issuance),
        ("PUBLIC_DOMAIN", format!("localhost:{https_port}")),
        ("SELFHOST_GATEWAY_HOST_PORT", p.gateway_port.to_string()),
        ("SELFHOST_KEYCLOAK_HOST_PORT", p.keycloak_port.to_string()),
        ("SELFHOST_EDGE_HOST_PORT", p.edge_port.to_string()),
        ("SELFHOST_OPENBAO_HOST_PORT", p.openbao_port.to_string()),
    ] {
        values.insert(key.into(), value);
    }
    if let Some((keycloak, openbao)) = managed_identity_images {
        values.insert("MARTY_KEYCLOAK_KMS_IMAGE".into(), keycloak);
        values.insert("MARTY_OPENBAO_DIDCOMM_IMAGE".into(), openbao);
    }
    for key in [
        "PUBLIC_API_URL",
        "UI_BASE_URL",
        "ISSUER_BASE_URL",
        "MARTY_ISSUER_BASE_URL",
        "CORS_ORIGINS",
        "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL",
    ] {
        values.insert(key.into(), p.origin.clone());
    }
    for (key, suffix) in [
        ("OIDC_ISSUER_URL_EXTERNAL", "/realms/11id"),
        ("OIDC_REDIRECT_URI", "/v1/auth/callback"),
        ("OIDC_POST_LOGOUT_REDIRECT_URI", "/"),
    ] {
        values.insert(key.into(), format!("{}{suffix}", p.origin));
    }
    for key in [
        "KEYCLOAK_USER_REGISTRATION_ENABLED",
        "KEYCLOAK_VERIFY_EMAIL",
        "KEYCLOAK_RESET_PASSWORD_ENABLED",
        "KEYCLOAK_SOCIAL_LOGIN_ENABLED",
        "KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED",
        "KEYCLOAK_SMTP_SSL",
        "KEYCLOAK_SMTP_STARTTLS",
        "ORGANIZATION_CREATION_ENABLED",
        "CANVAS_PORTABLE_INTEGRATION_ENABLED",
        "CANVAS_LEGACY_EVENT_INGEST_ENABLED",
        "CANVAS_MIRROR_WORKER_ENABLED",
        "CANVAS_ALLOW_PRIVATE_BASE_URLS",
        "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS",
        "DID_PUBLIC_FALLBACK_ENABLED",
        "DIDCOMM_ALLOW_PRIVATE_ENDPOINTS",
    ] {
        values.insert(key.into(), "false".into());
    }
    for key in [
        "UI_ADDITIONAL_BASE_URLS",
        "KEYCLOAK_SMTP_HOST",
        "KEYCLOAK_SMTP_USERNAME",
        "SMTP_HOST",
        "SMTP_USERNAME",
        "CANVAS_CREDENTIALS_API_BASE_URL",
        "CANVAS_CREDENTIALS_PUBLISH_URL",
        "CANVAS_CREDENTIALS_STATUS_SYNC_URL",
        "CANVAS_CREDENTIALS_ISSUER_ID",
        "CANVAS_CREDENTIALS_BADGECLASS_ID",
        "CANVAS_PILOT_ORGANIZATION_IDS",
        "CANVAS_PRIVATE_ORIGIN_ALLOWLIST",
        "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST",
        "UNIVERSAL_RESOLVER_URL",
        "DID_WEB_ALLOWED_HOSTS",
    ] {
        values.insert(key.into(), String::new());
    }
    if let Some(foundation) = foundation {
        foundation.apply_environment(&mut values)?;
    }
    required_variables(compose, &values)?;
    let mut env_bytes = Vec::new();
    for (key, value) in values {
        require(
            ![
                "REPLACE_",
                "/path/to/",
                "prod.example.com",
                "openbao.example.com",
                "smtp.example.com",
            ]
            .iter()
            .any(|sentinel| value.contains(sentinel)),
        )?;
        require(
            !value
                .chars()
                .any(|c| c.is_control() || c == '\'' || c == '\\'),
        )?;
        env_bytes.extend_from_slice(format!("{key}='{value}'\n").as_bytes());
    }
    Ok(ApplicationEnvironment {
        env_bytes,
        required_private_directories: [
            "state",
            "state/postgres",
            "state/redis",
            "state/applicant",
            "backups",
            "openbao-exports",
            "openbao-snapshot-identity",
        ]
        .into_iter()
        .map(|name| p.installation.join(name))
        .collect(),
        optional_empty_secrets: OPTIONAL_EMPTY_SECRETS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        operator_account_created: false,
        installation_ready: false,
    })
}

/// Select only the fixed immutable snapshot after canonical source rendering.
/// All other environment bytes remain exactly as admitted.
pub fn select_generation(source: &[u8], installation: &std::path::Path) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(source).map_err(|_| REFUSED)?;
    let expected = format!(
        "SELFHOST_SECRET_DIR='{}'",
        safe_path(&installation.join("secrets"))?
    );
    let replacement = format!(
        "SELFHOST_SECRET_DIR='{}'",
        safe_path(&installation.join("application-generation"))?
    );
    require(
        text.lines()
            .filter(|line| line.starts_with("SELFHOST_SECRET_DIR="))
            .count()
            == 1
            && text.lines().any(|line| line == expected),
    )?;
    Ok(text
        .lines()
        .map(|line| {
            if line == expected {
                replacement.as_str()
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
        .into_iter()
        .chain([b'\n'])
        .collect())
}

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
    const COMPOSE: &str = include_str!("../../../../docker-compose.selfhost.prod.yml");
    fn parameters() -> ApplicationParameters {
        ApplicationParameters {
            installation: PathBuf::from("/private/marty $literal #path"),
            applicant_container_group: rootful_applicant_group(),
            version: "v1.2.3".into(),
            origin: "https://localhost:18443".into(),
            gateway_port: 18000,
            keycloak_port: 18180,
            edge_port: 19080,
            openbao_port: 18200,
        }
    }
    fn images() -> BTreeMap<String, String> {
        [
            ("gateway", "services"),
            ("signing-keys", "services"),
            ("issuance", "services"),
            ("issuance-native", "services"),
            ("keycloak", "keycloak"),
            ("keycloak-configurator", "keycloak"),
            ("openbao_didcomm_image", "openbao-didcomm"),
        ]
        .into_iter()
        .map(|(role, image)| {
            (
                role.into(),
                format!(
                    "ghcr.io/elevenid/marty-ui-oss/{image}@sha256:{}",
                    "a".repeat(64)
                ),
            )
        })
        .collect()
    }
    fn tls() -> String {
        parse(EXAMPLE)
            .unwrap()
            .into_iter()
            .filter(|(k, _)| k.contains("_TLS_KMS_KEY_"))
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect()
    }
    #[test]
    fn renders_actual_example_tls_and_canonical_compose_without_secrets() {
        let result = render(EXAMPLE, COMPOSE, &tls(), &parameters(), &images()).unwrap();
        let text = String::from_utf8(result.env_bytes).unwrap();
        for expected in [
            "PUBLIC_DOMAIN='localhost:18443'\n",
            "OIDC_ISSUER_URL_EXTERNAL='https://localhost:18443/realms/11id'\n",
            "SELFHOST_SECRET_DIR='/private/marty $literal #path/secrets'\n",
            "BAO_ADDR='https://openbao:8200'\n",
            "KEYCLOAK_SOCIAL_LOGIN_ENABLED='false'\n",
            "MARTY_ORG_ADMIN_EMAIL='operator@localhost'\n",
        ] {
            assert!(text.contains(expected), "missing {expected}");
        }
        assert!(text
            .lines()
            .all(|line| !line.split_once('=').unwrap().1.contains("REPLACE_")));
        assert!(!text.contains("_PASSWORD="));
        assert!(!result.operator_account_created);
        assert_eq!(result.optional_empty_secrets.len(), 6);
    }
    #[test]
    fn applicant_environment_uses_the_container_group_without_changing_other_inputs() {
        use crate::installer_state::{applicant_container_group, RuntimeBinding, RuntimeProfile};
        let mut p = parameters();
        let rootful = render(EXAMPLE, COMPOSE, &tls(), &p, &images()).unwrap();
        let rootful_text = String::from_utf8(rootful.env_bytes).unwrap();
        assert!(rootful_text.contains(&format!(
            "APPLICANT_STATE_GID='{}'\n",
            p.applicant_container_group.host_gid()
        )));
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
        p.applicant_container_group = applicant_container_group(&binding).unwrap();
        let rootless = render(EXAMPLE, COMPOSE, &tls(), &p, &images()).unwrap();
        let rootless_text = String::from_utf8(rootless.env_bytes).unwrap();
        assert!(rootless_text.contains("APPLICANT_STATE_GID='0'\n"));
        assert_eq!(
            rootful_text
                .lines()
                .filter(|line| !line.starts_with("APPLICANT_STATE_GID="))
                .collect::<Vec<_>>(),
            rootless_text
                .lines()
                .filter(|line| !line.starts_with("APPLICANT_STATE_GID="))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rejects_unsafe_origin_paths_ports_and_versions() {
        for origin in [
            "http://localhost:18443",
            "https://localhost:443",
            "https://localhost:018443",
            "https://localhost:18443/",
            "https://user@localhost:18443",
            "https://localhost:18443\nBAD=x",
            "https://example.com:18443",
        ] {
            let mut p = parameters();
            p.origin = origin.into();
            assert!(render(EXAMPLE, COMPOSE, &tls(), &p, &images()).is_err());
        }
        for path in [
            "relative",
            "/private/../other",
            "/private/a'b",
            "/private/a\nb",
            "/private/a\\b",
        ] {
            let mut p = parameters();
            p.installation = path.into();
            assert!(render(EXAMPLE, COMPOSE, &tls(), &p, &images()).is_err());
        }
        let mut p = parameters();
        p.gateway_port = p.openbao_port;
        assert!(render(EXAMPLE, COMPOSE, &tls(), &p, &images()).is_err());
        p = parameters();
        p.version = "latest".into();
        assert!(render(EXAMPLE, COMPOSE, &tls(), &p, &images()).is_err());
    }
    #[test]
    fn rejects_unknown_duplicate_or_changed_example_tls_and_required_inputs() {
        for example in [
            format!("{EXAMPLE}\nUNKNOWN=anything\n"),
            format!("{EXAMPLE}\nKEYCLOAK_ADMIN=other\n"),
            EXAMPLE.replace("KEYCLOAK_ADMIN=admin", "KEYCLOAK_ADMIN=attacker"),
            EXAMPLE.replace("KEYCLOAK_REALM=11id", ""),
        ] {
            assert_ne!(example, EXAMPLE, "fixture mutation must change the example");
            assert!(render(&example, COMPOSE, &tls(), &parameters(), &images()).is_err());
        }
        for fragment in [
            tls().replace("_KEY_VERSION=1", "_KEY_VERSION=2"),
            format!("{}UNKNOWN=x\n", tls()),
            String::new(),
        ] {
            assert_ne!(
                fragment,
                tls(),
                "fixture mutation must change the TLS fragment"
            );
            assert!(render(EXAMPLE, COMPOSE, &fragment, &parameters(), &images()).is_err());
        }
        assert!(render(
            EXAMPLE,
            &format!("{COMPOSE}\nvalue: ${{UNKNOWN_REQUIRED:?missing}}"),
            &tls(),
            &parameters(),
            &images()
        )
        .is_err());
        let mut image = images();
        image.remove("keycloak");
        assert!(render(EXAMPLE, COMPOSE, &tls(), &parameters(), &image).is_err());
        image = images();
        image.insert("keycloak-configurator".into(), "other".into());
        assert!(render(EXAMPLE, COMPOSE, &tls(), &parameters(), &image).is_err());
    }
    #[test]
    fn generation_environment_changes_only_exact_admitted_secret_directory() {
        let root = std::path::Path::new("/private/install $literal #path");
        let source=b"A='unchanged'\nSELFHOST_SECRET_DIR='/private/install $literal #path/secrets'\nB='unchanged'\n";
        let selected = select_generation(source, root).unwrap();
        assert_eq!(selected,b"A='unchanged'\nSELFHOST_SECRET_DIR='/private/install $literal #path/application-generation'\nB='unchanged'\n");
        assert!(select_generation(&selected, root).is_err());
        assert!(select_generation(b"SELFHOST_SECRET_DIR='/etc'\n", root).is_err());
        let mut duplicate = source.to_vec();
        duplicate.extend_from_slice(source);
        assert!(select_generation(&duplicate, root).is_err());
    }
}
