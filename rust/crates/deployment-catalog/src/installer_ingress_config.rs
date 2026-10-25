//! Installer-only nginx origin wiring. Caller authenticates the shipped source
//! and persists this generated configuration before starting the owned edge.
//! Mount readonly at /etc/nginx/conf.d/default.conf.template: the shipped
//! entrypoint's explicit envsubst allowlist leaves this resolved file unchanged,
//! writes default.conf, and runs nginx -t. Do not readonly-mount default.conf
//! while retaining that entrypoint, which unconditionally writes that path.
#![cfg(target_os = "linux")]

pub type Result<T> = std::result::Result<T, String>;
const TEMPLATE: &str = include_str!("../../../../docker/nginx-selfhost.prod.conf.template");
const REFUSED: &str = "installer ingress template or origin differs from the reviewed contract";

fn normalized(text: &str) -> Result<String> {
    if text.len() > 128 * 1024 || text.contains('\0') {
        return Err(REFUSED.into());
    }
    let text = text.replace("\r\n", "\n");
    if text.contains('\r') {
        return Err(REFUSED.into());
    }
    Ok(text)
}

/// Preserve the exact released routing contract; only pin the installer public
/// authority and resolve the fixed container DNS upstreams. Unknown source drift
/// is refused rather than rewritten heuristically. This does not provision TLS.
pub fn render(template: &str, origin: &str) -> Result<String> {
    let text = normalized(template)?;
    if text != normalized(TEMPLATE)? {
        return Err(REFUSED.into());
    }
    let port_text = origin.strip_prefix("https://localhost:").ok_or(REFUSED)?;
    let port: u16 = port_text.parse().map_err(|_| REFUSED)?;
    if port < 1024 || port_text != port.to_string() {
        return Err(REFUSED.into());
    }
    let authority = format!("localhost:{port}");
    let mut output = String::new();
    let mut hosts = 0;
    let mut proxies = 0;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        if trimmed.starts_with("proxy_pass ") {
            proxies += 1;
        }
        match trimmed {
            "listen 80;" => {
                output.push_str(line);
                output.push('\n');
                // Nginx sees clear HTTP internally. Keep automatic trailing-
                // slash redirects relative to the browser's actual HTTPS origin.
                output.push_str(&format!("{indent}absolute_redirect off;\n"));
            }
            "server_name ${PUBLIC_DOMAIN};" => {
                output.push_str(&format!("{indent}server_name localhost;\n"))
            }
            "proxy_set_header Host $host;" => {
                hosts += 1;
                for (name, value) in [
                    ("Host", authority.as_str()),
                    ("X-Forwarded-Host", authority.as_str()),
                    ("X-Forwarded-Proto", "https"),
                    ("X-Forwarded-Port", port_text),
                ] {
                    output.push_str(&format!("{indent}proxy_set_header {name} {value};\n"));
                }
            }
            "proxy_set_header X-Forwarded-Host $host;"
            | "proxy_set_header X-Forwarded-Proto $scheme;"
            | "proxy_set_header X-Forwarded-Proto https;"
            | "proxy_set_header X-Forwarded-Port 443;" => {}
            _ => {
                // Exact-source matching above closes this finite substitution
                // table. Runtime nginx variables ($1, $host, etc.) are untouched.
                let resolved = line
                    .replace("${UI_UPSTREAM}", "ui:80")
                    .replace("${GATEWAY_UPSTREAM}", "gateway:8000")
                    .replace("${FLOW_UPSTREAM}", "flow:8011")
                    .replace("${KEYCLOAK_UPSTREAM}", "keycloak:8080")
                    // External Canvas is disabled in the installer profile.
                    // These exact origins cannot authorize a foreign frame site.
                    .replace("${CANVAS_REAL_PUBLIC_HOST}", &authority)
                    .replace("${CANVAS_SANDBOX_PUBLIC_HOST}", &authority);
                output.push_str(&resolved);
                output.push('\n');
            }
        }
    }
    if proxies == 0 || hosts != proxies || output.contains("${") {
        return Err(REFUSED.into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn route_lines(text: &str) -> Vec<&str> {
        text.lines()
            .map(str::trim)
            .filter(|line| {
                line.starts_with("location ")
                    || line.starts_with("proxy_pass ")
                    || line.starts_with("rewrite ")
                    || line.starts_with("return ")
                    || line.starts_with("proxy_redirect ")
            })
            .collect()
    }
    #[test]
    fn actual_routing_is_preserved_and_every_proxy_has_exact_origin_headers() {
        let output = render(TEMPLATE, "https://localhost:18443").unwrap();
        assert_eq!(route_lines(TEMPLATE), route_lines(&output));
        assert!(output.contains("server_name localhost;"));
        assert!(output.contains("listen 80;\n    absolute_redirect off;\n"));
        assert!(!output.contains("${"));
        assert!(!output.contains("proxy_set_header Host $host;"));
        assert!(!output.contains("proxy_set_header X-Forwarded-Proto $scheme;"));
        assert!(!output.contains("proxy_set_header X-Forwarded-Port 443;"));
        let mut proxy = false;
        let mut headers = Vec::new();
        for line in output.lines().map(str::trim) {
            if line.starts_with("location ") {
                proxy = false;
                headers.clear();
            }
            if line.starts_with("proxy_pass ") {
                proxy = true;
            }
            if line.starts_with("proxy_set_header Host ")
                || line.starts_with("proxy_set_header X-Forwarded-Host ")
                || line.starts_with("proxy_set_header X-Forwarded-Proto ")
                || line.starts_with("proxy_set_header X-Forwarded-Port ")
            {
                headers.push(line);
            }
            if line == "}" && proxy {
                assert_eq!(
                    headers,
                    [
                        "proxy_set_header Host localhost:18443;",
                        "proxy_set_header X-Forwarded-Host localhost:18443;",
                        "proxy_set_header X-Forwarded-Proto https;",
                        "proxy_set_header X-Forwarded-Port 18443;"
                    ]
                );
                proxy = false;
            }
        }
        for upstream in ["ui:80", "gateway:8000", "flow:8011", "keycloak:8080"] {
            assert!(output.contains(upstream));
        }
    }
    #[test]
    fn refuses_origin_injection_and_template_drift() {
        for origin in [
            "http://localhost:18443",
            "https://foreign:18443",
            "https://localhost:443",
            "https://localhost:0",
            "https://localhost:65536",
            "https://localhost:018443",
            "https://localhost:+18443",
            "https://localhost:18443/",
            "https://localhost:18443;",
            "https://localhost:18443\ninclude /etc/other;",
            "https://localhost:18443?x",
        ] {
            assert!(render(TEMPLATE, origin).is_err(), "accepted {origin:?}");
        }
        for drift in [
            format!("{TEMPLATE}\n# unknown\n"),
            TEMPLATE.replace("proxy_pass http://$keycloak;", "proxy_pass http://foreign;"),
            TEMPLATE.replace("Host $host;", "Host $http_host;"),
            TEMPLATE.replace("listen 80;", "listen 443 ssl;"),
            TEMPLATE.replace("${UI_UPSTREAM}", "${UNREVIEWED_UPSTREAM}"),
        ] {
            assert!(render(&drift, "https://localhost:18443").is_err());
        }
    }
    #[test]
    fn only_line_ending_normalization_is_allowed() {
        let lf = normalized(TEMPLATE).unwrap();
        assert_eq!(
            render(&lf, "https://localhost:18443").unwrap(),
            render(&lf.replace('\n', "\r\n"), "https://localhost:18443").unwrap()
        );
        assert!(render(&format!("{lf}\r"), "https://localhost:18443").is_err());
        assert!(render(&format!("{lf}\0"), "https://localhost:18443").is_err());
    }
}
