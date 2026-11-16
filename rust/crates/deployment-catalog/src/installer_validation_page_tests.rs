use super::*;

fn built_page() -> String {
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../ui/index.html"
    ))
    .replace("/src/index.jsx", "/assets/index-a1B_2.js")
    .replace(
        "</head>",
        "<link rel=\"stylesheet\" href=\"/assets/index-c3D_4.css\"></head>",
    )
}

fn configuration(canonical: &str, aliases: &str) -> Vec<u8> {
    format!("window.__MARTY_RUNTIME_CONFIG__ = Object.assign({{}}, window.__MARTY_RUNTIME_CONFIG__, {{\n  googleAnalyticsMeasurementId: '',\n  hosting: {{\n    canonicalOrigin: '{canonical}',\n    publicEntryOrigins: {aliases}\n  }}\n}});\n").into_bytes()
}

fn emitted_configuration(
    canonical: &str,
    alias: Option<&str>,
    sections: &str,
    organization_creation: Option<&str>,
) -> Vec<u8> {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let target = root.path().join("target");
    std::fs::create_dir_all(source.join("console")).unwrap();
    std::fs::create_dir(&target).unwrap();
    std::fs::write(source.join("index.html"), built_page()).unwrap();
    std::fs::write(source.join("console/index.html"), built_page()).unwrap();
    let mut script = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../scripts/ui-selfhost-start.sh"
    ))
    .to_owned();
    // Exercise the actual emitter; only its unrelated secret loader and static
    // directories change, following the existing Python startup-hook fixture.
    for (from, to) in [
        (
            ". /scripts/load-secrets-env.sh",
            ": # no secrets in this fixture",
        ),
        (
            "SOURCE_DIR=\"/opt/marty-ui-static\"",
            "SOURCE_DIR=\"$MARTY_TEST_SOURCE\"",
        ),
        (
            "TARGET_DIR=\"/usr/share/nginx/html\"",
            "TARGET_DIR=\"$MARTY_TEST_TARGET\"",
        ),
    ] {
        assert_eq!(script.matches(from).count(), 1);
        script = script.replacen(from, to, 1);
    }
    let mut command = std::process::Command::new("sh");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("MARTY_TEST_SOURCE", &source)
        .env("MARTY_TEST_TARGET", &target)
        .env("UI_CANONICAL_ORIGIN", canonical)
        .env(
            "UI_PUBLIC_ENTRY_ORIGINS",
            serde_json::to_string(&alias.into_iter().collect::<Vec<_>>()).unwrap(),
        )
        .env("UI_ENABLED_SECTIONS", sections)
        .args(["-c", &script]);
    if let Some(choice) = organization_creation {
        command.env("ORGANIZATION_CREATION_ENABLED", choice);
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    std::fs::read(target.join("runtime-config.js")).unwrap()
}

#[test]
fn runtime_configuration_accepts_the_actual_startup_emitter() {
    let canonical = "https://marty.example.com:8443";
    for choice in [None, Some("false"), Some("true")] {
        for (sections, alias) in [
            ("public,console", None),
            ("public", Some("https://203.0.113.10:8443")),
            ("console", None),
        ] {
            let bytes = emitted_configuration(canonical, alias, sections, choice);
            assert!(runtime_configuration(&bytes, canonical, alias, sections));
            assert!(!runtime_configuration(
                &bytes,
                "https://foreign.example",
                alias,
                sections
            ));
            assert!(!runtime_configuration(&bytes, canonical, alias, "none"));
            if alias.is_some() {
                assert!(!runtime_configuration(&bytes, canonical, None, sections));
            }
        }
    }
}

#[test]
fn runtime_configuration_rejects_malformed_organization_fields_and_extra_code() {
    let canonical = "https://marty.example.com:8443";
    let emitted = String::from_utf8(emitted_configuration(
        canonical,
        None,
        "public,console",
        Some("false"),
    ))
    .unwrap();
    let field = "organizationCreationEnabled: false,";
    assert_eq!(emitted.matches(field).count(), 1);
    for replacement in [
        "organizationCreationEnabled: 'false',",
        "organizationCreationEnabled: \"false\",",
        "organizationCreationEnabled: 0,",
        "organizationCreationEnabled: null,",
        "organizationCreationEnabled: FALSE,",
        "organizationCreationEnabled: [],",
        "organizationCreationEnabled: false || true,",
        "organizationCreationEnabled: (() => false)(),",
        "organizationCreationEnabled: false, organizationCreationEnabled: true,",
        "organizationCreationEnabled: false, unknownSetting: true,",
        "unknownSetting: false,",
    ] {
        let changed = emitted.replace(field, replacement);
        assert!(
            !runtime_configuration(changed.as_bytes(), canonical, None, "public,console"),
            "{replacement}"
        );
    }
    for changed in [
        format!("{emitted}fetch('https://foreign.example');"),
        format!("window.unexpected = true;{emitted}"),
    ] {
        assert!(!runtime_configuration(
            changed.as_bytes(),
            canonical,
            None,
            "public,console"
        ));
    }
}

#[test]
fn built_entry_requires_the_application_document_and_bounded_local_assets() {
    let page = built_page();
    assert_eq!(
        entry_assets(page.as_bytes()).unwrap(),
        vec![
            Asset {
                path: "/assets/index-a1B_2.js".into(),
                stylesheet: false
            },
            Asset {
                path: "/assets/index-c3D_4.css".into(),
                stylesheet: true
            },
        ]
    );
    for changed in [
        page.replace("/assets/index-a1B_2.js", "/src/index.jsx"),
        page.replace("/assets/index-a1B_2.js", "https://foreign.example/entry.js"),
        page.replace("/assets/index-c3D_4.css", "/assets/../private.css"),
        page.replace("<div id=\"root\"></div>", "<div>proxy ready</div>"),
        page.replace("/runtime-config.js", "/unbound-config.js"),
        page.replace(
            "</body>",
            "<script type=\"module\" src=\"/assets/extra.js\"></script></body>",
        ),
        page.replace("/assets/index-a1B_2.js", "/assets/index.js?remote=1"),
        page.replace(
            "</body>",
            "<script src=\"https://foreign.example/entry.js\"></script></body>",
        ),
        page.replace(
            "</head>",
            "<link rel=\"modulepreload\" href=\"https://foreign.example/vendor.js\"></head>",
        ),
        "<html><body>healthy</body></html>".into(),
        " ".repeat(HTML_LIMIT + 1),
    ] {
        assert!(entry_assets(changed.as_bytes()).is_none());
    }
    let preloaded = page.replace(
        "</head>",
        "<link rel=\"modulepreload\" href=\"/assets/vendor-1.js\"></head>",
    );
    assert_eq!(
        entry_assets(preloaded.as_bytes()).unwrap().last().unwrap(),
        &Asset {
            path: "/assets/vendor-1.js".into(),
            stylesheet: false
        }
    );
}

#[test]
fn runtime_origins_must_match_exactly_without_evaluating_javascript() {
    let canonical = "https://marty.example.com:8443";
    for alias in ["https://203.0.113.10:8443", "https://[2001:db8::1]:8443"] {
        let aliases = serde_json::to_string(&vec![alias]).unwrap();
        let bytes = configuration(canonical, &aliases);
        assert!(runtime_configuration(
            &bytes,
            canonical,
            Some(alias),
            "public,console"
        ));
        assert!(!runtime_configuration(
            &bytes,
            "https://foreign.example",
            Some(alias),
            "public,console"
        ));
        assert!(!runtime_configuration(
            &bytes,
            canonical,
            None,
            "public,console"
        ));
        let mut injected = bytes.clone();
        injected.extend_from_slice(b"fetch('https://foreign.example');");
        assert!(!runtime_configuration(
            &injected,
            canonical,
            Some(alias),
            "public,console"
        ));
    }
    assert!(runtime_configuration(
        &configuration(canonical, "[]"),
        canonical,
        None,
        "public,console"
    ));
    for aliases in [
        "['https://203.0.113.10:8443']",
        "[\"https://203.0.113.10:8443\",\"https://203.0.113.10:8443\"]",
        "[window.location.origin]",
        "[\"https://203.0.113.10:8443/\"]",
    ] {
        assert!(!runtime_configuration(
            &configuration(canonical, aliases),
            canonical,
            Some("https://203.0.113.10:8443"),
            "public,console"
        ));
    }
}

#[test]
fn runtime_sections_match_the_bound_selection_and_legacy_defaults() {
    let canonical = "https://marty.example.com:8443";
    let legacy = configuration(canonical, "[]");
    assert!(!runtime_configuration(&legacy, canonical, None, "console"));
    for (selection, sections) in [
        ("public,console", r#"["public","console"]"#),
        ("public", r#"["public"]"#),
        ("console", r#"["console"]"#),
        ("none", "[]"),
    ] {
        let text = String::from_utf8(legacy.clone()).unwrap().replace(
            "hosting:",
            &format!("web: {{ enabled_sections: {sections} }}, hosting:"),
        );
        assert!(runtime_configuration(
            text.as_bytes(),
            canonical,
            None,
            selection
        ));
        assert!(!runtime_configuration(
            text.as_bytes(),
            canonical,
            None,
            "unknown"
        ));
    }
    for sections in [
        r#"["console","console"]"#,
        r#"["marketing"]"#,
        "[window.location.origin]",
    ] {
        let text = String::from_utf8(legacy.clone()).unwrap().replace(
            "hosting:",
            &format!("web: {{ enabled_sections: {sections} }}, hosting:"),
        );
        assert!(!runtime_configuration(
            text.as_bytes(),
            canonical,
            None,
            "console"
        ));
    }
}

#[tokio::test]
async fn real_tls_page_rejects_redirect_placeholder_cookie_and_foreign_runtime() {
    use crate::installer_validation::transport_tests::certificate;
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let root = tempfile::tempdir().unwrap();
    let (certificate, key) = certificate(root.path(), "page", "localhost");
    let der = CertificateDer::from_pem_file(&certificate).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der], PrivateKeyDer::from_pem_file(&key).unwrap())
    .unwrap();
    for variant in [
        "valid",
        "redirect",
        "placeholder",
        "cookie",
        "foreign_runtime",
        "asset_html",
        "missing_preload",
    ] {
        let (mut trust, initial) = crate::installer_validation::transport_tests::serve(
            &certificate,
            &key,
            vec![],
            std::time::Duration::ZERO,
        )
        .await;
        initial.abort();
        let _ = initial.await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        trust.local_probe_address = listener.local_addr().unwrap();
        trust.origin = format!("https://localhost:{}", trust.local_probe_address.port());
        let canonical = trust.origin.clone();
        let expected = canonical.clone();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let tls = Arc::new(tls.clone());
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut stream = tokio_rustls::TlsAcceptor::from(tls.clone())
                    .accept(tcp)
                    .await
                    .unwrap();
                let mut request = [0; 4096];
                let length = stream.read(&mut request).await.unwrap();
                let text = std::str::from_utf8(&request[..length]).unwrap();
                assert!(text.starts_with("GET /"));
                assert!(!text.to_ascii_lowercase().contains("authorization:"));
                assert!(!text.to_ascii_lowercase().contains("cookie:"));
                count.fetch_add(1, Ordering::SeqCst);
                let path = text.split_whitespace().nth(1).unwrap();
                let (status, content_type, body) = match path {
                    "/" if variant == "redirect" => ("302 Found", "text/html", "redirect".into()),
                    "/" if variant == "placeholder" => {
                        ("200 OK", "text/html", "<html>healthy</html>".into())
                    }
                    "/" => (
                        "200 OK",
                        "text/html",
                        built_page().replace(
                            "</head>",
                            "<link rel=\"modulepreload\" href=\"/assets/vendor-1.js\"></head>",
                        ),
                    ),
                    "/runtime-config.js" => (
                        "200 OK",
                        "application/javascript",
                        String::from_utf8(configuration(
                            if variant == "foreign_runtime" {
                                "https://foreign.example"
                            } else {
                                &expected
                            },
                            "[]",
                        ))
                        .unwrap(),
                    ),
                    "/startup.js" => (
                        "200 OK",
                        "text/javascript",
                        "document.documentElement.classList.add('app-loading');".into(),
                    ),
                    path if path.ends_with(".css") => {
                        ("200 OK", "text/css", "body { margin: 0; }".into())
                    }
                    "/assets/vendor-1.js" if variant == "missing_preload" => {
                        ("404 Not Found", "text/html", "missing".into())
                    }
                    _ if variant == "asset_html" => (
                        "200 OK",
                        "application/javascript",
                        " \n<!DOCTYPE html><html>fallback</html>".into(),
                    ),
                    _ => (
                        "200 OK",
                        "application/javascript",
                        "document.getElementById('root').textContent = 'entry';".into(),
                    ),
                };
                let extra = if variant == "cookie" {
                    "Set-Cookie: session=unexpected\r\n"
                } else {
                    ""
                };
                let response = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        // Alias policy is also checked for Set-Cookie; the valid case here is
        // canonical because API rejection belongs to the separate edge tests.
        let result = document(
            &trust,
            &canonical,
            None,
            variant == "cookie",
            "/",
            "public,console",
        )
        .await;
        assert_eq!(result.is_some(), variant == "valid", "{variant}");
        assert!(requests.load(Ordering::SeqCst) <= 6);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn real_tls_section_selection_validates_enabled_pages_and_rejects_disabled_route_leaks() {
    use crate::installer_validation::transport_tests::{certificate, serve};
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let root = tempfile::tempdir().unwrap();
    let (certificate, key) = certificate(root.path(), "sections", "localhost");
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_file(&certificate).unwrap()],
        PrivateKeyDer::from_pem_file(&key).unwrap(),
    )
    .unwrap();
    let mut cases = Vec::new();
    for sections in ["none", "console", "public"] {
        let mut disabled = Vec::new();
        if sections != "public" {
            disabled.extend(["/", "/index.html", "/login", "/apply"]);
        }
        if sections != "console" {
            disabled.extend(["/console", "/console/", "/console/index.html"]);
        }
        if sections == "none" {
            disabled.extend(["/runtime-config.js", "/startup.js", "/config.json"]);
        }
        cases.push((sections, disabled.clone(), None));
        for path in &disabled {
            for leak in ["document", "redirect", "cookie", "location"] {
                cases.push((sections, disabled.clone(), Some((*path, leak))));
            }
        }
    }
    for (sections, disabled, leak) in cases {
        let (mut trust, initial) =
            serve(&certificate, &key, vec![], std::time::Duration::ZERO).await;
        initial.abort();
        let _ = initial.await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        trust.local_probe_address = listener.local_addr().unwrap();
        trust.origin = format!("https://localhost:{}", trust.local_probe_address.port());
        let canonical = trust.origin.clone();
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let observed = requests.clone();
        let tls = Arc::new(tls.clone());
        let excluded = disabled.clone();
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut stream = tokio_rustls::TlsAcceptor::from(tls.clone())
                    .accept(tcp)
                    .await
                    .unwrap();
                let mut request = [0; 4096];
                let length = stream.read(&mut request).await.unwrap();
                let request = std::str::from_utf8(&request[..length]).unwrap();
                assert!(request.starts_with("GET /"));
                let headers = request.to_ascii_lowercase();
                assert!(!headers.contains("authorization:"));
                assert!(!headers.contains("cookie:"));
                let path = request.split_whitespace().nth(1).unwrap();
                observed.lock().unwrap().push(path.to_owned());
                let mut extra = "";
                let (status, media_type, body) = if leak.is_some_and(|(entry, _)| entry == path) {
                    match leak.unwrap().1 {
                        "document" => ("200 OK", "text/html", built_page()),
                        "redirect" => {
                            extra = "Location: https://foreign.example/\r\n";
                            ("302 Found", "text/plain", "redirect".into())
                        }
                        "cookie" => {
                            extra = "Set-Cookie: fixture=unexpected\r\n";
                            ("404 Not Found", "text/plain", "disabled".into())
                        }
                        "location" => {
                            extra = "Location: /console\r\n";
                            ("404 Not Found", "text/plain", "disabled".into())
                        }
                        _ => unreachable!(),
                    }
                } else if excluded.contains(&path) {
                    ("404 Not Found", "text/plain", "disabled".into())
                } else {
                    match path {
                        "/" | "/console" => ("200 OK", "text/html", built_page()),
                        "/runtime-config.js" => {
                            let selected = serde_json::to_string(&vec![sections]).unwrap();
                            let config = String::from_utf8(configuration(&canonical, "[]"))
                                .unwrap()
                                .replace(
                                    "hosting:",
                                    &format!("web: {{ enabled_sections: {selected} }}, hosting:"),
                                );
                            ("200 OK", "application/javascript", config)
                        }
                        "/startup.js" | "/assets/index-a1B_2.js" => (
                            "200 OK",
                            "application/javascript",
                            "document.getElementById('root').textContent = 'entry';".into(),
                        ),
                        "/assets/index-c3D_4.css" => {
                            ("200 OK", "text/css", "body { margin: 0; }".into())
                        }
                        _ => ("404 Not Found", "text/plain", "absent".into()),
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let (passed, observation) = check(&trust, None, sections).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(passed, [leak.is_none(), true], "{sections}: {leak:?}");
        assert!(observation.is_none());
        let requests = requests.lock().unwrap();
        if leak.is_none() {
            for path in disabled {
                assert!(
                    requests.iter().any(|observed| observed == path),
                    "{sections}: {path}"
                );
            }
        }
        if sections == "none" {
            assert!(!requests.iter().any(|path| path.starts_with("/assets/")));
        } else {
            assert_eq!(
                requests[0],
                if sections == "public" {
                    "/"
                } else {
                    "/console"
                }
            );
            assert!(requests.contains(&"/runtime-config.js".into()));
            assert!(requests.contains(&"/assets/index-a1B_2.js".into()));
            assert!(requests.contains(&"/assets/index-c3D_4.css".into()));
        }
    }
}
