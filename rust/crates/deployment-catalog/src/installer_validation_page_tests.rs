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
        assert!(runtime_configuration(&bytes, canonical, Some(alias)));
        assert!(!runtime_configuration(
            &bytes,
            "https://foreign.example",
            Some(alias)
        ));
        assert!(!runtime_configuration(&bytes, canonical, None));
        let mut injected = bytes.clone();
        injected.extend_from_slice(b"fetch('https://foreign.example');");
        assert!(!runtime_configuration(&injected, canonical, Some(alias)));
    }
    assert!(runtime_configuration(
        &configuration(canonical, "[]"),
        canonical,
        None
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
            Some("https://203.0.113.10:8443")
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
        let result = document(&trust, &canonical, None, variant == "cookie").await;
        assert_eq!(result.is_some(), variant == "valid", "{variant}");
        assert!(requests.load(Ordering::SeqCst) <= 6);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
