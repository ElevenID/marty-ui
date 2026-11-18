use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[test]
fn frozen_python_validation_corpus() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spruce-metadata-probe-v1.json"
    ))
    .unwrap();
    let base = corpus["base"].as_str().unwrap();
    let org = corpus["organization_id"].as_str().unwrap();
    let issuer = format!("{base}/org/{org}");
    let vct = format!("{base}/credentials/marty-verified-member-badge");
    for case in corpus["cases"].as_array().unwrap() {
        let actual = match case["kind"].as_str().unwrap() {
            "issuer" => marty_spruce_metadata_probe::validate_issuer(&case["input"], &issuer, &vct),
            "member_vct" => marty_spruce_metadata_probe::validate_member_vct(&case["input"], &vct),
            other => panic!("unknown corpus kind: {other}"),
        };
        if let Some(expected) = case.get("error") {
            assert_eq!(
                actual.unwrap_err(),
                expected.as_str().unwrap(),
                "{}",
                case["name"]
            );
        } else {
            assert_eq!(actual.unwrap(), case["summary"], "{}", case["name"]);
        }
    }
}

#[test]
fn malformed_configuration_id_cannot_inject_log_lines() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spruce-metadata-probe-v1.json"
    ))
    .unwrap();
    let mut issuer = corpus["probe_success"]["issuer_metadata"].clone();
    issuer["credential_configurations_supported"]
        .as_object_mut()
        .unwrap()
        .insert("bad\nid".to_owned(), Value::Null);
    let base = corpus["base"].as_str().unwrap();
    let org = corpus["organization_id"].as_str().unwrap();
    let error = marty_spruce_metadata_probe::validate_issuer(
        &issuer,
        &format!("{base}/org/{org}"),
        &format!("{base}/credentials/marty-verified-member-badge"),
    )
    .unwrap_err();
    assert_eq!(error, "Malformed credential configurations: ['bad\\nid']");
}

#[tokio::test]
async fn invalid_origin_fails_before_network_io() {
    assert_eq!(
        marty_spruce_metadata_probe::probe("http://localhost", "org")
            .await
            .unwrap_err(),
        "Beta origin must be an absolute HTTPS URL"
    );
}

#[tokio::test]
async fn frozen_python_probe_order_and_summary() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spruce-metadata-probe-v1.json"
    ))
    .unwrap();
    let success = &corpus["probe_success"];
    let expected_urls: Vec<String> = success["requested_urls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observed_fetch = observed.clone();
    let issuer = success["issuer_metadata"].clone();
    let member = success["member_vct_metadata"].clone();
    let result = marty_spruce_metadata_probe::probe_with_fetch(
        corpus["base"].as_str().unwrap(),
        corpus["organization_id"].as_str().unwrap(),
        move |url| {
            let index = {
                let mut urls = observed_fetch.lock().unwrap();
                urls.push(url);
                urls.len() - 1
            };
            let body = if index < 2 {
                issuer.clone()
            } else {
                member.clone()
            };
            async move { Ok(body) }
        },
    )
    .await
    .unwrap();
    assert_eq!(result, success["summary"]);
    assert_eq!(*observed.lock().unwrap(), expected_urls);
}

#[tokio::test]
async fn differing_canonical_and_appended_stop_before_vct_fetch() {
    let observed = Arc::new(Mutex::new(0usize));
    let count = observed.clone();
    let failure = marty_spruce_metadata_probe::probe_with_fetch(
        "https://beta.elevenidllc.com",
        "org",
        move |_| {
            let index = {
                let mut value = count.lock().unwrap();
                *value += 1;
                *value
            };
            async move { Ok(serde_json::json!({"index": index})) }
        },
    )
    .await
    .unwrap_err();
    assert_eq!(failure, "Canonical and appended metadata differ");
    assert_eq!(*observed.lock().unwrap(), 2);
}

async fn fetch_from_mock(status: u16, content_type: &str, body: &str) -> Result<Value, String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/metadata", listener.local_addr().unwrap());
    let response = format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 2048];
        let read = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..read]).to_ascii_lowercase();
        assert!(request.contains("accept: application/json"));
        assert!(request.contains("user-agent: marty-mip-conformance/0.5.0"));
        stream.write_all(response.as_bytes()).unwrap();
    });
    let client = reqwest::Client::builder()
        .user_agent("Marty-MIP-Conformance/0.5.0")
        .build()
        .unwrap();
    let result = marty_spruce_metadata_probe::fetch_json(&client, &url).await;
    server.join().unwrap();
    result.map_err(|message| message.replacen(&url, "{url}", 1))
}

#[tokio::test]
async fn http_contract_rejects_status_media_type_and_payload_errors() {
    assert_eq!(
        fetch_from_mock(500, "application/json", "{}")
            .await
            .unwrap_err(),
        "{url} returned HTTP 500"
    );
    assert_eq!(
        fetch_from_mock(200, "text/html", "{}").await.unwrap_err(),
        "{url} is not JSON"
    );
    assert_eq!(
        fetch_from_mock(200, "application/json", "no")
            .await
            .unwrap_err(),
        "{url} contains invalid JSON"
    );
    assert_eq!(
        fetch_from_mock(200, "application/json", "[]")
            .await
            .unwrap_err(),
        "{url} must contain a JSON object"
    );
    assert_eq!(
        fetch_from_mock(200, "application/json; charset=utf-8", "{}")
            .await
            .unwrap(),
        serde_json::json!({})
    );
}
