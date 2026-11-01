use super::*;
use axum::body::to_bytes;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
};

const DNS: &str = "marty.example.com";
const IP: &str = "203.0.113.10";
const TOKEN: &str = "abcdefghijklmnopqrstuv";
const SECOND_TOKEN: &str = "ABCDEFGHIJKLMNOPQRSTUV";
const THUMBPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const NOW: u64 = 1_700_000_000;

fn allowed() -> AllowedIdentifiers {
    AllowedIdentifiers::from_origins(
        "https://marty.example.com:8443",
        Some("https://203.0.113.10:8443"),
    )
    .unwrap()
}

fn record(identifier: &str, token: &str) -> Value {
    json!({"identifier": identifier, "token": token, "key_authorization": format!("{token}.{THUMBPRINT}")})
}

fn snapshot(now: u64) -> Value {
    json!({"schema": SNAPSHOT_SCHEMA, "created_at": now, "expires_at": now + 300,
        "challenges": [record(DNS, TOKEN), record(IP, SECOND_TOKEN)]})
}

fn parses(value: &Value, allowed: &AllowedIdentifiers, now: u64) -> bool {
    Snapshot::parse(&serde_json::to_vec(value).unwrap(), allowed, now).is_ok()
}

fn publish(path: &Path, value: &Value) {
    let temporary = path.join("next.json");
    fs::write(&temporary, serde_json::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)).unwrap();
    File::open(&temporary).unwrap().sync_all().unwrap();
    fs::rename(temporary, path.join(SNAPSHOT_BASENAME)).unwrap();
    File::open(path).unwrap().sync_all().unwrap();
}

fn request(host: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("{PATH_PREFIX}{token}"))
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap()
}

#[test]
fn public_snapshot_is_bound_to_identifiers_and_bounded_lifetime() {
    let accepted = snapshot(NOW);
    assert!(parses(&accepted, &allowed(), NOW));
    assert!(parses(&accepted, &allowed(), NOW + 299));
    assert!(!parses(&accepted, &allowed(), NOW + 300));
    assert!(!parses(&accepted, &allowed(), NOW - 1));
    let mut value = accepted.clone();
    value["expires_at"] = (NOW + MAX_LIFETIME_SECONDS).into();
    assert!(parses(&value, &allowed(), NOW));
    value["expires_at"] = (NOW + MAX_LIFETIME_SECONDS + 1).into();
    assert!(!parses(&value, &allowed(), NOW));
    for (field, invalid) in [
        ("schema", json!("elevenid.acme-http01/v2")),
        ("expires_at", json!(NOW)),
        ("expires_at", json!(u64::MAX)),
        ("created_at", json!(NOW + 1)),
        ("created_at", json!(-1)),
        ("account_private_key", json!("must never be projected")),
    ] {
        let mut value = accepted.clone();
        value[field] = invalid;
        assert!(!parses(&value, &allowed(), NOW), "field {field}");
    }
    let mut empty = accepted.clone();
    empty["challenges"] = json!([]);
    assert!(parses(&empty, &allowed(), NOW));
    let mut unknown = accepted.clone();
    unknown["challenges"][0]["identifier"] = json!("other.example.com");
    assert!(!parses(&unknown, &allowed(), NOW));
    let dns_only = AllowedIdentifiers::from_origins("https://marty.example.com", None).unwrap();
    assert!(!parses(&accepted, &dns_only, NOW));
}

#[test]
fn malformed_duplicate_or_ambiguous_records_fail_closed() {
    for records in [
        json!([record(DNS, TOKEN), record(DNS, SECOND_TOKEN)]),
        json!([record(DNS, TOKEN), record(IP, TOKEN)]),
        json!([
            record(DNS, TOKEN),
            record(IP, SECOND_TOKEN),
            record(IP, TOKEN)
        ]),
    ] {
        let mut value = snapshot(NOW);
        value["challenges"] = records;
        assert!(!parses(&value, &allowed(), NOW));
    }
    for field in ["identifier", "token", "key_authorization"] {
        let mut value = snapshot(NOW);
        value["challenges"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(!parses(&value, &allowed(), NOW));
    }
    let mut value = snapshot(NOW);
    value["challenges"][0]["authorization_url"] = json!("https://ca.example/private");
    assert!(!parses(&value, &allowed(), NOW));
    let encoded = serde_json::to_string(&snapshot(NOW)).unwrap();
    for (from, to) in [
        (
            format!("\"created_at\":{NOW}"),
            format!("\"created_at\":{NOW},\"created_at\":{NOW}"),
        ),
        (
            format!("\"token\":\"{TOKEN}\""),
            format!("\"token\":\"{TOKEN}\",\"token\":\"{TOKEN}\""),
        ),
    ] {
        let duplicate = encoded.replace(&from, &to);
        assert_ne!(duplicate, encoded);
        assert!(Snapshot::parse(duplicate.as_bytes(), &allowed(), NOW).is_err());
    }
    assert!(Snapshot::parse(b"not JSON", &allowed(), NOW).is_err());
    assert!(Snapshot::parse(
        &vec![b' '; MAX_SNAPSHOT_BYTES as usize + 1],
        &allowed(),
        NOW
    )
    .is_err());
}

#[test]
fn token_and_key_authorization_are_exact_public_base64url_values() {
    for token in [
        "a".repeat(21),
        "a".repeat(257),
        format!("{TOKEN}="),
        format!("{TOKEN}/"),
        format!("{TOKEN}%2f"),
        format!("{TOKEN}."),
        format!("{TOKEN}\n"),
    ] {
        let mut value = snapshot(NOW);
        value["challenges"][0] = record(DNS, &token);
        assert!(!parses(&value, &allowed(), NOW), "invalid token");
    }
    let mut longest = snapshot(NOW);
    longest["challenges"][0] = record(DNS, &"a".repeat(256));
    assert!(parses(&longest, &allowed(), NOW));
    for authorization in [
        format!("{SECOND_TOKEN}.{THUMBPRINT}"),
        format!("{TOKEN}.{}", "A".repeat(42)),
        format!("{TOKEN}.{}", "A".repeat(44)),
        format!("{TOKEN}.{}+", "A".repeat(42)),
        format!("{TOKEN}.{THUMBPRINT}.suffix"),
        format!("{TOKEN}.{}B", "A".repeat(42)),
    ] {
        let mut value = snapshot(NOW);
        value["challenges"][0]["key_authorization"] = authorization.into();
        assert!(!parses(&value, &allowed(), NOW));
    }
}

#[test]
fn host_admission_uses_exact_http_authorities_and_ignores_forwarded_identity() {
    let allowed = allowed();
    for host in [DNS, "marty.example.com:80", IP, "203.0.113.10:80"] {
        let mut value = request(host, TOKEN);
        value.headers_mut().insert(
            "forwarded",
            "host=other.example;proto=https".parse().unwrap(),
        );
        value
            .headers_mut()
            .insert("x-forwarded-host", "other.example".parse().unwrap());
        assert!(
            allowed
                .request(value.method(), value.headers(), value.uri())
                .is_some(),
            "{host}"
        );
    }
    for host in [
        "other.example.com",
        "MARTY.example.com",
        "marty.example.com.",
        "marty.example.com:443",
        "marty.example.com:8443",
        "marty.example.com:080",
        "marty.example.com:80:80",
        "name@marty.example.com",
        "203.0.113.11",
        "203.000.113.10",
        "203.0.113.10:8080",
    ] {
        let mut value = request(host, TOKEN);
        value
            .headers_mut()
            .insert("x-forwarded-host", DNS.parse().unwrap());
        assert!(
            allowed
                .request(value.method(), value.headers(), value.uri())
                .is_none(),
            "{host}"
        );
    }
    let mut duplicate = request(DNS, TOKEN);
    duplicate
        .headers_mut()
        .append(header::HOST, DNS.parse().unwrap());
    assert!(allowed
        .request(duplicate.method(), duplicate.headers(), duplicate.uri())
        .is_none());
    duplicate.headers_mut().remove(header::HOST);
    assert!(allowed
        .request(duplicate.method(), duplicate.headers(), duplicate.uri())
        .is_none());
    for (url, admitted) in [
        (format!("http://{DNS}{PATH_PREFIX}{TOKEN}"), true),
        (format!("http://{DNS}:80{PATH_PREFIX}{TOKEN}"), true),
        (format!("https://{DNS}{PATH_PREFIX}{TOKEN}"), false),
        (
            format!("http://other.example.com{PATH_PREFIX}{TOKEN}"),
            false,
        ),
    ] {
        let value = Request::builder()
            .uri(url)
            .header(header::HOST, DNS)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            allowed
                .request(value.method(), value.headers(), value.uri())
                .is_some(),
            admitted
        );
    }
}

#[test]
fn ipv6_has_unbracketed_snapshot_identity_and_bracketed_http_authority() {
    let allowed = AllowedIdentifiers::from_origins(
        "https://marty.example.com",
        Some("https://[2001:db8::10]:8443"),
    )
    .unwrap();
    for host in ["[2001:db8::10]", "[2001:db8::10]:80"] {
        assert_eq!(allowed.identifier_for_authority(host), Some("2001:db8::10"));
    }
    for host in [
        "2001:db8::10",
        "2001:db8::10:80",
        "[2001:0db8::10]",
        "[2001:db8::10]:443",
        "[2001:db8::11]",
    ] {
        assert!(allowed.identifier_for_authority(host).is_none());
    }
    let mut value = snapshot(NOW);
    value["challenges"][1]["identifier"] = json!("2001:db8::10");
    assert!(parses(&value, &allowed, NOW));
    value["challenges"][1]["identifier"] = json!("[2001:db8::10]");
    assert!(!parses(&value, &allowed, NOW));
}

#[test]
fn configuration_cannot_admit_an_unconfigured_identity_or_privileged_listener() {
    for canonical in [
        "https://203.0.113.10",
        "https://localhost",
        "https://marty",
        "http://marty.example.com",
        "https://marty.example.com/",
    ] {
        assert!(AllowedIdentifiers::from_origins(canonical, None).is_err());
    }
    for alias in [
        "https://other.example.com",
        "https://127.0.0.1",
        "https://[::1]",
        "http://203.0.113.10",
        "https://203.0.113.10/",
    ] {
        assert!(
            AllowedIdentifiers::from_origins("https://marty.example.com", Some(alias)).is_err()
        );
    }
    for bind in [
        "0.0.0.0:0",
        "0.0.0.0:80",
        "127.0.0.1:1023",
        "224.0.0.1:8080",
        "255.255.255.255:8080",
        "[::ffff:127.0.0.1]:8080",
    ] {
        assert!(validate_bind(bind).is_err(), "{bind}");
    }
    for bind in ["0.0.0.0:8080", "127.0.0.1:18080", "[::]:8080"] {
        assert!(validate_bind(bind).is_ok());
    }
}

#[test]
fn projection_reloads_atomic_replacements_and_fails_closed_on_bad_files() {
    let dir = tempfile::tempdir().unwrap();
    let held = Directory::open(dir.path()).unwrap();
    let pathname = dir.path().join(SNAPSHOT_BASENAME);
    assert!(held.read(&allowed(), NOW).is_err());
    publish(dir.path(), &snapshot(NOW));
    assert_eq!(held.read(&allowed(), NOW).unwrap().challenges.len(), 2);
    let mut changed = snapshot(NOW);
    changed["challenges"] = json!([record(DNS, &"z".repeat(24))]);
    publish(dir.path(), &changed);
    assert_eq!(
        held.read(&allowed(), NOW).unwrap().challenges[0].token,
        "z".repeat(24)
    );
    assert!(held.read(&allowed(), NOW + 300).is_err());

    for data in [
        Vec::new(),
        vec![b' '; MAX_SNAPSHOT_BYTES as usize + 1],
        b"{broken".to_vec(),
    ] {
        fs::write(&pathname, data).unwrap();
        assert!(held.read(&allowed(), NOW).is_err());
    }
    publish(dir.path(), &snapshot(NOW));
    fs::set_permissions(&pathname, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(held.read(&allowed(), NOW).is_err());
    fs::remove_file(&pathname).unwrap();
    fs::create_dir(&pathname).unwrap();
    assert!(held.read(&allowed(), NOW).is_err());
    fs::remove_dir(&pathname).unwrap();
    let other = dir.path().join("other.json");
    fs::write(&other, serde_json::to_vec(&snapshot(NOW)).unwrap()).unwrap();
    symlink(&other, &pathname).unwrap();
    assert!(held.read(&allowed(), NOW).is_err());
    fs::remove_file(&pathname).unwrap();
    fs::hard_link(&other, &pathname).unwrap();
    assert!(held.read(&allowed(), NOW).is_err());
    fs::remove_file(&pathname).unwrap();
    let fifo = CString::new(pathname.as_os_str().as_bytes()).unwrap();
    // SAFETY: the nul-terminated path is valid throughout mkfifo, and the
    // temporary directory belongs to this test only.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(
        held.read(&allowed(), NOW).is_err(),
        "FIFO must not block waiting for a writer"
    );
}

#[test]
fn projection_directory_rejects_symlinks_in_every_component() {
    let temp = tempfile::tempdir().unwrap();
    let actual = temp.path().join("actual");
    fs::create_dir(&actual).unwrap();
    let alias = temp.path().join("alias");
    symlink(&actual, &alias).unwrap();
    assert!(Directory::open(&alias).is_err());
    fs::create_dir(actual.join("child")).unwrap();
    assert!(Directory::open(&alias.join("child")).is_err());
    assert!(Directory::open(&PathBuf::from("relative")).is_err());
    fs::set_permissions(&actual, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Directory::open(&actual).is_err());
}

#[tokio::test]
async fn handler_serves_public_proof_and_nothing_else_without_tls_or_kms() {
    let dir = tempfile::tempdir().unwrap();
    let state = Responder::open(dir.path(), allowed()).unwrap();
    assert_eq!(
        handle(State(state.clone()), request(DNS, TOKEN))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    publish(dir.path(), &snapshot(now));
    for (host, token) in [
        (DNS, TOKEN),
        ("marty.example.com:80", TOKEN),
        (IP, SECOND_TOKEN),
        ("203.0.113.10:80", SECOND_TOKEN),
    ] {
        let mut value = request(host, token);
        value
            .headers_mut()
            .insert(header::COOKIE, "session=ignored".parse().unwrap());
        value
            .headers_mut()
            .insert(header::AUTHORIZATION, "Bearer ignored".parse().unwrap());
        let response = handle(State(state.clone()), value).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert!(!response.headers().contains_key(header::LOCATION));
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), format!("{token}.{THUMBPRINT}").as_bytes());
    }
    for (host, token) in [
        ("unknown.example.com", TOKEN),
        (DNS, SECOND_TOKEN),
        (IP, TOKEN),
        (DNS, "unknownabcdefghijklmnop"),
    ] {
        assert_eq!(
            handle(State(state.clone()), request(host, token))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    for method in [
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
    ] {
        let mut value = request(DNS, TOKEN);
        *value.method_mut() = method;
        assert_eq!(
            handle(State(state.clone()), value).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    for path in [
        "/".into(),
        "/health".into(),
        "/ready".into(),
        "/admin".into(),
        "/v1/auth/me".into(),
        format!("{PATH_PREFIX}{TOKEN}?query=1"),
        format!("{PATH_PREFIX}{TOKEN}/"),
        format!("{PATH_PREFIX}../{TOKEN}"),
        format!("{PATH_PREFIX}%2e%2e/{TOKEN}"),
        format!("{PATH_PREFIX}{TOKEN}%2f"),
        format!("/.well-known//acme-challenge/{TOKEN}"),
        format!("{PATH_PREFIX}{TOKEN}\\suffix"),
    ] {
        let value = Request::builder()
            .uri(path)
            .header(header::HOST, DNS)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            handle(State(state.clone()), value).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    for (name, value) in [
        (header::UPGRADE, "websocket"),
        (header::TRANSFER_ENCODING, "chunked"),
        (header::CONTENT_LENGTH, "1"),
    ] {
        let mut request = request(DNS, TOKEN);
        request.headers_mut().insert(name, value.parse().unwrap());
        assert_eq!(
            handle(State(state.clone()), request).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    publish(dir.path(), &snapshot(now - 301));
    assert_eq!(
        handle(State(state.clone()), request(DNS, TOKEN))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    fs::write(dir.path().join(SNAPSHOT_BASENAME), b"malformed").unwrap();
    assert_eq!(
        handle(State(state), request(DNS, TOKEN)).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn live_http_listener_observes_publication_after_startup() {
    let dir = tempfile::tempdir().unwrap();
    let state = Responder::open(dir.path(), allowed()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, state.router()).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{address}{PATH_PREFIX}{TOKEN}");
    assert_eq!(
        client
            .get(&url)
            .header(header::HOST, DNS)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    publish(dir.path(), &snapshot(now));
    let response = client
        .get(&url)
        .header(header::HOST, DNS)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.unwrap(),
        format!("{TOKEN}.{THUMBPRINT}")
    );
    fs::remove_file(dir.path().join(SNAPSHOT_BASENAME)).unwrap();
    assert_eq!(
        client
            .get(&url)
            .header(header::HOST, DNS)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
}
