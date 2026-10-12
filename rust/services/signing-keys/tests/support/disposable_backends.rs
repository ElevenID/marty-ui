use marty_signing_keys::flow_envelope::OpenBaoEnvelopeProvider;
use redis::AsyncCommands;
use serde_json::Value;

pub async fn disposable_redis_url() -> String {
    let url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let parsed = reqwest::Url::parse(&url).expect("disposable Redis URL syntax");
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1" | "localhost" | "::1")
    ));
    assert!(parsed
        .path()
        .trim_start_matches('/')
        .parse::<u8>()
        .is_ok_and(|db| db >= 13));
    let nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE")
        .expect("disposable Redis sentinel value");
    assert!(nonce.len() >= 16, "disposable Redis sentinel is too short");
    let client = redis::Client::open(url.as_str()).expect("disposable Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("disposable Redis connection");
    let observed: Option<String> = connection
        .get("marty:tests:disposable-guard")
        .await
        .expect("disposable Redis sentinel read");
    assert_eq!(observed.as_deref(), Some(nonce.as_str()));
    url
}

pub async fn disposable_openbao_envelope() -> OpenBaoEnvelopeProvider {
    let url = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    let parsed = reqwest::Url::parse(&url).expect("disposable OpenBao URL syntax");
    assert!(parsed.scheme() == "http" && parsed.host_str() == Some("127.0.0.1"));
    assert_eq!(std::env::var("BAO_TOKEN").as_deref(), Ok(token.as_str()));
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
        .expect("disposable OpenBao sentinel value");
    assert!(nonce.len() >= 16);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let marker: Value = client
        .get(format!("{url}/v1/secret/data/marty-test-disposable-guard"))
        .header("X-Vault-Token", &token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(marker["data"]["data"]["nonce"], nonce);
    OpenBaoEnvelopeProvider::new(url, token).unwrap()
}
