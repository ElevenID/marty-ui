//! Guarded disposable Redis proof for server-owned pairing tickets.

use marty_device_registration::pairing_ticket::{PairingTicketRepository, RedisPairingTickets};
use redis::aio::ConnectionManager;

#[tokio::test]
#[ignore = "requires guarded disposable Redis and nonce sentinel"]
async fn pairing_token_is_not_stored_and_redeems_once_under_race() {
    let url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let parsed = reqwest::Url::parse(&url).expect("Redis URL syntax");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/13");
    let nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE").expect("guard nonce");
    let client = redis::Client::open(url.as_str()).expect("disposable Redis client");
    let mut connection = ConnectionManager::new(client)
        .await
        .expect("Redis connection");
    let guard: String = redis::cmd("GET")
        .arg("marty:tests:disposable-guard")
        .query_async(&mut connection)
        .await
        .expect("read disposable sentinel");
    assert_eq!(guard, nonce);

    let store = RedisPairingTickets::connect(&url, 300)
        .await
        .expect("pairing Redis store");
    let ticket = store
        .issue("user-a", "org-a")
        .await
        .expect("pairing ticket");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("device-registration:pairing:*")
        .query_async(&mut connection)
        .await
        .expect("disposable pairing inventory");
    assert_eq!(keys.len(), 1);
    assert!(!keys[0].contains(&ticket.token));
    let stored: String = redis::cmd("GET")
        .arg(&keys[0])
        .query_async(&mut connection)
        .await
        .expect("scoped record");
    assert!(!stored.contains(&ticket.token));
    let ttl: i64 = redis::cmd("TTL")
        .arg(&keys[0])
        .query_async(&mut connection)
        .await
        .expect("pairing TTL");
    assert!((1..=300).contains(&ttl));
    let (first, second) = tokio::join!(store.take(&ticket.token), store.take(&ticket.token));
    let winners = [first.unwrap(), second.unwrap()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(winners, vec![ticket.scope]);
    let remaining: i64 = redis::cmd("EXISTS")
        .arg(&keys[0])
        .query_async(&mut connection)
        .await
        .expect("consumed ticket absent");
    assert_eq!(remaining, 0);
}
