use std::collections::BTreeMap;

use marty_gateway::providers::{DistributedProviderConfig, GatewayDistributedProviders};
use mmf_platform::{
    IdempotencyBegin, IdempotencyRequest, IdempotencyResponse, IdempotencyStore,
    RedisIdempotencyStore,
};
use mmf_security::{
    DistributedRateLimiter, RateLimitQuota, RateLimitRule, RateLimitScope, RateLimitStrategy,
    RedisRateLimiter,
};
use uuid::Uuid;

fn redis_url() -> String {
    std::env::var("MARTY_GATEWAY_TEST_REDIS_URL")
        .expect("MARTY_GATEWAY_TEST_REDIS_URL must identify disposable Redis")
}

#[tokio::test]
#[ignore = "requires disposable Redis; CI runs this test explicitly"]
async fn production_gateway_redis_state_is_atomic_and_replay_safe() {
    let redis_url = redis_url();
    let suffix = Uuid::new_v4().simple().to_string();
    let providers = GatewayDistributedProviders::compose(&DistributedProviderConfig {
        production: true,
        redis_url: Some(redis_url.clone()),
        rate_limit_prefix: format!("marty:test:gateway:rate:{suffix}"),
        idempotency_prefix: format!("marty:test:gateway:idempotency:{suffix}"),
        idempotency_ttl_ms: 10_000,
        idempotency_lock_ttl_ms: 5_000,
    })
    .await
    .expect("compose production Redis providers");
    assert!(providers.redis_backed);

    let limiter = RedisRateLimiter::connect(
        &redis_url,
        format!("marty:test:gateway:strategies:{suffix}"),
    )
    .await
    .expect("connect rate limiter");
    limiter.health_check().await.expect("rate limiter health");
    for strategy in [
        RateLimitStrategy::SlidingWindow,
        RateLimitStrategy::FixedWindow,
        RateLimitStrategy::TokenBucket,
        RateLimitStrategy::LeakyBucket,
    ] {
        let rule = RateLimitRule {
            name: format!("strategy-{strategy:?}-{suffix}"),
            scope: RateLimitScope::PerUser,
            strategy,
            limit: 1,
            window_ms: 10_000,
            burst_size: 0,
            enabled: true,
        };
        let quota = RateLimitQuota {
            user_id: Some("user-1".into()),
            ..RateLimitQuota::default()
        };
        assert!(
            limiter
                .check(&rule, &quota, 1_000)
                .await
                .expect("first rate check")
                .allowed,
            "{strategy:?} first request"
        );
        assert!(
            !limiter
                .check(&rule, &quota, 1_001)
                .await
                .expect("second rate check")
                .allowed,
            "{strategy:?} second request"
        );
    }

    let idempotency = RedisIdempotencyStore::connect(
        &redis_url,
        format!("marty:test:gateway:idempotency-contract:{suffix}"),
        10_000,
        5_000,
    )
    .await
    .expect("connect idempotency store");
    idempotency
        .health_check()
        .await
        .expect("idempotency health");
    let request = IdempotencyRequest {
        principal_id: "user-1".into(),
        key: format!("request-{suffix}"),
        method: "POST".into(),
        path: "/v1/organizations".into(),
        query: String::new(),
        body: br#"{"name":"Example"}"#.to_vec(),
    };
    let lease = match idempotency.begin(&request, 1_000).await.expect("begin") {
        IdempotencyBegin::Started(lease) => lease,
        outcome => panic!("first operation must own lease, got {outcome:?}"),
    };
    assert!(matches!(
        idempotency.begin(&request, 1_001).await.expect("repeat"),
        IdempotencyBegin::InProgress
    ));
    let conflicting = IdempotencyRequest {
        body: br#"{"name":"Different"}"#.to_vec(),
        ..request.clone()
    };
    assert!(matches!(
        idempotency
            .begin(&conflicting, 1_002)
            .await
            .expect("conflict"),
        IdempotencyBegin::Conflict
    ));
    let response = IdempotencyResponse {
        status: 201,
        body: br#"{"id":"org-1"}"#.to_vec(),
        content_type: Some("application/json".into()),
        headers: BTreeMap::from([("location".into(), "/v1/organizations/org-1".into())]),
    };
    idempotency
        .complete(&lease, response.clone(), 1_003)
        .await
        .expect("complete");
    assert_eq!(
        idempotency.begin(&request, 1_004).await.expect("replay"),
        IdempotencyBegin::Replay(response)
    );
}
