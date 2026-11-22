//! Actual binary/config/connect/listener gate using disposable PostgreSQL roles,
//! real TLS OpenBao/Redis/Signing Keys, and explicitly read-only wire fixtures.
//! This does not call assemble(), sign a request/receipt, qualify the real
//! policy/template owner services, or qualify a production deployment.
#![allow(dead_code)] // Existing owner support is shared with the lifecycle suite.

use axum::http::StatusCode;
use serde_json::json;
use std::sync::atomic::Ordering;

#[path = "support/live_signing.rs"]
mod live_signing;
#[path = "support/live_support.rs"]
mod live_support;
#[path = "support/live_wire.rs"]
mod live_wire;
mod support;

use live_support::{
    available_address, caller, environment, provider_calls, rejected_before_listen, setting,
    Executable, Server,
};
use support::{database::Database, owned::Owned, TestResult};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit disposable PostgreSQL/OpenBao/Redis live-runtime wrapper"]
async fn actual_executable_qualifies_remote_readiness_mtls_and_fail_closed_startup() -> TestResult {
    assert_eq!(setting("MARTY_TEST_DELEGATED_USE_LIVE"), "true");
    marty_service_runtime::install_tls_crypto_provider();
    let db = Database::new().await?;
    let owned = Owned::seed(&db.admin).await?;
    let mut keys = live_signing::SigningKeys::start(owned.organization).await?;
    let reads = live_wire::Reads::default();
    let (mut template, mut policy) = live_wire::readers(&owned, &reads).await?;
    let mut references = Server::https(live_wire::reference_health(&reads)).await?;
    let env = environment(&owned, &db, &keys, &template, &policy, &references)?;
    let no_business_signing = [
        format!("transit/sign/{}", keys.key),
        "transit/sign/receipt-ed25519".into(),
        "transit/hmac/marty-sign-grant-flow-wallet-v1/sha2-256".into(),
        "transit/hmac/marty-sign-grant-delegated-decision-v1/sha2-256".into(),
    ]
    .into_iter()
    .map(|path| Ok((path.clone(), provider_calls(&path)?)))
    .collect::<TestResult<Vec<_>>>()?;
    let host_tls_path = format!(
        "transit/sign/{}",
        setting("MARTY_TEST_USE_SERVER_TLS_KMS_KEY_NAME")
    );
    let tls_before = provider_calls(&host_tls_path)?;

    // Even a complete usable configuration remains disabled before all I/O.
    let mut disabled = env.clone();
    disabled.remove("MARTY_DELEGATED_USE_ENABLED");
    disabled.insert(
        "DELEGATED_USE_TLS_CERT_FILE".into(),
        "/unreadable-disabled-public-certificate".into(),
    );
    rejected_before_listen(
        &disabled,
        "requires explicit MARTY_DELEGATED_USE_ENABLED=true",
    )
    .await?;

    let mut executable = Executable::start(&env).await?;
    let client = caller(None).await?;
    let origin = format!("https://{}", env["DELEGATED_USE_LISTEN_ADDR"]);
    for route in ["/health", "/ready"] {
        let response = client.get(format!("{origin}{route}")).send().await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(response.headers().get("pragma").unwrap(), "no-cache");
        assert!(response.bytes().await?.is_empty());
    }
    assert!(reads.policy.load(Ordering::SeqCst) >= 3);
    assert!(reads.template.load(Ordering::SeqCst) >= 3);
    assert!(reads.health.load(Ordering::SeqCst) >= 8);

    // This is the actual mounted receipt route. An exact absent original is a
    // read-only 404, not a receipt lifecycle fixture or permission to retry work.
    let receipt_route = format!(
        "{origin}/internal/v1/organizations/{}/delegated-use/receipts/recover",
        owned.organization
    );
    let recovery = json!({
        "profile": marty_delegated_authority::DELEGATION_COMMAND_PROFILE,
        "command": "RECOVER_RESULT",
        "original_command_id": uuid::Uuid::new_v4(),
        "expected_command_digest": format!("sha256:{}", "ab".repeat(32)),
    });
    let response = client.post(&receipt_route).json(&recovery).send().await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(response.headers().get("pragma").unwrap(), "no-cache");
    assert_eq!(
        response.json::<serde_json::Value>().await?["detail"],
        "delegation_use_result_not_found"
    );
    let finalize = json!({
        "profile": marty_delegated_authority::DELEGATION_COMMAND_PROFILE,
        "command": "FINALIZE_USE",
        "command_id": uuid::Uuid::new_v4(),
        "challenge_id": uuid::Uuid::new_v4(),
        "proof_submission_id": uuid::Uuid::new_v4(),
    });
    let response = client.post(&receipt_route).json(&finalize).send().await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");

    // A CA-valid unlisted leaf still cannot act as a registered machine.
    let unknown = caller(Some(setting("MARTY_TEST_USE_UNMAPPED_CALLER_CERT_FILE"))).await?;
    for route in ["/health", "/ready"] {
        assert_eq!(
            unknown
                .get(format!("{origin}{route}"))
                .send()
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        unknown
            .post(&receipt_route)
            .json(&recovery)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let no_certificate = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_der(&std::fs::read(setting(
            "MARTY_TEST_USE_CA_DER_FILE",
        ))?)?)
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    assert!(no_certificate
        .get(format!("{origin}/health"))
        .send()
        .await
        .is_err());
    for (name, value) in [
        ("x-service-token", live_support::SERVICE_TOKEN),
        ("x-marty-use-principal-id", owned.principal.id.as_str()),
        ("x-forwarded-client-cert", "fixture-certificate-header"),
        ("authorization", "Bearer fixture-unused"),
    ] {
        assert_eq!(
            client
                .get(format!("{origin}/ready"))
                .header(name, value)
                .send()
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .post(&receipt_route)
                .header(name, value)
                .json(&recovery)
                .send()
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        client
            .get(format!("{origin}/ready?override=true"))
            .send()
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        provider_calls(&host_tls_path)? > tls_before,
        "actual remote TLS signer was not exercised"
    );

    // Current privilege drift is detected by the real readiness route, and a
    // fresh process with that drift must not open its TCP listener.
    db.sql(format!(
        "GRANT UPDATE ON delegated_authority_service.delegation_grants TO {}",
        db.roles["use_writer"]
    ))
    .await?;
    assert_eq!(
        client.get(format!("{origin}/ready")).send().await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    executable.close().await?;
    rejected_before_listen(&env, "runtime qualification failed before listening").await?;
    db.sql(format!(
        "REVOKE UPDATE ON delegated_authority_service.delegation_grants FROM {}",
        db.roles["use_writer"]
    ))
    .await?;

    for (field, value) in [
        (
            "DELEGATED_USE_SERVICE_TOKEN",
            "unaccepted-wire-service-token-00000000001".into(),
        ),
        (
            "DELEGATED_USE_WORKLOAD_TLS_CERT_FILE",
            setting("MARTY_TEST_POLICY_FLOW_CLIENT_WRONG_URI_CERT_FILE"),
        ),
        (
            "DELEGATED_USE_CREDENTIAL_TEMPLATE_GRPC_TARGET",
            format!("https://{}", available_address()?),
        ),
        // A different valid public point keeps configuration valid and tests
        // the actual remote resolver's exact selected-key comparison.
        (
            "DELEGATED_USE_RECEIPT_PUBLIC_JWK",
            support::crypto::public_jwk(&support::crypto::signing_key()).to_string(),
        ),
    ] {
        let mut invalid = env.clone();
        invalid.insert(field.into(), value);
        rejected_before_listen(&invalid, "runtime qualification failed before listening").await?;
    }

    // A pin mismatch uses the same CA and same workload URI; only the configured
    // certificate digest changes. No service/header fallback can make it valid.
    let mut wrong_pin = env.clone();
    wrong_pin.insert(
        "DELEGATED_USE_WORKLOAD_BINDINGS".into(),
        json!([{
            "workload_uri":setting("MARTY_TEST_USE_CALLER_URI"),
            "leaf_sha256":format!("sha256:{}", "77".repeat(32)),
            "principal_id":owned.principal.id,
        }])
        .to_string(),
    );
    let mut restarted = Executable::start(&wrong_pin).await?;
    assert_eq!(
        client
            .get(format!("{origin}/health"))
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    restarted.close().await?;

    for (path, before) in no_business_signing {
        assert_eq!(
            provider_calls(&path)?,
            before,
            "readiness used business signing authority"
        );
    }
    let writes: (i64,) =
        sqlx::query_as("SELECT count(*) FROM delegated_authority_service.use_command_claims")
            .fetch_one(&db.admin)
            .await?;
    assert_eq!(writes.0, 0, "startup probes created a command claim");
    drop((client, unknown, no_certificate));
    template.close().await?;
    policy.close().await?;
    references.close().await?;
    keys.server.close().await?;
    db.close().await;
    Ok(())
}
