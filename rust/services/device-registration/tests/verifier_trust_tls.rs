//! Real TLS transport to an owned loopback owner-response fixture, not a deployed owner.
use marty_device_registration::wallet_issuer_trust::WalletIssuerTrustClient;
use marty_device_registration::wallet_verifier_trust::WalletVerifierTrustClient;

const PROFILE: &str = "00000000-0000-4000-8000-000000000002";

#[tokio::test]
#[ignore = "requires the owned verifier TLS fixture driver"]
async fn fixed_owner_tls_authentication_and_closed_response_controls() {
    let origin = std::env::var("MARTY_VERIFIER_TLS_FIXTURE_ORIGIN").expect("owned TLS origin");
    let parsed = reqwest::Url::parse(&origin).unwrap();
    assert_eq!(parsed.scheme(), "https");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/");
    let ca = std::fs::read(std::env::var("MARTY_VERIFIER_TLS_FIXTURE_CA").unwrap()).unwrap();
    let token = std::env::var("MARTY_VERIFIER_TLS_FIXTURE_TOKEN").unwrap();
    let nonce = std::env::var("MARTY_VERIFIER_TLS_FIXTURE_NONCE").unwrap();
    let certificates = reqwest::Certificate::from_pem_bundle(&ca).unwrap();
    assert!(!certificates.is_empty());
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5));
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    let guard = builder
        .build()
        .unwrap()
        .get(format!("{origin}fixture-guard/{nonce}"))
        .send()
        .await
        .unwrap();
    assert_eq!(guard.status(), reqwest::StatusCode::OK);
    assert_eq!(guard.text().await.unwrap(), nonce);

    let client = WalletVerifierTrustClient::new(&origin, &token, Some(&ca)).unwrap();
    client
        .admit(PROFILE, "org-a", "browser-user")
        .await
        .unwrap();
    let snapshot = client
        .fetch(PROFILE, "org-a", "browser-user", "registered-client")
        .await
        .unwrap();
    assert_eq!(
        snapshot["authority"]["registration"]["client_id"],
        "registered-client"
    );
    let locator =
        "https://verifier.example/v1/flows/instances/11111111-2222-4333-8444-555555555555/request";
    let managed = client
        .fetch_managed(
            PROFILE,
            "org-a",
            "browser-user",
            "decentralized_identifier:did:web:verifier.example",
            locator,
        )
        .await
        .unwrap();
    assert_eq!(managed["contract"], "marty.wallet/verifier-authority/v2");
    assert_eq!(managed["request"]["request_uri"], locator);
    assert!(client
        .fetch_managed(
            PROFILE,
            "org-a",
            "browser-user",
            "decentralized_identifier:did:web:verifier.example",
            "https://attacker.example/request"
        )
        .await
        .is_err());
    assert!(client.admit(PROFILE, "org-a", "other-user").await.is_err());
    assert!(client
        .fetch(PROFILE, "other-org", "browser-user", "registered-client")
        .await
        .is_err());
    let wrong_token = WalletVerifierTrustClient::new(&origin, &"x".repeat(40), Some(&ca)).unwrap();
    assert!(wrong_token
        .admit(PROFILE, "org-a", "browser-user")
        .await
        .is_err());
    for client_id in [
        "redirect",
        "oversized",
        "duplicate",
        "wrong-scope",
        "expired",
        "private-key",
    ] {
        assert!(
            client
                .fetch(PROFILE, "org-a", "browser-user", client_id)
                .await
                .is_err(),
            "{client_id}"
        );
    }
    // The loopback certificate is private to this fixture. No configured CA and
    // a hostname absent from its SAN must both fail certificate validation.
    let untrusted = WalletVerifierTrustClient::new(&origin, &token, None).unwrap();
    assert!(untrusted
        .admit(PROFILE, "org-a", "browser-user")
        .await
        .is_err());
    let wrong_name = origin.replace("127.0.0.1", "localhost");
    let wrong_name = WalletVerifierTrustClient::new(&wrong_name, &token, Some(&ca)).unwrap();
    assert!(wrong_name
        .admit(PROFILE, "org-a", "browser-user")
        .await
        .is_err());
    let issuer_profile = "00000000-0000-4000-8000-000000000003";
    let issuer = WalletIssuerTrustClient::new(&origin, &token, Some(&ca)).unwrap();
    let snapshot = issuer
        .fetch(issuer_profile, "org-a", "browser-user")
        .await
        .unwrap();
    assert_eq!(snapshot["contract"], "marty.wallet/issuer-authority/v2");
    assert_eq!(snapshot["require_not_before"], true);
    assert_eq!(
        snapshot["issuer_keys"][0]["credential_authorizations"][0]["vct"],
        "https://credentials.example/identity"
    );
    for case in [
        "redirect",
        "oversized",
        "duplicate",
        "wrong-scope",
        "expired",
        "private-key",
        "unknown",
        "no-grants",
        "wrong-media",
    ] {
        assert!(
            issuer
                .fetch(issuer_profile, "org-a", &format!("issuer-case-{case}"))
                .await
                .is_err(),
            "{case}"
        );
    }
    assert!(issuer
        .fetch(issuer_profile, "other-org", "browser-user")
        .await
        .is_err());
    assert!(issuer
        .fetch(issuer_profile, "org-a", "other-user")
        .await
        .is_err());
    let wrong_token = WalletIssuerTrustClient::new(&origin, &"x".repeat(40), Some(&ca)).unwrap();
    assert!(wrong_token
        .fetch(issuer_profile, "org-a", "browser-user")
        .await
        .is_err());
    let untrusted = WalletIssuerTrustClient::new(&origin, &token, None).unwrap();
    assert!(untrusted
        .fetch(issuer_profile, "org-a", "browser-user")
        .await
        .is_err());
    let wrong_name =
        WalletIssuerTrustClient::new(&origin.replace("127.0.0.1", "localhost"), &token, Some(&ca))
            .unwrap();
    assert!(wrong_name
        .fetch(issuer_profile, "org-a", "browser-user")
        .await
        .is_err());
}
