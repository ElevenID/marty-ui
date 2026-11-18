use marty_auth::{build_wallet_options, default_wallet_choices, render_wallet_link};

const REQUEST_URI: &str = "https://issuer.example/request/1";
const DID_OUTER: &str = "openid4vp://authorize?client_id=decentralized_identifier%3Adid%3Aweb%3Averifier.example&request_uri_method=post&request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1";

#[test]
fn default_wallet_links_match_the_python_protocol_contract() {
    let options = build_wallet_options(DID_OUTER, REQUEST_URI, &default_wallet_choices()).unwrap();
    assert_eq!(options.len(), 2);
    assert_eq!(options[0].id, "sprucekit");
    assert_eq!(options[0].href, DID_OUTER);
    assert_eq!(options[0].android_href, "intent://authorize?client_id=decentralized_identifier%3Adid%3Aweb%3Averifier.example&request_uri_method=post&request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1#Intent;scheme=openid4vp;package=com.spruceid.mobilesdkexample;end");
    assert_eq!(options[1].id, "lissi");
    assert_eq!(options[1].href, "openid4vp://authorize?client_id=did%3Aweb%3Averifier.example&request_uri_method=post&request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1%3Fcompat%3Dlissi");
}

#[test]
fn lissi_is_hidden_for_non_did_identity_and_stale_template_values_are_removed() {
    let outer = "openid4vp://authorize?client_id=https%3A%2F%2Fverifier.example%2Fcallback&request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1";
    let options = build_wallet_options(outer, REQUEST_URI, &default_wallet_choices()).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].id, "sprucekit");
    let rendered = render_wallet_link(
        "walletapp://authorize?client_id=stale&request_uri_method=post&request_uri=stale",
        outer,
        REQUEST_URI,
        "",
    )
    .unwrap();
    assert!(rendered.contains("client_id=https%3A%2F%2Fverifier.example%2Fcallback"));
    assert!(rendered.contains("request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"));
    assert!(!rendered.contains("request_uri_method"));
    assert!(!rendered.contains("stale"));
}

#[test]
fn malformed_or_ambiguous_outer_requests_fail_closed() {
    for outer in [
        "openid4vp://authorize?client_id=did%3Aexample%3A1",
        "openid4vp://authorize?request_uri=a&request_uri=b",
        "openid4vp://authorize?request_uri=a&request_uri_method=POST",
    ] {
        assert!(build_wallet_options(outer, "a", &default_wallet_choices()).is_err());
    }
    assert!(build_wallet_options(
        DID_OUTER,
        "https://attacker.example/request",
        &default_wallet_choices()
    )
    .is_err());
}
