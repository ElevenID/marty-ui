use std::collections::HashMap;

use marty_auth::{
    default_wallet_choices, render_credential_login_error_page, render_credential_login_page,
    wallet_choices_from_lookup, CredentialLoginErrorPage, CredentialLoginPageInput,
    CREDENTIAL_LOGIN_CSS, CREDENTIAL_LOGIN_JAVASCRIPT,
};
use sha2::{Digest as _, Sha256};

const OID4VP_URI: &str = "openid4vp://authorize?client_id=decentralized_identifier%3Adid%3Aweb%3Averifier.example&request_uri_method=post&request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1";
const REQUEST_URI: &str = "https://issuer.example/request/1";

#[test]
fn credential_page_matches_the_language_neutral_python_golden_output() {
    let page = render_credential_login_page(
        &CredentialLoginPageInput {
            nonce: "nonce-123".into(),
            flow_instance_id: "flow/one".into(),
            oid4vp_uri: OID4VP_URI.into(),
            request_uri: REQUEST_URI.into(),
        },
        &default_wallet_choices(),
    )
    .unwrap();
    assert_eq!(page.len(), 7_682);
    assert_eq!(
        sha256(&page),
        "1efcd52fdf497d9487d4b08a4c2d8aa2566a0f8d54b04acfcd22a7fa5f9d8eca"
    );
    assert!(page.contains("data-nonce=\"nonce-123\""));
    assert!(page.contains("/v1/flows/instances/flow%2Fone/request?transport=dc_api"));
    assert!(page.contains("<option value=\"sprucekit\""));
    assert!(page.contains("<option value=\"lissi\""));
    assert!(page.contains("(function() {"));
    assert!(!page.contains("(function() {{"));
}

#[test]
fn credential_error_page_matches_the_language_neutral_python_golden_output() {
    let page = render_credential_login_error_page(&CredentialLoginErrorPage {
        title: "Wallet unavailable",
        message: "Try another sign-in method.",
        primary_action_href: "/login?next=a&b=c",
        primary_action_label: "Back to sign in",
        secondary_action_href: "/",
        secondary_action_label: "Home",
        operator_details: "Flow <offline> & retry",
    })
    .unwrap();
    assert_eq!(page.len(), 1_306);
    assert_eq!(
        sha256(&page),
        "4b6d7e311c016969111804874cb217e23ee0a55be6ab3d07f217ad46e126cec6"
    );
    assert!(page.contains("/login?next=a&amp;b=c"));
    assert!(page.contains("Flow &lt;offline&gt; &amp; retry"));
}

#[test]
fn static_assets_are_compiled_from_the_shared_service_files() {
    assert_eq!(
        CREDENTIAL_LOGIN_CSS,
        include_str!("../../../../services/auth/assets/credential-login.css")
    );
    assert_eq!(
        CREDENTIAL_LOGIN_JAVASCRIPT,
        include_str!("../../../../services/auth/assets/credential-login.js")
    );
    assert!(CREDENTIAL_LOGIN_CSS.contains(".status-detail"));
    assert!(CREDENTIAL_LOGIN_JAVASCRIPT.contains("credential_login.wallet"));
}

#[test]
fn every_legacy_operator_wallet_override_is_preserved() {
    let values = HashMap::from([
        (
            "CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE",
            "spruce://{oid4vp_uri_encoded}",
        ),
        (
            "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
            "spruce-android://{request_uri_encoded}",
        ),
        (
            "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_DEEP_LINK_TEMPLATE",
            "spruce-ios://deep/{oid4vp_uri_encoded}",
        ),
        (
            "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
            "https://spruce.example/{oid4vp_uri_encoded}",
        ),
        (
            "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE",
            "example.spruce",
        ),
        (
            "CREDENTIAL_LOGIN_LUCY_DEEP_LINK_TEMPLATE",
            "legacy-lissi://{oid4vp_uri_encoded}",
        ),
        (
            "CREDENTIAL_LOGIN_LISSI_ANDROID_DEEP_LINK_TEMPLATE",
            "lissi-android://{request_uri_encoded}",
        ),
        (
            "CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE",
            "lissi-ios://{oid4vp_uri_encoded}",
        ),
        ("CREDENTIAL_LOGIN_LISSI_ANDROID_PACKAGE", "example.lissi"),
    ]);
    let choices = wallet_choices_from_lookup(|name| values.get(name).map(ToString::to_string));
    assert_eq!(choices[0].generic_template, "spruce://{oid4vp_uri_encoded}");
    assert_eq!(
        choices[0].ios_template,
        "https://spruce.example/{oid4vp_uri_encoded}"
    );
    assert_eq!(choices[0].android_package, "example.spruce");
    assert_eq!(
        choices[1].generic_template,
        "legacy-lissi://{oid4vp_uri_encoded}"
    );
    assert_eq!(choices[1].android_package, "example.lissi");
}

fn sha256(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
