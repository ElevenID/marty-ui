//! Pure public routing/authorization contract; no provider, Redis or network.
use marty_gateway::authorization::{api_key_allowed, resolve_action};
#[test]
fn mdoc_ceremonies_never_inherit_passport_or_generic_signing_authority() {
    for (path, required) in [
        (
            "/v1/signing-keys/issuer-identities/mdoc-iaca-self-signed-certificate",
            "mdoc-certificate:issue-iaca",
        ),
        (
            "/v1/signing-keys/issuer-identities/mdoc-dsc-certificate",
            "mdoc-certificate:issue",
        ),
    ] {
        assert_eq!(resolve_action("POST", path).unwrap().permission, required);
        for scopes in [
            vec!["admin:full".into()],
            vec![required.into()],
            vec!["signing-key:create".into()],
            vec!["passport-certificate:issue".into()],
        ] {
            assert!(!api_key_allowed(required, &scopes));
        }
    }
    assert_eq!(
        resolve_action("POST", "/v1/signing-keys/issuer-identities/dsc-certificate")
            .unwrap()
            .permission,
        "passport-certificate:issue"
    );
    assert_eq!(
        resolve_action(
            "POST",
            "/v1/signing-keys/issuer-identities/csca-self-signed-certificate"
        )
        .unwrap()
        .permission,
        "passport-certificate:issue-csca"
    );
}
