use std::collections::BTreeMap;

use marty_auth::{
    oidc_config_from_values, oidc_preflight_config_from_values, validate_ui_locales,
    OidcAuthenticationFreshness, OidcClientAuthMethod, OidcMaxAge, OidcPrompt, OidcUserInfoMode,
};
use serde_json::json;

fn external() -> BTreeMap<String, String> {
    [
        ("OIDC_PROVIDER_MODE", "external"),
        ("OIDC_ISSUER_URL", "https://identity.example"),
        ("OIDC_CLIENT_ID", "client"),
        ("OIDC_REDIRECT_URI", "https://ui.example/v1/auth/callback"),
    ]
    .into_iter()
    .map(|(name, value)| (name.into(), value.into()))
    .collect()
}

#[test]
fn explicit_api_callback_origin_binds_full_and_metadata_only_oidc_configuration() {
    let mut values = external();
    values.remove("OIDC_REDIRECT_URI");
    values.insert("UI_BASE_URL".into(), "https://console.example".into());
    values.insert(
        "AUTH_PUBLIC_API_ORIGIN".into(),
        "https://api.example/".into(),
    );
    assert_eq!(
        oidc_config_from_values(values.clone())
            .unwrap()
            .redirect_uri,
        "https://api.example/v1/auth/callback"
    );
    assert!(oidc_preflight_config_from_values(values.clone()).is_ok());
    values.insert(
        "OIDC_REDIRECT_URI".into(),
        "https://console.example/v1/auth/callback".into(),
    );
    assert!(oidc_config_from_values(values.clone()).is_err());
    assert!(oidc_preflight_config_from_values(values.clone()).is_err());
    values.insert(
        "OIDC_REDIRECT_URI".into(),
        "https://api.example/v1/auth/callback".into(),
    );
    assert!(oidc_config_from_values(values.clone()).is_ok());
    values.insert("AUTH_PUBLIC_API_ORIGIN".into(), "http://api.example".into());
    assert!(oidc_config_from_values(values).is_err());
}

#[test]
fn oidc_only_configuration_needs_no_database_and_preserves_legacy_defaults() {
    let values = external();
    let config = oidc_config_from_values(values.clone()).unwrap();
    assert_eq!(
        config.selected_client_auth_method(),
        OidcClientAuthMethod::None
    );
    assert_eq!(config.prompt, [OidcPrompt::Consent, OidcPrompt::Login]);
    assert_eq!(config.max_age, OidcMaxAge::Seconds(0));
    assert_eq!(config.userinfo_mode, OidcUserInfoMode::Disabled);
    assert!(config.provider_name.is_none());
    let mut values = values;
    values.insert("OIDC_CLIENT_SECRET".into(), "synthetic-secret".into());
    assert_eq!(
        oidc_config_from_values(values.clone())
            .unwrap()
            .selected_client_auth_method(),
        OidcClientAuthMethod::ClientSecretPost
    );
    values.insert("OIDC_TOKEN_ENDPOINT_AUTH_METHOD".into(), String::new());
    assert_eq!(
        oidc_config_from_values(values)
            .unwrap()
            .selected_client_auth_method(),
        OidcClientAuthMethod::ClientSecretPost
    );
}

#[test]
fn metadata_preflight_needs_no_secret_while_runtime_still_requires_one() {
    let mut inherited = external();
    inherited.insert(
        "OIDC_CLIENT_SECRET_FILE".into(),
        "/nonexistent/private/secret".into(),
    );
    assert!(oidc_preflight_config_from_values(inherited).is_err());
    for method in ["client_secret_post", "client_secret_basic"] {
        let mut values = external();
        values.insert("OIDC_TOKEN_ENDPOINT_AUTH_METHOD".into(), method.into());
        values.insert(
            "OIDC_CLIENT_SECRET_FILE".into(),
            "/nonexistent/private/secret".into(),
        );
        assert!(oidc_preflight_config_from_values(values.clone()).is_ok());
        assert!(oidc_config_from_values(values.clone()).is_err());
        values.insert("OIDC_CLIENT_SECRET".into(), String::new());
        assert!(oidc_preflight_config_from_values(values.clone()).is_ok());
        assert!(oidc_config_from_values(values).is_err());
    }
}

#[test]
fn explicit_policy_preserves_empty_prompt_and_validates_new_configuration() {
    let mut values = external();
    values.insert("OIDC_CLIENT_SECRET".into(), "synthetic-secret".into());
    values.insert(
        "OIDC_TOKEN_ENDPOINT_AUTH_METHOD".into(),
        "client_secret_basic".into(),
    );
    values.insert("OIDC_PROMPT".into(), String::new());
    values.insert("OIDC_MAX_AGE_SECONDS".into(), "omit".into());
    values.insert("OIDC_USERINFO_MODE".into(), "fallback".into());
    let config = oidc_config_from_values(values.clone()).unwrap();
    assert!(config.prompt.is_empty());
    assert_eq!(config.max_age, OidcMaxAge::Omit);
    assert_eq!(
        config.selected_client_auth_method(),
        OidcClientAuthMethod::ClientSecretBasic
    );
    assert_eq!(config.userinfo_mode, OidcUserInfoMode::Fallback);
    for (name, value) in [
        ("OIDC_TOKEN_ENDPOINT_AUTH_METHOD", "private_key_jwt"),
        ("OIDC_PROMPT", "none login"),
        ("OIDC_PROMPT", "login login"),
        ("OIDC_PROMPT", "create"),
        ("OIDC_MAX_AGE_SECONDS", "86401"),
        ("OIDC_MAX_AGE_SECONDS", "-1"),
        ("OIDC_MAX_AGE_SECONDS", "1.5"),
        ("OIDC_USERINFO_MODE", "always"),
        ("OIDC_PROVIDER_NAME", " bad name"),
        ("OIDC_ACCOUNT_URL", "https://foreign.example/account"),
    ] {
        let mut invalid = values.clone();
        invalid.insert(name.into(), value.into());
        assert!(oidc_config_from_values(invalid).is_err(), "{name}: {value}");
    }
}

#[test]
fn locale_validation_rejects_control_parameter_and_size_abuse() {
    for value in ["en", "fr-CA en", "zh-Hant-TW", "pt-BR"] {
        assert_eq!(validate_ui_locales(value).unwrap(), value);
    }
    for value in [
        "",
        " en",
        "en ",
        "en  fr",
        "en\nfr",
        "en_US",
        "en&prompt=none",
        "en/en",
        "en EN",
        "a",
        "en-",
    ] {
        assert!(validate_ui_locales(value).is_err(), "{value:?}");
    }
    assert!(validate_ui_locales(&"en".repeat(65)).is_err());
    assert!(validate_ui_locales("en fr de es it pt nl sv da").is_err());
}

#[test]
fn freshness_accepts_consent_delay_but_rejects_missing_old_future_and_wrong_type_claims() {
    let policy = OidcAuthenticationFreshness {
        max_age_seconds: 60,
        leeway_seconds: 30,
    };
    let started = 1_800_000_000_i64;
    for auth_time in [started - 90, started, started + 240] {
        assert!(policy
            .validate(
                &json!({"auth_time": auth_time, "iat": started + 240}),
                started,
                started + 300
            )
            .is_ok());
    }
    for claims in [
        json!({"iat": started}),
        json!({"auth_time": started - 91, "iat": started}),
        json!({"auth_time": started + 331, "iat": started + 331}),
        json!({"auth_time": started + 40, "iat": started}),
        json!({"auth_time": started.to_string(), "iat": started}),
        json!({"auth_time": 0, "iat": started}),
    ] {
        assert!(policy.validate(&claims, started, started + 300).is_err());
    }
}
