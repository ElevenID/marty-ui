use base64::Engine as _;
use chrono::Utc;
use marty_auth::{
    build_session_impersonation, build_ui_redirect_url, oidc_callback_url,
    resolve_post_auth_redirect, sanitize_redirect_uri, AuthenticatedUser, Session, SessionSpec,
    UiOriginPolicy, UserType,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    redirect_cases: Vec<RedirectCase>,
    origin_cases: Vec<OriginCase>,
    impersonation_cases: Vec<ImpersonationCase>,
}

#[derive(Deserialize)]
struct RedirectCase {
    ui_base_url: String,
    redirect_uri: Option<String>,
    sanitized: String,
    resolved: String,
    absolute: String,
}

#[derive(Deserialize)]
struct OriginCase {
    primary: String,
    additional: Vec<String>,
    forwarded_host: String,
    forwarded_proto: String,
    selected: String,
}

#[derive(Deserialize)]
struct ImpersonationCase {
    user_id: String,
    email: String,
    organization_id: String,
    organization_name: String,
    claims: Value,
    handoff: Option<Value>,
    expected: Option<Value>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../../contracts/auth-http-kernels-behavior.json"
    ))
    .expect("valid Auth HTTP kernel fixture")
}

#[test]
fn redirect_and_origin_selection_match_the_language_neutral_contract() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    for case in fixture.redirect_cases {
        assert_eq!(
            sanitize_redirect_uri(case.redirect_uri.as_deref(), &case.ui_base_url),
            case.sanitized
        );
        assert_eq!(
            resolve_post_auth_redirect(case.redirect_uri.as_deref(), &case.ui_base_url),
            case.resolved
        );
        assert_eq!(
            build_ui_redirect_url(case.redirect_uri.as_deref(), &case.ui_base_url),
            case.absolute
        );
    }
    for case in fixture.origin_cases {
        let policy = UiOriginPolicy::new(&case.primary, &case.additional).unwrap();
        assert_eq!(
            policy.select(
                Some(&case.forwarded_host),
                None,
                Some(&case.forwarded_proto),
                Some("http")
            ),
            case.selected
        );
        assert_eq!(
            oidc_callback_url(policy.select(
                Some(&case.forwarded_host),
                None,
                Some(&case.forwarded_proto),
                Some("http")
            )),
            format!("{}/v1/auth/callback", case.selected)
        );
    }
}

#[test]
fn fixed_api_callback_preserves_only_allowlisted_console_return_origins() {
    let policy = UiOriginPolicy::new("https://console.example", ["https://secondary.example"])
        .unwrap()
        .with_api_callback_origin("https://api.example/")
        .unwrap();
    for selected in ["https://console.example", "https://secondary.example"] {
        assert_eq!(
            policy.oidc_callback_url(selected),
            "https://api.example/v1/auth/callback"
        );
    }
    let bound = policy.login_redirect_uri(
        Some("https://secondary.example/console/profile?tab=security"),
        policy.primary(),
    );
    assert_eq!(
        bound,
        "https://secondary.example/console/profile?tab=security"
    );
    assert_eq!(
        policy.ui_redirect_url(Some(&bound), policy.primary()),
        bound
    );
    assert_eq!(
        policy.login_redirect_uri(Some("/"), policy.primary()),
        "https://console.example/console"
    );
    assert_eq!(policy.local_logout_redirect(), "https://console.example/");
    assert_eq!(
        policy.ui_redirect_url(
            Some("https://untrusted.example/console/profile?token=discard"),
            policy.primary()
        ),
        "https://console.example/console/profile"
    );
    for invalid in [
        "//untrusted.example",
        "javascript:alert(1)",
        "https://user:pass@console.example/console",
        "https://console.example/\\untrusted",
        "/console\r\nlocation:bad",
    ] {
        assert_eq!(
            policy.ui_redirect_url(Some(invalid), policy.primary()),
            "https://console.example/console"
        );
    }
}

#[test]
fn api_callback_origin_rejects_credential_and_transport_ambiguity() {
    for invalid in [
        "http://api.example",
        "https://api.example/path",
        "https://api.example?query=value",
        "https://api.example#fragment",
        "https://user:pass@api.example",
        "//api.example",
        " https://api.example",
    ] {
        assert!(
            UiOriginPolicy::new("https://console.example", std::iter::empty::<&str>())
                .unwrap()
                .with_api_callback_origin(invalid)
                .is_err(),
            "{invalid}"
        );
    }
    for origin in [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ] {
        let policy = UiOriginPolicy::new("http://localhost:3000", std::iter::empty::<&str>())
            .unwrap()
            .with_api_callback_origin(origin)
            .unwrap();
        assert_eq!(
            policy.oidc_callback_url(policy.primary()),
            format!("{origin}/v1/auth/callback")
        );
    }
}

#[test]
fn impersonation_context_matches_the_language_neutral_contract() {
    for case in fixture().impersonation_cases {
        let now = Utc::now();
        let session = Session::create(SessionSpec {
            user: AuthenticatedUser {
                user_id: case.user_id,
                email: case.email,
                username: None,
                given_name: None,
                family_name: None,
                user_type: UserType::Applicant,
                applicant_id: None,
                roles: Vec::new(),
                organization_id: Some(case.organization_id),
                organization_name: Some(case.organization_name),
                organization: None,
                default_organization_id: None,
                default_organization_name: None,
                organizations: Vec::new(),
                organization_context_unavailable: false,
                organization_context_error: None,
                onboarding_completed: None,
                picture: None,
                impersonation: None,
                did_subject: None,
            },
            ttl_seconds: 60,
            now,
            ip_address: None,
            user_agent: None,
            id_token: None,
            refresh_token: None,
            oidc_claims: Some(case.claims),
        });
        let handoff = case.handoff.map(|handoff| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&handoff).unwrap())
        });
        let actual = build_session_impersonation(&session, handoff.as_deref());
        match (actual, case.expected) {
            (None, None) => {}
            (Some(actual), Some(expected)) => {
                assert!(actual.active);
                assert_eq!(
                    actual.admin_user_id.as_deref(),
                    expected["admin_user_id"].as_str()
                );
                assert_eq!(
                    actual.admin_username.as_deref(),
                    expected["admin_username"].as_str()
                );
                assert_eq!(
                    actual.admin_email.as_deref(),
                    expected["admin_email"].as_str()
                );
                assert_eq!(
                    actual.target_user_id.as_deref(),
                    expected["target_user_id"].as_str()
                );
                assert_eq!(
                    actual.target_email.as_deref(),
                    expected["target_email"].as_str()
                );
                assert_eq!(
                    actual.organization_id.as_deref(),
                    expected["organization_id"].as_str()
                );
                assert_eq!(
                    actual.organization_name.as_deref(),
                    expected["organization_name"].as_str()
                );
                assert_eq!(
                    actual.launch_mode.as_deref(),
                    expected["launch_mode"].as_str()
                );
            }
            _ => panic!("impersonation result did not match fixture"),
        }
    }
}

#[test]
fn malformed_origins_and_handoffs_fail_closed() {
    for origin in [
        "file:///tmp/ui",
        "https://user:pass@example.test",
        "not a URL",
    ] {
        assert!(UiOriginPolicy::new(origin, std::iter::empty::<&str>()).is_err());
    }
    let policy = UiOriginPolicy::new("https://ui.example", std::iter::empty::<&str>()).unwrap();
    assert_eq!(
        policy.select(Some("user:pass@ui.example"), None, Some("https"), None),
        "https://ui.example"
    );
    assert!(marty_auth::decode_impersonation_handoff(Some("not-base64")).is_none());
}
