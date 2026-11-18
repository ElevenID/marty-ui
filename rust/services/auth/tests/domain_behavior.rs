use chrono::{DateTime, Duration, Utc};
use marty_auth::{
    pkce_s256_challenge, AuthenticatedUser, OidcUserInfo, Session, SessionSpec, SessionStatus,
    UserType,
};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/auth-behavior.json"
    )))
    .expect("auth behavior fixture must be valid JSON")
}

fn fixed_now() -> DateTime<Utc> {
    "2026-08-20T12:00:00Z"
        .parse()
        .expect("fixed timestamp must parse")
}

fn user_from_case(case: &Value) -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: "user-1".to_owned(),
        email: case["email"]
            .as_str()
            .expect("email must be a string")
            .to_owned(),
        username: case["username"].as_str().map(str::to_owned),
        given_name: case["given_name"].as_str().map(str::to_owned),
        family_name: case["family_name"].as_str().map(str::to_owned),
        user_type: UserType::Applicant,
        applicant_id: None,
        roles: Vec::new(),
        organization_id: None,
        organization_name: None,
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
    }
}

#[test]
fn oidc_claim_mapping_matches_shared_vectors() {
    for case in fixture()["claim_cases"].as_array().expect("claim cases") {
        let actual = OidcUserInfo::from_claims(&case["primary"], Some(&case["secondary"]));
        let expected = &case["expected"];
        assert_eq!(actual.sub, expected["sub"]);
        assert_eq!(actual.email, expected["email"]);
        assert_eq!(
            actual.email_verified,
            expected["email_verified"].as_bool().unwrap_or(false)
        );
        assert_eq!(
            actual.organization_id,
            expected["organization_id"].as_str().map(str::to_owned)
        );
        assert_eq!(
            actual.organization_name,
            expected["organization_name"].as_str().map(str::to_owned)
        );
        assert_eq!(
            json!(actual.roles),
            expected["roles"],
            "claim case {}",
            case["name"]
        );
    }
}

#[test]
fn display_name_precedence_matches_shared_vectors() {
    for case in fixture()["display_name_cases"]
        .as_array()
        .expect("display cases")
    {
        assert_eq!(
            user_from_case(case).display_name(),
            case["expected"].as_str().expect("expected display name"),
        );
    }
}

#[test]
fn session_validity_matches_shared_vectors() {
    let now = fixed_now();
    for case in fixture()["session_validity_cases"]
        .as_array()
        .expect("session cases")
    {
        let status: SessionStatus = serde_json::from_value(case["status"].clone()).expect("status");
        let offset = case["expires_offset_seconds"].as_i64().expect("offset");
        let mut session = Session::create(SessionSpec {
            user: user_from_case(&json!({
                "email": "alice@example.com", "username": null, "given_name": null, "family_name": null
            })),
            ttl_seconds: 60,
            now,
            ip_address: None,
            user_agent: None,
            id_token: None,
            refresh_token: None,
            oidc_claims: None,
        });
        session.status = status;
        session.expires_at = now + Duration::seconds(offset);
        assert_eq!(
            session.is_valid_at(now),
            case["valid"].as_bool().expect("valid")
        );
        assert_eq!(
            session.remaining_ttl_seconds_at(now),
            case["remaining_ttl_seconds"].as_i64().expect("ttl")
        );
    }
}

#[test]
fn pkce_s256_matches_shared_vectors() {
    for vector in fixture()["pkce_vectors"].as_array().expect("PKCE vectors") {
        assert_eq!(
            pkce_s256_challenge(vector["verifier"].as_str().expect("verifier")),
            vector["challenge"].as_str().expect("challenge"),
        );
    }
}

#[test]
fn frozen_surface_is_unique_and_complete() {
    let fixture = fixture();
    let routes = fixture["http_routes"].as_array().expect("HTTP routes");
    let unique = routes
        .iter()
        .map(|route| format!("{} {}", route["method"], route["path"]))
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(routes.len(), 14);
    assert_eq!(unique.len(), routes.len());
    assert_eq!(
        fixture["grpc_methods"]
            .as_array()
            .expect("gRPC methods")
            .len(),
        6
    );
}
