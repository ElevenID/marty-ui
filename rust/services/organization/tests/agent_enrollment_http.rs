//! Fail-closed managed enrollment transport checks do not require a database.
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use chrono::{Duration, Utc};
use marty_organization::{
    agent_directory::{
        decode_agent_request, AgentDirectoryService, AgentEnrollmentConfiguration,
        AgentEnrollmentSession, CompleteAgentEnrollment, CreateAgentEnrollmentChallenge,
    },
    agent_directory_http::{organization_agent_admin_router, AgentDirectoryHttpState},
    postgres::PostgresOrganizationStore,
    OrganizationServiceConfig,
};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "synthetic-service-token-for-enrollment-tests";
const ORG: &str = "11111111-1111-4111-8111-111111111111";
const USER: &str = "22222222-2222-4222-8222-222222222222";
const AGENT: &str = "33333333-3333-4333-8333-333333333333";
const CHALLENGE: &str = "44444444-4444-4444-8444-444444444444";
fn router(enabled: bool) -> Router {
    let store = PostgresOrganizationStore::new(
        PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .unwrap(),
    );
    let mut service = AgentDirectoryService::new(store);
    if enabled {
        service = service.with_enrollment(
            AgentEnrollmentConfiguration::new(
                "urn:application-test:enrollment".into(),
                "urn:application-test:policy:v1".into(),
                1,
                120,
            )
            .unwrap(),
        );
    }
    organization_agent_admin_router(AgentDirectoryHttpState::new(service, TOKEN.into()).unwrap())
}
fn request(method: &str, path: &str, body: &str) -> Request<Body> {
    let now = Utc::now();
    Request::builder()
        .method(method)
        .uri(path)
        .header("x-service-token", TOKEN)
        .header("x-user-id", USER)
        .header("x-organization-id", ORG)
        .header(
            "x-required-permission",
            if method == "GET" {
                "agent-identity:view"
            } else {
                "agent-identity:enroll"
            },
        )
        .header("content-type", "application/json")
        .header("x-marty-enrollment-organization-id", ORG)
        .header("x-marty-enrollment-user-id", USER)
        .header(
            "x-marty-enrollment-session-ref",
            format!("urn:marty:session:sha256:{}", "a".repeat(64)),
        )
        .header(
            "x-marty-enrollment-observed-at",
            (now - Duration::seconds(1)).to_rfc3339(),
        )
        .header(
            "x-marty-enrollment-valid-until",
            (now + Duration::seconds(20)).to_rfc3339(),
        )
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[test]
fn enrollment_configuration_requires_explicit_directory_service_and_audience_selection() {
    let mut values = std::collections::BTreeMap::from([(
        "DATABASE_URL".into(),
        "postgresql://unused:unused@127.0.0.1:1/unused".into(),
    )]);
    assert!(OrganizationServiceConfig::from_values(values.clone())
        .unwrap()
        .agent_enrollment
        .is_none());
    values.insert("MARTY_AGENT_ENROLLMENT_ENABLED".into(), "true".into());
    assert!(OrganizationServiceConfig::from_values(values.clone()).is_err());
    values.insert("MARTY_AGENT_ADMIN_ENABLED".into(), "true".into());
    assert!(OrganizationServiceConfig::from_values(values.clone()).is_err());
    values.insert("GRPC_SERVICE_TOKEN".into(), TOKEN.into());
    assert!(OrganizationServiceConfig::from_values(values.clone()).is_err());
    values.insert(
        "MARTY_AGENT_ENROLLMENT_AUDIENCE".into(),
        "urn:application-test:enrollment".into(),
    );
    assert!(OrganizationServiceConfig::from_values(values.clone())
        .unwrap()
        .agent_enrollment
        .is_some());
    for (field, value) in [
        ("MARTY_AGENT_ENROLLMENT_AUDIENCE", "relative-value"),
        ("MARTY_AGENT_ENROLLMENT_MAX_AGE_SECONDS", "0"),
        ("MARTY_AGENT_ENROLLMENT_MAX_AGE_SECONDS", "301"),
        ("MARTY_AGENT_ENROLLMENT_POLICY_REVISION", "0"),
        ("MARTY_AGENT_ENROLLMENT_POLICY_PROFILE", "not a URI"),
    ] {
        let mut invalid = values.clone();
        invalid.insert(field.into(), value.into());
        assert!(
            OrganizationServiceConfig::from_values(invalid).is_err(),
            "{field}={value}"
        );
    }
}

#[test]
fn enrollment_request_types_cannot_supply_expected_context_or_proof_verdicts() {
    for body in [
        r#"{"expected_revision":1,"expected_revision":2}"#,
        r#"{"expected_revision":1,"challenge_id":"caller"}"#,
        r#"{"expected_revision":1,"key_id":"caller"}"#,
        r#"{"expected_revision":1,"provenance":"KEY_CONTROL_VERIFIED"}"#,
    ] {
        assert!(decode_agent_request::<CreateAgentEnrollmentChallenge>(body.as_bytes()).is_err());
    }
    for body in [
        r#"{"proof":"a","proof":"b"}"#,
        r#"{"proof":"a","verified":true}"#,
        r#"{"proof":"a","challenge":{}}"#,
        r#"{"proof":"a","public_key_jwk":{}}"#,
        r#"{"proof":"a","session_ref":"caller"}"#,
    ] {
        assert!(decode_agent_request::<CompleteAgentEnrollment>(body.as_bytes()).is_err());
    }
    let request = CompleteAgentEnrollment {
        proof: "private-proof-marker".into(),
    };
    assert!(!format!("{request:?}").contains("private-proof-marker"));
    let now = Utc::now();
    let org = Uuid::parse_str(ORG).unwrap();
    let user = Uuid::parse_str(USER).unwrap();
    for reference in [
        format!("sha256:{}", "a".repeat(64)),
        format!("urn:marty:session:sha256:{}", "A".repeat(64)),
        format!("urn:marty:session:sha256:{}\n", "a".repeat(63)),
    ] {
        assert!(AgentEnrollmentSession::new(
            org,
            user,
            reference,
            now,
            now + Duration::seconds(20)
        )
        .is_err());
    }
    assert!(AgentEnrollmentSession::new(
        org,
        user,
        format!("urn:marty:session:sha256:{}", "a".repeat(64)),
        now,
        now + Duration::seconds(31)
    )
    .is_err());
}

#[tokio::test]
async fn enrollment_http_is_default_off_for_every_new_route() {
    for (method, path, body) in [
        (
            "POST",
            format!("/v1/organizations/{ORG}/agents/{AGENT}/enrollment-challenges"),
            r#"{"expected_revision":1}"#,
        ),
        (
            "GET",
            format!("/v1/organizations/{ORG}/agents/{AGENT}/enrollment-challenges/{CHALLENGE}"),
            "",
        ),
        (
            "POST",
            format!(
                "/v1/organizations/{ORG}/agents/{AGENT}/enrollment-challenges/{CHALLENGE}/complete"
            ),
            r#"{"proof":"unused"}"#,
        ),
    ] {
        assert_eq!(
            router(false)
                .oneshot(request(method, &path, body))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn enrollment_http_rejects_missing_duplicate_and_mismatched_session_context() {
    let app = router(true);
    let path = format!("/v1/organizations/{ORG}/agents/{AGENT}/enrollment-challenges");
    for field in [
        "x-marty-enrollment-organization-id",
        "x-marty-enrollment-user-id",
        "x-marty-enrollment-session-ref",
        "x-marty-enrollment-observed-at",
        "x-marty-enrollment-valid-until",
    ] {
        for duplicate in [false, true] {
            let mut req = request("POST", &path, r#"{"expected_revision":1}"#);
            if duplicate {
                let value = req.headers()[field].clone();
                req.headers_mut().append(field, value);
            } else {
                req.headers_mut().remove(field);
            }
            let response = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{field} duplicate={duplicate}"
            );
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
    }
    for (field, value) in [
        ("x-marty-enrollment-organization-id", AGENT),
        ("x-marty-enrollment-user-id", AGENT),
        ("x-marty-enrollment-session-ref", "raw-session"),
        ("x-marty-enrollment-observed-at", "invalid"),
        ("x-marty-enrollment-valid-until", "2100-01-01T00:00:00Z"),
    ] {
        let mut req = request("POST", &path, r#"{"expected_revision":1}"#);
        req.headers_mut().insert(field, value.parse().unwrap());
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "{field}"
        );
    }
}

#[tokio::test]
async fn enrollment_http_rejects_ambiguous_bodies_and_read_side_mutation() {
    let app = router(true);
    let base = format!("/v1/organizations/{ORG}/agents/{AGENT}/enrollment-challenges");
    for body in [
        r#"{"expected_revision":1,"expected_revision":2}"#,
        r#"{"expected_revision":1,"proof":"caller"}"#,
        r#"{"expected_revision":null}"#,
        r#"{"expected_revision":0}"#,
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request("POST", &base, body))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for body in [
        r#"{"proof":"a","proof":"b"}"#,
        r#"{"proof":"a","verified":true}"#,
        r#"{"proof":""}"#,
        r#"{"proof":null}"#,
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(
                    "POST",
                    &format!("{base}/{CHALLENGE}/complete"),
                    body
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(request("GET", &format!("{base}/{CHALLENGE}"), "{}"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.oneshot(request(
            "GET",
            &format!("{base}/{CHALLENGE}?renew=true"),
            ""
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
}
