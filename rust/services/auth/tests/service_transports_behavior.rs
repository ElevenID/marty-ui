use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{TimeZone as _, Utc};
use marty_auth::{
    auth_event_message, credential_verification_flow, credential_verification_request,
    domain_event, ApplicantProvisioningStore, ApplicantUpsert, AuthEvent, AuthEventPublisher,
    AuthGrpcChannelFactories, AuthenticatedUser, CanvasApplicantProfileProvisioner,
    MmfApplicantProfileProvisioner, MmfApplicantProvisioningStore, MmfAuthEventPublisher,
    StartCredentialVerification, UserType,
};
use mmf_messaging::{
    EventFilter, MemoryTransport, MessageTransport, MessagingConfig, Subscription,
};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, OutboundHttpClient,
    OutboundHttpRequest, OutboundHttpResponse, PlatformError,
};
use serde_json::Value;
use tokio::sync::Mutex;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/auth-service-transport-behavior.json"
    ))
    .unwrap()
}

#[test]
fn flow_request_and_fail_closed_response_match_the_shared_contract() {
    let request = credential_verification_request(&StartCredentialVerification {
        presentation_policy_id: "policy-1".into(),
        organization_id: "org-1".into(),
        issuer_did: "did:web:verifier.example".into(),
        callback_url: "https://auth.example/callback".into(),
        user_id: "auth-service".into(),
    });
    let expected = &contract()["flow_verification"];
    assert_eq!(request.response_type, expected["response_type"]);
    assert_eq!(request.request_transport, expected["request_transport"]);
    assert_eq!(request.presentation_policy_id, "policy-1");
    assert_eq!(request.organization_id, "org-1");
    assert_eq!(request.issuer_did, "did:web:verifier.example");
    assert_eq!(request.callback_url, "https://auth.example/callback");
    assert!(credential_verification_flow(Default::default()).is_err());
    let response = marty_auth::flow_proto::VerificationRequestResponse {
        instance_id: "flow-1".into(),
        qr_code_data: "openid4vp://authorize?request_uri=request".into(),
        ..Default::default()
    };
    assert_eq!(
        credential_verification_flow(response).unwrap().instance_id,
        "flow-1"
    );
}

#[tokio::test]
async fn both_grpc_clients_are_created_only_by_shared_mmf_factories() {
    fn factory(target: &str) -> GrpcChannelFactory {
        GrpcChannelFactory::new(
            GrpcChannelConfig {
                target: target.into(),
                ..GrpcChannelConfig::default()
            },
            GrpcTlsMaterial::default(),
        )
        .unwrap()
    }
    let clients = AuthGrpcChannelFactories {
        flow: factory("http://flow:9011"),
        organization: factory("http://organization:9002"),
    }
    .connect_lazy()
    .unwrap();
    let _ = clients.credential_verification();
    let _ = clients.organization_provisioning("org-1");
}

#[derive(Default)]
struct HttpStub {
    request: Mutex<Option<OutboundHttpRequest>>,
}

#[async_trait]
impl OutboundHttpClient for HttpStub {
    async fn execute(
        &self,
        request: OutboundHttpRequest,
    ) -> Result<OutboundHttpResponse, PlatformError> {
        *self.request.lock().await = Some(request);
        Ok(OutboundHttpResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: br#"{"id":"applicant-1","user_id":"oidc-1","email":"alice@example.com","given_name":"Alice","family_name":"Example","status":"DRAFT","application_data":{"preserved":"yes"},"created_at":"2026-08-22T00:00:00Z","updated_at":"2026-08-22T01:00:00Z"}"#.to_vec(),
        })
    }
}

#[tokio::test]
async fn applicant_profile_transport_preserves_headers_body_and_response_bound() {
    let client = Arc::new(HttpStub::default());
    let adapter =
        MmfApplicantProfileProvisioner::new(client.clone(), "http://applicant:8006").unwrap();
    let applicant_id = adapter.ensure_profile(&user()).await.unwrap();
    assert_eq!(applicant_id.as_deref(), Some("applicant-1"));
    let request = client.request.lock().await.clone().unwrap();
    let expected = &contract()["applicant_profile"];
    assert_eq!(request.url, "http://applicant:8006/v1/me/applicant-profile");
    assert_eq!(
        request.maximum_response_bytes,
        expected["maximum_response_bytes"]
    );
    for header in expected["required_headers"].as_array().unwrap() {
        assert!(request.headers.contains_key(header.as_str().unwrap()));
    }
    let body: Value = serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
    assert!(body.get("organization_id").is_none());
    assert_eq!(body["email"], "alice@example.com");
    assert!(
        MmfApplicantProfileProvisioner::new(client, "http://user:password@applicant:8006").is_err()
    );
}

#[tokio::test]
async fn jit_applicant_transport_is_fail_closed_and_preserves_profile_state() {
    let client = Arc::new(HttpStub::default());
    let profiles =
        MmfApplicantProfileProvisioner::new(client.clone(), "http://applicant:8006").unwrap();
    let store = MmfApplicantProvisioningStore::new(profiles, "org-1").unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 22, 1, 0, 0).unwrap();
    let profile = store
        .upsert(&ApplicantUpsert {
            new_id: "ignored-by-owner".into(),
            account_id: "oidc-1".into(),
            email: "alice@example.com".into(),
            given_names: Some("Alice".into()),
            surname: Some("Example".into()),
            fallback_given_names: "Unknown".into(),
            fallback_surname: "Unknown".into(),
            date_of_birth: now.date_naive(),
            nationality: "UNK".into(),
            extra_data_patch: serde_json::json!({"last_login_at": now.to_rfc3339()}),
            now,
        })
        .await
        .unwrap();
    assert_eq!(profile.id, "applicant-1");
    assert_eq!(profile.account_id.as_deref(), Some("oidc-1"));
    assert_eq!(profile.given_names, "Alice");
    assert_eq!(profile.extra_data["preserved"], "yes");
    let request = client.request.lock().await.clone().unwrap();
    let body: Value = serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
    assert_eq!(
        body["vetting_data_patch"]["last_login_at"],
        now.to_rfc3339()
    );
    assert_eq!(request.headers["x-user-id"], "oidc-1");
    assert!(MmfApplicantProvisioningStore::new(
        MmfApplicantProfileProvisioner::new(client, "http://applicant:8006").unwrap(),
        ""
    )
    .is_err());
}

#[tokio::test]
async fn auth_events_use_one_mmf_envelope_and_transport() {
    let transport = Arc::new(MemoryTransport::new(MessagingConfig::default()).unwrap());
    transport.connect().await.unwrap();
    transport
        .subscribe(Subscription {
            id: "test".into(),
            topic: contract()["auth_events"]["topic"].as_str().unwrap().into(),
            consumer_group: None,
            filter: EventFilter::default(),
        })
        .await
        .unwrap();
    let publisher = MmfAuthEventPublisher::new(transport.clone());
    let events = [
        AuthEvent::UserAuthenticated {
            user_id: "user-1".into(),
            email: "alice@example.com".into(),
            organization_id: Some("org-1".into()),
            ip_address: Some("192.0.2.1".into()),
        },
        AuthEvent::SessionCreated {
            session_id: "session-1".into(),
            user_id: "user-1".into(),
            organization_id: Some("org-1".into()),
            expires_at: Utc.with_ymd_and_hms(2026, 8, 22, 0, 0, 0).unwrap(),
        },
        AuthEvent::UserLoggedOut {
            user_id: "user-1".into(),
            session_id: "session-1".into(),
            logout_type: "user_initiated".into(),
            organization_id: Some("org-1".into()),
        },
        AuthEvent::SessionRevoked {
            session_id: "session-1".into(),
            user_id: "user-1".into(),
            revoked_by: "user-1".into(),
            reason: "logout".into(),
            organization_id: Some("org-1".into()),
        },
    ];
    for event in &events {
        publisher.publish(event).await.unwrap();
    }
    let messages = transport.poll("test", 10, u64::MAX - 1).await.unwrap();
    let behavior = contract();
    let expected = behavior["auth_events"]["message_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let actual = messages
        .iter()
        .map(|message| message.message_type.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert!(messages
        .iter()
        .all(|message| message.topic == "auth.events"));
    assert!(messages
        .iter()
        .all(|message| message.metadata.tenant_id.as_deref() == Some("org-1")));
    assert_eq!(
        auth_event_message(&events[0])
            .unwrap()
            .metadata
            .tenant_id
            .as_deref(),
        Some("org-1")
    );
    let event = domain_event(auth_event_message(&events[0]).unwrap()).unwrap();
    assert_eq!(event.event_type, "user_authenticated");
    assert_eq!(event.aggregate_id, "user-1");
    assert_eq!(event.aggregate_type, "auth");
    assert_eq!(event.organization_id, "org-1");
    assert_eq!(event.data["email"], "alice@example.com");
}

fn user() -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: "user-1".into(),
        email: "alice@example.com".into(),
        username: Some("alice".into()),
        given_name: Some("Alice".into()),
        family_name: Some("Example".into()),
        user_type: UserType::Applicant,
        applicant_id: None,
        roles: vec!["applicant".into()],
        organization_id: Some("org-1".into()),
        organization_name: Some("Marty".into()),
        organization: None,
        default_organization_id: Some("org-1".into()),
        default_organization_name: Some("Marty".into()),
        organizations: Vec::new(),
        organization_context_unavailable: false,
        organization_context_error: None,
        onboarding_completed: None,
        picture: None,
        impersonation: None,
        did_subject: None,
    }
}
