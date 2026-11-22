//! The public transport associates one compact VP with an already emitted
//! request. These tests deliberately do not treat association as proof validity.

use super::*;
use axum::body::Body;
use marty_delegated_authority::{
    use_mtls::{DelegatedUseWorkloadBinding, DelegatedUseWorkloadBindings},
    DelegationFlowContextV1, Principal, PrincipalType, DELEGATION_FLOW_CONTEXT_KEY,
};
use marty_oid4vci::presentation_request::PresentationRequestArtifacts;
use marty_oid4vp_contract::FrozenPolicyIdentity;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use crate::{
    delegation_start::DELEGATION_VERIFIER_CLIENT_ID_KEY,
    presentation_request::{freeze_flow_presentation_request, FROZEN_PRESENTATION_REQUEST_KEY},
};

const ORIGIN: &str = "https://machine-wallet.example";
const QUERY_ID: &str = "configured-machine-requirement-7";
const PROOF: &str = "eyJhbGciOiJFUzI1NiJ9.eyJ2cCI6e319.c2lnbmF0dXJl";
const VERIFIER: &str = "decentralized_identifier:did:web:machine-wallet.example";

fn emitted() -> FlowInstanceRecord {
    let now = Utc::now();
    let challenge_id = Uuid::new_v4();
    let organization_id = Uuid::new_v4();
    let binding = DelegationFlowContextV1 {
        challenge_id,
        organization_id,
        grant_id: Uuid::new_v4(),
        grant_revision: 2,
        actor: Principal {
            principal_type: PrincipalType::MachineIdentity,
            id: "urn:machine:wallet-fixture".into(),
        },
        action: "urn:operation:read".into(),
        audience: "https://consumer.example".into(),
        resource: "urn:resource:fixture".into(),
        operation_profile: "urn:operation:exact-v1".into(),
        operation_digest: format!("sha256:{}", "b".repeat(64)),
        session_ref: None,
        establishment_evidence_ref: None,
        session_key_thumbprint: None,
    };
    let mut instance = FlowInstanceRecord {
        id: challenge_id.to_string(),
        flow_definition_id: Uuid::new_v4().to_string(),
        organization_id: organization_id.to_string(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: json!({
            "nonce": "server-generated-frozen-nonce",
            "presentation_policy_id": "policy-1",
            "oid4vp_client_id": VERIFIER,
            "flow_type": "oid4vp_presentation",
            "request_uri": format!("{ORIGIN}/v1/flows/instances/{challenge_id}/request"),
            "oid4vp_verifier_context": true,
            "oid4vp_expected_state": challenge_id.to_string(),
            "oid4vp_response_uri": format!("{ORIGIN}/v1/flows/instances/{challenge_id}/submit")
        }),
        step_history: vec![],
        state_history: vec![],
        subject_id: Some(binding.actor.id.clone()),
        subject_type: "machine_identity".into(),
        external_reference: None,
        application_flow_key_hash: None,
        started_at: Some(now),
        completed_at: None,
        expires_at: Some(now + Duration::seconds(120)),
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
    };
    instance.context[DELEGATION_FLOW_CONTEXT_KEY] = serde_json::to_value(binding).unwrap();
    instance.context[DELEGATION_VERIFIER_CLIENT_ID_KEY] = json!(VERIFIER);
    let artifacts = PresentationRequestArtifacts {
        presentation_definition: json!({}),
        dcql_query: json!({"credentials": [{
            "id": QUERY_ID,
            "format": "jwt_vc_json",
            "require_cryptographic_holder_binding": true,
            "meta": {
                "marty_securing_profile": "marty_nested_vc2_jwt_v1",
                "type_values": [["MachineCredential"]]
            }
        }]}),
    };
    freeze_flow_presentation_request(
        &mut instance,
        FrozenPolicyIdentity {
            id: "policy-1".into(),
            version: 1,
            content_digest: format!("sha256:{}", "a".repeat(64)),
        },
        None,
        &artifacts,
    )
    .unwrap();
    // Match request_object::record_presentation_message: this is its MIP
    // projection, whose payload deliberately omits the JWT-only iss/state.
    instance.context["mip_messages"]["presentation_request"] = json!({
        "mip_version": "0.3.1",
        "message_type": "PresentationRequest",
        "message_id": Uuid::new_v4(),
        "correlation_id": instance.id,
        "timestamp": now.to_rfc3339(),
        "sender_id": VERIFIER,
        "nonce": instance.context["nonce"],
        "payload": {
            "client_id": VERIFIER,
            "nonce": instance.context["nonce"],
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "response_uri": instance.context["oid4vp_response_uri"],
            "dcql_query": artifacts.dcql_query,
            "presentation_definition": null,
            "mip_flow_instance_id": instance.id,
            "mip_policy_id": "policy-1"
        },
        "signature": null
    });
    instance
}

fn form(instance: &FlowInstanceRecord, vp_token: &str) -> Vec<u8> {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", &instance.id)
        .append_pair("vp_token", vp_token)
        .finish()
        .into_bytes()
}

fn valid_form(instance: &FlowInstanceRecord) -> DirectPost {
    DirectPost::parse(
        &form(instance, &json!({QUERY_ID: [PROOF]}).to_string()),
        Uuid::parse_str(&instance.id).unwrap(),
    )
    .unwrap()
}

#[test]
fn exact_emitted_query_associates_original_compact_bytes_without_verifying_them() {
    let instance = emitted();
    let payload = &instance.context["mip_messages"]["presentation_request"]["payload"];
    assert!(payload.get("iss").is_none());
    assert!(payload.get("state").is_none());
    assert_eq!(payload.get("presentation_definition"), Some(&json!(null)));
    assert_eq!(
        associate_direct_post(&instance, &instance, ORIGIN, &valid_form(&instance)).unwrap(),
        PROOF.as_bytes()
    );
    // Idempotent historical submission association remains possible after the
    // active owner finalized it; submit_input separately checks current access
    // and permits only recovery of the exact already retained proof.
    let mut terminal = instance.clone();
    terminal.status = FlowInstanceStatus::Completed;
    terminal.completed_at = Some(Utc::now());
    terminal.result = Some(json!({"synthetic": true}));
    assert_eq!(
        associate_direct_post(&terminal, &instance, ORIGIN, &valid_form(&instance)).unwrap(),
        PROOF.as_bytes()
    );
}

#[test]
fn direct_post_rejects_ambiguous_or_extra_form_authority() {
    let instance = emitted();
    let id = Uuid::parse_str(&instance.id).unwrap();
    let valid =
        String::from_utf8(form(&instance, &json!({QUERY_ID: [PROOF]}).to_string())).unwrap();
    for invalid_form in [
        String::new(),
        format!("{valid}&state={id}"),
        format!("{valid}&%73tate={id}"),
        format!("{valid}&vp_token=%7B%7D"),
        format!("{valid}&presentation_submission=%7B%7D"),
        format!("{valid}&request_uri=https%3A%2F%2Fattacker.example"),
        format!("{valid}&error=access_denied"),
        format!("{valid}&"),
        format!("{valid}&state"),
        valid.replace(&id.to_string(), &Uuid::new_v4().to_string()),
        format!("state={id}&vp_token={PROOF}"),
        format!("state={id}&vp_token=%7"),
        format!("state={id}&vp_token=%GG"),
        format!("state={id}&vp_token=%ff"),
        format!("state={id}&vp_token=%7B%7D&%ff=x"),
        format!("state={id}&vp_token=%7B%7D&%73tate%00={id}"),
    ] {
        assert!(DirectPost::parse(invalid_form.as_bytes(), id).is_err());
    }
    assert!(DirectPost::parse(valid.as_bytes(), Uuid::nil()).is_err());
    assert!(DirectPost::parse(&vec![b'a'; MAX_DIRECT_POST_BYTES + 1], id).is_err());
    assert!(DirectPost::parse(
        &form(
            &instance,
            &format!("{{{}", "a".repeat(MAX_DIRECT_POST_VALUE_BYTES))
        ),
        id
    )
    .is_err());
}

#[test]
fn response_cannot_replace_query_id_profile_coverage_or_compact_token_shape() {
    let instance = emitted();
    let invalid_responses = [
        format!("{{\"another-query\":[\"{PROOF}\"]}}"),
        format!("{{\"{QUERY_ID}\":[\"{PROOF}\"],\"other\":[\"{PROOF}\"]}}"),
        format!("{{\"{QUERY_ID}\":[\"{PROOF}\"],\"{QUERY_ID}\":[\"{PROOF}\"]}}"),
        format!("{{\"{QUERY_ID}\":[\"{PROOF}\",\"a.b.c\"]}}"),
        format!("{{\"{QUERY_ID}\":[\"{PROOF}\",\"{PROOF}\"]}}"),
        format!("{{\"{QUERY_ID}\":\"{PROOF}\"}}"),
        format!("{{\"{QUERY_ID}\":[]}}"),
        format!("{{\"{QUERY_ID}\":[null]}}"),
        json!({QUERY_ID: ["a.b"]}).to_string(),
        json!({QUERY_ID: ["a..c"]}).to_string(),
        json!({QUERY_ID: ["a.b.c.d"]}).to_string(),
        json!({QUERY_ID: ["a.b.c="]}).to_string(),
        json!({QUERY_ID: ["a.b.c "]}).to_string(),
        json!({QUERY_ID: ["a.b.é"]}).to_string(),
        json!({QUERY_ID: [format!("a.b.{}", "c".repeat(262_145))]}).to_string(),
        "{}".into(),
        "{broken-json".into(),
    ];
    for response in invalid_responses {
        let raw = form(&instance, &response);
        let result = DirectPost::parse(&raw, Uuid::parse_str(&instance.id).unwrap())
            .and_then(|post| associate_direct_post(&instance, &instance, ORIGIN, &post));
        assert!(
            result.is_err(),
            "accepted response shape: {}",
            response.len()
        );
    }
    // Even a consistently frozen and emitted alternative query cannot widen
    // this public surface's separately selected machine-credential profile.
    for direct_profile in [false, true] {
        let mut different_profile = instance.clone();
        let mut artifacts = load_frozen_flow_presentation_request(&instance)
            .unwrap()
            .artifacts();
        let entry = &mut artifacts.dcql_query["credentials"][0];
        if direct_profile {
            entry["format"] = json!("application/vc+jwt");
            entry["meta"]["marty_securing_profile"] = json!("w3c_vc2_jose_2026_v1");
        } else {
            entry["meta"]
                .as_object_mut()
                .unwrap()
                .remove("marty_securing_profile");
        }
        freeze_flow_presentation_request(
            &mut different_profile,
            load_frozen_flow_presentation_request(&instance)
                .unwrap()
                .policy_revision,
            None,
            &artifacts,
        )
        .unwrap();
        different_profile.context["mip_messages"]["presentation_request"]["payload"]
            ["dcql_query"] = artifacts.dcql_query;
        assert!(associate_direct_post(
            &different_profile,
            &different_profile,
            ORIGIN,
            &valid_form(&instance),
        )
        .is_err());
    }
}

#[test]
fn submitted_state_and_retained_request_cannot_cross_authority_snapshots() {
    let instance = emitted();
    let post = valid_form(&instance);
    for mutation in 0..20 {
        let mut retained = instance.clone();
        match mutation {
            0 => {
                retained.context[DELEGATION_FLOW_CONTEXT_KEY]["actor"]["id"] =
                    json!("urn:machine:other")
            }
            1 => {
                retained.context[DELEGATION_FLOW_CONTEXT_KEY]["operation_digest"] =
                    json!(format!("sha256:{}", "c".repeat(64)))
            }
            2 => retained.context[DELEGATION_FLOW_CONTEXT_KEY]["grant_revision"] = json!(3),
            3 => retained.expires_at = Some(Utc::now()),
            4 => retained.context["request_uri"] = json!("https://attacker.example/request"),
            5 => retained.context["oid4vp_verifier_context"] = json!(false),
            6 => retained.context["oid4vp_expected_state"] = json!(Uuid::new_v4()),
            7 => retained.context["oid4vp_response_uri"] = json!("https://attacker.example/submit"),
            8 => {
                retained.context["mip_messages"]["presentation_request"]["payload"]["nonce"] =
                    json!("replaced-nonce")
            }
            9 => {
                retained.context["mip_messages"]["presentation_request"]["payload"]
                    ["response_mode"] = json!("direct_post.jwt")
            }
            10 => {
                retained.context["mip_messages"]["presentation_request"]["payload"]
                    ["response_type"] = json!("id_token")
            }
            11 => {
                retained.context["mip_messages"]["presentation_request"]["sender_id"] =
                    json!("did:web:attacker.example")
            }
            12 => {
                retained.context["mip_messages"]["presentation_request"]["payload"]["dcql_query"]
                    ["credentials"][0]["id"] = json!("other-query")
            }
            13 => {
                retained.context["mip_messages"]["presentation_request"]["payload"]
                    ["presentation_definition"] = json!({})
            }
            14 => {
                retained.context[FROZEN_PRESENTATION_REQUEST_KEY]["dcql_query_digest"] =
                    json!(format!("sha256:{}", "d".repeat(64)))
            }
            15 => {
                retained.context["mip_messages"]["presentation_request"]["correlation_id"] =
                    json!(Uuid::new_v4())
            }
            16 => {
                retained.context["mip_messages"]["presentation_request"]["nonce"] =
                    json!("other-nonce")
            }
            17 => {
                retained.context["mip_messages"]["presentation_request"]["payload"]
                    ["mip_flow_instance_id"] = json!(Uuid::new_v4())
            }
            18 => {
                retained.context["mip_messages"]["presentation_request"]["payload"]
                    ["mip_policy_id"] = json!("other-policy")
            }
            _ => {
                retained.context["mip_messages"]["presentation_request"]["message_type"] =
                    json!("OtherMessage")
            }
        }
        assert!(
            associate_direct_post(&instance, &retained, ORIGIN, &post).is_err(),
            "mutation {mutation}"
        );
    }
    let wrong_state = DirectPost {
        state: Uuid::new_v4().to_string(),
        vp_token: post.vp_token.clone(),
    };
    assert!(associate_direct_post(&instance, &instance, ORIGIN, &wrong_state).is_err());
    assert!(associate_direct_post(&instance, &instance, "https://other.example", &post).is_err());
    let mut missing = instance.clone();
    missing
        .context
        .as_object_mut()
        .unwrap()
        .remove(FROZEN_PRESENTATION_REQUEST_KEY);
    assert!(associate_direct_post(&missing, &instance, ORIGIN, &post).is_err());
}

#[test]
fn selected_form_content_type_is_unambiguous() {
    for accepted in [
        "application/x-www-form-urlencoded",
        "APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8",
    ] {
        assert!(is_direct_post_content_type(accepted));
    }
    for rejected in [
        "application/json",
        "application/octet-stream",
        "application/x-www-form-urlencoded; charset=iso-8859-1",
        "application/x-www-form-urlencoded; charset=utf-8; charset=utf-8",
        "application/x-www-form-urlencoded; boundary=unselected",
        "application/x-www-form-urlencoded, application/json",
    ] {
        assert!(!is_direct_post_content_type(rejected));
    }
}

struct UnreachableAccess;
#[async_trait::async_trait]
impl DelegationUseIngressAuthorizer for UnreachableAccess {
    async fn authorize_ingress(
        &self,
        _: &DelegationCommandCaller,
        _: Uuid,
        _: DelegationUseIngressOperation,
        _: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess> {
        panic!("HTTP identity rejection must happen before owner authorization")
    }
}

fn app() -> Arc<FlowDelegatedUseIngress> {
    Arc::new(FlowDelegatedUseIngress {
        repository: PostgresFlowRepository::new(
            PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/not_a_database")
                .unwrap(),
        ),
        providers: Default::default(),
        access: Arc::new(UnreachableAccess),
        public_base_url: ORIGIN.into(),
        options: Default::default(),
        configuration_digest: format!("sha256:{}", "e".repeat(64)),
        storage_id: Uuid::new_v4(),
    })
}

#[tokio::test]
async fn wallet_router_requires_mtls_selection_and_rejects_header_identity() {
    let organization = Uuid::new_v4();
    assert!(delegated_use_wallet_router(FlowDelegatedUseHttpState::new(
        app(),
        Arc::new(
            DelegationUseHttpAuthenticator::trusted_forwarder(
                "synthetic-internal-forwarding-token".into(),
                organization
            )
            .unwrap()
        )
    ))
    .is_err());
    let bindings = DelegatedUseWorkloadBindings::new(vec![DelegatedUseWorkloadBinding::new(
        "spiffe://example.test/wallet".into(),
        format!("sha256:{}", "f".repeat(64)),
        "urn:machine:wallet-fixture".into(),
    )
    .unwrap()])
    .unwrap();
    let router = delegated_use_wallet_router(FlowDelegatedUseHttpState::new(
        app(),
        Arc::new(DelegationUseHttpAuthenticator::mutual_tls(organization, bindings).unwrap()),
    ))
    .unwrap();
    for (method, endpoint) in [("GET", "request"), ("POST", "submit")] {
        for spoof in [
            None,
            Some("x-client-cert"),
            Some("x-marty-use-principal-id"),
            Some("authorization"),
        ] {
            let mut request = axum::http::Request::builder()
                .method(method)
                .uri(format!("/v1/flows/instances/{}/{endpoint}", Uuid::new_v4()));
            if let Some(header) = spoof {
                request = request.header(header, "synthetic-caller-assertion");
            }
            let response = router
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if spoof.is_some() {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::UNAUTHORIZED
                }
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        }
    }
}
