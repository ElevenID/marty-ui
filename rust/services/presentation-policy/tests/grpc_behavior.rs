use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use marty_presentation_policy::{
    presentation_policy_proto::{
        presentation_policy_service_server::PresentationPolicyService, CreatePolicyRequest,
        EvaluatePresentationRequest as EvaluatePresentationMessage, GetPolicyRequest,
        HealthCheckRequest, ListPoliciesRequest, Oid4vpEvaluationTransport, PolicyIdRequest,
        UpdatePolicyRequest,
    },
    EvaluatePresentationRequest, PolicyApplication, PolicyAuthorization, PolicyRepository,
    PresentationPolicy, PresentationPolicyGrpcService, PresentationVerificationError,
    PresentationVerificationOrchestrator,
};
use serde_json::{json, Value};
use tonic::{Code, Request};
use uuid::Uuid;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Default)]
struct Repository(Mutex<BTreeMap<Uuid, PresentationPolicy>>);

#[async_trait]
impl PolicyRepository for Repository {
    async fn save(&self, policy: &PresentationPolicy) -> Result<(), String> {
        self.0.lock().unwrap().insert(policy.id, policy.clone());
        Ok(())
    }

    async fn get(&self, policy_id: Uuid) -> Result<Option<PresentationPolicy>, String> {
        Ok(self.0.lock().unwrap().get(&policy_id).cloned())
    }

    async fn list(&self, organization_id: Uuid) -> Result<Vec<PresentationPolicy>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .values()
            .filter(|policy| policy.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn delete(&self, policy_id: Uuid) -> Result<(), String> {
        self.0.lock().unwrap().remove(&policy_id);
        Ok(())
    }
}

struct Authorization(Uuid);

#[async_trait]
impl PolicyAuthorization for Authorization {
    async fn require(
        &self,
        principal_id: &str,
        organization_id: Uuid,
        _action: &'static str,
    ) -> Result<(), String> {
        if principal_id == "user-1" && organization_id == self.0 {
            Ok(())
        } else {
            Err("denied".into())
        }
    }
}

struct VerifiedFacts;

struct CountedVerifiedFacts(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait]
impl PresentationVerificationOrchestrator for CountedVerifiedFacts {
    async fn verify(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        VerifiedFacts.verify(policy, request).await
    }
}

#[async_trait]
impl PresentationVerificationOrchestrator for VerifiedFacts {
    async fn verify(
        &self,
        policy: &PresentationPolicy,
        _request: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError> {
        let template = &policy.credential_requirements[0].credential_template_id;
        Ok(json!({
            "policy": {},
            "credentials": [{
                "credential_id": "credential-1",
                "credential_template_ids": [template],
                "credential_format": "sd-jwt",
                "claims": {"email": "member@example.com"},
                "issuer_id": "did:example:issuer",
                "signature_verified": true,
                "signature_failure_reason": null,
                "trust_profile_verified": true,
                "trust_failure_reason": null,
                "trust_level": 80,
                "compliance_statuses": [],
                "accreditations": [],
                "issued_at_epoch_seconds": 999,
                "revocation_checked_at_epoch_seconds": null,
                "not_revoked": null,
                "credential_status": "active",
                "warnings": []
            }],
            "evaluation_time_epoch_seconds": 1000,
            "holder_binding_verified": false,
            "holder_binding_method": null,
            "proof_profile": null,
            "challenge_verified": false,
            "audience_verified": false,
            "replay_check_verified": false,
            "proof_epoch_seconds": null,
            "external_authorization": {"evaluated": true, "allowed": true, "reasons": [], "errors": []},
            "presentation_count": 1
        }))
    }
}

fn service(organization_id: Uuid) -> PresentationPolicyGrpcService {
    PresentationPolicyGrpcService::new(
        Arc::new(PolicyApplication::new(
            Arc::new(Repository::default()),
            Arc::new(Authorization(organization_id)),
        )),
        Arc::new(VerifiedFacts),
        Some(TOKEN.into()),
        true,
    )
    .unwrap()
}

fn authenticated<T>(message: T) -> Request<T> {
    let mut request = service_authenticated(message);
    request
        .metadata_mut()
        .insert("x-user-id", "user-1".parse().unwrap());
    request
}

fn service_authenticated<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("x-service-token", TOKEN.parse().unwrap());
    request
}

fn create_request(organization_id: Uuid) -> CreatePolicyRequest {
    CreatePolicyRequest {
        organization_id: organization_id.to_string(),
        name: "Member login".into(),
        description: "Sign in with membership".into(),
        credential_requirements_json: json!([{
            "credential_template_id": "member",
            "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
            "requested_claims": [{
                "claim_name": "email",
                "constraints": [{"claim_name": "email", "constraint_type": "presence"}]
            }]
        }])
        .to_string(),
        display_metadata_json: json!({
            "title": "Member login",
            "purpose": "identity_verification",
            "verifier_name": "Marty"
        })
        .to_string(),
        ..CreatePolicyRequest::default()
    }
}

#[tokio::test]
async fn principal_authenticated_fallback_cannot_supply_workload_oid4vp_transport() {
    let organization_id = Uuid::new_v4();
    let service = service(organization_id);
    let policy = service
        .create_policy(authenticated(create_request(organization_id)))
        .await
        .unwrap()
        .into_inner();
    let active = service
        .activate_policy(authenticated(PolicyIdRequest {
            policy_id: policy.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let error = service
        .evaluate_presentation(authenticated(EvaluatePresentationMessage {
            policy_id: policy.id.clone(),
            vp_token: "header.payload.signature".into(),
            nonce: "nonce-1".into(),
            audience: "verifier-1".into(),
            oid4vp_transport: Some(Oid4vpEvaluationTransport::default()),
            ..EvaluatePresentationMessage::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    let legacy = service
        .evaluate_presentation(authenticated(EvaluatePresentationMessage {
            policy_id: policy.id,
            expected_policy_revision: active.policy_revision,
            vp_token: "header.payload.signature".into(),
            nonce: "nonce-1".into(),
            audience: "verifier-1".into(),
            ..EvaluatePresentationMessage::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(legacy.decision, "allow");
    assert_eq!(legacy.nonce, "nonce-1");
}

#[tokio::test]
async fn all_ten_grpc_methods_use_shared_native_behavior_and_security() {
    let organization_id = Uuid::new_v4();
    let service = service(organization_id);

    let missing_auth = service
        .health_check(Request::new(HealthCheckRequest {}))
        .await
        .unwrap_err();
    assert_eq!(missing_auth.code(), Code::Unauthenticated);
    assert_eq!(
        service
            .health_check(authenticated(HealthCheckRequest {}))
            .await
            .unwrap()
            .into_inner()
            .status,
        "serving"
    );

    let created = service
        .create_policy(authenticated(create_request(organization_id)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.status, "draft");
    let policy_id = created.id.clone();
    let requirements: Value = serde_json::from_str(&created.credential_requirements_json).unwrap();
    assert_eq!(requirements[0]["credential_template_id"], "member");
    assert!(requirements[0]["id"].as_str().is_some());

    let fetched = service
        .get_policy(authenticated(GetPolicyRequest {
            policy_id: policy_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.id, policy_id);

    let listed = service
        .list_policies(authenticated(ListPoliciesRequest {
            organization_id: organization_id.to_string(),
            status: "draft".into(),
            limit: 100,
            offset: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.total, 1);
    assert_eq!(listed.policies.len(), 1);

    let updated = service
        .update_policy(authenticated(UpdatePolicyRequest {
            policy_id: policy_id.clone(),
            name: "Updated login".into(),
            ..UpdatePolicyRequest::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.name, "Updated login");

    let active = service
        .activate_policy(authenticated(PolicyIdRequest {
            policy_id: policy_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(active.status, "active");

    let evaluated = service
        .evaluate_presentation(authenticated(EvaluatePresentationMessage {
            policy_id: policy_id.clone(),
            expected_policy_revision: active.policy_revision.clone(),
            vp_token: "header.payload.signature".into(),
            nonce: "challenge-1".into(),
            audience: "https://verifier.example".into(),
            context_json: "{}".into(),
            ..EvaluatePresentationMessage::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(evaluated.decision, "allow");
    assert_eq!(evaluated.nonce, "challenge-1");
    assert_eq!(evaluated.policy_revision, active.policy_revision);
    let claims: Value = serde_json::from_str(&evaluated.verified_claims_json).unwrap();
    assert_eq!(claims["email"], "member@example.com");

    let suspended = service
        .suspend_policy(authenticated(PolicyIdRequest {
            policy_id: policy_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(suspended.status, "suspended");

    let version = service
        .new_version_policy(authenticated(PolicyIdRequest {
            policy_id: policy_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(version.status, "draft");
    assert_eq!(version.version, 2);
    let version_requirements: Value =
        serde_json::from_str(&version.credential_requirements_json).unwrap();
    assert_eq!(version_requirements, requirements);

    let deleted = service
        .delete_policy(authenticated(PolicyIdRequest {
            policy_id: version.id,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(deleted.success);
}

#[tokio::test]
async fn malformed_json_and_untrusted_principals_fail_closed_before_writes() {
    let organization_id = Uuid::new_v4();
    let service = service(organization_id);
    let malformed = service
        .create_policy(authenticated(CreatePolicyRequest {
            credential_requirements_json: "not-json".into(),
            ..create_request(organization_id)
        }))
        .await
        .unwrap_err();
    assert_eq!(malformed.code(), Code::InvalidArgument);

    let mut request = authenticated(create_request(organization_id));
    request
        .metadata_mut()
        .insert("x-user-id", "attacker".parse().unwrap());
    let forbidden = service.create_policy(request).await.unwrap_err();
    assert_eq!(forbidden.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn exact_internal_operations_use_service_auth_while_management_requires_a_principal() {
    let organization_id = Uuid::new_v4();
    let service = service(organization_id);
    let policy = service
        .create_policy(authenticated(create_request(organization_id)))
        .await
        .unwrap()
        .into_inner();

    let fetched = service
        .get_policy(service_authenticated(GetPolicyRequest {
            policy_id: policy.id,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.organization_id, organization_id.to_string());

    let evaluation_without_workload_identity = service
        .evaluate_presentation(service_authenticated(EvaluatePresentationMessage {
            policy_id: fetched.id.clone(),
            vp_token: "header.payload.signature".into(),
            nonce: "challenge-1".into(),
            audience: "https://verifier.example".into(),
            context_json: "{}".into(),
            ..EvaluatePresentationMessage::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(
        evaluation_without_workload_identity.code(),
        Code::Unauthenticated
    );

    let list_error = service
        .list_policies(service_authenticated(ListPoliciesRequest {
            organization_id: organization_id.to_string(),
            status: String::new(),
            limit: 100,
            offset: 0,
        }))
        .await
        .unwrap_err();
    assert_eq!(list_error.code(), Code::Unauthenticated);

    let unauthenticated = service
        .get_policy(Request::new(GetPolicyRequest {
            policy_id: fetched.id,
        }))
        .await
        .unwrap_err();
    assert_eq!(unauthenticated.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn saved_revision_mismatch_fails_before_verification_and_matching_result_is_authoritative() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let organization_id = Uuid::new_v4();
    let repository = Arc::new(Repository::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let service = PresentationPolicyGrpcService::new(
        Arc::new(PolicyApplication::new(
            repository.clone(),
            Arc::new(Authorization(organization_id)),
        )),
        Arc::new(CountedVerifiedFacts(calls.clone())),
        Some(TOKEN.into()),
        true,
    )
    .unwrap();
    let created = service
        .create_policy(authenticated(create_request(organization_id)))
        .await
        .unwrap()
        .into_inner();
    let active = service
        .activate_policy(authenticated(PolicyIdRequest {
            policy_id: created.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let revision = active.policy_revision.clone().unwrap();
    let request = EvaluatePresentationMessage {
        policy_id: active.id.clone(),
        vp_token: "header.payload.signature".into(),
        nonce: "revision-challenge".into(),
        audience: "https://verifier.example".into(),
        expected_policy_revision: Some(revision.clone()),
        // Untrusted context must not replace the authoritative output revision.
        context_json: json!({"policy_revision": {"id": "attacker"}}).to_string(),
        ..EvaluatePresentationMessage::default()
    };

    let mut missing = request.clone();
    missing.expected_policy_revision = None;
    assert_eq!(
        service
            .evaluate_presentation(authenticated(missing))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );

    for mutation in 0..4 {
        let mut altered = request.clone();
        let expected = altered.expected_policy_revision.as_mut().unwrap();
        match mutation {
            0 => expected.organization_id = Uuid::new_v4().to_string(),
            1 => expected.id = Uuid::new_v4().to_string(),
            2 => expected.version += 1,
            _ => expected.content_digest = format!("sha256:{}", "0".repeat(64)),
        }
        assert_eq!(
            service
                .evaluate_presentation(authenticated(altered))
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
    }
    let mut malformed = request.clone();
    malformed
        .expected_policy_revision
        .as_mut()
        .unwrap()
        .content_digest = "not-a-digest".into();
    assert_eq!(
        service
            .evaluate_presentation(authenticated(malformed))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let result = service
        .evaluate_presentation(authenticated(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.policy_revision, Some(revision));
    assert_eq!(result.decision, "allow");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let policy_id = Uuid::parse_str(&active.id).unwrap();
    {
        let mut stored = repository.0.lock().unwrap();
        let policy = stored.get_mut(&policy_id).unwrap();
        policy.status = marty_presentation_policy::PolicyStatus::Suspended;
        policy.updated_at += chrono::Duration::seconds(1);
    }
    let suspended = service
        .get_policy(service_authenticated(GetPolicyRequest {
            policy_id: active.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let mut suspended_request = request.clone();
    suspended_request.expected_policy_revision = suspended.policy_revision;
    assert_eq!(
        service
            .evaluate_presentation(authenticated(suspended_request))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    {
        let mut stored = repository.0.lock().unwrap();
        let policy = stored.get_mut(&policy_id).unwrap();
        policy.status = marty_presentation_policy::PolicyStatus::Active;
        policy.updated_at += chrono::Duration::seconds(1);
    }
    assert_eq!(
        service
            .evaluate_presentation(authenticated(request.clone()))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let reactivated = service
        .get_policy(service_authenticated(GetPolicyRequest {
            policy_id: active.id,
        }))
        .await
        .unwrap()
        .into_inner();
    let mut restarted = request;
    restarted.expected_policy_revision = reactivated.policy_revision.clone();
    let result = service
        .evaluate_presentation(authenticated(restarted))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.policy_revision, reactivated.policy_revision);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
