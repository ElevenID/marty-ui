use std::sync::Arc;

use chrono::Utc;
use mmf_security::{SecurityError, ServiceTokenAuthenticator};
use serde_json::{json, Map, Value};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
    grpc_security::{PresentationGrpcSecurity, EVALUATE_PRESENTATION_METHOD, GET_POLICY_METHOD},
    http_service::{
        apply_update_from_transport, build_policy_from_transport, evaluate_policy,
        PresentationPolicyHttpError,
    },
    presentation_policy_proto::{
        presentation_policy_service_server::PresentationPolicyService, CreatePolicyRequest,
        DeletePolicyResponse, EvaluatePresentationRequest as EvaluatePresentationMessage,
        GetPolicyRequest, HealthCheckRequest, HealthCheckResponse, ListPoliciesRequest,
        ListPoliciesResponse, PolicyEvaluationResponse, PolicyIdRequest, PolicyResponse,
        UpdatePolicyRequest,
    },
    EvaluatePresentationRequest, PolicyApplication, PolicyApplicationError, PolicyStatus,
    PresentationPolicy, PresentationVerificationOrchestrator,
};

#[derive(Clone)]
pub struct PresentationPolicyGrpcService {
    application: Arc<PolicyApplication>,
    verification: Arc<dyn PresentationVerificationOrchestrator>,
    service_authenticator: Arc<ServiceTokenAuthenticator>,
    workload_security: Option<Arc<PresentationGrpcSecurity>>,
}

impl PresentationPolicyGrpcService {
    pub fn new(
        application: Arc<PolicyApplication>,
        verification: Arc<dyn PresentationVerificationOrchestrator>,
        service_token: Option<String>,
        service_authentication_required: bool,
    ) -> Result<Self, SecurityError> {
        Ok(Self {
            application,
            verification,
            service_authenticator: Arc::new(ServiceTokenAuthenticator::new(
                service_token,
                service_authentication_required,
            )?),
            workload_security: None,
        })
    }

    pub fn with_workload_security(mut self, security: Arc<PresentationGrpcSecurity>) -> Self {
        self.workload_security = Some(security);
        self
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        self.service_authenticator
            .authenticate(metadata(request, "x-service-token").as_deref())
            .map_err(|_| {
                Status::unauthenticated("PRESENTATION_POLICY.GRPC_SERVICE_AUTHENTICATION_REQUIRED")
            })
    }

    fn authenticate_workload<T>(&self, request: &Request<T>, method: &str) -> Result<(), Status> {
        self.authenticate(request)?;
        self.workload_security
            .as_ref()
            .ok_or_else(|| Status::unavailable("workload authorization is unavailable"))?
            .authorize(request, method)
    }

    fn principal<T>(&self, request: &Request<T>) -> Result<String, Status> {
        metadata(request, "x-user-id").ok_or_else(|| {
            Status::unauthenticated("PRESENTATION_POLICY.GRPC_AUTHENTICATION_REQUIRED")
        })
    }
}

#[tonic::async_trait]
impl PresentationPolicyService for PresentationPolicyGrpcService {
    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        if self.workload_security.is_some() {
            self.authenticate_workload(&request, GET_POLICY_METHOD)?;
        } else {
            self.authenticate(&request)?;
        }
        let policy = self
            .application
            .get_for_internal_service(parse_uuid(&request.get_ref().policy_id)?)
            .await
            .map_err(application_status)?;
        Ok(Response::new(policy_message(&policy)?))
    }

    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        self.authenticate(&request)?;
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        let organization_id = parse_uuid(&input.organization_id)?;
        let status = parse_optional_status(&input.status)?;
        let limit = if input.limit <= 0 {
            100usize
        } else {
            usize::try_from(input.limit).unwrap_or(usize::MAX).min(500)
        };
        let offset = usize::try_from(input.offset.max(0)).unwrap_or(0);
        let all = self
            .application
            .list(&principal, organization_id)
            .await
            .map_err(application_status)?;
        let matching = all
            .into_iter()
            .filter(|policy| status.is_none_or(|status| policy.status == status))
            .collect::<Vec<_>>();
        let total = i32::try_from(matching.len()).unwrap_or(i32::MAX);
        let policies = matching
            .iter()
            .skip(offset)
            .take(limit)
            .map(policy_message)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListPoliciesResponse { policies, total }))
    }

    async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        self.authenticate(&request)?;
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        let mut value = Map::new();
        value.insert("organization_id".into(), json!(input.organization_id));
        value.insert("name".into(), json!(input.name));
        insert_text(&mut value, "description", input.description);
        insert_text(
            &mut value,
            "compliance_profile_id",
            input.compliance_profile_id,
        );
        value.insert("prefer_predicates".into(), json!(input.prefer_predicates));
        insert_text(&mut value, "fallback_policy", input.fallback_policy);
        insert_json(
            &mut value,
            "credential_requirements",
            input.credential_requirements_json,
        )?;
        insert_json(
            &mut value,
            "alternative_requirements",
            input.alternative_requirements_json,
        )?;
        insert_json(&mut value, "display_metadata", input.display_metadata_json)?;
        let policy =
            build_policy_from_transport(Value::Object(value), Utc::now()).map_err(http_status)?;
        let policy = self
            .application
            .create(&principal, policy)
            .await
            .map_err(application_status)?;
        Ok(Response::new(policy_message(&policy)?))
    }

    async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        self.authenticate(&request)?;
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        let mut policy = self
            .application
            .get_for_update(&principal, parse_uuid(&input.policy_id)?)
            .await
            .map_err(application_status)?;
        let mut patch = Map::new();
        insert_text(&mut patch, "name", input.name);
        insert_text(&mut patch, "description", input.description);
        insert_text(
            &mut patch,
            "compliance_profile_id",
            input.compliance_profile_id,
        );
        apply_update_from_transport(&mut policy, Value::Object(patch), Utc::now())
            .map_err(http_status)?;
        let policy = self
            .application
            .update(&principal, policy)
            .await
            .map_err(application_status)?;
        Ok(Response::new(policy_message(&policy)?))
    }

    async fn activate_policy(
        &self,
        request: Request<PolicyIdRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        self.authenticate(&request)?;
        let principal = self.principal(&request)?;
        let policy = self
            .application
            .activate(
                &principal,
                parse_uuid(&request.get_ref().policy_id)?,
                Utc::now(),
            )
            .await
            .map_err(application_status)?;
        Ok(Response::new(policy_message(&policy)?))
    }

    async fn suspend_policy(
        &self,
        request: Request<PolicyIdRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        self.authenticate(&request)?;
        let principal = self.principal(&request)?;
        let policy = self
            .application
            .suspend(
                &principal,
                parse_uuid(&request.get_ref().policy_id)?,
                Utc::now(),
            )
            .await
            .map_err(application_status)?;
        Ok(Response::new(policy_message(&policy)?))
    }

    async fn new_version_policy(
        &self,
        request: Request<PolicyIdRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        self.authenticate(&request)?;
        let principal = self.principal(&request)?;
        let policy = self
            .application
            .new_version(
                &principal,
                parse_uuid(&request.get_ref().policy_id)?,
                Uuid::new_v4(),
                Utc::now(),
            )
            .await
            .map_err(application_status)?;
        Ok(Response::new(policy_message(&policy)?))
    }

    async fn delete_policy(
        &self,
        request: Request<PolicyIdRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        self.authenticate(&request)?;
        let principal = self.principal(&request)?;
        self.application
            .delete(&principal, parse_uuid(&request.get_ref().policy_id)?)
            .await
            .map_err(application_status)?;
        Ok(Response::new(DeletePolicyResponse { success: true }))
    }

    async fn evaluate_presentation(
        &self,
        request: Request<EvaluatePresentationMessage>,
    ) -> Result<Response<PolicyEvaluationResponse>, Status> {
        if self.workload_security.is_some() {
            self.authenticate_workload(&request, EVALUATE_PRESENTATION_METHOD)?;
        } else {
            self.authenticate(&request)?;
        }
        let principal = self.principal(&request)?;
        let input = request.into_inner();
        let policy = self
            .application
            .get_for_evaluation(&principal, parse_uuid(&input.policy_id)?)
            .await
            .map_err(application_status)?;
        let context = if input.context_json.trim().is_empty() {
            Map::new()
        } else {
            serde_json::from_str::<Value>(&input.context_json)
                .map_err(|_| Status::invalid_argument("context_json must be a JSON object"))?
                .as_object()
                .cloned()
                .ok_or_else(|| Status::invalid_argument("context_json must be a JSON object"))?
        };
        let evaluation = EvaluatePresentationRequest {
            vp_token: Value::String(input.vp_token),
            trust_profile_id: optional_text(input.trust_profile_id),
            nonce: optional_text(input.nonce),
            audience: optional_text(input.audience),
            context,
            trusted_internal_context: true,
        };
        let result = evaluate_policy(self.verification.as_ref(), &policy, &evaluation)
            .await
            .map_err(http_status)?;
        Ok(Response::new(evaluation_message(&result)?))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        self.authenticate(&request)?;
        Ok(Response::new(HealthCheckResponse {
            status: "serving".into(),
        }))
    }
}

fn policy_message(policy: &PresentationPolicy) -> Result<PolicyResponse, Status> {
    Ok(PolicyResponse {
        id: policy.id.to_string(),
        organization_id: policy.organization_id.to_string(),
        name: policy.name.clone(),
        description: policy.description.clone().unwrap_or_default(),
        status: status_name(policy.status).into(),
        display_metadata_json: serialize(&policy.display_metadata)?,
        credential_requirements_json: serialize(&policy.credential_requirements)?,
        alternative_requirements_json: serialize(&policy.alternative_requirements)?,
        compliance_profile_id: policy
            .compliance_profile_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        version: i32::try_from(policy.version).unwrap_or(i32::MAX),
        created_at: policy.created_at.to_rfc3339(),
        updated_at: policy.updated_at.to_rfc3339(),
    })
}

fn evaluation_message(value: &Value) -> Result<PolicyEvaluationResponse, Status> {
    Ok(PolicyEvaluationResponse {
        result: text(value, "result")?,
        policy_id: text(value, "policy_id")?,
        policy_name: text(value, "policy_name")?,
        credential_results_json: serialize(&value["credential_results"])?,
        total_requirements: integer(value, "total_requirements")?,
        satisfied_requirements: integer(value, "satisfied_requirements")?,
        required_satisfied: integer(value, "required_satisfied")?,
        required_total: integer(value, "required_total")?,
        decision: text(value, "decision")?,
        decision_reason: text(value, "decision_reason")?,
        verified_claims_json: serialize(&value["verified_claims"])?,
        evaluation_timestamp: text(value, "evaluation_timestamp")?,
        nonce: value["nonce"].as_str().unwrap_or_default().to_owned(),
    })
}

fn insert_text(object: &mut Map<String, Value>, name: &str, value: String) {
    if let Some(value) = optional_text(value) {
        object.insert(name.into(), Value::String(value));
    }
}

fn insert_json(object: &mut Map<String, Value>, name: &str, value: String) -> Result<(), Status> {
    if let Some(value) = optional_text(value) {
        object.insert(
            name.into(),
            serde_json::from_str(&value)
                .map_err(|_| Status::invalid_argument(format!("{name} must be valid JSON")))?,
        );
    }
    Ok(())
}

fn serialize(value: &impl serde::Serialize) -> Result<String, Status> {
    serde_json::to_string(value)
        .map_err(|_| Status::internal("PRESENTATION_POLICY.SERIALIZATION_FAILED"))
}

fn text(value: &Value, name: &str) -> Result<String, Status> {
    value[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Status::internal("PRESENTATION_POLICY.INVALID_NATIVE_RESULT"))
}

fn integer(value: &Value, name: &str) -> Result<i32, Status> {
    value[name]
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| Status::internal("PRESENTATION_POLICY.INVALID_NATIVE_RESULT"))
}

fn parse_uuid(value: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(value).map_err(|_| Status::invalid_argument("identifier must be a UUID"))
}

fn parse_optional_status(value: &str) -> Result<Option<PolicyStatus>, Status> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "draft" => Ok(Some(PolicyStatus::Draft)),
        "active" => Ok(Some(PolicyStatus::Active)),
        "suspended" => Ok(Some(PolicyStatus::Suspended)),
        "archived" => Ok(Some(PolicyStatus::Archived)),
        _ => Err(Status::invalid_argument("invalid policy status")),
    }
}

fn status_name(status: PolicyStatus) -> &'static str {
    match status {
        PolicyStatus::Draft => "draft",
        PolicyStatus::Active => "active",
        PolicyStatus::Suspended => "suspended",
        PolicyStatus::Archived => "archived",
    }
}

fn optional_text(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn metadata<T>(request: &Request<T>, name: &str) -> Option<String> {
    request
        .metadata()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn application_status(error: PolicyApplicationError) -> Status {
    match error {
        PolicyApplicationError::NotFound => Status::not_found("Presentation Policy not found"),
        PolicyApplicationError::Forbidden => {
            Status::permission_denied("PRESENTATION_POLICY.FORBIDDEN")
        }
        PolicyApplicationError::Conflict(detail) => Status::failed_precondition(detail),
        PolicyApplicationError::Domain(error) => Status::invalid_argument(error.to_string()),
        PolicyApplicationError::Dependency => {
            Status::unavailable("PRESENTATION_POLICY.DEPENDENCY_UNAVAILABLE")
        }
    }
}

fn http_status(error: PresentationPolicyHttpError) -> Status {
    match error.status.as_u16() {
        400 => Status::failed_precondition(error.detail),
        401 => Status::unauthenticated(error.detail),
        403 => Status::permission_denied(error.detail),
        404 => Status::not_found(error.detail),
        409 => Status::aborted(error.detail),
        422 => Status::invalid_argument(error.detail),
        503 => Status::unavailable(error.detail),
        _ => Status::internal(error.detail),
    }
}
