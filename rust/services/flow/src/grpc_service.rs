use std::{
    collections::{BTreeMap, HashMap},
    pin::Pin,
    sync::Arc,
};

use chrono::{DateTime, Utc};
use futures_core::Stream;
use marty_verification::flow::{FlowInstanceStatus, TransitionOutcome};
use mmf_push::WebhookDestinationRegistry;
use mmf_security::{
    ApplicationEventAuthError, ApplicationEventAuthenticator, ApplicationEventReplayStore,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
    advance_instance_record, apply_physical_advance_side_effect, definition_references,
    execute_application_event_plan,
    flow_proto::{
        flow_service_server::FlowService, ActivateFlowDefinitionRequest,
        AdvanceFlowRequest as ProtoAdvanceFlowRequest, ApplicationApprovedEvent,
        ApplicationApprovedResponse, CancelFlowRequest, CreateFlowDefinitionRequest as ProtoCreate,
        DeleteFlowDefinitionRequest, DeleteFlowDefinitionResponse, FlowArtifact as ProtoArtifact,
        FlowDefinitionResponse as ProtoDefinition, FlowInstanceEvent,
        FlowInstanceResponse as ProtoInstance, FlowResultResponse, FlowStep as ProtoStep,
        FlowTransition as ProtoTransition, GetFlowDefinitionRequest, GetFlowInstanceRequest,
        GetFlowResultRequest, HealthCheckRequest, HealthCheckResponse, ListFlowArtifactsRequest,
        ListFlowArtifactsResponse, ListFlowDefinitionsRequest, ListFlowDefinitionsResponse,
        ListFlowInstancesRequest, ListFlowInstancesResponse, StartFlowRequest as ProtoStartFlow,
        StartVerificationRequest, StreamFlowUpdatesRequest, VerificationRequestResponse,
    },
    prepare_instance_start, prepare_profiled_verification_start, start_instance_record,
    ApplicationApprovalError, ApplicationApprovedWebhook, ApprovalStrategy, ArtifactStatus,
    DefinitionStatus, FlowApiError, FlowArtifactRecord, FlowDefinitionRecord, FlowGrpcSecurity,
    FlowInstanceExecutionError, FlowInstanceRecord, FlowInstanceSideEffectError, FlowProviderError,
    FlowProviderRegistry, FlowRecordError, FlowServiceConfig, Oid4vpProfile,
    PostgresFlowRepository, RedisApplicationEventReplayStore, RepositoryError, RequestTransport,
    RequestUriMethod, StartFlowRequest, StartVerificationFlowRequest, VerificationResponseType,
    VerificationStartOptions,
};

const USER_ID_METADATA: &str = "x-user-id";
const STREAM_CAPACITY: usize = 256;
const DEFAULT_TIMEOUT_SECONDS: u32 = 3_600;
const DEFAULT_MAX_RETRIES: u32 = 3;

#[derive(Clone)]
pub struct FlowGrpcApplicationApprovalOptions {
    authenticator: ApplicationEventAuthenticator,
    replay_store: Arc<dyn ApplicationEventReplayStore>,
}

impl FlowGrpcApplicationApprovalOptions {
    pub fn from_config(
        config: &FlowServiceConfig,
        nonce_store: redis::aio::ConnectionManager,
    ) -> Result<Self, ApplicationEventAuthError> {
        let secret = config
            .application_event_hmac_key
            .as_deref()
            .ok_or(ApplicationEventAuthError::Configuration)?;
        Ok(Self {
            authenticator: ApplicationEventAuthenticator::new(
                secret,
                i64::from(config.application_event_max_age_seconds),
                u64::from(config.application_event_replay_ttl_seconds),
            )?,
            replay_store: Arc::new(RedisApplicationEventReplayStore::new(nonce_store)),
        })
    }
}

#[derive(Clone)]
struct FlowEventEnvelope {
    organization_id: String,
    flow_type: String,
    event: FlowInstanceEvent,
}

#[derive(Clone)]
pub struct FlowGrpcService {
    repository: PostgresFlowRepository,
    providers: Arc<FlowProviderRegistry>,
    security: Arc<FlowGrpcSecurity>,
    public_base_url: String,
    callbacks: WebhookDestinationRegistry,
    verification: VerificationStartOptions,
    application: FlowGrpcApplicationApprovalOptions,
    events: broadcast::Sender<FlowEventEnvelope>,
}

impl FlowGrpcService {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        repository: PostgresFlowRepository,
        providers: Arc<FlowProviderRegistry>,
        security: Arc<FlowGrpcSecurity>,
        public_base_url: String,
        callbacks: WebhookDestinationRegistry,
        verification: VerificationStartOptions,
        application: FlowGrpcApplicationApprovalOptions,
    ) -> Self {
        let (events, _) = broadcast::channel(STREAM_CAPACITY);
        Self {
            repository,
            providers,
            security,
            public_base_url,
            callbacks,
            verification,
            application,
            events,
        }
    }

    async fn authorize<T>(
        &self,
        request: &Request<T>,
        organization_id: &str,
        permission: &str,
    ) -> Result<String, Status> {
        self.security.authenticate_service(request)?;
        let principal = request
            .metadata()
            .get(USER_ID_METADATA)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| Status::unauthenticated("user authentication is required"))?;
        self.providers
            .authorize(principal, organization_id, permission, false)
            .await
            .map_err(provider_status)?;
        Ok(principal.to_owned())
    }

    async fn required_definition(&self, id: &str) -> Result<FlowDefinitionRecord, Status> {
        self.repository
            .definition(id)
            .await
            .map_err(repository_status)?
            .ok_or_else(|| Status::not_found("Flow definition not found"))
    }

    async fn required_instance(&self, id: &str) -> Result<FlowInstanceRecord, Status> {
        self.repository
            .instance(id)
            .await
            .map_err(repository_status)?
            .ok_or_else(|| Status::not_found("Flow instance not found"))
    }

    fn emit(
        &self,
        event_type: &'static str,
        instance: &FlowInstanceRecord,
        artifact: Option<&FlowArtifactRecord>,
    ) {
        let flow_type = instance
            .context
            .get("protocol_flow_type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let _ = self.events.send(FlowEventEnvelope {
            organization_id: instance.organization_id.clone(),
            flow_type,
            event: FlowInstanceEvent {
                event_type: event_type.into(),
                instance_id: instance.id.clone(),
                definition_id: instance.flow_definition_id.clone(),
                current_step_id: instance.current_step_id.clone().unwrap_or_default(),
                status: public_instance_status(instance.status).into(),
                artifact: artifact.map(proto_artifact).transpose().ok().flatten(),
                timestamp: Utc::now().to_rfc3339(),
            },
        });
    }
}

#[tonic::async_trait]
impl FlowService for FlowGrpcService {
    async fn create_flow_definition(
        &self,
        request: Request<ProtoCreate>,
    ) -> Result<Response<ProtoDefinition>, Status> {
        let principal = self
            .authorize(
                &request,
                &request.get_ref().organization_id,
                "flow-definition:create",
            )
            .await?;
        let now = Utc::now();
        let record = definition_from_proto(request.into_inner(), now)?;
        crate::validate_definition_references(
            &self.providers,
            &principal,
            &record.organization_id,
            &definition_references(&record),
            true,
        )
        .await
        .map_err(provider_status)?;
        record.kernel().map_err(record_status)?;
        self.repository
            .save_definition(&record)
            .await
            .map_err(repository_status)?;
        Ok(Response::new(proto_definition(&record)?))
    }

    async fn get_flow_definition(
        &self,
        request: Request<GetFlowDefinitionRequest>,
    ) -> Result<Response<ProtoDefinition>, Status> {
        self.security.authenticate_service(&request)?;
        let record = self.required_definition(&request.get_ref().flow_id).await?;
        self.authorize(&request, &record.organization_id, "flow-definition:view")
            .await?;
        Ok(Response::new(proto_definition(&record)?))
    }

    async fn list_flow_definitions(
        &self,
        request: Request<ListFlowDefinitionsRequest>,
    ) -> Result<Response<ListFlowDefinitionsResponse>, Status> {
        let organization_id = request.get_ref().organization_id.clone();
        self.authorize(&request, &organization_id, "flow-definition:view")
            .await?;
        let status_filter = optional(&request.get_ref().status)
            .map(parse_definition_status)
            .transpose()?;
        let definitions = self
            .repository
            .definitions_for_tenant(&organization_id)
            .await
            .map_err(repository_status)?
            .into_iter()
            .filter(|record| status_filter.is_none_or(|status| record.status == status))
            .map(|record| proto_definition(&record))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListFlowDefinitionsResponse { definitions }))
    }

    async fn activate_flow_definition(
        &self,
        request: Request<ActivateFlowDefinitionRequest>,
    ) -> Result<Response<ProtoDefinition>, Status> {
        self.security.authenticate_service(&request)?;
        let mut record = self.required_definition(&request.get_ref().flow_id).await?;
        let principal = self
            .authorize(
                &request,
                &record.organization_id,
                "flow-definition:activate",
            )
            .await?;
        record.kernel().map_err(record_status)?;
        crate::validate_definition_references(
            &self.providers,
            &principal,
            &record.organization_id,
            &definition_references(&record),
            true,
        )
        .await
        .map_err(provider_status)?;
        record.status = DefinitionStatus::Active;
        record.updated_at = Utc::now();
        self.repository
            .save_definition(&record)
            .await
            .map_err(repository_status)?;
        Ok(Response::new(proto_definition(&record)?))
    }

    async fn delete_flow_definition(
        &self,
        request: Request<DeleteFlowDefinitionRequest>,
    ) -> Result<Response<DeleteFlowDefinitionResponse>, Status> {
        self.security.authenticate_service(&request)?;
        let record = self.required_definition(&request.get_ref().flow_id).await?;
        self.authorize(&request, &record.organization_id, "flow-definition:delete")
            .await?;
        if record.status != DefinitionStatus::Draft {
            return Err(Status::failed_precondition(
                "Only draft flows can be deleted",
            ));
        }
        let success = self
            .repository
            .delete_definition(&record.id)
            .await
            .map_err(repository_status)?;
        Ok(Response::new(DeleteFlowDefinitionResponse { success }))
    }

    async fn start_flow_instance(
        &self,
        request: Request<ProtoStartFlow>,
    ) -> Result<Response<ProtoInstance>, Status> {
        self.security.authenticate_service(&request)?;
        let definition = self
            .required_definition(&request.get_ref().flow_definition_id)
            .await?;
        let principal = self
            .authorize(&request, &definition.organization_id, "flow-instance:start")
            .await?;
        let input = request.into_inner();
        let now = Utc::now();
        let instance = start_instance_record(
            &definition,
            StartFlowRequest {
                organization_id: definition.organization_id.clone(),
                flow_definition_id: input.flow_definition_id,
                subject_id: nonempty(input.subject_id),
                subject_type: nonempty(input.subject_type).unwrap_or_else(|| "person".into()),
                external_reference: nonempty(input.external_reference),
                initial_context: Value::Object(string_map_to_json(input.initial_context)),
            },
            &principal,
            now,
        )
        .map_err(execution_status)?;
        let prepared = prepare_instance_start(
            &self.providers,
            &definition,
            instance,
            &self.public_base_url,
            now,
        )
        .await
        .map_err(side_effect_status)?;
        if !self
            .repository
            .save_started_instance(&prepared.instance, prepared.artifact.as_ref())
            .await
            .map_err(repository_status)?
        {
            return Err(Status::already_exists("Flow instance already exists"));
        }
        self.emit("started", &prepared.instance, prepared.artifact.as_ref());
        if let Some(artifact) = prepared.artifact.as_ref() {
            self.emit("artifact_created", &prepared.instance, Some(artifact));
        }
        Ok(Response::new(proto_instance(&prepared.instance)?))
    }

    async fn get_flow_instance(
        &self,
        request: Request<GetFlowInstanceRequest>,
    ) -> Result<Response<ProtoInstance>, Status> {
        self.security.authenticate_service(&request)?;
        let instance = self
            .required_instance(&request.get_ref().instance_id)
            .await?;
        self.authorize(&request, &instance.organization_id, "flow-instance:view")
            .await?;
        Ok(Response::new(proto_instance(&instance)?))
    }

    async fn list_flow_instances(
        &self,
        request: Request<ListFlowInstancesRequest>,
    ) -> Result<Response<ListFlowInstancesResponse>, Status> {
        let organization_id = request.get_ref().organization_id.clone();
        self.authorize(&request, &organization_id, "flow-instance:view")
            .await?;
        let limit = request.get_ref().limit;
        let offset = request.get_ref().offset;
        if limit < 0 || offset < 0 || limit > 500 {
            return Err(Status::invalid_argument("pagination is out of range"));
        }
        let status = optional(&request.get_ref().status)
            .map(parse_instance_status)
            .transpose()?;
        let all = self
            .repository
            .instances_for_tenant(
                &organization_id,
                optional(&request.get_ref().flow_definition_id),
                status,
            )
            .await
            .map_err(repository_status)?;
        let total = i32::try_from(all.len()).unwrap_or(i32::MAX);
        let take = if limit == 0 { 100 } else { limit as usize };
        let instances = all
            .into_iter()
            .skip(offset as usize)
            .take(take)
            .map(|record| proto_instance(&record))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListFlowInstancesResponse {
            instances,
            total,
        }))
    }

    async fn advance_flow_instance(
        &self,
        request: Request<ProtoAdvanceFlowRequest>,
    ) -> Result<Response<ProtoInstance>, Status> {
        self.security.authenticate_service(&request)?;
        let current = self
            .required_instance(&request.get_ref().instance_id)
            .await?;
        let principal = self
            .authorize(&request, &current.organization_id, "flow-instance:advance")
            .await?;
        let definition = self
            .required_definition(&current.flow_definition_id)
            .await?;
        let input = request.into_inner();
        let outcome = parse_transition_outcome(default_success(&input.step_result))?;
        let expected_status = current.status;
        let expected_updated_at = current.updated_at;
        let current = apply_physical_advance_side_effect(
            &self.providers,
            &definition,
            current,
            outcome,
            &Value::Object(string_map_to_json(input.data.clone())),
        )
        .await
        .map_err(side_effect_status)?;
        let advanced = advance_instance_record(
            &definition,
            &current,
            crate::AdvanceFlowRequest {
                step_result: default_success(&input.step_result).into(),
                data: Value::Object(string_map_to_json(input.data)),
            },
            &principal,
            Utc::now(),
        )
        .map_err(execution_status)?;
        if !self
            .repository
            .compare_and_swap_instance(&advanced, expected_status, expected_updated_at)
            .await
            .map_err(repository_status)?
        {
            return Err(Status::aborted("Flow instance changed concurrently"));
        }
        let event_type = if advanced.status.is_terminal() {
            "completed"
        } else {
            "advanced"
        };
        self.emit(event_type, &advanced, None);
        Ok(Response::new(proto_instance(&advanced)?))
    }

    async fn cancel_flow_instance(
        &self,
        request: Request<CancelFlowRequest>,
    ) -> Result<Response<ProtoInstance>, Status> {
        self.security.authenticate_service(&request)?;
        let current = self
            .required_instance(&request.get_ref().instance_id)
            .await?;
        let principal = self
            .authorize(&request, &current.organization_id, "flow-instance:cancel")
            .await?;
        if current.status.is_terminal() {
            return Err(Status::failed_precondition("Flow already ended"));
        }
        let cancelled = self
            .repository
            .cancel_instance(&current.id, &principal, Utc::now())
            .await
            .map_err(repository_status)?
            .ok_or_else(|| Status::aborted("Flow already ended"))?;
        self.emit("cancelled", &cancelled, None);
        Ok(Response::new(proto_instance(&cancelled)?))
    }

    async fn get_flow_result(
        &self,
        request: Request<GetFlowResultRequest>,
    ) -> Result<Response<FlowResultResponse>, Status> {
        self.security.authenticate_service(&request)?;
        let instance = self
            .required_instance(&request.get_ref().instance_id)
            .await?;
        self.authorize(&request, &instance.organization_id, "flow-instance:view")
            .await?;
        Ok(Response::new(proto_result(&instance)?))
    }

    async fn list_flow_artifacts(
        &self,
        request: Request<ListFlowArtifactsRequest>,
    ) -> Result<Response<ListFlowArtifactsResponse>, Status> {
        self.security.authenticate_service(&request)?;
        let instance = self
            .required_instance(&request.get_ref().instance_id)
            .await?;
        self.authorize(&request, &instance.organization_id, "flow-instance:view")
            .await?;
        let artifacts = self
            .repository
            .artifacts_for_instance(&instance.id)
            .await
            .map_err(repository_status)?
            .iter()
            .map(proto_artifact)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListFlowArtifactsResponse { artifacts }))
    }

    async fn start_verification(
        &self,
        request: Request<StartVerificationRequest>,
    ) -> Result<Response<VerificationRequestResponse>, Status> {
        self.security
            .authorize_workload(&request, crate::START_VERIFICATION_METHOD)?;
        let input = request.into_inner();
        let principal_id = verification_principal(&input)?;
        let response_type = parse_response_type(default_value(&input.response_type, "vp_token"))?;
        let prepared = prepare_profiled_verification_start(
            &self.providers,
            &self.callbacks,
            StartVerificationFlowRequest {
                presentation_policy_id: nonempty(input.presentation_policy_id),
                organization_id: input.organization_id,
                issuer_did: input.issuer_did,
                response_type,
                trust_profile_id: nonempty(input.trust_profile_id),
                deployment_profile_id: nonempty(input.deployment_profile_id),
                external_reference: nonempty(input.external_reference),
                callback_url: nonempty(input.callback_url),
                oid4vp_profile: Oid4vpProfile::Standard,
                request_transport: parse_request_transport(default_value(
                    &input.request_transport,
                    "request_uri",
                ))?,
                request_uri_method: RequestUriMethod::Get,
                expiry_minutes: if input.expiry_minutes == 0 {
                    15
                } else {
                    u16::try_from(input.expiry_minutes)
                        .map_err(|_| Status::invalid_argument("expiry_minutes is invalid"))?
                },
            },
            &self.public_base_url,
            true,
            &self.verification,
            &principal_id,
            Utc::now(),
        )
        .await
        .map_err(verification_start_status)?;
        if !self
            .repository
            .save_started_instance(&prepared.instance, None)
            .await
            .map_err(repository_status)?
        {
            return Err(Status::already_exists(
                "Verification transaction already exists",
            ));
        }
        self.emit("started", &prepared.instance, None);
        Ok(Response::new(VerificationRequestResponse {
            instance_id: prepared.response.instance_id,
            flow_definition_id: prepared.response.flow_definition_id,
            request_uri: prepared.response.request_uri,
            qr_code_data: prepared.response.qr_code_data,
            presentation_policy_id: prepared.response.presentation_policy_id,
            nonce: prepared.response.nonce,
            expires_at: prepared.response.expires_at,
            status: prepared.response.status,
        }))
    }

    async fn application_approved(
        &self,
        request: Request<ApplicationApprovedEvent>,
    ) -> Result<Response<ApplicationApprovedResponse>, Status> {
        self.security
            .authorize_workload(&request, crate::APPLICATION_APPROVED_METHOD)?;
        let metadata = request
            .metadata()
            .iter()
            .filter_map(|entry| match entry {
                tonic::metadata::KeyAndValueRef::Ascii(key, value) => value
                    .to_str()
                    .ok()
                    .map(|value| (key.as_str().to_ascii_lowercase(), value.to_owned())),
                tonic::metadata::KeyAndValueRef::Binary(_, _) => None,
            })
            .collect::<BTreeMap<_, _>>();
        let input = request.into_inner();
        let event = ApplicationApprovedWebhook {
            event_type: input.event_type,
            aggregate_id: input.aggregate_id,
            aggregate_type: input.aggregate_type,
            organization_id: input.organization_id,
            data: string_map_to_decoded_json(input.data),
            timestamp: input.timestamp,
        };
        let payload = serde_json::to_value(&event)
            .map_err(|_| Status::invalid_argument("Application event is malformed"))?;
        let now = Utc::now();
        let evidence = self
            .application
            .authenticator
            .authenticate(&payload, &metadata, now.timestamp())
            .map_err(application_auth_status)?;
        let result = execute_application_event_plan(
            &event,
            &evidence,
            crate::ApplicationEventExecutionContext {
                authenticator: &self.application.authenticator,
                replay_store: self.application.replay_store.as_ref(),
                repository: &self.repository,
                providers: &self.providers,
                public_base_url: &self.public_base_url,
            },
            now,
        )
        .await
        .map_err(application_status)?;
        for instance_id in &result.instance_ids {
            if let Ok(Some(instance)) = self.repository.instance(instance_id).await {
                self.emit("started", &instance, None);
                if let Ok(artifacts) = self.repository.artifacts_for_instance(instance_id).await {
                    for artifact in artifacts {
                        self.emit("artifact_created", &instance, Some(&artifact));
                    }
                }
            }
        }
        Ok(Response::new(ApplicationApprovedResponse {
            success: result.success,
            flows_triggered: i32::try_from(result.flows_triggered).unwrap_or(i32::MAX),
        }))
    }

    type StreamFlowUpdatesStream =
        Pin<Box<dyn Stream<Item = Result<FlowInstanceEvent, Status>> + Send + 'static>>;

    async fn stream_flow_updates(
        &self,
        request: Request<StreamFlowUpdatesRequest>,
    ) -> Result<Response<Self::StreamFlowUpdatesStream>, Status> {
        self.security.authenticate_service(&request)?;
        let filter = request.get_ref().clone();
        let organization_id = if filter.organization_id.is_empty() {
            if filter.instance_id.is_empty() {
                return Err(Status::invalid_argument(
                    "organization_id or instance_id is required",
                ));
            }
            self.required_instance(&filter.instance_id)
                .await?
                .organization_id
        } else {
            filter.organization_id.clone()
        };
        self.authorize(&request, &organization_id, "flow-instance:view")
            .await?;
        if !filter.instance_id.is_empty() {
            let instance = self.required_instance(&filter.instance_id).await?;
            if instance.organization_id != organization_id {
                return Err(Status::not_found("Flow instance not found"));
            }
        }
        let stream =
            BroadcastStream::new(self.events.subscribe()).filter_map(move |item| match item {
                Ok(envelope)
                    if envelope.organization_id == organization_id
                        && (filter.instance_id.is_empty()
                            || envelope.event.instance_id == filter.instance_id)
                        && (filter.flow_types.is_empty()
                            || filter.flow_types.contains(&envelope.flow_type)) =>
                {
                    Some(Ok(envelope.event))
                }
                Ok(_) => None,
                Err(_) => Some(Err(Status::resource_exhausted(
                    "Flow update subscriber fell behind",
                ))),
            });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        self.security.authenticate_service(&request)?;
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(self.repository.pool())
            .await
            .map_err(|_| Status::unavailable("Flow persistence is unavailable"))?;
        Ok(Response::new(HealthCheckResponse {
            status: "serving".into(),
        }))
    }
}

fn definition_from_proto(
    input: ProtoCreate,
    now: DateTime<Utc>,
) -> Result<FlowDefinitionRecord, Status> {
    required(&input.organization_id, "organization_id")?;
    required(&input.name, "name")?;
    let flow_type = parse_flow_type(default_value(&input.flow_type, "oid4vci_pre_authorized"))?;
    let mut aliases = BTreeMap::new();
    let mut steps = Vec::with_capacity(input.steps.len());
    for (index, step) in input.steps.into_iter().enumerate() {
        required(&step.name, "steps.name")?;
        let step_type = default_value(&step.step_type, "user_input").to_ascii_lowercase();
        validate_step_type(&step_type)?;
        let id = if step.step_id.trim().is_empty() {
            Uuid::new_v4().to_string()
        } else {
            step.step_id.clone()
        };
        aliases.insert(index.to_string(), id.clone());
        aliases.insert(step.step_id, id.clone());
        let mut config = string_map_to_decoded_json(step.config);
        config
            .entry("protocol_step".into())
            .or_insert_with(|| Value::String(step.name.clone()));
        steps.push(json!({
            "id": id,
            "name": step.name,
            "step_type": step_type,
            "config": config,
        }));
    }
    if steps.is_empty() {
        return Err(Status::invalid_argument("Flow must have at least one step"));
    }
    let transitions = input
        .transitions
        .into_iter()
        .map(|transition| {
            let from = aliases
                .get(&transition.from_step_id)
                .cloned()
                .unwrap_or(transition.from_step_id);
            let to = aliases
                .get(&transition.to_step_id)
                .cloned()
                .unwrap_or(transition.to_step_id);
            let outcome = parse_transition_outcome(default_success(&transition.condition))?;
            Ok(json!({
                "id": Uuid::new_v4().to_string(),
                "from_step_id": from,
                "to_step_id": to,
                "condition": outcome,
            }))
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let requested_start = if input.start_step_id.is_empty() {
        "0"
    } else {
        &input.start_step_id
    };
    let start_step_id = aliases
        .get(requested_start)
        .cloned()
        .or_else(|| Some(requested_start.to_owned()));
    let record = FlowDefinitionRecord {
        id: Uuid::new_v4().to_string(),
        organization_id: input.organization_id,
        name: input.name,
        description: nonempty(input.description),
        status: DefinitionStatus::Active,
        flow_type,
        steps,
        transitions,
        start_step_id,
        credential_template_id: nonempty(input.credential_template_id),
        application_template_id: None,
        presentation_policy_id: nonempty(input.presentation_policy_id),
        delivery_destination_profile_id: None,
        deployment_profile_id: nonempty(input.deployment_profile_id),
        deployment_profile_ids: Vec::new(),
        trust_profile_id: None,
        approval_strategy: ApprovalStrategy::Auto,
        hooks: BTreeMap::new(),
        trigger: None,
        extension: None,
        preconditions: input.preconditions,
        default_timeout_seconds: u32::try_from(if input.default_timeout_seconds == 0 {
            DEFAULT_TIMEOUT_SECONDS as i32
        } else {
            input.default_timeout_seconds
        })
        .map_err(|_| Status::invalid_argument("default_timeout_seconds is invalid"))?,
        max_retries: u32::try_from(if input.max_retries == 0 {
            DEFAULT_MAX_RETRIES as i32
        } else {
            input.max_retries
        })
        .map_err(|_| Status::invalid_argument("max_retries is invalid"))?,
        retry_cooldown_minutes: 5,
        enable_resume: input.enable_resume,
        version: 1,
        created_at: now,
        updated_at: now,
    };
    record.kernel().map_err(record_status)?;
    Ok(record)
}

fn proto_definition(record: &FlowDefinitionRecord) -> Result<ProtoDefinition, Status> {
    let steps = record
        .steps
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| Status::internal("Stored Flow definition is invalid"))?;
            let config = object
                .get("config")
                .and_then(Value::as_object)
                .map(json_object_to_string_map)
                .transpose()?
                .unwrap_or_default();
            Ok(ProtoStep {
                step_id: object_string(object, "id")?,
                name: object_string(object, "name")?,
                step_type: object_string(object, "step_type")?,
                config,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let transitions = record
        .transitions
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| Status::internal("Stored Flow definition is invalid"))?;
            Ok(ProtoTransition {
                from_step_id: object_string(object, "from_step_id")?,
                to_step_id: object_string(object, "to_step_id")?,
                condition: object_string(object, "condition")?,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    Ok(ProtoDefinition {
        id: record.id.clone(),
        organization_id: record.organization_id.clone(),
        name: record.name.clone(),
        description: record.description.clone().unwrap_or_default(),
        status: enum_string(record.status)?,
        flow_type: enum_string(record.flow_type)?,
        steps,
        transitions,
        start_step_id: record.start_step_id.clone().unwrap_or_default(),
        preconditions: record.preconditions.clone(),
        credential_template_id: record.credential_template_id.clone().unwrap_or_default(),
        presentation_policy_id: record.presentation_policy_id.clone().unwrap_or_default(),
        deployment_profile_id: record.deployment_profile_id.clone().unwrap_or_default(),
        default_timeout_seconds: i32::try_from(record.default_timeout_seconds)
            .map_err(|_| Status::internal("Stored Flow timeout is invalid"))?,
        version: i32::try_from(record.version)
            .map_err(|_| Status::internal("Stored Flow version is invalid"))?,
        created_at: record.created_at.to_rfc3339(),
        updated_at: record.updated_at.to_rfc3339(),
    })
}

fn proto_instance(record: &FlowInstanceRecord) -> Result<ProtoInstance, Status> {
    let context = crate::public_context(&record.context);
    let context = context
        .as_object()
        .map(json_object_to_string_map)
        .transpose()?
        .unwrap_or_default();
    let flow_type = context
        .get("protocol_flow_type")
        .cloned()
        .unwrap_or_default();
    Ok(ProtoInstance {
        id: record.id.clone(),
        flow_definition_id: record.flow_definition_id.clone(),
        organization_id: record.organization_id.clone(),
        status: public_instance_status(record.status).into(),
        current_step_id: record.current_step_id.clone().unwrap_or_default(),
        context,
        subject_id: record.subject_id.clone().unwrap_or_default(),
        external_reference: record.external_reference.clone().unwrap_or_default(),
        started_at: timestamp(record.started_at),
        completed_at: timestamp(record.completed_at),
        expires_at: timestamp(record.expires_at),
        result: optional_json(record.result.as_ref())?,
        error: record.error.clone().unwrap_or_default(),
        created_at: record.created_at.to_rfc3339(),
        updated_at: record.updated_at.to_rfc3339(),
        flow_id: if record.flow_definition_id.starts_with("__") {
            String::new()
        } else {
            record.flow_definition_id.clone()
        },
        protocol_status: public_instance_status(record.status).into(),
        flow_type,
        current_step: context_string(&record.context, "current_step_name"),
        current_step_index: context_u32(&record.context, "current_step_index")
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or_default(),
        issued_credential_id: context_string(&record.context, "issued_credential_id"),
        error_code: context_string(&record.context, "error_code"),
    })
}

fn proto_result(record: &FlowInstanceRecord) -> Result<FlowResultResponse, Status> {
    let result = record.result.as_ref();
    let object = result.and_then(Value::as_object);
    let verified_claims = object
        .map(json_object_to_string_map)
        .transpose()?
        .unwrap_or_default();
    Ok(FlowResultResponse {
        instance_id: record.id.clone(),
        status: public_instance_status(record.status).into(),
        result: optional_json(result)?,
        decision: object
            .and_then(|value| value.get("decision"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        decision_reason: object
            .and_then(|value| value.get("decision_reason"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        verified_claims,
        evaluation_timestamp: timestamp(record.completed_at),
    })
}

fn proto_artifact(record: &FlowArtifactRecord) -> Result<ProtoArtifact, Status> {
    Ok(ProtoArtifact {
        id: record.id.clone(),
        flow_instance_id: record.flow_instance_id.clone(),
        credential_offer_uri: record.credential_offer_uri.clone().unwrap_or_default(),
        qr_payload: record.qr_payload.clone().unwrap_or_default(),
        pre_authorized_code: record.pre_authorized_code.clone().unwrap_or_default(),
        expires_at: timestamp(record.expires_at),
        scanned_at: timestamp(record.scanned_at),
        status: match record.status {
            ArtifactStatus::Active => "active",
            ArtifactStatus::Scanned => "scanned",
            ArtifactStatus::Expired => "expired",
            ArtifactStatus::Revoked => "revoked",
        }
        .into(),
        state: record.state.clone().unwrap_or_default(),
        attempt_number: i32::try_from(record.attempt_number)
            .map_err(|_| Status::internal("Stored artifact attempt is invalid"))?,
        created_at: record.created_at.to_rfc3339(),
        updated_at: record.updated_at.to_rfc3339(),
    })
}

fn parse_flow_type(value: &str) -> Result<crate::FlowType, Status> {
    let normalized = value.trim().to_ascii_lowercase();
    let canonical = match normalized.as_str() {
        "issuance" | "issuance_oid4vci" => "oid4vci_pre_authorized",
        "verification" | "verification_oid4vp" | "presentation" => "oid4vp_presentation",
        "renewal" => "credential_renewal",
        "revocation" => "credential_revocation",
        "siop_v2" => "siopv2",
        other => other,
    };
    serde_json::from_value(Value::String(canonical.into()))
        .map_err(|_| Status::invalid_argument("flow_type is invalid"))
}

fn parse_definition_status(value: &str) -> Result<DefinitionStatus, Status> {
    let canonical = match value.trim().to_ascii_lowercase().as_str() {
        "draft" => "DRAFT",
        "active" => "ACTIVE",
        "paused" | "suspended" => "PAUSED",
        "archived" => "ARCHIVED",
        _ => return Err(Status::invalid_argument("status is invalid")),
    };
    serde_json::from_value(Value::String(canonical.into()))
        .map_err(|_| Status::invalid_argument("status is invalid"))
}

fn parse_instance_status(value: &str) -> Result<FlowInstanceStatus, Status> {
    serde_json::from_value(Value::String(value.trim().to_ascii_lowercase()))
        .map_err(|_| Status::invalid_argument("status is invalid"))
}

fn parse_transition_outcome(value: &str) -> Result<TransitionOutcome, Status> {
    serde_json::from_value(Value::String(value.trim().to_ascii_lowercase()))
        .map_err(|_| Status::invalid_argument("step_result or transition condition is invalid"))
}

fn parse_response_type(value: &str) -> Result<VerificationResponseType, Status> {
    serde_json::from_value(Value::String(value.trim().to_ascii_lowercase()))
        .map_err(|_| Status::invalid_argument("response_type is invalid"))
}

fn parse_request_transport(value: &str) -> Result<RequestTransport, Status> {
    serde_json::from_value(Value::String(value.trim().to_ascii_lowercase()))
        .map_err(|_| Status::invalid_argument("request_transport is invalid"))
}

fn validate_step_type(value: &str) -> Result<(), Status> {
    const TYPES: &[&str] = &[
        "start",
        "user_input",
        "data_collection",
        "verification",
        "validation",
        "approval",
        "issuance",
        "callback",
        "wait",
        "decision",
        "end",
    ];
    if TYPES.contains(&value) {
        Ok(())
    } else {
        Err(Status::invalid_argument("step_type is invalid"))
    }
}

fn string_map_to_json(values: impl IntoIterator<Item = (String, String)>) -> Map<String, Value> {
    values
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect()
}

fn string_map_to_decoded_json(
    values: impl IntoIterator<Item = (String, String)>,
) -> BTreeMap<String, Value> {
    values
        .into_iter()
        .map(|(key, value)| {
            let decoded = serde_json::from_str(&value).unwrap_or(Value::String(value));
            (key, decoded)
        })
        .collect()
}

fn json_object_to_string_map(
    object: &Map<String, Value>,
) -> Result<HashMap<String, String>, Status> {
    object
        .iter()
        .map(|(key, value)| Ok((key.clone(), json_value_string(value)?)))
        .collect()
}

fn json_value_string(value: &Value) -> Result<String, Status> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Null => Ok("None".into()),
        Value::Bool(value) => Ok(if *value { "True" } else { "False" }.into()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value)
            .map_err(|_| Status::internal("Stored Flow state is not serializable")),
    }
}

fn enum_string<T: Serialize>(value: T) -> Result<String, Status> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| Status::internal("Stored Flow enum is invalid"))
}

fn object_string(object: &Map<String, Value>, name: &str) -> Result<String, Status> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Status::internal("Stored Flow definition is invalid"))
}

fn context_string(value: &Value, name: &str) -> String {
    value
        .get(name)
        .map(|value| json_value_string(value).unwrap_or_default())
        .unwrap_or_default()
}

fn context_u32(value: &Value, name: &str) -> Option<u32> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
}

fn optional_json(value: Option<&Value>) -> Result<String, Status> {
    value.map_or_else(
        || Ok(String::new()),
        |value| {
            serde_json::to_string(value)
                .map_err(|_| Status::internal("Stored Flow result is not serializable"))
        },
    )
}

fn timestamp(value: Option<DateTime<Utc>>) -> String {
    value.map(|value| value.to_rfc3339()).unwrap_or_default()
}

fn public_instance_status(status: FlowInstanceStatus) -> &'static str {
    crate::public_status(status)
}

fn required(value: &str, name: &'static str) -> Result<(), Status> {
    if value.trim().is_empty() {
        Err(Status::invalid_argument(format!("{name} is required")))
    } else {
        Ok(())
    }
}

fn optional(value: &str) -> Option<&str> {
    (!value.trim().is_empty()).then_some(value)
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn default_value<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value
    }
}

fn verification_principal(input: &StartVerificationRequest) -> Result<String, Status> {
    let principal = input.user_id.trim();
    if principal.is_empty() {
        Err(Status::unauthenticated(
            "verification principal is required",
        ))
    } else {
        Ok(principal.to_owned())
    }
}

fn default_success(value: &str) -> &str {
    default_value(value, "success")
}

fn repository_status(_error: RepositoryError) -> Status {
    Status::unavailable("Flow persistence is unavailable")
}

fn record_status(_error: FlowRecordError) -> Status {
    Status::internal("Stored Flow state is invalid")
}

fn provider_status(error: FlowProviderError) -> Status {
    match error {
        FlowProviderError::Rejected { .. } => {
            Status::permission_denied("Operation is not authorized")
        }
        FlowProviderError::NotFound { .. } => {
            Status::not_found("Referenced resource was not found")
        }
        FlowProviderError::Conflict { .. } => {
            Status::already_exists("Referenced resource conflicts")
        }
        FlowProviderError::InvalidResponse { .. }
        | FlowProviderError::Unavailable { .. }
        | FlowProviderError::Missing(_) => {
            Status::unavailable("Required Flow provider is unavailable")
        }
    }
}

fn execution_status(error: FlowInstanceExecutionError) -> Status {
    match error {
        FlowInstanceExecutionError::DefinitionNotActive
        | FlowInstanceExecutionError::NotAdvanceable(_)
        | FlowInstanceExecutionError::PreconditionsNotMet(_)
        | FlowInstanceExecutionError::NoCurrentStep => {
            Status::failed_precondition(error.to_string())
        }
        FlowInstanceExecutionError::DefinitionTenantMismatch => {
            Status::not_found("Flow definition not found")
        }
        FlowInstanceExecutionError::Record(_) => Status::internal("Stored Flow state is invalid"),
        _ => Status::invalid_argument(error.to_string()),
    }
}

fn side_effect_status(error: FlowInstanceSideEffectError) -> Status {
    match error {
        FlowInstanceSideEffectError::Provider(error) => provider_status(error),
        _ => Status::unavailable("Flow protocol side effect failed"),
    }
}

fn verification_start_status(error: crate::FlowVerificationStartError) -> Status {
    match error {
        crate::FlowVerificationStartError::Api(_) => Status::invalid_argument(error.to_string()),
        crate::FlowVerificationStartError::Provider(error) => provider_status(error),
        crate::FlowVerificationStartError::InvalidPolicy => {
            Status::not_found("Presentation policy not found")
        }
        crate::FlowVerificationStartError::CallbackRejected => {
            Status::permission_denied("Callback destination is not registered")
        }
        crate::FlowVerificationStartError::HaipDisabled => {
            Status::failed_precondition("HAIP is disabled")
        }
        crate::FlowVerificationStartError::PrincipalRequired => {
            Status::unauthenticated("Verification principal is required")
        }
        _ => Status::unavailable("Verification request could not be created"),
    }
}

fn application_auth_status(error: ApplicationEventAuthError) -> Status {
    match error {
        ApplicationEventAuthError::ReplayedEvent => Status::already_exists(error.code()),
        ApplicationEventAuthError::Configuration
        | ApplicationEventAuthError::ReplayStoreUnavailable => Status::unavailable(error.code()),
        _ => Status::unauthenticated(error.code()),
    }
}

fn application_status(error: ApplicationApprovalError) -> Status {
    match error {
        ApplicationApprovalError::Authentication(error) => application_auth_status(error),
        ApplicationApprovalError::Api(FlowApiError { .. }) => {
            Status::invalid_argument("Application event is invalid")
        }
        ApplicationApprovalError::Conflict(_) => {
            Status::already_exists("Application offer conflicts")
        }
        _ => Status::unavailable("Application event could not be processed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_definition_dto_maps_to_one_valid_native_record() {
        let input = ProtoCreate {
            organization_id: "org-1".into(),
            name: "Issue".into(),
            flow_type: "issuance_oid4vci".into(),
            steps: vec![
                ProtoStep {
                    step_id: "0".into(),
                    name: "create_offer".into(),
                    step_type: "start".into(),
                    config: HashMap::new(),
                },
                ProtoStep {
                    step_id: "1".into(),
                    name: "done".into(),
                    step_type: "end".into(),
                    config: HashMap::new(),
                },
            ],
            transitions: vec![ProtoTransition {
                from_step_id: "0".into(),
                to_step_id: "1".into(),
                condition: "success".into(),
            }],
            start_step_id: "0".into(),
            default_timeout_seconds: 600,
            max_retries: 3,
            enable_resume: true,
            ..ProtoCreate::default()
        };
        let record = definition_from_proto(input, Utc::now()).expect("record");
        assert_eq!(record.flow_type, crate::FlowType::Oid4vciPreAuthorized);
        assert_eq!(record.status, DefinitionStatus::Active);
        record.kernel().expect("native kernel");
        let response = proto_definition(&record).expect("response");
        assert_eq!(response.steps.len(), 2);
        assert_eq!(response.transitions.len(), 1);
    }

    #[test]
    fn protobuf_string_maps_have_stable_transport_neutral_json() {
        let values = BTreeMap::from([
            ("boolean".into(), "true".into()),
            ("object".into(), r#"{"b":2,"a":1}"#.into()),
            ("legacy".into(), "plain".into()),
        ]);
        let decoded = string_map_to_decoded_json(values);
        assert_eq!(decoded["boolean"], json!(true));
        assert_eq!(decoded["object"], json!({"a": 1, "b": 2}));
        assert_eq!(decoded["legacy"], json!("plain"));
    }

    #[test]
    fn verification_start_requires_and_normalizes_the_workload_principal() {
        let mut input = StartVerificationRequest::default();
        assert_eq!(
            verification_principal(&input).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        input.user_id = " auth-service ".into();
        assert_eq!(verification_principal(&input).unwrap(), "auth-service");
    }

    #[test]
    fn private_instance_context_is_not_projected_to_grpc() {
        let now = Utc::now();
        let record = FlowInstanceRecord {
            id: "instance-1".into(),
            flow_definition_id: "flow-1".into(),
            organization_id: "org-1".into(),
            status: FlowInstanceStatus::InProgress,
            current_step_id: Some("step-1".into()),
            context: json!({"visible": "yes", "_marty_secret": "no"}),
            step_history: Vec::new(),
            state_history: Vec::new(),
            subject_id: None,
            subject_type: "person".into(),
            external_reference: None,
            application_flow_key_hash: None,
            started_at: Some(now),
            completed_at: None,
            expires_at: None,
            result: None,
            error: None,
            created_at: now,
            updated_at: now,
        };
        let response = proto_instance(&record).expect("response");
        assert_eq!(
            response.context.get("visible").map(String::as_str),
            Some("yes")
        );
        assert!(!response.context.contains_key("_marty_secret"));
    }

    #[test]
    fn all_released_transition_conditions_are_native() {
        for condition in [
            "success",
            "failure",
            "timeout",
            "user_cancel",
            "approval_granted",
            "approval_denied",
            "condition_met",
            "always",
            "qr_scanned",
            "token_exchanged",
            "credential_issued",
        ] {
            parse_transition_outcome(condition).expect(condition);
        }
    }
}
