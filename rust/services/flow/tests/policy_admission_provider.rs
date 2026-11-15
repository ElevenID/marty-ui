//! Wire-level compatibility: an older server must not silently ignore an
//! admitted policy precondition, even if it returns an ordinary allow result.
use std::sync::{Arc, Mutex};

use marty_flow::{
    presentation_policy_proto::{
        presentation_policy_service_client::PresentationPolicyServiceClient,
        presentation_policy_service_server::{
            PresentationPolicyService, PresentationPolicyServiceServer,
        },
        CreatePolicyRequest, DeletePolicyResponse, EvaluatePresentationRequest, GetPolicyRequest,
        HealthCheckRequest, HealthCheckResponse, ListPoliciesRequest, ListPoliciesResponse,
        PolicyEvaluationResponse, PolicyIdRequest, PolicyResponse, PolicyRevision,
        UpdatePolicyRequest,
    },
    GrpcPresentationPolicyProvider, PresentationEvaluationRequest, PresentationPolicyProvider,
};
use marty_oid4vp_contract::FrozenPolicyIdentity;
use tokio::{net::TcpListener, sync::oneshot};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Server, Request, Response, Status};

#[derive(Default)]
struct State {
    advertised: String,
    evaluated: String,
    received: Vec<String>,
}

struct PolicyServer(Arc<Mutex<State>>);
fn wire_revision(digest: &str) -> Option<PolicyRevision> {
    (!digest.is_empty()).then(|| PolicyRevision {
        organization_id: "org-1".into(),
        id: "policy-1".into(),
        version: 1,
        content_digest: digest.into(),
    })
}

#[tonic::async_trait]
impl PresentationPolicyService for PolicyServer {
    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        Ok(Response::new(PolicyResponse {
            id: request.into_inner().policy_id,
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_requirements_json: "[]".into(),
            version: 1,
            policy_revision: wire_revision(&self.0.lock().unwrap().advertised),

            ..PolicyResponse::default()
        }))
    }
    async fn evaluate_presentation(
        &self,
        request: Request<EvaluatePresentationRequest>,
    ) -> Result<Response<PolicyEvaluationResponse>, Status> {
        assert_eq!(request.metadata().get("x-user-id").unwrap(), "operator-1");
        let input = request.into_inner();
        assert!(!input
            .context_json
            .contains("_marty_expected_policy_configuration_digest"));
        let mut state = self.0.lock().unwrap();
        state
            .received
            .push(input.expected_policy_revision.unwrap().content_digest);
        Ok(Response::new(PolicyEvaluationResponse {
            policy_id: input.policy_id,
            nonce: input.nonce,
            result: "passed".into(),
            decision: "allow".into(),
            policy_revision: wire_revision(&state.evaluated),
            verified_claims_json: "{}".into(),
            credential_results_json: "[]".into(),

            ..PolicyEvaluationResponse::default()
        }))
    }
    async fn list_policies(
        &self,
        _: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn create_policy(
        &self,
        _: Request<CreatePolicyRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn update_policy(
        &self,
        _: Request<UpdatePolicyRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn activate_policy(
        &self,
        _: Request<PolicyIdRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn suspend_policy(
        &self,
        _: Request<PolicyIdRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn new_version_policy(
        &self,
        _: Request<PolicyIdRequest>,
    ) -> Result<Response<PolicyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn delete_policy(
        &self,
        _: Request<PolicyIdRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn health_check(
        &self,
        _: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

#[tokio::test]
async fn admission_requires_an_owner_digest_and_exact_evaluation_echo_over_grpc() {
    let state = Arc::new(Mutex::new(State::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = oneshot::channel::<()>();
    let service = PresentationPolicyServiceServer::new(PolicyServer(state.clone()));
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let client = PresentationPolicyServiceClient::connect(target)
        .await
        .unwrap();
    let provider =
        GrpcPresentationPolicyProvider::new(client, Some("0123456789abcdef0123456789abcdef"))
            .unwrap();
    let admitted = format!("sha256:{}", "a".repeat(64));
    let different = format!("sha256:{}", "b".repeat(64));
    // Missing typed revision cannot admit any canonical verification.
    assert!(provider.get_policy("policy-1").await.is_err());
    assert!(provider.configuration_digest("policy-1").await.is_err());
    state.lock().unwrap().advertised = "malformed".into();
    assert!(provider.get_policy("policy-1").await.is_err());
    assert!(provider.configuration_digest("policy-1").await.is_err());
    state.lock().unwrap().advertised.clone_from(&admitted);
    assert_eq!(
        provider.configuration_digest("policy-1").await.unwrap(),
        admitted
    );
    assert_eq!(
        provider
            .get_policy("policy-1")
            .await
            .unwrap()
            .policy_revision
            .content_digest,
        admitted
    );
    let mut request = PresentationEvaluationRequest {
        policy_id: "policy-1".into(),
        expected_policy_revision: FrozenPolicyIdentity {
            id: "policy-1".into(),
            version: 1,
            content_digest: admitted.clone(),
        },
        organization_id: "org-1".into(),
        principal_id: "operator-1".into(),
        presentation: "synthetic.token.signature".into(),
        nonce: "nonce-1".into(),
        audience: "did:web:verifier.example".into(),
        oid4vp_transport: None,
        context: Default::default(),
    };
    assert!(
        provider.evaluate(&request).await.is_err(),
        "missing echo from an older service must fail closed"
    );
    state.lock().unwrap().evaluated = different;
    assert_ne!(
        provider.evaluate(&request).await.unwrap().policy_revision,
        request.expected_policy_revision,
        "canonical finalization must reject this returned revision"
    );
    state.lock().unwrap().evaluated.clone_from(&admitted);
    assert_eq!(provider.evaluate(&request).await.unwrap().decision, "allow");
    assert_eq!(state.lock().unwrap().received, vec![admitted.clone(); 3]);
    request.expected_policy_revision.content_digest = "malformed".into();
    assert!(provider.evaluate(&request).await.is_err());
    assert_eq!(
        state.lock().unwrap().received.len(),
        3,
        "invalid typed revision must not make an RPC"
    );
    stop.send(()).unwrap();
    task.await.unwrap();
}
