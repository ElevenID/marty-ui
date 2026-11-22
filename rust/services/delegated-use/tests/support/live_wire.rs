//! Explicit read-only transport fixtures. These are not the policy/template
//! owner implementations and return no verification/authorization evidence.
//! All other RPC methods are unavailable. Production host adapters perform the
//! real TLS, service-token, protobuf, identity and readiness checks against them.

use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use axum::{http, routing::get, Json, Router};
use marty_flow::{
    credential_template_proto::{GetTemplateRequest, TemplateResponse},
    presentation_policy_proto::{GetPolicyRequest, PolicyResponse, PolicyRevision},
    CredentialTemplateProvider, PresentationPolicyProvider,
};
use marty_service_runtime::{keyless_incoming, wait_for_shutdown};
use serde_json::json;
use tonic::{
    codegen::{Body, BoxFuture, StdError},
    Request, Response, Status,
};

use super::live_support::{identity, Server, ISSUANCE_KEY, SERVICE_TOKEN};
use crate::support::{
    crypto::{CREDENTIAL_TEMPLATE, PRESENTATION_POLICY},
    owned::Owned,
    TestResult,
};

const TEMPLATE_SERVICE: &str = "marty.ui.credential_template.v1.CredentialTemplateService";
const TEMPLATE_METHOD: &str =
    "/marty.ui.credential_template.v1.CredentialTemplateService/GetTemplate";
const POLICY_SERVICE: &str = "marty.ui.presentation_policy.v1.PresentationPolicyService";
const POLICY_METHOD: &str = "/marty.ui.presentation_policy.v1.PresentationPolicyService/GetPolicy";

#[derive(Clone, Default)]
pub struct Reads {
    pub policy: Arc<AtomicUsize>,
    pub template: Arc<AtomicUsize>,
    pub health: Arc<AtomicUsize>,
}

fn authenticate<T>(request: &Request<T>, workload: bool) -> Result<(), Status> {
    if request
        .metadata()
        .get("x-service-token")
        .and_then(|value| value.to_str().ok())
        != Some(SERVICE_TOKEN)
        || request.metadata().contains_key("x-user-id")
    {
        return Err(Status::unauthenticated(
            "fixture service credential required",
        ));
    }
    if workload
        && marty_service_runtime::workload::peer_uri_sans(request)
            != std::collections::BTreeSet::from(["spiffe://marty.internal/service/flow".into()])
    {
        return Err(Status::permission_denied("fixture workload not authorized"));
    }
    Ok(())
}

// Use the generated wire messages and Tonic codec. Unlike a complete generated
// server, this fixture has no mutation, evaluation or signing method to call.
macro_rules! read_service {
    ($name:ident, $request:ty, $response:ty, $service:ident, $method:ident, $field:ident, $workload:literal) => {
        #[derive(Clone)]
        struct $name {
            response: $response,
            reads: Arc<AtomicUsize>,
        }
        impl tonic::server::UnaryService<$request> for $name {
            type Response = $response;
            type Future = BoxFuture<Response<Self::Response>, Status>;
            fn call(&mut self, request: Request<$request>) -> Self::Future {
                let response = self.response.clone();
                let reads = self.reads.clone();
                Box::pin(async move {
                    authenticate(&request, $workload)?;
                    if request.get_ref().$field != response.id {
                        return Err(Status::not_found("fixture read identity"));
                    }
                    reads.fetch_add(1, Ordering::SeqCst);
                    Ok(Response::new(response))
                })
            }
        }
        impl<B> tonic::codegen::Service<http::Request<B>> for $name
        where
            B: Body + Send + 'static,
            B::Error: Into<StdError> + Send + 'static,
        {
            type Response = http::Response<tonic::body::Body>;
            type Error = Infallible;
            type Future = BoxFuture<Self::Response, Self::Error>;
            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, request: http::Request<B>) -> Self::Future {
                let method = self.clone();
                Box::pin(async move {
                    if request.uri().path() != $method {
                        return Ok(Status::unimplemented("read-only wire fixture").into_http());
                    }
                    let codec = tonic_prost::ProstCodec::default();
                    let mut grpc = tonic::server::Grpc::new(codec)
                        .max_decoding_message_size(4096)
                        .max_encoding_message_size(65536);
                    Ok(grpc.unary(method, request).await)
                })
            }
        }
        impl tonic::server::NamedService for $name {
            const NAME: &'static str = $service;
        }
    };
}

read_service!(
    TemplateRead,
    GetTemplateRequest,
    TemplateResponse,
    TEMPLATE_SERVICE,
    TEMPLATE_METHOD,
    template_id,
    false
);
read_service!(
    PolicyRead,
    GetPolicyRequest,
    PolicyResponse,
    POLICY_SERVICE,
    POLICY_METHOD,
    policy_id,
    true
);

pub async fn readers(owned: &Owned, reads: &Reads) -> TestResult<(Server, Server)> {
    let policy = owned.ports.get_policy(PRESENTATION_POLICY).await?;
    let template = owned.ports.get_template(CREDENTIAL_TEMPLATE).await?;
    let template = TemplateRead {
        response: TemplateResponse {
            id: template.id,
            organization_id: template.organization_id,
            status: template.status,
            credential_type: template.credential_type,
            supported_formats: template.supported_formats,
            issuer_did: template.issuer_did,
            credential_payload_format: template.credential_format,
            issuance_protocol: template.issuance_protocol,
            issuer_algorithm: template.issuer_algorithm.unwrap_or_default(),
            wallet_configs_json: "[]".into(),
            ..Default::default()
        },
        reads: reads.template.clone(),
    };
    let policy = PolicyRead {
        response: PolicyResponse {
            id: policy.id.clone(),
            organization_id: policy.organization_id.clone(),
            status: policy.status,
            version: policy.policy_revision.version as i32,
            holder_binding_required: policy.holder_binding_required,
            policy_revision: Some(PolicyRevision {
                organization_id: policy.organization_id,
                id: policy.id,
                version: policy.policy_revision.version,
                content_digest: policy.policy_revision.content_digest,
            }),
            credential_requirements_json: serde_json::to_string(&policy.credential_requirements)?,
            ..Default::default()
        },
        reads: reads.policy.clone(),
    };
    let files = identity("MARTY_TEST_POLICY_GRPC_SERVER_TLS", None)?;
    let template_acceptor = files
        .grpc_acceptor_without_client_auth(8, std::time::Duration::from_secs(5))
        .await?;
    let ca = std::path::PathBuf::from(super::live_support::setting(
        "MARTY_TEST_POLICY_WORKLOAD_CA_CERT",
    ));
    let policy_acceptor = files
        .grpc_acceptor(&ca, 8, std::time::Duration::from_secs(5))
        .await?;
    let template_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let template_address = template_listener.local_addr()?;
    let policy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let policy_address = policy_listener.local_addr()?;
    let (template_stop, mut template_shutdown) = tokio::sync::watch::channel(false);
    let (policy_stop, mut policy_shutdown) = tokio::sync::watch::channel(false);
    let template_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(template)
            .serve_with_incoming_shutdown(
                keyless_incoming(template_listener, template_acceptor),
                async move {
                    wait_for_shutdown(&mut template_shutdown).await;
                },
            )
            .await
            .map_err(|_| "template wire server failed".to_owned())
    });
    let policy_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(policy)
            .serve_with_incoming_shutdown(
                keyless_incoming(policy_listener, policy_acceptor),
                async move {
                    wait_for_shutdown(&mut policy_shutdown).await;
                },
            )
            .await
            .map_err(|_| "policy wire server failed".to_owned())
    });
    Ok((
        Server::new(template_address, template_stop, template_task),
        Server::new(policy_address, policy_stop, policy_task),
    ))
}

pub fn reference_health(reads: &Reads) -> Router {
    let reads = reads.health.clone();
    Router::new().route(
        "/health",
        get(move |headers: http::HeaderMap| {
            let reads = reads.clone();
            async move {
                let service = headers.get("x-service-token").and_then(|v| v.to_str().ok());
                let issuance = headers.get("x-api-key").and_then(|v| v.to_str().ok());
                let authorized = (service == Some(SERVICE_TOKEN) && issuance.is_none())
                    || (issuance == Some(ISSUANCE_KEY) && service.is_none());
                if authorized {
                    reads.fetch_add(1, Ordering::SeqCst);
                    (
                        http::StatusCode::OK,
                        Json(json!({"status":"healthy","fixture":"read-only-health"})),
                    )
                } else {
                    (
                        http::StatusCode::UNAUTHORIZED,
                        Json(json!({"error":"fixture credential required"})),
                    )
                }
            }
        }),
    )
}
