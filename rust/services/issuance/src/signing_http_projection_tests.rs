//! Real native tenant/LTI routers and remote HTTP adapters; credential response
//! mapper tested separately, without claiming a deployed or database graph.
use super::*;
use crate::{
    canvas_lti_tool_signing::{
        HttpCanvasLtiToolIdentityResolver, HttpCanvasLtiToolSignatureProvider,
        IssuerDidCanvasLtiToolJwtSigner,
    },
    canvas_readiness_runtime::{
        CanvasReadinessChallengeProvider, LiveCanvasReadinessChallengeProvider,
    },
    signing_http_response::tests::{Peer, Reply},
    signing_policy::HttpProofPolicyResolver,
    tenant_discovery::{TenantDiscoveryRepository, TenantDiscoveryService},
    IssuanceRuntime, IssuanceServiceConfig,
};
use axum::body::Body;
use marty_oid4vci::discovery::{TenantCredentialMetadata, TenantCredentialTemplate};
use std::time::Duration;
use tower::ServiceExt;

struct Templates;
#[async_trait::async_trait]
impl TenantDiscoveryRepository for Templates {
    async fn templates(
        &self,
        organization: &str,
    ) -> Result<Vec<TenantCredentialTemplate>, TenantDiscoveryError> {
        assert_eq!(organization, "org-a");
        Ok(vec![TenantCredentialTemplate {
            credential_type: "OpenBadgeCredential".into(),
            supported_formats: vec!["dc+sd-jwt".into()],
            metadata: TenantCredentialMetadata {
                issuer_did: Some("did:web:issuer.example".into()),
                ..Default::default()
            },
        }])
    }
}

#[tokio::test]
async fn native_tenant_lti_and_readiness_preserve_their_distinct_privacy_boundaries() {
    let peer = Peer::new(Reply::json(
        503,
        br#"{"detail":"synthetic-private-diagnostic"}"#.as_slice(),
    ))
    .await;
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let documents = StaticDiscoveryDocuments::new("https://issuer.example", "Issuer");
    let policy = HttpProofPolicyResolver::new(
        peer.base.clone(),
        Some("synthetic-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let tenant = router_with_tenant_discovery(
        runtime.state(),
        documents.clone(),
        TransportPolicy::new([]),
        TenantDiscoveryService::new(documents.clone(), Arc::new(Templates), Arc::new(policy)),
    );
    let resolver = HttpCanvasLtiToolIdentityResolver::new(
        peer.base.clone(),
        Some("synthetic-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let signatures = HttpCanvasLtiToolSignatureProvider::new(
        peer.base.clone(),
        Some("synthetic-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    let signer = Arc::new(IssuerDidCanvasLtiToolJwtSigner::new(
        "org-a",
        "did:web:issuer.example",
        true,
        Arc::new(resolver),
        Arc::new(signatures),
    ));
    let lti = router_with_canvas_lti_tool_signer(
        runtime.state(),
        documents,
        TransportPolicy::new([]),
        signer.clone(),
    );
    let readiness = LiveCanvasReadinessChallengeProvider::new(
        signer,
        peer.base.clone(),
        Some("synthetic-key"),
        Duration::from_secs(2),
    )
    .unwrap();
    for (mut reply, tenant_status) in [
        (
            Reply::json(
                401,
                br#"{"detail":"synthetic-private-diagnostic"}"#.as_slice(),
            ),
            503,
        ),
        (
            Reply::json(
                503,
                br#"{"detail":"synthetic-private-diagnostic"}"#.as_slice(),
            ),
            503,
        ),
        (Reply::json(503, br#"{"detail":"\ud800"}"#.as_slice()), 503),
        (
            Reply::json(502, br#"{"detail":"selected"}"#.as_slice()),
            500,
        ),
        (Reply::json(302, b"invalid-json".as_slice()), 500),
    ] {
        if reply.status == 502 {
            reply.content_type = "application/json; charset=utf-16".into();
        }
        peer.set(reply);
        let before = peer.request_count();
        let response = tenant
            .clone()
            .oneshot(
                Request::get("/.well-known/openid-credential-issuer/org/org-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), tenant_status);
        let expected: &[u8] = if tenant_status == 500 {
            b"Internal Server Error"
        } else {
            br#"{"detail":"Issuer proof policy is temporarily unavailable"}"#
        };
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .as_ref(),
            expected
        );
        let response = lti
            .clone()
            .oneshot(
                Request::get("/v1/integrations/canvas/lti/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .as_ref(),
            br#"{"detail":"Canvas LTI tool signing is temporarily unavailable"}"#
        );
        assert!(!readiness.lti_tool_signing_ready(chrono::Utc::now()).await);
        let template = json!({"issuer_did":"did:web:issuer.example", "issuer_algorithm":"RS256", "credential_payload_format":"dc+sd-jwt"});
        assert!(
            !readiness
                .kms_did_signing_ready("org-a", template.as_object().unwrap(), chrono::Utc::now())
                .await
        );
        assert_eq!(peer.request_count() - before, 4);
        peer.assert_last_resolution_request();
    }
    peer.close().await;
}

#[tokio::test]
async fn real_remote_cause_keeps_unmasked_credential_and_masked_deep_linking_projections() {
    for body in [
        br#"{"detail":"synthetic-private-diagnostic"}"#.as_slice(),
        br#"{"detail":"\ud800"}"#.as_slice(),
        br#"{"detail":"\u0000"}"#.as_slice(),
    ] {
        let (peer, cause) = Peer::failure(body).await;
        let expected = cause
            .scalar_detail()
            .map(|detail| serde_json::to_vec(&json!({"detail": detail})).unwrap());
        let response =
            CredentialIssuanceHttpError(CredentialIssuanceError::SigningResponse(cause.clone()))
                .into_response();
        assert_eq!(
            response.status(),
            if expected.is_some() { 503 } else { 500 }
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .as_ref(),
            expected.as_deref().unwrap_or(b"Internal Server Error")
        );
        let response = CanvasLtiDeepLinkingHttpError::Service(
            CanvasLtiDeepLinkingError::RemoteSigningResponse(cause),
        )
        .into_response();
        assert_eq!(response.status(), 503);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-private-diagnostic"));
        assert!(!bytes.contains(&0));
        peer.close().await;
    }
}
