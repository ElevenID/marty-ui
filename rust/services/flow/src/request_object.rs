use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::presentation_request::PresentationRequestArtifacts;
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    FlowInstanceRecord, FlowKeyEnvelope, FlowKeyEnvelopeRequest, FlowProviderError,
    FlowProviderRegistry, SigningIdentity, SigningRequest,
};

const REQUEST_FORMAT: &str = "oauth-authz-req+jwt";
const REQUEST_PURPOSE: &str = "oid4vp_request_signing";
const REQUEST_ALGORITHM: &str = "ES256";
const MIP_VERSION: &str = "0.3.1";

#[derive(Clone, Debug, PartialEq)]
pub struct SignedRequestObject {
    pub instance: FlowInstanceRecord,
    pub compact_jwt: String,
    pub client_id: String,
    pub response_uri: String,
}

#[derive(Debug, Error)]
pub enum FlowRequestObjectError {
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error("FLOW.REQUEST_OBJECT_INVALID_INSTANCE: {0}")]
    InvalidInstance(&'static str),
    #[error("FLOW.REQUEST_OBJECT_UNSUPPORTED_PROFILE: {0}")]
    UnsupportedProfile(&'static str),
    #[error("FLOW.REQUEST_OBJECT_SERIALIZATION")]
    Serialization,
    #[error("FLOW.REQUEST_OBJECT_INVALID_CLOCK")]
    InvalidClock,
}

pub async fn build_standard_request_object(
    providers: &FlowProviderRegistry,
    mut instance: FlowInstanceRecord,
    artifacts: Option<&PresentationRequestArtifacts>,
    public_base_url: &str,
    verifier_client_id: Option<&str>,
    wallet_nonce: Option<&str>,
    now: DateTime<Utc>,
) -> Result<SignedRequestObject, FlowRequestObjectError> {
    let context = instance
        .context
        .as_object()
        .ok_or(FlowRequestObjectError::InvalidInstance(
            "context must be an object",
        ))?;
    if context.get("request_transport").and_then(Value::as_str) == Some("url_query") {
        return Err(FlowRequestObjectError::UnsupportedProfile(
            "url_query has no request object",
        ));
    }
    let haip = context.get("oid4vp_profile").and_then(Value::as_str) == Some("haip");
    let issuer_did = context
        .get("oid4vp_issuer_did")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("did:"))
        .ok_or(FlowRequestObjectError::InvalidInstance(
            "oid4vp_issuer_did is required",
        ))?
        .to_owned();
    let identity_provider =
        providers
            .signing_identity
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "signing_identity",
            })?;
    let identity = identity_provider
        .resolve(
            &instance.organization_id,
            &issuer_did,
            REQUEST_PURPOSE,
            REQUEST_FORMAT,
            Some(REQUEST_ALGORITHM),
        )
        .await?;
    identity.validate_binding(
        &instance.organization_id,
        &issuer_did,
        REQUEST_PURPOSE,
        REQUEST_FORMAT,
        Some(REQUEST_ALGORITHM),
    )?;
    let is_siop = context.get("flow_type").and_then(Value::as_str) == Some("siop_v2");
    let base = public_base_url.trim_end_matches('/');
    let response_uri = if is_siop {
        format!("{base}/v1/flows/siop/submit")
    } else {
        format!("{base}/v1/flows/instances/{}/submit", instance.id)
    };
    let client_id = if is_siop {
        verifier_client_id
            .filter(|value| !value.trim().is_empty())
            .map_or_else(|| format!("{base}/verifier"), str::to_owned)
    } else {
        format!("decentralized_identifier:{}", identity.issuer_did)
    };
    let nonce = context
        .get("nonce")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(FlowRequestObjectError::InvalidInstance("nonce is required"))?
        .to_owned();
    let expires_at = instance
        .expires_at
        .or_else(|| now.checked_add_signed(Duration::minutes(15)))
        .ok_or(FlowRequestObjectError::InvalidClock)?;
    let response_encryption = if haip && !is_siop {
        Some(response_encryption_key(providers, &instance).await?)
    } else {
        None
    };
    let mut payload = if is_siop {
        json!({
            "aud": "https://self-issued.me/v2",
            "client_id": client_id,
            "exp": expires_at.timestamp(),
            "iat": now.timestamp(),
            "iss": client_id,
            "nonce": nonce,
            "redirect_uri": response_uri,
            "response_type": "id_token",
            "scope": "openid",
            "state": instance.id,
            "subject_syntax_types_supported": ["urn:ietf:params:oauth:jwk-thumbprint"]
        })
    } else {
        let artifacts = artifacts.ok_or(FlowRequestObjectError::InvalidInstance(
            "OID4VP query artifacts are required",
        ))?;
        json!({
            "aud": "https://self-issued.me/v2",
            "client_id": client_id,
            "client_metadata": standard_client_metadata(base),
            "dcql_query": artifacts.dcql_query,
            "exp": expires_at.timestamp(),
            "iat": now.timestamp(),
            "iss": client_id,
            "nonce": nonce,
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "response_uri": response_uri,
            "state": instance.id
        })
    };
    if let Some((public_jwk, _)) = &response_encryption {
        payload["response_mode"] = json!("direct_post.jwt");
        payload["client_metadata"]["encrypted_response_enc_values_supported"] = json!(["A256GCM"]);
        payload["client_metadata"]["jwks"] = json!({"keys": [public_jwk]});
    }
    if let Some(wallet_nonce) = wallet_nonce.filter(|value| !value.trim().is_empty()) {
        payload
            .as_object_mut()
            .ok_or(FlowRequestObjectError::Serialization)?
            .insert("wallet_nonce".into(), json!(wallet_nonce));
    }
    let compact_jwt = sign_payload(identity_provider.as_ref(), &identity, &payload).await?;
    let instance_id = instance.id.clone();
    let context =
        instance
            .context
            .as_object_mut()
            .ok_or(FlowRequestObjectError::InvalidInstance(
                "context must be an object",
            ))?;
    if is_siop {
        context.insert("siop_client_id".into(), json!(client_id));
    } else {
        context.insert("oid4vp_client_id".into(), json!(client_id));
        context.insert("oid4vp_response_uri".into(), json!(response_uri));
        context.insert("oid4vp_expected_state".into(), json!(instance_id));
        context.insert("verification_audience".into(), json!(client_id));
        context.insert("oid4vp_verifier_context".into(), json!(true));
        if let Some((public_jwk, envelope)) = response_encryption {
            context.insert(
                "haip_response_encryption_public_jwk".into(),
                public_jwk.clone(),
            );
            context.insert(
                "haip_response_encryption_key_envelope".into(),
                json!(envelope.envelope),
            );
            context.insert("oid4vp_response_encryption_jwk".into(), public_jwk);
            context.insert("haip_response_mode".into(), json!("direct_post.jwt"));
            context.insert("haip_jwe_alg".into(), json!("ECDH-ES"));
            context.insert("haip_jwe_enc".into(), json!("A256GCM"));
        } else {
            context.insert("oid4vp_response_encryption_jwk".into(), Value::Null);
        }
        record_presentation_message(
            context,
            &instance_id,
            &client_id,
            &nonce,
            &response_uri,
            &payload,
            now,
        )?;
    }
    instance.updated_at = now;
    Ok(SignedRequestObject {
        instance,
        compact_jwt,
        client_id,
        response_uri,
    })
}

async fn response_encryption_key(
    providers: &FlowProviderRegistry,
    instance: &FlowInstanceRecord,
) -> Result<(Value, FlowKeyEnvelope), FlowRequestObjectError> {
    let context = instance
        .context
        .as_object()
        .ok_or(FlowRequestObjectError::InvalidInstance(
            "context must be an object",
        ))?;
    if let (Some(public), Some(envelope)) = (
        context
            .get("haip_response_encryption_public_jwk")
            .filter(|value| value.is_object()),
        context
            .get("haip_response_encryption_key_envelope")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("vault:")),
    ) {
        return Ok((
            public.clone(),
            FlowKeyEnvelope {
                organization_id: instance.organization_id.clone(),
                flow_instance_id: instance.id.clone(),
                purpose: "oid4vp_response_decryption".into(),
                envelope: envelope.into(),
            },
        ));
    }
    let provider = providers
        .flow_key_envelope
        .as_ref()
        .ok_or(FlowProviderError::Unavailable {
            provider: "flow_key_envelope",
        })?;
    let (public_json, private_json) =
        marty_verification::jwk::generate_haip_response_encryption_jwk_pair().map_err(|error| {
            FlowRequestObjectError::Provider(FlowProviderError::Rejected {
                provider: "flow_key_envelope",
                message: error.to_string(),
            })
        })?;
    let public: Value =
        serde_json::from_str(&public_json).map_err(|_| FlowRequestObjectError::Serialization)?;
    let private: Value =
        serde_json::from_str(&private_json).map_err(|_| FlowRequestObjectError::Serialization)?;
    if !public.is_object()
        || public.get("d").is_some()
        || private.get("d").and_then(Value::as_str).is_none()
    {
        return Err(FlowRequestObjectError::Serialization);
    }
    let envelope = provider
        .wrap(&FlowKeyEnvelopeRequest {
            organization_id: instance.organization_id.clone(),
            flow_instance_id: instance.id.clone(),
            purpose: "oid4vp_response_decryption".into(),
            key_json: private_json,
        })
        .await?;
    if envelope.organization_id != instance.organization_id
        || envelope.flow_instance_id != instance.id
        || envelope.purpose != "oid4vp_response_decryption"
        || !envelope.envelope.starts_with("vault:")
    {
        return Err(FlowProviderError::InvalidResponse {
            provider: "flow_key_envelope",
            message: "response encryption envelope binding mismatch".into(),
        }
        .into());
    }
    Ok((public, envelope))
}

async fn sign_payload(
    provider: &dyn crate::SigningIdentityProvider,
    identity: &SigningIdentity,
    payload: &Value,
) -> Result<String, FlowRequestObjectError> {
    let header = json!({
        "alg": REQUEST_ALGORITHM,
        "kid": identity.verification_method_id,
        "typ": REQUEST_FORMAT
    });
    let protected = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|_| FlowRequestObjectError::Serialization)?);
    let payload = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(payload).map_err(|_| FlowRequestObjectError::Serialization)?);
    let signing_input = format!("{protected}.{payload}");
    let request = SigningRequest {
        organization_id: identity.organization_id.clone(),
        issuer_did: identity.issuer_did.clone(),
        verification_method_id: identity.verification_method_id.clone(),
        key_purpose: REQUEST_PURPOSE.into(),
        credential_format: REQUEST_FORMAT.into(),
        algorithm: REQUEST_ALGORITHM.into(),
        payload_b64url: URL_SAFE_NO_PAD.encode(signing_input.as_bytes()),
    };
    let result = provider.sign(&request).await?;
    result.validate_binding(&request)?;
    Ok(format!("{signing_input}.{}", result.signature_raw_b64url))
}

fn standard_client_metadata(base_url: &str) -> Value {
    json!({
        "client_name": "ElevenID LLC",
        "logo_uri": format!("{base_url}/favicon.svg"),
        "vp_formats_supported": {
            "dc+sd-jwt": {
                "kb-jwt_alg_values": ["ES256", "EdDSA"],
                "sd-jwt_alg_values": ["ES256", "EdDSA"]
            },
            "jwt_vc_json": {"alg_values_supported": ["ES256", "EdDSA"]},
            "jwt_vp": {"alg_values_supported": ["ES256", "EdDSA"]},
            "ldp_vp": {"proof_type_values_supported": ["Ed25519Signature2020"]},
            "mso_mdoc": {"alg_values_supported": ["ES256"]},
            "vc+sd-jwt": {
                "kb-jwt_alg_values": ["ES256", "EdDSA"],
                "sd-jwt_alg_values": ["ES256", "EdDSA"]
            }
        }
    })
}

fn record_presentation_message(
    context: &mut Map<String, Value>,
    instance_id: &str,
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    request: &Value,
    now: DateTime<Utc>,
) -> Result<(), FlowRequestObjectError> {
    let message = json!({
        "mip_version": MIP_VERSION,
        "message_type": "PresentationRequest",
        "message_id": Uuid::new_v4().to_string(),
        "correlation_id": instance_id,
        "timestamp": now.to_rfc3339(),
        "sender_id": client_id,
        "nonce": nonce,
        "payload": {
            "client_id": client_id,
            "response_type": "vp_token",
            "nonce": nonce,
            "presentation_definition": request.get("presentation_definition"),
            "dcql_query": request.get("dcql_query"),
            "mip_flow_instance_id": instance_id,
            "mip_policy_id": context.get("presentation_policy_id"),
            "response_mode": request.get("response_mode"),
            "response_uri": response_uri
        },
        "signature": null
    });
    context
        .entry("mip_messages")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(FlowRequestObjectError::InvalidInstance(
            "mip_messages must be an object",
        ))?
        .insert("presentation_request".into(), message);
    Ok(())
}
