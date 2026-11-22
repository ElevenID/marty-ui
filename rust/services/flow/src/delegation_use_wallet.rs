//! Selected machine-wallet routes on the certificate-authenticated use host.
//! These adapters associate one DCQL response with the retained request; they
//! neither verify a VP nor invoke ordinary Flow presentation finalization.

use super::*;
use crate::presentation_request::load_frozen_flow_presentation_request;
use marty_oid4vp_contract::{
    jwt_vc_profile::{profiled_jwt_vc_query, JwtVcSecuringProfile},
    Oid4vpEvaluationTransportV1, QueryKind,
};

// A full-size compact VP plus bounded JSON/form syntax, including percent
// encoding every byte. The decoded VP retains the existing proof-byte bound.
const MAX_DIRECT_POST_BYTES: usize = 3 * (262_144 + 1_024);
const MAX_DIRECT_POST_VALUE_BYTES: usize = 262_144 + 1_024;

pub(super) enum ProofInput<'a> {
    Original(&'a [u8]),
    DirectPost(DirectPost),
}
impl ProofInput<'_> {
    pub(super) fn has_valid_size(&self) -> bool {
        match self {
            Self::Original(proof) => {
                !proof.is_empty() && proof.len() <= MAX_DELEGATE_PROOF_BYTES.min(262_144)
            }
            Self::DirectPost(form) => {
                !form.vp_token.is_empty() && form.vp_token.len() <= MAX_DIRECT_POST_VALUE_BYTES
            }
        }
    }
}

// Deliberately no Debug/Serialize implementation: form values contain proof.
pub(super) struct DirectPost {
    state: String,
    vp_token: String,
}

fn invalid() -> DelegationUseCommandError {
    DelegationUseCommandError::InvalidCommand
}
fn conflict(_: impl fmt::Debug) -> DelegationUseCommandError {
    DelegationUseCommandError::Conflict
}

fn decode_form_component(raw: &[u8]) -> Result<String> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                let hex = raw.get(index + 1..index + 3).ok_or_else(invalid)?;
                let high = (hex[0] as char).to_digit(16).ok_or_else(invalid)?;
                let low = (hex[1] as char).to_digit(16).ok_or_else(invalid)?;
                decoded.push((high * 16 + low) as u8);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).map_err(|_| invalid())
}

impl DirectPost {
    fn parse(raw: &[u8], challenge_id: Uuid) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX_DIRECT_POST_BYTES || challenge_id.is_nil() {
            return Err(invalid());
        }
        let mut state = None;
        let mut vp_token = None;
        for field in raw.split(|byte| *byte == b'&') {
            let equals = field
                .iter()
                .position(|byte| *byte == b'=')
                .ok_or_else(invalid)?;
            let name = decode_form_component(&field[..equals])?;
            let value = decode_form_component(&field[equals + 1..])?;
            match name.as_str() {
                "state" if state.is_none() => state = Some(value),
                "vp_token" if vp_token.is_none() => vp_token = Some(value),
                _ => return Err(invalid()),
            }
        }
        let state = state
            .filter(|value| *value == challenge_id.to_string())
            .ok_or_else(invalid)?;
        let vp_token = vp_token
            .filter(|value| {
                value.len() <= MAX_DIRECT_POST_VALUE_BYTES && value.trim_start().starts_with('{')
            })
            .ok_or_else(invalid)?;
        Ok(Self { state, vp_token })
    }
}

impl FlowDelegatedUseIngress {
    /// Accept only the selected unencrypted DCQL direct-post form. Association
    /// and original-byte retention share the ordinary proof transaction and
    /// current-access checks. Cryptographic verification still belongs to use
    /// finalization, and no public form can supply frozen request authority.
    pub async fn submit_direct_post(
        &self,
        context: &AuthenticatedDelegationUseContext,
        challenge_id: Uuid,
        raw_form: &[u8],
    ) -> Result<FlowDelegatedProofSubmission> {
        context
            .check(Utc::now())
            .map_err(|_| DelegationUseCommandError::AccessDenied)?;
        let form = DirectPost::parse(raw_form, challenge_id)?;
        self.submit_input(context, challenge_id, ProofInput::DirectPost(form))
            .await
    }

    pub(super) async fn direct_post_proof(
        &self,
        connection: &mut PgConnection,
        current: &FlowInstanceRecord,
        form: &DirectPost,
    ) -> Result<Vec<u8>> {
        let binding = validate_delegation_snapshot(current).map_err(conflict)?;
        let retained = sqlx::query(
            "SELECT request_bytes,request_digest,configuration_digest,instance_snapshot,actor_type,actor_id
             FROM flow_service.delegated_request_results
             WHERE challenge_id=$1 AND organization_id=$2",
        )
        .bind(binding.binding.challenge_id)
        .bind(binding.binding.organization_id)
        .fetch_optional(connection)
        .await
        .map_err(unavailable)?
        .ok_or(DelegationUseCommandError::Conflict)?;
        let bytes: Vec<u8> = retained.try_get("request_bytes").map_err(unavailable)?;
        let request_digest: String = retained.try_get("request_digest").map_err(unavailable)?;
        let configuration: String = retained
            .try_get("configuration_digest")
            .map_err(unavailable)?;
        let actor = serde_json::to_value(&binding.binding.actor).map_err(unavailable)?;
        if bytes.is_empty()
            || bytes.len() > MAX_REQUEST_BYTES
            || digest(&bytes) != request_digest
            || configuration != self.configuration_digest
            || Some(
                retained
                    .try_get::<String, _>("actor_type")
                    .map_err(unavailable)?
                    .as_str(),
            ) != actor["type"].as_str()
            || retained
                .try_get::<String, _>("actor_id")
                .map_err(unavailable)?
                != binding.binding.actor.id
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        let emitted: FlowInstanceRecord =
            serde_json::from_value(retained.try_get("instance_snapshot").map_err(unavailable)?)
                .map_err(conflict)?;
        associate_direct_post(current, &emitted, &self.public_base_url, form)
    }
}

fn associate_direct_post(
    current: &FlowInstanceRecord,
    emitted: &FlowInstanceRecord,
    public_base_url: &str,
    form: &DirectPost,
) -> Result<Vec<u8>> {
    let frozen = load_frozen_flow_presentation_request(current).map_err(conflict)?;
    let emitted_frozen = load_frozen_flow_presentation_request(emitted).map_err(conflict)?;
    let binding = validate_delegation_snapshot(current).map_err(conflict)?;
    let emitted_binding = validate_delegation_snapshot(emitted).map_err(conflict)?;
    if form.state != current.id
        || emitted_binding.binding != binding.binding
        || emitted_binding.verifier_client_id != binding.verifier_client_id
        || emitted_binding.nonce != binding.nonce
        || emitted_binding.expires_at != binding.expires_at
        || serde_json::to_value(&frozen).map_err(unavailable)?
            != serde_json::to_value(&emitted_frozen).map_err(unavailable)?
    {
        return Err(DelegationUseCommandError::Conflict);
    }
    let profile = profiled_jwt_vc_query(&frozen.dcql_query)
        .map_err(conflict)?
        .ok_or(DelegationUseCommandError::Conflict)?;
    if profile.binding.securing_profile() != JwtVcSecuringProfile::MartyNestedVc2JwtV1 {
        return Err(DelegationUseCommandError::Conflict);
    }
    let request_uri = format!(
        "{public_base_url}/v1/flows/instances/{}/request",
        current.id
    );
    let response_uri = format!("{public_base_url}/v1/flows/instances/{}/submit", current.id);
    // This is the request owner's MIP projection, not the compact request's
    // JWT claims. The owner records state in its context/correlation fields,
    // and projects an unselected presentation_definition as JSON null.
    let message = &emitted.context["mip_messages"]["presentation_request"];
    let payload = &message["payload"];
    if emitted.context["request_uri"].as_str() != Some(request_uri.as_str())
        || current.context["request_uri"].as_str() != Some(request_uri.as_str())
        || emitted.context["oid4vp_verifier_context"] != true
        || emitted.context["oid4vp_expected_state"].as_str() != Some(current.id.as_str())
        || emitted.context["oid4vp_response_uri"].as_str() != Some(response_uri.as_str())
        || message["message_type"] != "PresentationRequest"
        || message["correlation_id"].as_str() != Some(current.id.as_str())
        || message["sender_id"].as_str() != Some(binding.verifier_client_id.as_str())
        || message["nonce"] != frozen.nonce
        || payload["mip_flow_instance_id"].as_str() != Some(current.id.as_str())
        || payload["mip_policy_id"].as_str() != Some(frozen.policy_revision.id.as_str())
        || payload["response_uri"].as_str() != Some(response_uri.as_str())
        || payload["response_mode"] != "direct_post"
        || payload["response_type"] != "vp_token"
        || payload["client_id"].as_str() != Some(binding.verifier_client_id.as_str())
        || payload["nonce"] != frozen.nonce
        || payload["dcql_query"] != frozen.dcql_query
        || payload
            .get("presentation_definition")
            .is_some_and(|definition| !definition.is_null())
    {
        return Err(DelegationUseCommandError::Conflict);
    }
    // The public contract deliberately excludes the association library's
    // historical bare-token fallback. Its duplicate-safe JSON map validates
    // exact query coverage without taking any query ID from the wallet.
    if !form.vp_token.trim_start().starts_with('{') {
        return Err(invalid());
    }
    let associated = Oid4vpEvaluationTransportV1 {
        credential_authority: frozen.credential_authority,
        query_kind: QueryKind::Dcql,
        query_document: frozen.dcql_query,
        query_digest: frozen.dcql_query_digest,
        presentation_submission: None,
        vp_token_raw: form.vp_token.clone(),
        verifier_client_id: binding.verifier_client_id,
        request_nonce: frozen.nonce,
    }
    .associate_response()
    .map_err(|_| invalid())?;
    if associated.presentation_count != 1
        || associated.tokens.len() != 1
        || associated.tokens[0].query_id != profile.id
    {
        return Err(invalid());
    }
    let token = &associated.tokens[0].token;
    let parts: Vec<_> = token.split('.').collect();
    if token.len() > MAX_DELEGATE_PROOF_BYTES.min(262_144)
        || parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        })
    {
        return Err(invalid());
    }
    Ok(token.as_bytes().to_vec())
}

/// Explicit caller-facing selection on the same mandatory mTLS listener.
/// An ordinary listener or service-token forwarder cannot install a functional
/// wallet surface. Knowledge of a URI never supplies a machine identity.
pub fn delegated_use_wallet_router(state: FlowDelegatedUseHttpState) -> Result<Router> {
    if !state.authenticator.uses_mutual_tls() {
        return Err(DelegationUseCommandError::InvalidCommand);
    }
    Ok(Router::new()
        .route(
            "/v1/flows/instances/{challenge_id}/request",
            get(retrieve_wallet_request),
        )
        .route(
            "/v1/flows/instances/{challenge_id}/submit",
            post(submit_wallet_response),
        )
        .with_state(state)
        .layer(middleware::from_fn(no_store)))
}

async fn retrieve_wallet_request(
    State(state): State<FlowDelegatedUseHttpState>,
    Path(challenge): Path<String>,
    request: Request,
) -> std::result::Result<Response, UseHttpError> {
    let context = state
        .authenticator
        .authenticate_selected_organization(&request)?;
    let challenge_id = challenge_id(&challenge)?;
    retrieve_authenticated(&state.application, context, challenge_id, request).await
}

async fn submit_wallet_response(
    State(state): State<FlowDelegatedUseHttpState>,
    Path(challenge): Path<String>,
    request: Request,
) -> std::result::Result<Json<FlowDelegatedProofSubmission>, UseHttpError> {
    let context = state
        .authenticator
        .authenticate_selected_organization(&request)?;
    let challenge_id = challenge_id(&challenge)?;
    if request.uri().query().is_some() {
        return Err(UseHttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_delegated_flow_request",
        ));
    }
    let types: Vec<_> = request
        .headers()
        .get_all(header::CONTENT_TYPE)
        .iter()
        .collect();
    if types.len() != 1
        || !types[0]
            .to_str()
            .ok()
            .is_some_and(is_direct_post_content_type)
    {
        return Err(UseHttpError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "delegated_flow_direct_post_required",
        ));
    }
    let raw = tokio::time::timeout(
        READ_TIMEOUT,
        to_bytes(request.into_body(), MAX_DIRECT_POST_BYTES),
    )
    .await
    .map_err(|_| UseHttpError::new(StatusCode::REQUEST_TIMEOUT, "delegated_flow_body_timeout"))?
    .map_err(|_| {
        UseHttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "delegated_flow_body_too_large",
        )
    })?;
    context.check(Utc::now())?;
    Ok(Json(
        state
            .application
            .submit_direct_post(&context, challenge_id, &raw)
            .await?,
    ))
}

fn is_direct_post_content_type(value: &str) -> bool {
    let parts: Vec<_> = value.split(';').map(str::trim).collect();
    parts
        .first()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
        && (parts.len() == 1
            || (parts.len() == 2 && parts[1].eq_ignore_ascii_case("charset=utf-8")))
}

#[cfg(test)]
#[path = "delegation_use_wallet_tests.rs"]
mod tests;
