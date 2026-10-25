//! Gateway domain operations; transport authorization remains in runtime.
use super::*;

pub(super) async fn load_template_issuer_context(
    state: &Arc<GatewayRuntimeState>,
    identity: &TrustedIdentityContext,
    input: &crate::template_issuer_options::OptionsRequest,
) -> Result<crate::template_issuer_options::TemplateIssuerContext, Response> {
    input
        .validate()
        .map_err(|error| detail_response(error.0, error.1))?;
    if identity.organization_id.as_deref() != Some(&input.organization_id) {
        return Err(detail_response(
            403,
            "Request is not authorized for this organization",
        ));
    }
    let path = format!(
        "/v1/compliance-profiles/{}",
        utf8_percent_encode(&input.compliance_profile_id, NON_ALPHANUMERIC)
    );
    let response = execute_proxy_request(
        state,
        identity,
        HttpMethod::Get,
        &path,
        Vec::new(),
        BTreeMap::new(),
    )
    .await
    .map_err(|response| {
        detail_response(
            if matches!(response.status().as_u16(), 403 | 404 | 422) {
                response.status().as_u16()
            } else {
                503
            },
            "Compliance profile could not be loaded.",
        )
    })?;
    let profile = response_json(&response)
        .ok_or_else(|| detail_response(502, "Compliance profile returned invalid data."))?;
    crate::template_issuer_options::TemplateIssuerContext::from_profile(input, &profile)
        .map_err(|error| detail_response(error.0, error.1))
}

pub(super) async fn resolve_template_issuer_binding(
    state: &Arc<GatewayRuntimeState>,
    context: &crate::template_issuer_options::TemplateIssuerContext,
    issuer_did: &str,
) -> Result<Vec<Value>, crate::template_issuer_options::OptionsError> {
    use crate::template_issuer_options::OptionsError;
    let mut bindings = Vec::new();
    for format in &context.formats {
        let response = signing_service_request(state, HttpMethod::Post, "/internal/compat/resolve-issuer-did", Some(serde_json::to_vec(&json!({
            "organization_id":context.organization_id, "issuer_did":issuer_did,
            "credential_format":format.signing_wire(), "key_purpose":format.issuer_key_purpose()
        })).expect("public issuer resolution"))).await
            .map_err(|_| OptionsError(503, "Issuer registry is unavailable."))?;
        match response.status_code {
            409 => {
                return Err(OptionsError(
                    409,
                    "Issuer DID is ambiguous for the template. Repair its registry bindings.",
                ))
            }
            400 | 404 | 422 => {
                return Err(OptionsError(
                    422,
                    "Issuer DID is incompatible with the template.",
                ))
            }
            status if status >= 400 => {
                return Err(OptionsError(503, "Issuer registry is unavailable."))
            }
            _ => {}
        }
        let resolved = response_json(&response)
            .ok_or(OptionsError(502, "Issuer registry returned invalid data."))?;
        bindings.push(context.binding(issuer_did, *format, &resolved)?);
    }
    Ok(bindings)
}

pub(super) async fn template_issuer_options_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let bytes = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let input: crate::template_issuer_options::OptionsRequest = match serde_json::from_slice(&bytes)
    {
        Ok(input) => input,
        Err(_) => {
            return detail_response(422, "Issuer option request is outside the public contract.")
        }
    };
    let context = match load_template_issuer_context(&state, &identity, &input).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let mut list = GatewayRequest::new(
        HttpMethod::Get,
        "/v1/signing-keys/issuer-identities",
        now_ms(),
    );
    list.query = BTreeMap::from([
        (
            "organization_id".into(),
            vec![context.organization_id.clone()],
        ),
        (
            "credential_format".into(),
            vec![context.primary.canonical().into()],
        ),
        (
            "key_purpose".into(),
            vec![context.primary.issuer_key_purpose().into()],
        ),
    ]);
    let response = match state
        .proxy
        .execute(
            list,
            &identity,
            &proxy_overrides(&state, "/v1/signing-keys/issuer-identities", &identity),
        )
        .await
    {
        Ok(response) if response.status_code < 400 => response,
        Ok(response) if response.status_code == 409 => {
            return detail_response(
                409,
                "Issuer inventory is ambiguous. Repair its registry bindings.",
            )
        }
        _ => return detail_response(503, "Issuer inventory is unavailable."),
    };
    let body = response_json(&response);
    let Some(identities) = body.as_ref().and_then(|body| body["identities"].as_array()) else {
        return detail_response(502, "Issuer inventory returned invalid data.");
    };
    let mut dids = BTreeSet::new();
    for identity in identities {
        let Some(did) = identity["issuer_did"]
            .as_str()
            .filter(|did| did.starts_with("did:") && did.len() <= 2048)
        else {
            return detail_response(502, "Issuer inventory returned an invalid identity.");
        };
        if identity["status"] != "active"
            || identity["key_purpose"] != context.primary.issuer_key_purpose()
            || identity["credential_format"]
                .as_str()
                .and_then(|format| marty_credential_template::CredentialFormat::parse(format).ok())
                != Some(context.primary)
        {
            return detail_response(502, "Issuer inventory returned an incompatible identity.");
        }
        dids.insert(did.to_owned());
    }
    let mut available = Vec::new();
    let mut rejected = Vec::new();
    for did in dids {
        match resolve_template_issuer_binding(&state, &context, &did).await {
            Ok(bindings) => available.push(json!({"issuer_did":did, "bindings":bindings})),
            Err(error) if matches!(error.0,409|422) => rejected.push(json!({"issuer_did":did, "reason":if error.0==409 {"ambiguous_identity"} else {"incompatible_identity"}})),
            Err(error) => return detail_response(error.0, error.1),
        }
    }
    let mut result = context.describe();
    result["identities"] = json!(available);
    result["rejected_issuers"] = json!(rejected);
    ([("cache-control", "no-store")], Json(result)).into_response()
}

pub(super) async fn credential_template_create_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let mut body = match credential_template_contract::canonicalize_create(&body) {
        Ok(body) => body,
        Err(_) => {
            return detail_response(
                422,
                "Credential-template request is outside the public contract",
            )
        }
    };
    let organization_id = body["organization_id"]
        .as_str()
        .expect("validated organization")
        .to_owned();
    if identity.organization_id.as_deref() != Some(organization_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    if let Some(trust_profile_id) = body.get("trust_profile_id").and_then(Value::as_str) {
        let path = format!(
            "/v1/trust-profiles/{}",
            utf8_percent_encode(trust_profile_id, NON_ALPHANUMERIC)
        );
        if let Err(response) = execute_proxy_request(
            &state,
            &identity,
            HttpMethod::Get,
            &path,
            Vec::new(),
            BTreeMap::new(),
        )
        .await
        {
            return response;
        }
    }
    let input: crate::template_issuer_options::OptionsRequest = match serde_json::from_value(
        json!({
            "organization_id":organization_id,
            "compliance_profile_id":body["compliance_profile_id"],
            "credential_payload_format":body.get("credential_payload_format").filter(|value| !value.is_null())
                .or_else(|| body["supported_formats"].as_array().and_then(|values| values.first())),
            "supported_formats":body["supported_formats"]
        }),
    ) {
        Ok(input) => input,
        Err(_) => return detail_response(422, "Template format selection is invalid."),
    };
    let context = match load_template_issuer_context(&state, &identity, &input).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if let Err(error) = context.validate_template(&body) {
        return detail_response(error.0, error.1);
    }
    let issuer_did = body["issuer_did"]
        .as_str()
        .expect("validated DID")
        .to_owned();
    if let Err(error) = resolve_template_issuer_binding(&state, &context, &issuer_did).await {
        return detail_response(error.0, error.1);
    }
    body["credential_payload_format"] = json!(context.primary.canonical());
    body["supported_formats"] = json!(context
        .formats
        .iter()
        .map(|format| format.canonical())
        .collect::<Vec<_>>());
    body["issuance_protocol"] = json!(context.protocol.wire());
    body["issuer_did"] = Value::String(issuer_did);
    let response = match execute_json_proxy(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/credential-templates",
        body,
        BTreeMap::new(),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response
        .body
        .as_deref()
        .and_then(|body| serde_json::from_slice(body).ok())
        .and_then(|value| credential_template_contract::public_response(value).ok());
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Credential-template service returned an invalid public response",
        );
    };
    let mut response = response;
    response.body = serde_json::to_vec(&projected).ok();
    response.headers.remove("content-length");
    upstream_response(response)
}

pub(super) fn issuer_key_purpose(credential_format: Option<&str>) -> &'static str {
    match credential_format
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "mdoc" | "mso_mdoc" | "zk_mdoc" => "mdoc_dsc",
        "vds_nc" | "vdsnc" => "vdsnc_signing",
        "icao_emrtd" => "x509_doc_signer",
        _ => "vc_jwt_issuer",
    }
}

pub(super) async fn flow_definition_write_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let update = request.method() == "PATCH";
    let public_path = request.uri().path().to_owned();
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let headers = request_headers(request.headers());
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let canonical = match flow_contract::canonicalize_definition(&body, update) {
        Ok(body) => body,
        Err(_) => {
            return detail_response(
                422,
                "Flow definition request is outside the public contract",
            )
        }
    };
    let organization_id = canonical["organization_id"]
        .as_str()
        .expect("canonical flow organization");
    if identity.organization_id.as_deref() != Some(organization_id) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    for (kind, resource_id) in flow_contract::definition_references(&canonical) {
        let (path, not_found_status) = match kind {
            "credential-templates" => (
                format!(
                    "/v1/credential-templates/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                404,
            ),
            "application-templates" => (
                format!(
                    "/v1/application-templates/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                404,
            ),
            "presentation-policies" => (
                format!(
                    "/v1/presentation-policies/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                422,
            ),
            "delivery-destinations" => (
                format!(
                    "/v1/delivery-destinations/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                422,
            ),
            "trust-profiles" => (
                format!(
                    "/v1/trust-profiles/{}",
                    utf8_percent_encode(&resource_id, NON_ALPHANUMERIC)
                ),
                422,
            ),
            _ => unreachable!("known flow reference"),
        };
        if execute_proxy_request(
            &state,
            &identity,
            HttpMethod::Get,
            &path,
            Vec::new(),
            BTreeMap::new(),
        )
        .await
        .is_err()
        {
            return detail_response(
                not_found_status,
                &format!("Flow dependency not found: {resource_id}"),
            );
        }
    }
    let method = if update {
        HttpMethod::Patch
    } else {
        HttpMethod::Post
    };
    let response = match execute_proxy_request(
        &state,
        &identity,
        method,
        &public_path,
        serde_json::to_vec(&canonical).expect("canonical flow definition"),
        headers,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response_json(&response).and_then(|value| {
        flow_contract::project_response(value, flow_contract::FlowResponseKind::Definition).ok()
    });
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Flow service returned a response outside the public contract",
        );
    };
    let mut response = response;
    response.body = serde_json::to_vec(&projected).ok();
    response.headers.remove("content-length");
    response.headers.remove("content-encoding");
    response.headers.remove("transfer-encoding");
    response
        .headers
        .insert("content-type".into(), "application/json".into());
    upstream_response(response)
}

pub(super) async fn presentation_policy_write_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let update = request.method() == "PATCH";
    let public_path = request.uri().path().to_owned();
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let owner_context = resource_owner_context(
        request.extensions().get::<GatewayIdentity>(),
        request.headers(),
    );
    let headers = request_headers(request.headers());
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let mut canonical =
        match presentation_policy_contract::canonicalize_request(&body, update, true) {
            Ok(body) => body,
            Err(_) => {
                return detail_response(
                    422,
                    "Presentation policy request is outside the public contract",
                )
            }
        };
    let organization_id = canonical["organization_id"]
        .as_str()
        .expect("canonical policy organization")
        .to_owned();
    if identity.organization_id.as_deref() != Some(organization_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    if update {
        let owner = match state
            .owners
            .resolve_organization("presentation-policies", &public_path, &owner_context)
            .await
        {
            Ok(owner) => owner,
            Err(_) => return detail_response(502, "Unable to resolve presentation policy owner"),
        };
        if owner.as_deref() != Some(organization_id.as_str()) {
            return detail_response(404, "Presentation Policy not found");
        }
    }
    let template_ids = presentation_policy_contract::credential_template_ids(&canonical)
        .into_iter()
        .collect::<BTreeSet<_>>();
    for template_id in template_ids {
        let template_path = format!(
            "/v1/credential-templates/{}",
            utf8_percent_encode(&template_id, NON_ALPHANUMERIC)
        );
        let template = match execute_proxy_request(
            &state,
            &identity,
            HttpMethod::Get,
            &template_path,
            Vec::new(),
            BTreeMap::new(),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                return detail_response(
                    422,
                    &format!("Credential template not found: {template_id}"),
                )
            }
        };
        let Some(template) = response_json(&template) else {
            return detail_response(502, "Credential template service returned invalid JSON");
        };
        if template.get("organization_id").and_then(Value::as_str) != Some(organization_id.as_str())
        {
            return detail_response(
                422,
                &format!(
                    "Credential template must belong to the presentation policy organization: {template_id}"
                ),
            );
        }
        let Some(format) = template
            .get("credential_payload_format")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|format| !format.is_empty())
        else {
            return detail_response(
                502,
                &format!(
                    "Credential template has no canonical credential payload format: {template_id}"
                ),
            );
        };
        presentation_policy_contract::apply_authoritative_format(
            &mut canonical,
            &template_id,
            format,
        );
    }
    if update {
        canonical
            .as_object_mut()
            .expect("canonical policy object")
            .remove("organization_id");
    }
    let method = if update {
        HttpMethod::Patch
    } else {
        HttpMethod::Post
    };
    let response = match execute_proxy_request(
        &state,
        &identity,
        method,
        &public_path,
        serde_json::to_vec(&canonical).expect("canonical policy request"),
        headers,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response_json(&response)
        .and_then(|value| presentation_policy_contract::project_response(value).ok());
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Presentation policy service response violates the public contract",
        );
    };
    let mut response = response;
    response.body = serde_json::to_vec(&projected).ok();
    response.headers.remove("content-length");
    response.headers.remove("content-encoding");
    response.headers.remove("transfer-encoding");
    response
        .headers
        .insert("content-type".into(), "application/json".into());
    upstream_response(response)
}

pub(super) async fn verification_flow_start_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let owner_context = resource_owner_context(
        request.extensions().get::<GatewayIdentity>(),
        request.headers(),
    );
    let headers = request_headers(request.headers());
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let canonical = match verification_flow_contract::canonicalize_request(&body) {
        Ok(body) => body,
        Err(_) => {
            return detail_response(
                422,
                "Verification flow request is outside the public contract",
            )
        }
    };
    let organization_id = verification_flow_contract::organization_id(&canonical);
    if identity.organization_id.as_deref() != Some(organization_id) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    for (field, service, label) in [
        (
            "presentation_policy_id",
            "presentation-policies",
            "Presentation policy",
        ),
        ("trust_profile_id", "trust-profiles", "Trust profile"),
    ] {
        let Some(resource_id) = verification_flow_contract::reference(&canonical, field) else {
            continue;
        };
        let path = format!("/v1/{service}/{resource_id}");
        let owner = match state
            .owners
            .resolve_organization(service, &path, &owner_context)
            .await
        {
            Ok(owner) => owner,
            Err(_) => return detail_response(502, "Unable to resolve verification dependency"),
        };
        let Some(owner) = owner.filter(|owner| !owner.trim().is_empty()) else {
            return detail_response(422, &format!("{label} not found: {resource_id}"));
        };
        if owner.trim() != organization_id {
            return detail_response(403, &format!("{label} belongs to another organization."));
        }
    }
    let response = match execute_proxy_request(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/flows/verify",
        serde_json::to_vec(&canonical).expect("canonical verification request"),
        headers,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    let projected = response_json(&response)
        .and_then(|value| verification_flow_contract::project_response(value).ok());
    let Some(projected) = projected else {
        return detail_response(
            502,
            "Flow service returned an invalid public verification response",
        );
    };
    let mut response = response;
    response.body = serde_json::to_vec(&projected).ok();
    response.headers.remove("content-length");
    response.headers.remove("content-encoding");
    response.headers.remove("transfer-encoding");
    response
        .headers
        .insert("content-type".into(), "application/json".into());
    upstream_response(response)
}

pub(super) async fn issuance_create_handler(
    state: Arc<GatewayRuntimeState>,
    request: Request,
) -> Response {
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
        Ok(body) => body,
        Err(_) => return detail_response(413, "Request body too large"),
    };
    let input = match serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|value| IssuanceCreate::parse(value).ok())
    {
        Some(input) => input,
        None => return detail_response(422, "Issuance request is outside the public contract"),
    };
    if identity.organization_id.as_deref() != Some(input.organization_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }

    let template = if let Some(template_id) = input.credential_template_id.as_deref() {
        let path = format!(
            "/v1/credential-templates/{}",
            utf8_percent_encode(template_id, NON_ALPHANUMERIC)
        );
        let response = match execute_proxy_request(
            &state,
            &identity,
            HttpMethod::Get,
            &path,
            Vec::new(),
            BTreeMap::new(),
        )
        .await
        {
            Ok(response) => response,
            Err(response) => return response,
        };
        let Some(template) = response_json(&response) else {
            return detail_response(502, "Credential template service returned invalid data");
        };
        if template.get("organization_id").and_then(Value::as_str)
            != Some(input.organization_id.as_str())
        {
            return detail_response(
                403,
                "Access denied: credential template belongs to another organization",
            );
        }
        template
    } else {
        json!({})
    };
    let issuer_did = match input.select_issuer_did(&template) {
        Ok(value) => value,
        Err(error) => return detail_response(422, error.0),
    };
    let credential_format = input.credential_format(&template);
    let key_purpose = issuer_key_purpose(credential_format.as_deref());
    let resolution = match signing_service_request(
        &state,
        HttpMethod::Post,
        "/internal/compat/resolve-issuer-did",
        Some(
            serde_json::to_vec(&json!({
                "organization_id": input.organization_id,
                "issuer_did": issuer_did,
                "credential_format": credential_format,
                "key_purpose": key_purpose
            }))
            .expect("issuer resolution request serializes"),
        ),
    )
    .await
    {
        Ok(response) if response.status_code < 400 => response,
        Ok(response) => return upstream_response(response),
        Err(response) => return response,
    };
    let Some(resolved) = response_json(&resolution) else {
        return detail_response(
            503,
            "Signing-keys issuer DID resolver returned invalid data",
        );
    };
    let public_jwk = resolved.get("public_jwk").and_then(Value::as_object);
    let private_jwk = public_jwk.is_some_and(|jwk| {
        ["d", "p", "q", "k"]
            .iter()
            .any(|field| jwk.contains_key(*field))
    });
    if resolved.get("ok") != Some(&Value::Bool(true))
        || resolved.get("organization_id").and_then(Value::as_str)
            != Some(input.organization_id.as_str())
        || resolved.get("issuer_did").and_then(Value::as_str) != Some(issuer_did.as_str())
        || resolved.get("key_purpose").and_then(Value::as_str) != Some(key_purpose)
        || resolved
            .get("verification_method_id")
            .and_then(Value::as_str)
            .is_none_or(|method| !method.starts_with(&format!("{issuer_did}#")))
        || public_jwk.is_none()
        || private_jwk
    {
        return detail_response(
            422,
            "issuer_did must resolve to exactly one active organization-owned signing identity.",
        );
    }

    if let Some(registration) = input.registration() {
        let registration_path =
            internal_issuance_proxy_path(HttpMethod::Put, "/v1/issuance/oid4vci-clients");
        if let Err(response) = execute_json_proxy(
            &state,
            &identity,
            HttpMethod::Put,
            &registration_path,
            registration,
            BTreeMap::new(),
        )
        .await
        {
            return response;
        }
    }
    let downstream = match input.downstream(issuer_did) {
        Ok(value) => value,
        Err(error) => return detail_response(422, error.0),
    };
    let response = match execute_json_proxy(
        &state,
        &identity,
        HttpMethod::Post,
        "/v1/issuance",
        downstream,
        BTreeMap::new(),
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return response,
    };
    match response_projection::project(HttpMethod::Post, "/v1/issuance", response) {
        Ok(response) => upstream_response(response),
        Err(_) => detail_response(502, "Issuance service returned an invalid public response."),
    }
}
