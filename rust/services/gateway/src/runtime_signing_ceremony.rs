//! Gateway public ceremony authorization and grant minting. The receiving
//! Signing Keys service independently resolves keys and consumes one-use grants.
use super::*;
use marty_signing_grant::{GrantBinding, GrantError, SigningOrigin};

pub(super) async fn mint_public_issuer_csr_grant(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    path: &str,
    operation_id: &str,
    body: Option<&[u8]>,
    overrides: &ProxyOverrides,
) -> Result<String, Response> {
    let organization_id = identity
        .organization_id
        .as_deref()
        .filter(|tenant| !tenant.trim().is_empty())
        .ok_or_else(|| detail_response(403, "Trusted issuer CSR tenant is required."))?;
    if identity.required_permission.as_deref() != Some("signing-key:create")
        || overrides.headers.get("x-api-key") != state.issuer_sign_key.as_ref()
    {
        return Err(detail_response(
            403,
            "Issuer CSR operation is not authorized.",
        ));
    }
    let request: IssuerCsrIntent = body
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .ok_or_else(|| detail_response(422, "Issuer CSR request is invalid."))?;
    if request
        .organization_id
        .as_deref()
        .is_some_and(|tenant| tenant != organization_id)
    {
        return Err(detail_response(
            403,
            "Issuer CSR tenant does not match authorization.",
        ));
    }
    if !request.has_valid_certificate_identity() {
        return Err(detail_response(422, "Issuer CSR identity is invalid."));
    }
    let minter = state
        .issuer_csr_grant_minter
        .as_ref()
        .ok_or_else(|| detail_response(503, "Issuer CSR grant minter is unavailable."))?;
    let payload = request.bound_payload();
    let binding = request.grant_binding(operation_id, organization_id, path, &payload);
    mint_ceremony_grant(minter.as_ref(), &binding, "Issuer CSR").await
}

pub(super) async fn mint_public_service_csr_grant(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    path: &str,
    operation_id: &str,
    body: Option<&[u8]>,
    overrides: &ProxyOverrides,
) -> Result<String, Response> {
    let organization_id = identity
        .organization_id
        .as_deref()
        .filter(|tenant| !tenant.trim().is_empty())
        .ok_or_else(|| detail_response(403, "Trusted CSR tenant is required."))?;
    if identity.required_permission.as_deref() != Some("signing-key:create")
        || overrides.headers.get("x-api-key") != state.service_sign_gateway_key.as_ref()
    {
        return Err(detail_response(403, "CSR operation is not authorized."));
    }
    let service_id = path
        .strip_prefix("/v1/signing-keys/services/")
        .and_then(|tail| tail.strip_suffix("/certificate-csr"))
        .filter(|service_id| !service_id.is_empty() && !service_id.contains('/'))
        .ok_or_else(|| detail_response(404, "CSR service route not found."))?;
    let request: ServiceCsrIntent = body
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .ok_or_else(|| detail_response(422, "CSR request is invalid."))?;
    if request
        .organization_id
        .as_deref()
        .is_some_and(|tenant| tenant != organization_id)
    {
        return Err(detail_response(
            403,
            "CSR tenant does not match authorization.",
        ));
    }
    if !request.has_valid_key_request() {
        return Err(detail_response(
            422,
            "CSR key reference or algorithm is invalid.",
        ));
    }
    let minter = state
        .service_sign_grant_minter
        .as_ref()
        .ok_or_else(|| detail_response(503, "CSR grant minter is unavailable."))?;
    let payload = request.bound_payload();
    let binding = request.grant_binding(operation_id, organization_id, path, service_id, &payload);
    mint_ceremony_grant(minter.as_ref(), &binding, "CSR").await
}

pub(super) async fn mint_public_service_sign_grant(
    state: &GatewayRuntimeState,
    identity: &TrustedIdentityContext,
    path: &str,
    operation_id: &str,
    body: Option<&[u8]>,
    overrides: &ProxyOverrides,
) -> Result<String, Response> {
    let organization_id = identity
        .organization_id
        .as_deref()
        .filter(|tenant| !tenant.trim().is_empty())
        .ok_or_else(|| detail_response(403, "Trusted signing tenant is required."))?;
    if identity.required_permission.as_deref() != Some("signing-key:create")
        || overrides.headers.get("x-api-key") != state.service_sign_gateway_key.as_ref()
    {
        return Err(detail_response(403, "Signing operation is not authorized."));
    }
    let service_id = path
        .strip_prefix("/v1/signing-keys/services/")
        .and_then(|tail| tail.strip_suffix("/sign"))
        .filter(|service_id| !service_id.is_empty() && !service_id.contains('/'))
        .ok_or_else(|| detail_response(404, "Signing service route not found."))?;
    let request: Value = body
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .ok_or_else(|| detail_response(422, "Signing request must be a JSON object."))?;
    let payload = gateway_signing_payload(&request)
        .ok_or_else(|| detail_response(422, "Signing payload is invalid."))?;
    let request = request
        .as_object()
        .ok_or_else(|| detail_response(422, "Signing request must be a JSON object."))?;
    if request
        .get("organization_id")
        .is_some_and(|value| value.as_str() != Some(organization_id))
    {
        return Err(detail_response(
            403,
            "Signing tenant does not match authorization.",
        ));
    }
    let required = |name: &str| {
        request
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && *value == value.trim())
    };
    let (Some(key_reference), Some(key_purpose), Some(algorithm)) = (
        required("key_reference"),
        required("key_purpose"),
        required("algorithm"),
    ) else {
        return Err(detail_response(
            422,
            "Signing key, purpose and algorithm are required.",
        ));
    };
    let minter = state
        .service_sign_grant_minter
        .as_ref()
        .ok_or_else(|| detail_response(503, "Signing grant minter is unavailable."))?;
    let binding = GrantBinding {
        origin: SigningOrigin::GatewayService,
        operation_id,
        organization_id,
        route: path,
        service_id: Some(service_id),
        issuer_did: None,
        key_reference: Some(key_reference),
        key_purpose,
        algorithm,
        payload: &payload,
    };
    mint_ceremony_grant(minter.as_ref(), &binding, "Signing").await
}

fn gateway_signing_payload(request: &Value) -> Option<Vec<u8>> {
    let field = |name: &str| {
        request
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let payload = if let Some(encoded) = field("payload_b64") {
        let unpadded = encoded.trim_end_matches('=');
        URL_SAFE_NO_PAD
            .decode(unpadded)
            .or_else(|_| STANDARD_NO_PAD.decode(unpadded))
            .or_else(|_| URL_SAFE.decode(encoded))
            .or_else(|_| STANDARD.decode(encoded))
            .ok()?
    } else {
        hex::decode(field("payload_hex")?).ok()?
    };
    (!payload.is_empty()).then_some(payload)
}

async fn mint_ceremony_grant(
    minter: &dyn GrantMinting,
    binding: &GrantBinding<'_>,
    label: &str,
) -> Result<String, Response> {
    let unavailable = || detail_response(503, &format!("{label} grant minter is unavailable."));
    minter
        .mint(binding)
        .await
        .map_err(|error| match error {
            GrantError::Malformed | GrantError::BindingMismatch | GrantError::Expired => {
                detail_response(422, &format!("{label} grant binding is invalid."))
            }
            _ => unavailable(),
        })?
        .to_header_value()
        .map_err(|_| unavailable())
}
