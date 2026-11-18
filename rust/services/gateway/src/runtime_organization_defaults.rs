//! Gateway composition for organization defaults. Only the authenticated gateway
//! calls the native organization writer, after checking every non-null reference.
//! Native services still require service credentials and authorize the forwarded
//! actor. No internal settings route or unvalidated browser headers are exposed.

use super::*;
use marty_service_contracts::organization_defaults::{valid_reference_id, FIELDS};

pub(super) fn organization_id(path: &str) -> Option<&str> {
    path.strip_prefix("/v1/organizations/")?
        .strip_suffix("/defaults")
        .filter(|id| !id.is_empty() && !id.contains('/'))
}

fn parse_patch(body: &[u8]) -> Option<serde_json::Map<String, Value>> {
    let Value::Object(value) = serde_json::from_slice(body).ok()? else {
        return None;
    };
    (!value.is_empty()
        && value.keys().all(|field| FIELDS.contains(&field.as_str()))
        && value
            .values()
            .all(|value| value.is_null() || value.as_str().is_some_and(valid_reference_id)))
    .then_some(value)
}

fn public_response(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    (object.len() == FIELDS.len()
        && FIELDS.iter().all(|field| {
            object.get(*field).is_some_and(|value| {
                value.is_null() || value.as_str().is_some_and(valid_reference_id)
            })
        }))
    .then_some(value)
}

pub(super) async fn handler(state: Arc<GatewayRuntimeState>, request: Request) -> Response {
    let Some(org_id) = organization_id(request.uri().path()).map(str::to_owned) else {
        return detail_response(404, "Route not found");
    };
    let method = match request.method().as_str() {
        "GET" => HttpMethod::Get,
        "PATCH" => HttpMethod::Patch,
        _ => return detail_response(405, "Method not allowed"),
    };
    let identity = request
        .extensions()
        .get::<TrustedIdentityContext>()
        .cloned()
        .unwrap_or_default();
    if identity.organization_id.as_deref() != Some(org_id.as_str()) {
        return detail_response(403, "Request is not authorized for this organization");
    }
    let actor = request.extensions().get::<GatewayIdentity>().cloned();
    let headers = request_headers(request.headers());
    let path = request.uri().path().to_owned();
    let body = if method == HttpMethod::Patch {
        let body = match to_bytes(request.into_body(), state.maximum_body_bytes).await {
            Ok(body) => body,
            Err(_) => return detail_response(413, "Request body too large"),
        };
        let Some(patch) = parse_patch(&body) else {
            return detail_response(422, "Organization defaults are outside the public contract");
        };
        for (field, service) in [
            ("default_trust_profile_id", "trust-profiles"),
            ("default_policy_id", "presentation-policies"),
            ("default_template_id", "credential-templates"),
        ] {
            let Some(id) = patch.get(field).and_then(Value::as_str) else {
                continue;
            };
            let dependency_path = format!(
                "/v1/{service}/{}",
                utf8_percent_encode(id, NON_ALPHANUMERIC)
            );
            // Apply the same view grant as a public resource read. In particular,
            // organization:edit alone does not grant access to every resource.
            let dependency_identity = match authorize_tenant_request(
                "GET",
                &dependency_path,
                Some(&org_id),
                actor.as_ref(),
                state.memberships.as_ref(),
            )
            .await
            {
                TenantAuthorizationOutcome::Authorized(identity) => identity,
                TenantAuthorizationOutcome::Denied(error) => {
                    return detail_response(error.status, &error.detail)
                }
                TenantAuthorizationOutcome::Bypass => {
                    return detail_response(403, "Default resource access is not authorized")
                }
            };
            let response = match execute_proxy_request(
                &state,
                &dependency_identity,
                HttpMethod::Get,
                &dependency_path,
                Vec::new(),
                BTreeMap::new(),
            )
            .await
            {
                Ok(response) => response,
                Err(response) => return response,
            };
            let Some(resource) = response_json(&response) else {
                return detail_response(502, "Default resource returned invalid JSON");
            };
            if resource.get("id").and_then(Value::as_str) != Some(id)
                || resource
                    .get("organization_id")
                    .and_then(Value::as_str)
                    .is_none()
            {
                return detail_response(502, "Default resource returned an invalid identity");
            }
            if resource.get("organization_id").and_then(Value::as_str) != Some(org_id.as_str()) {
                return detail_response(403, "Default resource belongs to another organization");
            }
            if !resource
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status.eq_ignore_ascii_case("active"))
            {
                return detail_response(422, "Default resource must be active");
            }
        }
        serde_json::to_vec(&patch).expect("validated organization defaults JSON")
    } else {
        Vec::new()
    };
    let response =
        match execute_proxy_request(&state, &identity, method, &path, body, headers).await {
            Ok(response) => response,
            Err(response) => return response,
        };
    let Some(value) = response_json(&response).and_then(public_response) else {
        return detail_response(502, "Organization service returned invalid defaults");
    };
    let mut response = Json(value).into_response();
    insert_header(&mut response, "cache-control", "no-store");
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_contract_preserves_explicit_null_and_omitted_fields() {
        let value = parse_patch(br#"{"default_policy_id":null}"#).unwrap();
        assert_eq!(value.len(), 1);
        assert!(value["default_policy_id"].is_null());
        for body in [
            br#"{}"#.as_slice(),
            br#"[]"#,
            br#"{"settings":{"default_policy_id":null}}"#,
            br#"{"default_policy_id":null,"organization_id":"other"}"#,
            br#"{"default_policy_id":42}"#,
            br#"{"default_policy_id":""}"#,
            br#"{"default_policy_id":"."}"#,
            br#"{"default_policy_id":".."}"#,
            br#"{"default_policy_id":"../other"}"#,
        ] {
            assert!(parse_patch(body).is_none());
        }
    }

    #[test]
    fn defaults_response_requires_all_three_fields_and_never_exposes_private_settings() {
        let response = json!({
            "default_trust_profile_id": null,
            "default_policy_id": "policy-1",
            "default_template_id": null
        });
        assert_eq!(public_response(response.clone()), Some(response.clone()));
        let mut private = response.clone();
        private["settings"] = json!({"pilot_retention_enabled": true});
        assert!(public_response(private).is_none());
        let mut incomplete = response;
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("default_template_id");
        assert!(public_response(incomplete).is_none());
    }
}
