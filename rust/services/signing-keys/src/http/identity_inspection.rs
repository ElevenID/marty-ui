//! Read-only public DID inspection. Registry, KMS and public HTTPS are distinct observations.
use super::*;
use chrono::{DateTime, Utc};
use marty_didcomm::{did_resolver::DidResolutionResult, DidResolver};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InspectionQuery {
    organization_id: String,
    issuer_did: String,
    key_purpose: String,
    credential_format: String,
    algorithm: String,
}

impl InspectionQuery {
    fn identity(&self) -> IssuerIdentityRequest {
        IssuerIdentityRequest {
            organization_id: Some(self.organization_id.clone()),
            issuer_did: self.issuer_did.clone(),
            key_purpose: self.key_purpose.clone(),
            credential_format: self.credential_format.clone(),
            algorithm: self.algorithm.clone(),
            key_attestation_policy: None,
            cert_pem: None,
            cert_chain_pem: None,
        }
    }
}

pub(super) fn parameters() -> Value {
    json!(["organization_id", "issuer_did", "key_purpose", "credential_format", "algorithm"].map(|name| json!({
        "name":name,"in":"query","required":true,"schema":{"type":"string","minLength":1},
        "description":"Exact public identity tuple in the authorized organization. No provider, key reference or private profile selector is accepted."
    })))
}

pub(super) async fn inspect(
    State(state): State<AppState>,
    Query(query): Query<InspectionQuery>,
) -> Response {
    tokio::time::timeout(
        std::time::Duration::from_secs(25),
        inspect_current(state, query),
    )
    .await
    .unwrap_or_else(|_| {
        public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer inspection timed out. Retry the current identity.",
        )
    })
}

async fn inspect_current(state: AppState, query: InspectionQuery) -> Response {
    if query.issuer_did.len() > 2048
        || [
            &query.organization_id,
            &query.key_purpose,
            &query.credential_format,
            &query.algorithm,
        ]
        .iter()
        .any(|value| value.len() > 255)
    {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Identity inspection input is invalid.",
        );
    }
    let input = query.identity();
    if let Err(error) = validate_identity_scope(&query.organization_id, &input) {
        return error.into_response();
    }
    let profile = match one_matching_profile(&state, &query.organization_id, &input).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer inspection is unavailable.",
        );
    };
    let (document, document_source) = match compatibility
        .load_identity_document_with_source(&query.organization_id, &query.issuer_did)
        .await
    {
        Ok((document, source)) => match public_did_document(document) {
            Ok(document) if document["id"] == query.issuer_did => (document, source),
            _ => return public_error(StatusCode::BAD_GATEWAY, "Issuer document is malformed."),
        },
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Issuer document is unavailable.",
            )
        }
    };
    let methods = match method_views(&document) {
        Ok(methods) => methods,
        Err(()) => {
            return public_error(
                StatusCode::BAD_GATEWAY,
                "Issuer document methods are malformed.",
            )
        }
    };
    let resolution_request = ResolveIssuerDidRequest {
        organization_id: query.organization_id.clone(),
        issuer_did: query.issuer_did.clone(),
        verification_method_id: None,
        credential_format: Some(query.credential_format.clone()),
        key_purpose: Some(query.key_purpose.clone()),
        algorithm: Some(canonical_algorithm(&query.algorithm)),
    };
    let (resolved, current) = tokio::join!(
        tokio::time::timeout(
            std::time::Duration::from_secs(8),
            compatibility.resolve_issuer_did(&resolution_request)
        ),
        tokio::time::timeout(
            std::time::Duration::from_secs(8),
            compatibility.provider_public_key_for_profile(&query.organization_id, &profile)
        ),
    );
    let resolved = resolved.unwrap_or(Err(CompatibilityError::Unavailable));
    let current = current.unwrap_or(Err(CompatibilityError::Unavailable));
    let checked_at = Utc::now().to_rfc3339();
    let method_id = resolved
        .as_ref()
        .ok()
        .and_then(|value| value["verification_method_id"].as_str())
        .or_else(|| profile["verification_method_id"].as_str());
    let current = current
        .ok()
        .and_then(|value| public_issuer_jwk(&value).ok());
    let binding_matches = resolved
        .as_ref()
        .ok()
        .is_some_and(|value| same_managed_identity(&profile, value));
    let registry_check = key_observation(&methods, method_id, current.as_ref());
    let registry_unavailable = current.is_none()
        || resolved.as_ref().err().is_some_and(|error| {
            matches!(
                error,
                CompatibilityError::Unavailable | CompatibilityError::ServiceNotFound
            )
        });
    let registry_status = if registry_unavailable {
        "unavailable"
    } else if binding_matches && registry_check.0 {
        "matched"
    } else {
        "mismatch"
    };
    let canonical_url = canonical_document_url(state.public_domain.as_deref(), &query.issuer_did);
    let mut public_resolution = json!({"status":"unsupported", "checked_at":null, "retrieved_at":null,
        "content_sha256":null, "assertion_authorized":false, "document":null, "verification_methods":[]});
    if let Some(url) = &canonical_url {
        // A fresh resolver with only the configured HTTPS authority; never use
        // an internal fallback or an arbitrary URL supplied by the caller.
        let authority = reqwest::Url::parse(url)
            .ok()
            .map(|url| match url.port() {
                Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
                None => url.host_str().unwrap_or_default().to_owned(),
            })
            .unwrap_or_default();
        let resolver = DidResolver::new().allow_did_web_hosts([authority]);
        public_resolution = match tokio::time::timeout(
            std::time::Duration::from_secs(12),
            resolver.resolve_with_metadata(&query.issuer_did),
        )
        .await
        {
            Ok(Ok(resolution)) => public_observation(
                &query.issuer_did,
                method_id,
                current.as_ref(),
                resolution,
                &checked_at,
            ),
            _ => {
                json!({"status":"unavailable", "checked_at":Utc::now().to_rfc3339(), "retrieved_at":null,
                "content_sha256":null,"assertion_authorized":false,"document":null,"verification_methods":[]})
            }
        };
    }
    let certificate_chain = resolved
        .as_ref()
        .ok()
        .and_then(|value| value["issuer_x5c"].as_array())
        .filter(|values| !values.is_empty())
        .or_else(|| {
            method_id
                .and_then(|id| methods.iter().find(|method| method["id"] == id))
                .and_then(|method| method["x5c"].as_array())
        })
        .cloned()
        .unwrap_or_default();
    let certificate = certificate_view(&certificate_chain, current.as_ref());
    let assertion_ready = registry_status == "matched"
        && registry_check.1
        && public_resolution["status"] == "matched"
        && public_resolution["assertion_authorized"] == true;
    let published = !methods.is_empty();
    // Empty fallback documents have a generated timestamp, not a publication time.
    let updated_at = if published {
        timestamp(&document["updated_at"])
    } else {
        Value::Null
    };
    ([("cache-control", "no-store")], Json(json!({
        "organization_id":query.organization_id, "identity":identity_projection(&profile),
        "identity_created_at":timestamp(&profile["created_at"]), "identity_updated_at":timestamp(&profile["updated_at"]),
        "inspected_at":Utc::now().to_rfc3339(), "canonical_document_url":canonical_url,
        "registry":{"status":if published {"available"} else {"not_published"}, "source":document_source, "updated_at":updated_at,
            "document":document,"verification_methods":methods},
        "managed_signer":{"status":registry_status,"checked_at":checked_at,"verification_method_id":method_id,
            "assertion_authorized":registry_check.1,"public_jwk":current},
        "public_resolution":public_resolution, "certificate":certificate, "assertion_ready":assertion_ready
    }))).into_response()
}

fn timestamp(value: &Value) -> Value {
    value
        .as_str()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| json!(value.to_rfc3339()))
        .unwrap_or(Value::Null)
}

fn canonical_document_url(domain: Option<&str>, did: &str) -> Option<String> {
    let prefix = crate::identity_capabilities::managed_did_prefix(domain)?;
    let slug = did.strip_prefix(&prefix)?;
    let checked = documents::did_web_org_slug(did, domain)?;
    // Public routes normalize slugs, so reject aliases that would retrieve a
    // different document ID instead of claiming canonical publication.
    if slug != checked || matches!(slug, "." | "..") {
        return None;
    }
    let domain = domain?.trim();
    Some(format!("https://{domain}/orgs/{slug}/did.json"))
}

fn canonical_method(did: &str, id: &str) -> String {
    if id.starts_with('#') {
        format!("{did}{id}")
    } else {
        id.to_owned()
    }
}

fn method_views(document: &Value) -> Result<Vec<Value>, ()> {
    let did = document["id"].as_str().ok_or(())?;
    let mut methods = BTreeMap::<String, Value>::new();
    let mut assertions = std::collections::BTreeSet::new();
    for method in document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            document
                .get("assertionMethod")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|value| value.is_object()),
        )
    {
        if method["type"].as_str().is_none_or(str::is_empty)
            || method["controller"].as_str().is_none_or(str::is_empty)
        {
            return Err(());
        }
        let id = canonical_method(
            did,
            method["id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or(())?,
        );
        let mut method = method.clone();
        method["id"] = json!(id);
        if let Some(previous) = methods.insert(id, method.clone()) {
            if previous != method {
                return Err(());
            }
        }
    }
    for assertion in document
        .get("assertionMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = assertion
            .as_str()
            .or_else(|| assertion["id"].as_str())
            .ok_or(())?;
        assertions.insert(canonical_method(did, id));
    }
    Ok(methods.into_iter().map(|(id, method)| json!({
        "id":id, "type":method["type"], "controller":method["controller"],
        "assertion_authorized": assertions.contains(&id) && method["controller"] == did,
        "public_jwk":method["publicKeyJwk"], "x5c":method.get("x5c").or_else(|| method["publicKeyJwk"].get("x5c")).cloned().unwrap_or(json!([]))
    })).collect())
}

fn key_observation(
    methods: &[Value],
    expected: Option<&str>,
    current: Option<&Value>,
) -> (bool, bool) {
    let Some(method) =
        expected.and_then(|expected| methods.iter().find(|method| method["id"] == expected))
    else {
        return (false, false);
    };
    let matches =
        current.is_some_and(|current| documents::same_public_jwk(&method["public_jwk"], current));
    (matches, method["assertion_authorized"] == true)
}

fn public_observation(
    did: &str,
    method: Option<&str>,
    current: Option<&Value>,
    resolution: DidResolutionResult,
    checked_at: &str,
) -> Value {
    let document = serde_json::to_value(resolution.document)
        .ok()
        .and_then(|document| public_did_document(document).ok());
    let methods = document
        .as_ref()
        .filter(|document| document["id"] == did)
        .and_then(|document| method_views(document).ok());
    let Some(methods) = methods else {
        return json!({"status":"invalid","checked_at":checked_at,"retrieved_at":null,
        "content_sha256":null,"assertion_authorized":false,"document":null,"verification_methods":[]});
    };
    let observation = key_observation(&methods, method, current);
    json!({"status":if current.is_none() || method.is_none() {"unverified"} else if observation.0 {"matched"} else {"stale"},
        "checked_at":Utc::now().to_rfc3339(),"retrieved_at":resolution.retrieved_at,"content_sha256":resolution.content_sha256,
        "assertion_authorized":observation.1,"document":document,"verification_methods":methods})
}

fn certificate_view(chain: &[Value], current: Option<&Value>) -> Value {
    if chain.is_empty() {
        return json!({"status":"absent","x5c":[],"expires_at":null,"public_key_matches":null});
    }
    if chain
        .iter()
        .any(|value| value.as_str().is_none_or(str::is_empty))
    {
        return json!({"status":"invalid","x5c":[],"expires_at":null,"public_key_matches":null});
    }
    let Some(certificate) = chain.first().and_then(Value::as_str) else {
        return json!({"status":"invalid","x5c":[],"expires_at":null,"public_key_matches":null});
    };
    match documents::inspect_certificate(&InspectCertificateRequest {
        cert_pem: format!("-----BEGIN CERTIFICATE-----\n{certificate}\n-----END CERTIFICATE-----"),
        cert_chain_pem: None,
        expected_public_jwk: current.cloned(),
    }) {
        Ok(info) => {
            json!({"status":if DateTime::parse_from_rfc3339(&info.expires_at).is_ok_and(|expires| expires < Utc::now()) {"expired"} else {"not_expired"},
            "x5c":chain,"expires_at":info.expires_at,"public_key_matches":info.public_key_matches})
        }
        Err(_) => json!({"status":"invalid","x5c":[],"expires_at":null,"public_key_matches":null}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> Value {
        json!({"id":"did:web:issuer.example:orgs:acme","updated_at":"2026-10-23T00:00:00Z",
            "verificationMethod":[{"id":"#issuer", "type":"JsonWebKey2020", "controller":"did:web:issuer.example:orgs:acme",
                "publicKeyJwk":{"kty":"EC", "crv":"P-256", "x":"x", "y":"y"}}], "assertionMethod":["#issuer"]})
    }
    #[test]
    fn inspection_urls_use_the_deployment_authority_and_require_exact_managed_did() {
        assert_eq!(
            canonical_document_url(
                Some("issuer.example:18443"),
                "did:web:issuer.example%3A18443:orgs:acme"
            )
            .as_deref(),
            Some("https://issuer.example:18443/orgs/acme/did.json")
        );
        for did in [
            "did:web:other.example:orgs:acme",
            "did:web:issuer.example:orgs:ACME",
            "did:web:issuer.example:orgs:..",
            "did:web:issuer.example:orgs:acme:extra",
            "did:key:abc",
        ] {
            assert!(
                canonical_document_url(Some("issuer.example"), did).is_none(),
                "{did}"
            );
        }
    }
    #[test]
    fn inspection_separates_key_matching_assertion_authorization_and_ambiguous_documents() {
        let mut document = document();
        let current = document["verificationMethod"][0]["publicKeyJwk"].clone();
        let id = "did:web:issuer.example:orgs:acme#issuer";
        assert_eq!(
            key_observation(&method_views(&document).unwrap(), Some(id), Some(&current)),
            (true, true)
        );
        document["assertionMethod"] = json!([]);
        assert_eq!(
            key_observation(&method_views(&document).unwrap(), Some(id), Some(&current)),
            (true, false)
        );
        assert_eq!(
            key_observation(
                &method_views(&document).unwrap(),
                Some("did:web:other.example#issuer"),
                Some(&current)
            ),
            (false, false)
        );
        let mut changed = current;
        changed["x"] = json!("rotated");
        assert_eq!(
            key_observation(&method_views(&document).unwrap(), Some(id), Some(&changed)),
            (false, false)
        );
        let mut duplicate = document["verificationMethod"][0].clone();
        duplicate["publicKeyJwk"] = changed;
        document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(method_views(&document).is_err());
    }
    #[test]
    fn inspection_does_not_emit_private_registry_coordinates_or_fake_timestamps() {
        let mut document = document();
        document["signing_service_id"] = json!("private-service");
        document["verificationMethod"][0]["signing_key_reference"] = json!("private-key");
        document["verificationMethod"][0]["publicKeyJwk"]["auth_reference"] =
            json!("private-token");
        let document = public_did_document(document).unwrap();
        assert!(!document.to_string().contains("private-"));
        assert_eq!(timestamp(&json!("not-a-time")), Value::Null);
        assert_eq!(certificate_view(&[], None)["status"], "absent");
        assert_eq!(
            certificate_view(&[json!("not-a-certificate")], None)["status"],
            "invalid"
        );
    }
    #[test]
    fn inspection_query_rejects_private_selectors_and_duplicate_custody_shortcuts() {
        let query = json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example:orgs:acme",
            "key_purpose":"vc_jwt_issuer", "credential_format":"SD_JWT_VC", "algorithm":"ES256"});
        assert!(serde_json::from_value::<InspectionQuery>(query.clone()).is_ok());
        let mut private = query;
        private["issuer_profile_id"] = json!("private");
        assert!(serde_json::from_value::<InspectionQuery>(private).is_err());
    }

    #[test]
    fn inspection_public_observations_detect_stale_keys_missing_authorization_and_wrong_did() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/issuer-identity-inspection-example.json"
        ))
        .unwrap();
        let did = fixture["identity"]["issuer_did"].as_str().unwrap();
        let id = fixture["managed_signer"]["verification_method_id"].as_str();
        let current = &fixture["managed_signer"]["public_jwk"];
        let observed = |document: Value, key: Option<&Value>| {
            public_observation(
                did,
                id,
                key,
                DidResolutionResult {
                    document: serde_json::from_value(document).unwrap(),
                    source: "did:web:https".into(),
                    retrieved_at: "2026-10-23T20:01:00Z".into(),
                    content_sha256: "a".repeat(64),
                },
                "2026-10-23T20:01:00Z",
            )
        };
        let document = fixture["public_resolution"]["document"].clone();
        assert_eq!(
            observed(document.clone(), Some(current))["status"],
            "matched"
        );
        assert_eq!(observed(document.clone(), None)["status"], "unverified");
        let mut other_key = current.clone();
        other_key["x"] = json!("different");
        assert_eq!(
            observed(document.clone(), Some(&other_key))["status"],
            "stale"
        );
        let mut no_assertion = document.clone();
        no_assertion["assertionMethod"] = json!([]);
        let result = observed(no_assertion, Some(current));
        assert_eq!(result["status"], "matched");
        assert_eq!(result["assertion_authorized"], false);
        let mut wrong_did = document;
        wrong_did["id"] = json!("did:web:other.example");
        assert_eq!(observed(wrong_did, Some(current))["status"], "invalid");
    }

    #[tokio::test]
    async fn inspection_http_rejects_private_or_incomplete_queries_before_loading_dependencies() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let app = router_with_all_keys(
            "internal-fixture".into(),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let tuple = "organization_id=org-a&issuer_did=did%3Aweb%3Aissuer.example%3Aorgs%3Aacme&key_purpose=vc_jwt_issuer&credential_format=SD_JWT_VC&algorithm=ES256";
        for (query, expected) in [
            (format!("{tuple}&issuer_profile_id=private-sentinel"), 400),
            ("organization_id=org-a".into(), 400),
            (
                tuple.replace("organization_id=org-a", "organization_id="),
                422,
            ),
            (tuple.into(), 503),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!(
                        "/v1/signing-keys/issuer-identities/inspection?{query}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
        }
    }
}
