// Included inside runtime tests to exercise the production router and proxy boundary.
struct TemplateOptionsUpstream {
    mode: &'static str,
    writes: std::sync::Mutex<Vec<Value>>,
    resolutions: std::sync::Mutex<Vec<Value>>,
}

impl TemplateOptionsUpstream {
    fn new(mode: &'static str) -> Arc<Self> {
        Arc::new(Self {
            mode,
            writes: Default::default(),
            resolutions: Default::default(),
        })
    }
}

#[async_trait]
impl UpstreamClient for TemplateOptionsUpstream {
    async fn send(
        &self,
        service: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        let mut status = 200;
        let body = if request.path.starts_with("/v1/compliance-profiles/") {
            let mut profile = json!({"id":"profile-1", "organization_id":"org-1", "credential_format":"SD_JWT_VC",
                "issuance_protocol":"OID4VCI_PRE_AUTH", "status":"ACTIVE", "discoverable":true});
            match self.mode {
                "inactive" => profile["status"] = json!("SUSPENDED"),
                "other_profile_tenant" => profile["organization_id"] = json!("other"),
                "certificate" => {
                    profile["issuer_artifact_requirements"] = json!({"requires_x509_cert":true})
                }
                _ => {}
            }
            profile
        } else if request.path == "/v1/signing-keys/issuer-identities" {
            assert_eq!(service.service_name, "signing-keys");
            assert_eq!(request.query["organization_id"], vec!["org-1"]);
            assert_eq!(request.query["key_purpose"], vec!["vc_jwt_issuer"]);
            assert_eq!(request.query["credential_format"], vec!["SD_JWT_VC"]);
            json!({"identities":[
                {"issuer_did":"did:example:allowed", "credential_format":"SD_JWT_VC", "key_purpose":"vc_jwt_issuer", "algorithm":"ES256", "status":"active"},
                {"issuer_did":"did:example:ambiguous", "credential_format":"SD_JWT_VC", "key_purpose":"vc_jwt_issuer", "algorithm":"ES256", "status":"active"},
                {"issuer_did":"did:example:ambiguous", "credential_format":"SD_JWT_VC", "key_purpose":"vc_jwt_issuer", "algorithm":"ES384", "status":"active"}
            ]})
        } else if request.path == "/internal/compat/resolve-issuer-did" {
            assert_eq!(service.service_name, "signing-keys");
            assert_eq!(request.header("x-api-key"), Some("internal-signing-key"));
            let input: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
            assert!(
                input.get("algorithm").is_none(),
                "caller must not resolve ambiguity by choosing a key algorithm"
            );
            self.resolutions.lock().unwrap().push(input.clone());
            if input["issuer_did"] == "did:example:ambiguous" || self.mode == "stale" {
                status = 409;
                json!({"detail":"private-service private-key must-not-leak"})
            } else if self.mode == "unavailable" {
                status = 503;
                json!({"detail":"private-service private-key must-not-leak"})
            } else {
                let format = marty_credential_template::CredentialFormat::parse(
                    input["credential_format"].as_str().unwrap(),
                )
                .unwrap();
                assert_eq!(input["key_purpose"], format.issuer_key_purpose());
                let mut result = json!({"ok":true, "organization_id":"org-1", "issuer_did":input["issuer_did"],
                    "key_purpose":input["key_purpose"], "algorithm":"ES256", "public_jwk":{"kty":"EC"},
                    "signing_service":{"id":"private-service"}, "signing_key_reference":"private-key", "issuer_x5c":[],
                    "issuer_profile":{"organization_id":"org-1", "issuer_did":input["issuer_did"], "key_purpose":input["key_purpose"],
                        "credential_format":format.canonical(), "algorithm":"ES256", "status":"active"}});
                if self.mode == "other_binding_tenant" {
                    result["organization_id"] = json!("other");
                }
                if self.mode == "private_jwk" {
                    result["public_jwk"]["d"] = json!("must-not-leak");
                }
                result
            }
        } else if request.path == "/v1/credential-templates" && request.method == HttpMethod::Post {
            let input: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
            self.writes.lock().unwrap().push(input.clone());
            json!({"id":"template-1", "organization_id":"org-1", "name":input["name"], "issuer_did":input["issuer_did"],
                "credential_type":input["credential_type"], "credential_payload_format":input["credential_payload_format"],
                "issuance_protocol":input["issuance_protocol"], "claims":input["claims"], "status":"draft"})
        } else {
            panic!("unexpected template dependency {}", request.path);
        };
        Ok(GatewayResponse {
            status_code: status,
            set_cookies: Vec::new(),
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: Some(serde_json::to_vec(&body).unwrap()),
            response_time_ms: None,
            upstream_service: None,
        })
    }
}

async fn template_options_request(
    mode: &'static str,
    path: &str,
    payload: Value,
) -> (StatusCode, Value, Arc<TemplateOptionsUpstream>) {
    let upstream = TemplateOptionsUpstream::new(mode);
    let response = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        upstream.clone(),
    ))
    .oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header("cookie", "sessionId=valid")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await
    .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    (status, body, upstream)
}

#[tokio::test]
async fn template_issuer_options_resolve_each_format_and_expose_no_private_binding_selectors() {
    let (status,body,upstream) = template_options_request("valid", "/v1/credential-templates/issuer-options", json!({
        "organization_id":"org-1", "compliance_profile_id":"profile-1", "supported_formats":["SD_JWT_VC","MDOC"]
    })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["identities"].as_array().unwrap().len(), 1);
    assert_eq!(body["identities"][0]["issuer_did"], "did:example:allowed");
    assert_eq!(
        body["identities"][0]["bindings"].as_array().unwrap().len(),
        2
    );
    assert_eq!(body["requirements"]["doctype"], true);
    assert_eq!(
        body["rejected_issuers"],
        json!([{"issuer_did":"did:example:ambiguous","reason":"ambiguous_identity"}])
    );
    assert!(!body.to_string().contains("private-"));
    assert_eq!(upstream.resolutions.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn template_issuer_options_require_authenticated_tenant_create_permission_before_dependencies(
) {
    for (cookie, organization, membership, expected) in [
        (None, "org-1", None, StatusCode::UNAUTHORIZED),
        (
            Some("sessionId=valid"),
            "org-other",
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            Some("sessionId=valid"),
            "org-1",
            Some("allowed"),
            StatusCode::FORBIDDEN,
        ),
        (
            Some("sessionId=valid"),
            "org-1",
            Some("inactive"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let recorder = Arc::new(ActorRecordingUpstream::default());
        let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        if let Some(membership) = membership {
            Arc::get_mut(&mut state).unwrap().memberships =
                Arc::new(ScriptedMembership(membership));
        }
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/credential-templates/issuer-options")
            .header("content-type", "application/json");
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let response = gateway_router(state)
            .oneshot(
                request
                    .body(Body::from(
                        json!({
                            "organization_id":organization, "compliance_profile_id":"profile-1"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert!(recorder.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn template_issuer_options_fail_closed_on_stale_scope_private_material_and_service_failure() {
    for (mode, expected) in [
        ("inactive", 422),
        ("other_profile_tenant", 403),
        ("other_binding_tenant", 502),
        ("private_jwk", 502),
        ("unavailable", 503),
    ] {
        let (status, body, upstream) = template_options_request(
            mode,
            "/v1/credential-templates/issuer-options",
            json!({"organization_id":"org-1","compliance_profile_id":"profile-1"}),
        )
        .await;
        assert_eq!(status.as_u16(), expected, "{mode}: {body}");
        assert!(!body.to_string().contains("private-"));
        assert!(upstream.writes.lock().unwrap().is_empty());
    }
    let (status, body, _) = template_options_request(
        "certificate",
        "/v1/credential-templates/issuer-options",
        json!({"organization_id":"org-1","compliance_profile_id":"profile-1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["identities"], json!([]));
}

#[tokio::test]
async fn actual_template_creation_enforces_the_same_compliance_and_unambiguous_issuer_contract() {
    let base = json!({"organization_id":"org-1", "compliance_profile_id":"profile-1", "name":"Test", "credential_type":"EmployeeCredential",
        "issuer_did":"did:example:allowed", "vct":"https://issuer.example/credentials/employee", "supported_formats":["sd_jwt_vc"], "claims":[]});
    for (mode, expected) in [
        ("valid", 200),
        ("stale", 409),
        ("inactive", 422),
        ("certificate", 422),
        ("other_binding_tenant", 502),
    ] {
        let (status, body, upstream) =
            template_options_request(mode, "/v1/credential-templates", base.clone()).await;
        assert_eq!(status.as_u16(), expected, "{mode}: {body}");
        assert_eq!(
            upstream.writes.lock().unwrap().len(),
            usize::from(expected == 200)
        );
        if expected == 200 {
            let write = upstream.writes.lock().unwrap();
            assert_eq!(write[0]["credential_payload_format"], "SD_JWT_VC");
            assert_eq!(write[0]["issuance_protocol"], "OID4VCI_PRE_AUTH");
        }
    }
    for (field, value) in [
        ("credential_payload_format", json!(17)),
        ("supported_formats", json!("SD_JWT_VC")),
        ("issuance_protocol", json!(false)),
    ] {
        let mut invalid = base.clone();
        invalid[field] = value;
        let (status, _, upstream) =
            template_options_request("valid", "/v1/credential-templates", invalid).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{field}");
        assert!(upstream.writes.lock().unwrap().is_empty());
    }
    let mut mismatch = base;
    mismatch["credential_payload_format"] = json!("MDOC");
    mismatch["doctype"] = json!("org.example.document");
    let (status, _, upstream) =
        template_options_request("valid", "/v1/credential-templates", mismatch).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(upstream.writes.lock().unwrap().is_empty());
}
