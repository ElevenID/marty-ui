const DEFAULTS_ORGANIZATION_ID: &str = "11111111-1111-1111-1111-111111111111";

struct DefaultsMembership {
    member: bool,
    edit: bool,
    resource_view: bool,
}

impl Default for DefaultsMembership {
    fn default() -> Self {
        Self {
            member: true,
            edit: true,
            resource_view: true,
        }
    }
}

#[async_trait]
impl OrganizationMembershipProvider for DefaultsMembership {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        if !self.member {
            return Ok(None);
        }
        let mut permissions = BTreeSet::from(["organization:view".into()]);
        if self.edit {
            permissions.insert("organization:edit".into());
        }
        if self.resource_view {
            permissions.extend([
                "trust-profile:view".into(),
                "presentation-policy:view".into(),
                "credential-template:view".into(),
            ]);
        }
        // This actor can belong to multiple tenants; a readable resource from
        // another membership still cannot become this organization's default.
        Ok(Some(OrganizationMembership {
            user_id: user_id.into(),
            organization_id: organization_id.into(),
            status: "active".into(),
            role_names: BTreeSet::new(),
            permissions,
            is_owner: false,
        }))
    }
}

struct DefaultsRecordingUpstream {
    calls: std::sync::Mutex<Vec<(String, GatewayRequest)>>,
    stored: std::sync::Mutex<Value>,
    dependency_response: Option<(u16, Value)>,
}

#[async_trait]
impl UpstreamClient for DefaultsRecordingUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        let (status_code, value) = if instance.service_name == "organizations" {
            let mut stored = self.stored.lock().unwrap();
            if request.method == HttpMethod::Patch {
                let patch: Value =
                    serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
                stored
                    .as_object_mut()
                    .unwrap()
                    .extend(patch.as_object().unwrap().clone());
            }
            (200, stored.clone())
        } else if let Some(response) = &self.dependency_response {
            response.clone()
        } else {
            let id = percent_encoding::percent_decode_str(request.path.rsplit('/').next().unwrap())
                .decode_utf8()
                .unwrap()
                .into_owned();
            (
                200,
                json!({
                    "id": id,
                    "organization_id": DEFAULTS_ORGANIZATION_ID,
                    "status": if instance.service_name == "credential-templates" { "ACTIVE" } else { "active" }
                }),
            )
        };
        self.calls
            .lock()
            .unwrap()
            .push((instance.service_name.clone(), request));
        Ok(GatewayResponse {
            status_code,
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            set_cookies: Vec::new(),
            body: Some(serde_json::to_vec(&value).unwrap()),
            response_time_ms: None,
            upstream_service: None,
        })
    }
}

fn defaults_test_router(
    membership: DefaultsMembership,
    dependency_response: Option<(u16, Value)>,
) -> (Router, Arc<DefaultsRecordingUpstream>) {
    let recorder = Arc::new(DefaultsRecordingUpstream {
        calls: std::sync::Mutex::new(Vec::new()),
        stored: std::sync::Mutex::new(json!({
            "default_trust_profile_id": null,
            "default_policy_id": null,
            "default_template_id": null,
        })),
        dependency_response,
    });
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    Arc::get_mut(&mut state).unwrap().memberships = Arc::new(membership);
    (gateway_router(state), recorder)
}

fn defaults_request(method: &str, body: Value) -> Request {
    Request::builder()
        .method(method)
        .uri(format!(
            "/v1/organizations/{DEFAULTS_ORGANIZATION_ID}/defaults"
        ))
        // The selected organization differs from this session's stale org-1.
        .header("cookie", "sessionId=valid")
        .header("content-type", "application/json")
        .header("x-user-id", "forged-user")
        .header("x-organization-id", "forged-org")
        .header("x-required-permission", "forged-permission")
        .header("x-service-token", "forged-service-token")
        .body(if method == "GET" {
            Body::empty()
        } else {
            Body::from(serde_json::to_vec(&body).unwrap())
        })
        .unwrap()
}

#[tokio::test]
async fn organization_defaults_validate_all_references_then_save_and_clear_selected_keys() {
    let (router, recorder) = defaults_test_router(DefaultsMembership::default(), None);
    let patch = json!({
        "default_trust_profile_id": "trust-1",
        "default_policy_id": "policy-1",
        "default_template_id": "template-1"
    });
    let response = router
        .clone()
        .oneshot(defaults_request("PATCH", patch.clone()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), patch);
    {
        let calls = recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        for (index, service, permission) in [
            (0, "trust-profiles", "trust-profile:view"),
            (1, "presentation-policies", "presentation-policy:view"),
            (2, "credential-templates", "credential-template:view"),
            (3, "organizations", "organization:edit"),
        ] {
            assert_eq!(calls[index].0, service);
            assert_eq!(calls[index].1.header("x-user-id"), Some("user-1"));
            assert_eq!(
                calls[index].1.header("x-organization-id"),
                Some(DEFAULTS_ORGANIZATION_ID)
            );
            assert_eq!(
                calls[index].1.header("x-required-permission"),
                Some(permission)
            );
            assert_eq!(
                calls[index].1.header("x-service-token"),
                Some("s".repeat(32).as_str())
            );
        }
        assert!(calls[..3]
            .iter()
            .all(|(_, request)| request.method == HttpMethod::Get));
        assert_eq!(calls[3].1.method, HttpMethod::Patch);
    }
    let clear = router
        .clone()
        .oneshot(defaults_request("PATCH", json!({"default_policy_id":null})))
        .await
        .unwrap();
    assert_eq!(clear.status(), StatusCode::OK);
    assert_eq!(
        recorder.calls.lock().unwrap().len(),
        5,
        "clearing needs no dependency lookup"
    );
    let read = router
        .oneshot(defaults_request("GET", Value::Null))
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    let body = to_bytes(read.into_body(), 4096).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({
            "default_trust_profile_id":"trust-1",
            "default_policy_id":null,
            "default_template_id":"template-1"
        })
    );
}

#[tokio::test]
async fn organization_defaults_require_membership_edit_and_resource_view_before_any_upstream() {
    for membership in [
        DefaultsMembership {
            member: false,
            ..DefaultsMembership::default()
        },
        DefaultsMembership {
            edit: false,
            ..DefaultsMembership::default()
        },
        DefaultsMembership {
            resource_view: false,
            ..DefaultsMembership::default()
        },
    ] {
        let (router, recorder) = defaults_test_router(membership, None);
        let response = router
            .oneshot(defaults_request(
                "PATCH",
                json!({"default_policy_id":"policy-1"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(recorder.calls.lock().unwrap().is_empty());
    }
    let (router, recorder) = defaults_test_router(DefaultsMembership::default(), None);
    let mut request = defaults_request("PATCH", json!({"default_policy_id":null}));
    request.headers_mut().remove("cookie");
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(recorder.calls.lock().unwrap().is_empty());

    let (router, recorder) = defaults_test_router(
        DefaultsMembership {
            edit: false,
            resource_view: false,
            ..DefaultsMembership::default()
        },
        None,
    );
    let read = router
        .oneshot(defaults_request("GET", Value::Null))
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(recorder.calls.lock().unwrap().len(), 1);

    let (router, _) = defaults_test_router(
        DefaultsMembership {
            resource_view: false,
            ..DefaultsMembership::default()
        },
        None,
    );
    let clear = router
        .oneshot(defaults_request("PATCH", json!({"default_policy_id":null})))
        .await
        .unwrap();
    assert_eq!(
        clear.status(),
        StatusCode::OK,
        "editors can clear unavailable defaults"
    );
}

#[tokio::test]
async fn organization_defaults_never_write_foreign_inactive_missing_denied_or_malformed_references()
{
    for field in marty_service_contracts::organization_defaults::FIELDS {
        for (upstream_status, resource, expected) in [
            (
                200,
                json!({"id":"resource-1","organization_id":"22222222-2222-2222-2222-222222222222","status":"active"}),
                StatusCode::FORBIDDEN,
            ),
            (
                200,
                json!({"id":"resource-1","organization_id":DEFAULTS_ORGANIZATION_ID,"status":"draft"}),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                200,
                json!({"id":"different-id","organization_id":DEFAULTS_ORGANIZATION_ID,"status":"active"}),
                StatusCode::BAD_GATEWAY,
            ),
            (200, Value::Null, StatusCode::BAD_GATEWAY),
            (404, json!({"detail":"not found"}), StatusCode::NOT_FOUND),
            (403, json!({"detail":"not readable"}), StatusCode::FORBIDDEN),
            (
                503,
                json!({"detail":"unavailable"}),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let (router, recorder) = defaults_test_router(
                DefaultsMembership::default(),
                Some((upstream_status, resource)),
            );
            let patch = Value::Object(serde_json::Map::from_iter([(
                (*field).to_owned(),
                json!("resource-1"),
            )]));
            let response = router
                .oneshot(defaults_request("PATCH", patch))
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{field}");
            let calls = recorder.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert!(calls
                .iter()
                .all(|(service, request)| service != "organizations"
                    && request.method == HttpMethod::Get));
        }
    }
}

#[tokio::test]
async fn organization_defaults_reject_invalid_patches_without_dependency_or_persistence_calls() {
    for patch in [
        json!({}),
        json!({"settings":{}}),
        json!({"default_policy_id":null,"organization_id":"other"}),
        json!({"default_policy_id":false}),
        json!({"default_policy_id":"."}),
        json!({"default_policy_id":".."}),
    ] {
        let (router, recorder) = defaults_test_router(DefaultsMembership::default(), None);
        let response = router
            .oneshot(defaults_request("PATCH", patch))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(recorder.calls.lock().unwrap().is_empty());
    }
}
