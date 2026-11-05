//! Canonical public example routes with remote-only issuer/holder/verifier keys.
//! Membership, template metadata and trust/status transport are local fixtures.
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use marty_flow::*;
use marty_presentation_policy as pp;
use pp::PresentationVerificationOrchestrator;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
const ISSUER: &str = "did:web:demo.example:orgs:marty-demo-age";
const VERIFIER: &str = "did:web:demo.example:orgs:marty-demo-verifier";
const HOLDER: &str = "did:web:demo.example:orgs:marty-demo-holder";
const VCT: &str = "urn:marty:demo:age:1";
const ORIGIN: &str = "https://demo.example";

struct Operator {
    org: String,
}
struct NoExternalReferences;
#[async_trait]
impl FlowReferenceProvider for NoExternalReferences {
    async fn resolve(
        &self,
        _: FlowReferenceKind,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<FlowReference, FlowProviderError> {
        Err(FlowProviderError::Unavailable {
            provider: "unexpected_fixture_reference",
        })
    }
}
#[async_trait]
impl mmf_security::TenantMembershipProvider for Operator {
    async fn membership(
        &self,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<Option<mmf_security::TenantMembership>, mmf_security::SecurityError> {
        Ok(
            (principal_id == "demo-operator" && tenant_id == self.org).then(|| {
                mmf_security::TenantMembership {
                    principal_id: principal_id.into(),
                    tenant_id: tenant_id.into(),
                    status: "active".into(),
                    role_names: ["member".into()].into(),
                    permissions: ["flow-instance:start".into()].into(),
                    is_owner: false,
                }
            }),
        )
    }
}

struct Trust {
    org: Uuid,
    key: Value,
}
#[async_trait]
impl pp::PresentationTrustResolver for Trust {
    async fn load_profile(
        &self,
        id: Uuid,
        org: Uuid,
    ) -> Result<pp::ResolvedTrustProfile, pp::PresentationVerificationError> {
        assert_eq!(org, self.org);
        Ok(pp::ResolvedTrustProfile {
            id,
            organization_id: org,
            document: json!({"status":"active","system_issuer_overrides":{ISSUER:{"public_jwk":self.key}}}),
        })
    }
    async fn evaluate_issuer(
        &self,
        _: &pp::ResolvedTrustProfile,
        issuer: &str,
        format: marty_verification::credential_format::DetectedCredentialFormat,
    ) -> Result<pp::IssuerTrustEvidence, pp::PresentationVerificationError> {
        Ok(pp::IssuerTrustEvidence {
            trust_level: Some(100),
            verified: issuer == ISSUER
                && format == marty_verification::credential_format::DetectedCredentialFormat::SdJwt,
            ..Default::default()
        })
    }
}
struct Status;
#[async_trait]
impl pp::CredentialStatusResolver for Status {
    async fn resolve(
        &self,
        _: Uuid,
        issuer: &str,
        ids: &[String],
    ) -> Result<pp::CredentialStatusEvidence, pp::PresentationVerificationError> {
        assert_eq!(issuer, ISSUER);
        assert!(!ids.is_empty());
        Ok(pp::CredentialStatusEvidence {
            checked_at_epoch_seconds: Some(Utc::now().timestamp() as u64),
            not_revoked: Some(true),
            credential_status: Some("valid".into()),
            warnings: vec![],
        })
    }
}
struct Owner {
    policy: pp::PresentationPolicy,
    verifier: pp::VerifiedFactsOrchestrator,
}
struct Owners(Vec<Owner>);
impl Owners {
    fn get(&self, id: &str) -> &Owner {
        self.0
            .iter()
            .find(|owner| owner.policy.id.to_string() == id)
            .expect("configured fixture policy")
    }
}
#[async_trait]
impl PresentationPolicyProvider for Owners {
    async fn configuration_digest(&self, id: &str) -> Result<String, FlowProviderError> {
        self.get(id).configuration_digest(id).await
    }
    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        self.get(id).get_policy(id).await
    }
    async fn evaluate(
        &self,
        input: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        self.get(&input.policy_id).evaluate(input).await
    }
}
#[async_trait]
impl PresentationPolicyProvider for Owner {
    async fn configuration_digest(&self, id: &str) -> Result<String, FlowProviderError> {
        assert_eq!(id, self.policy.id.to_string());
        Ok(pp::policy_configuration_digest(&self.policy).unwrap())
    }
    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            id: id.into(),
            organization_id: self.policy.organization_id.to_string(),
            status: "active".into(),
            configuration_digest: self.configuration_digest(id).await?,
            credential_requirements: serde_json::from_value(
                serde_json::to_value(&self.policy.credential_requirements).unwrap(),
            )
            .unwrap(),
        })
    }
    async fn evaluate(
        &self,
        input: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        let mut context = input
            .context
            .clone()
            .into_iter()
            .collect::<serde_json::Map<_, _>>();
        let expected = context
            .remove("_marty_expected_policy_configuration_digest")
            .and_then(|v| v.as_str().map(str::to_owned));
        // Use the same owner digest that admission preview pinned, not a verdict fixture.
        let digest = pp::policy_configuration_digest(&self.policy).unwrap();
        let request = pp::EvaluatePresentationRequest {
            expected_configuration_digest: Some(digest.clone()),
            vp_token: json!(input.presentation),
            trust_profile_id: None,
            nonce: Some(input.nonce.clone()),
            audience: Some(input.audience.clone()),
            context,
            oid4vp_transport: input.oid4vp_transport.clone(),
            trusted_internal_context: true,
        };
        assert_eq!(expected.as_deref(), Some(digest.as_str()));
        let facts = self.verifier.verify(&self.policy, &request).await.unwrap();
        let result = pp::evaluate_verified_facts_for_policy(facts, &self.policy, &request).unwrap();
        Ok(serde_json::from_value(result).unwrap())
    }
}
struct Templates {
    org: String,
}
#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        Ok(CredentialTemplateReference {
            id: id.into(),
            organization_id: self.org.clone(),
            status: "active".into(),
            credential_type: "MartyDemoAgeCredential".into(),
            vct: VCT.into(),
            doctype: String::new(),
            supported_formats: vec!["dc+sd-jwt".into()],
            claims: vec![],
            issuer_did: ISSUER.into(),
            credential_format: "dc+sd-jwt".into(),
            issuance_protocol: "OID4VCI_PRE_AUTH".into(),
            wallet_configurations: vec![],
            issuer_algorithm: Some("ES256".into()),
        })
    }
    async fn wallet_formats(&self, _: &str) -> Result<Vec<String>, FlowProviderError> {
        Ok(vec!["dc+sd-jwt".into()])
    }
}

#[derive(Debug)]
struct PublicIssuer {
    key: String,
    kid: String,
}
impl marty_oid4vci::signer::CredentialSigner for PublicIssuer {
    fn sign(&self, _: &[u8]) -> marty_oid4vci::error::Oid4vciResult<Vec<u8>> {
        panic!("local private signing forbidden")
    }
    fn algorithm(&self) -> marty_oid4vci::types::SigningAlgorithm {
        marty_oid4vci::types::SigningAlgorithm::ES256
    }
    fn issuer_id(&self) -> &str {
        ISSUER
    }
    fn kid_url(&self) -> String {
        self.kid.clone()
    }
    fn public_jwk(&self) -> marty_oid4vci::error::Oid4vciResult<String> {
        Ok(self.key.clone())
    }
}

async fn public_call(
    app: &Router,
    origin: &str,
    method: &str,
    path: &str,
    key: &str,
    payload: Option<&Value>,
) -> (u16, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("origin", origin)
                .header("x-verification-session", key)
                .header("cookie", "sessionId=forged-browser-session")
                .header("authorization", "Bearer forged-browser-authority")
                .header("x-user-id", "forged-visitor")
                .header("x-organization-id", "forged-tenant")
                .header("x-api-key", "forged-key")
                .header("x-api-key-id", "forged-id")
                .header("x-api-key-scopes", "*")
                .header("x-authenticated-user-id", "forged-authenticated-user")
                .header("x-service-token", "forged-service-token")
                .header("idempotency-key", "must-not-cache-public-requests")
                .header("if-none-match", "*")
                .header("content-type", "application/json")
                .body(Body::from(
                    payload.map_or_else(String::new, Value::to_string),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 32768).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

pub async fn run(
    base: &str,
    org: &str,
    signing: HttpSigningProvider,
    holder: &SigningIdentity,
    endpoint: &str,
) {
    use marty_oid4vci::formats::sd_jwt::{
        assemble_sd_jwt, prepare_sd_jwt_with_options, SdJwtPreparationOptions,
    };
    let url = std::env::var("FLOW_PUBLIC_VERIFICATION_TEST_URL").expect("owned database URL");
    let parsed = reqwest::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/marty_public_verification_test");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let nonce: String = sqlx::query_scalar("SELECT nonce FROM public.marty_disposable_guard")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        nonce,
        std::env::var("MARTY_TEST_POSTGRES_DISPOSABLE_NONCE").unwrap()
    );
    sqlx::raw_sql("CREATE SCHEMA deployment_profile_service; CREATE TABLE deployment_profile_service.deployment_profiles(id text PRIMARY KEY, enabled_flow_ids jsonb NOT NULL DEFAULT '[]'::jsonb)").execute(&pool).await.unwrap();
    migrate_flow_schema(&pool).await.unwrap();
    let repository = PostgresFlowRepository::new(pool.clone());
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (did, purpose, format) in [
        (ISSUER, "vc_jwt_issuer", "SD_JWT_VC"),
        (VERIFIER, "oid4vp_request_signing", "SD_JWT_VC"),
    ] {
        let response=client.post(format!("{base}/v1/signing-keys/issuer-identities"))
            .query(&[("organization_id",org)]).header("x-api-key",super::INTERNAL)
            .json(&json!({"issuer_did":did,"key_purpose":purpose,"credential_format":format,"algorithm":"ES256"})).send().await.unwrap();
        let status = response.status();
        let value: Value = response.json().await.unwrap();
        assert!(status.is_success(), "{purpose}: {status} {value}");
    }
    let issuer = signing
        .resolve(org, ISSUER, "vc_jwt_issuer", "dc+sd-jwt", Some("ES256"))
        .await
        .unwrap();
    assert_ne!(issuer.signing_key_reference, holder.signing_key_reference);
    let verifier = signing
        .resolve(
            org,
            VERIFIER,
            "oid4vp_request_signing",
            "oauth-authz-req+jwt",
            Some("ES256"),
        )
        .await
        .unwrap();
    assert_ne!(issuer.public_jwk.get("x"), holder.public_jwk.get("x"));
    assert_ne!(verifier.public_jwk.get("x"), issuer.public_jwk.get("x"));
    assert_ne!(verifier.public_jwk.get("x"), holder.public_jwk.get("x"));
    let claims: marty_oid4vci::types::CredentialClaims=serde_json::from_value(json!({"subject_id":HOLDER,"credential_type":VCT,
        "claims":{"age_over_18":true,"age_over_21":false,"nickname":"do-not-disclose"},"expiration_seconds":300,
        "selective_disclosure_claims":["age_over_18","age_over_21","nickname"]})).unwrap();
    let prepared = prepare_sd_jwt_with_options(
        &PublicIssuer {
            key: json!(issuer.public_jwk).to_string(),
            kid: issuer.verification_method_id.clone(),
        },
        &claims,
        SdJwtPreparationOptions {
            typ: Some("dc+sd-jwt".into()),
            confirmation: Some(json!({"jwk":holder.public_jwk})),
            ..Default::default()
        },
    )
    .unwrap();
    let file = super::secret_file("MARTY_TEST_ISSUANCE_MINT_TOKEN");
    let minter = marty_signing_grant::minter::GrantMinter::for_managed_openbao(
        endpoint,
        marty_signing_grant::SigningOrigin::IssuanceCredential,
        file.path().into(),
    )
    .unwrap();
    let envelope = minter
        .mint(&marty_signing_grant::GrantBinding {
            origin: marty_signing_grant::SigningOrigin::IssuanceCredential,
            operation_id: &Uuid::new_v4().to_string(),
            organization_id: org,
            route: super::ROUTE,
            service_id: None,
            issuer_did: Some(ISSUER),
            key_reference: Some(&issuer.signing_key_reference),
            key_purpose: "vc_jwt_issuer",
            algorithm: "ES256",
            payload: prepared.signing_payload(),
        })
        .await
        .unwrap();
    let response=client.post(format!("{base}{}",super::ROUTE)).header("x-api-key",super::ISSUER_SIGN)
        .header(marty_signing_grant::HEADER_NAME,envelope.to_header_value().unwrap())
        .json(&json!({"organization_id":org,"issuer_did":ISSUER,"credential_format":"dc+sd-jwt","key_purpose":"vc_jwt_issuer",
            "algorithm":"ES256","key_reference":issuer.signing_key_reference,"payload_b64":URL_SAFE_NO_PAD.encode(prepared.signing_payload())}))
        .send().await.unwrap();
    let status = response.status();
    let signed: Value = response.json().await.unwrap();
    assert!(status.is_success(), "remote issuance {status}: {signed}");
    let raw = URL_SAFE_NO_PAD
        .decode(signed["signature_raw_b64"].as_str().unwrap())
        .unwrap();
    let marty_oid4vci::types::SignedCredential::SdJwt { compact, .. } =
        assemble_sd_jwt(prepared, &raw).unwrap()
    else {
        panic!("SD-JWT required")
    };
    let browser_enabled = std::env::var("MARTY_TEST_PUBLIC_DEMO_BROWSER").as_deref() == Ok("1");
    let mut browser_listener = if browser_enabled {
        Some(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap())
    } else {
        None
    };
    let mut browser_worker = if let Some(listener) = &browser_listener {
        let url = format!("http://{}", listener.local_addr().unwrap());
        Some(
            tokio::task::spawn_blocking(move || super::public_browser::BrowserWorker::start(&url))
                .await
                .unwrap(),
        )
    } else {
        None
    };
    let mut cases = vec![
        (0, "age_over_18", Some(true)),
        (1, "age_over_21", Some(false)),
        (2, "age_over_18", None),
    ];
    if browser_enabled {
        cases.push((3, "age_over_18", Some(true)));
    }
    for (index, claim, verified) in cases {
        let origin = if index == 3 {
            browser_worker.as_ref().unwrap().origin.as_str()
        } else {
            ORIGIN
        };
        let mut specimen = compact.clone();
        if verified.is_none() {
            let offset = specimen.split('~').next().unwrap().rfind('.').unwrap() + 1;
            let mut bytes = specimen.into_bytes();
            bytes[offset] = if bytes[offset] == b'A' { b'B' } else { b'A' };
            specimen = String::from_utf8(bytes).unwrap();
        }
        let policy_id = Uuid::new_v4().to_string();
        let policy = build_policy(org, &policy_id, claim);
        let digest = pp::policy_configuration_digest(&policy).unwrap();
        let owner = Owner {
            policy,
            verifier: pp::VerifiedFactsOrchestrator::new(
                Arc::new(pp::RustCredentialKernel),
                Arc::new(Trust {
                    org: Uuid::parse_str(org).unwrap(),
                    key: json!(issuer.public_jwk),
                }),
                Arc::new(Status),
            )
            .unwrap(),
        };
        let mut definition = create_definition_record(
            parse_request(json!({"organization_id":org,"name":"Synthetic age example",
            "flow_type":"oid4vp_presentation","presentation_policy_id":policy_id}))
            .unwrap(),
            Utc::now(),
        )
        .unwrap();
        definition.status = DefinitionStatus::Active;
        repository.save_definition(&definition).await.unwrap();
        let mut choices = json!([{"id":"threshold","label":"18 or older","definition":{"organization_id":org,"definition_id":definition.id,"version":definition.version},
            "presentation_policy_id":policy_id,"policy_configuration_digest":digest}]);
        let mut owners = vec![owner];
        if index == 3 {
            let alternate_id = Uuid::new_v4().to_string();
            let alternate = build_policy(org, &alternate_id, "age_over_21");
            let digest = pp::policy_configuration_digest(&alternate).unwrap();
            let mut alternate_definition = create_definition_record(
                parse_request(json!({"organization_id":org,"name":"Synthetic21+ example",
                "flow_type":"oid4vp_presentation","presentation_policy_id":alternate_id}))
                .unwrap(),
                Utc::now(),
            )
            .unwrap();
            alternate_definition.status = DefinitionStatus::Active;
            repository
                .save_definition(&alternate_definition)
                .await
                .unwrap();
            choices.as_array_mut().unwrap().push(json!({"id":"over-21","label":"21 or older","definition":{"organization_id":org,"definition_id":alternate_definition.id,"version":alternate_definition.version},
                "presentation_policy_id":alternate_id,"policy_configuration_digest":digest}));
            owners.push(Owner {
                policy: alternate,
                verifier: pp::VerifiedFactsOrchestrator::new(
                    Arc::new(pp::RustCredentialKernel),
                    Arc::new(Trust {
                        org: Uuid::parse_str(org).unwrap(),
                        key: json!(issuer.public_jwk),
                    }),
                    Arc::new(Status),
                )
                .unwrap(),
            });
        }
        let runtime=PublicVerificationOptions::from_json(&json!({"principal_id":"demo-operator","issuer_did":VERIFIER,"demo_holder_did":HOLDER,
            "limits":{"starts_per_minute":10,"starts_per_day":100,"maximum_active":10},"catalog":{"organization_id":org,"application_origin":origin,
            "notice":"Present a fictional age claim.","scenarios":[{"id":"age","label":"Age","choices":choices}],
            "examples":[{"id":"fictional-adult","scenario_id":"age","label":"Fictional adult","description":"Signed fictional age20.",
                "profile":{"credential_template_id":"demo-age","issuer_did":ISSUER,"vct":VCT},"credential":specimen}]}}).to_string(),index==3).unwrap();
        let app = flow_read_router(FlowHttpState {
            service_authenticator: None,
            repository: repository.clone(),
            providers: Arc::new(FlowProviderRegistry {
                reference_catalog: Some(Arc::new(NoExternalReferences)),
                tenant_membership: Some(Arc::new(Operator { org: org.into() })),
                signing_identity: Some(Arc::new(signing.clone())),
                presentation_policy: Some(Arc::new(Owners(owners))),
                credential_template: Some(Arc::new(Templates { org: org.into() })),
                ..Default::default()
            }),
            public_base_url: ORIGIN.into(),
            verification: FlowHttpVerificationOptions {
                public_verification: Some(runtime),
                ..Default::default()
            },
            application_approval: Default::default(),
        });
        let gateway = super::public_gateway::wrap(
            app,
            origin,
            if index == 3 {
                browser_listener.take()
            } else {
                None
            },
        )
        .await;
        if index == 3 {
            let worker = browser_worker.take().unwrap();
            let result = tokio::task::spawn_blocking(move || worker.run())
                .await
                .unwrap();
            assert_eq!(result["verified"], true);
            let consumed: i64 =
                sqlx::query_scalar("SELECT count(*) FROM flow_service.flow_nonce_consumptions")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(
                consumed, 4,
                "browser adds canonical allow and deny completions"
            );
            assert!(gateway.observed.load(std::sync::atomic::Ordering::SeqCst) >= 8);
            continue;
        }
        let app = &gateway.router;
        let base = "/v1/flows/public/verification";
        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(format!("{base}/sessions"))
                    .header("origin", origin)
                    .header("access-control-request-method", "POST")
                    .header(
                        "access-control-request-headers",
                        "content-type,x-verification-session",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.status().as_u16(), 200);
        assert_eq!(preflight.headers()["access-control-allow-origin"], origin);
        assert_eq!(preflight.headers()["access-control-allow-headers"], "*");
        assert_eq!(preflight.headers()["cache-control"], "no-store");
        for (path, method, origin) in [
            (format!("{base}/catalog"), "POST", origin),
            (format!("{base}/sessions"), "DELETE", origin),
            ("/v1/flows/definitions".into(), "POST", origin),
            (
                format!("{base}/sessions"),
                "POST",
                "https://attacker.example",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("OPTIONS")
                        .uri(path)
                        .header("origin", origin)
                        .header("access-control-request-method", method)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(!response.status().is_success());
            assert!(!response
                .headers()
                .contains_key("access-control-allow-origin"));
        }
        let ambiguous = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(format!("{base}/sessions"))
                    .header("origin", origin)
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!ambiguous.status().is_success());
        assert_eq!(
            gateway.observed.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "preflight must never reach Flow"
        );
        let key = URL_SAFE_NO_PAD.encode([31 + index; 32]);
        let (status, catalog) =
            public_call(app, origin, "GET", &format!("{base}/catalog"), &key, None).await;
        assert_eq!(status, 200);
        let preview_selection = json!({"catalog_revision":catalog["revision"],"scenario_id":"age","choice_id":"threshold"});
        let (status, preview) = public_call(
            app,
            origin,
            "POST",
            &format!("{base}/preview"),
            &key,
            Some(&preview_selection),
        )
        .await;
        assert_eq!(status, 200, "{preview}");
        assert_eq!(preview["claims"][0]["name"], claim);
        let mut selection = preview_selection;
        selection["consent"] = json!(true);
        selection["example_id"] = json!("fictional-adult");
        selection["request_digest"] = preview["request_digest"].clone();
        let mut injected = selection.clone();
        injected["organization_id"] = json!("forged-tenant");
        let (status, _) = public_call(
            app,
            origin,
            "POST",
            &format!("{base}/sessions"),
            &key,
            Some(&injected),
        )
        .await;
        assert_eq!(status, 422);
        let (status, _) = public_call(
            app,
            origin,
            "POST",
            &format!("{base}/sessions"),
            &key,
            Some(&json!({"padding":"a".repeat(4096)})),
        )
        .await;
        assert_eq!(status, 413);
        for duplicate in ["origin", "x-verification-session"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("{base}/sessions"))
                        .header("origin", origin)
                        .header("x-verification-session", &key)
                        .header(duplicate, if duplicate == "origin" { origin } else { &key })
                        .header("content-type", "application/json")
                        .body(Body::from(selection.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 400);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let wrong_origin = app
            .clone()
            .oneshot(
                Request::post(format!("{base}/sessions"))
                    .header("origin", "https://attacker.example")
                    .header("x-verification-session", &key)
                    .header("content-type", "application/json")
                    .body(Body::from(selection.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_origin.status().as_u16(), 403);
        assert_eq!(wrong_origin.headers()["cache-control"], "no-store");
        for path in ["/v1/flows/definitions", "/v1/flows/instances"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .header("x-verification-session", &key)
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                matches!(response.status().as_u16(), 401 | 403),
                "{path}: {}",
                response.status()
            );
        }
        let (status, session) = public_call(
            app,
            origin,
            "POST",
            &format!("{base}/sessions"),
            &key,
            Some(&selection),
        )
        .await;
        assert_eq!(status, 201, "{session}");
        let id = session["session_id"].as_str().unwrap();
        let path = format!("{base}/sessions/{id}/example");
        let (status, result) =
            public_call(app, origin, "POST", &path, &key, Some(&json!({}))).await;
        assert_eq!(status, 200, "{result}");
        if let Some(verified) = verified {
            assert_eq!(result["verified"], verified, "{result}");
            assert_eq!(
                result["status"],
                if verified { "completed" } else { "failed" },
                "{result}"
            );
        } else {
            assert!(result.get("verified").is_none(), "{result}");
            assert_eq!(result["example_status"], "input_rejected", "{result}");
        }
        let (_, recovered) = public_call(
            app,
            origin,
            "GET",
            &format!("{base}/sessions/{id}"),
            &key,
            None,
        )
        .await;
        assert_eq!(recovered, result);
        let text = result.to_string();
        for private in [ISSUER, HOLDER, claim, "do-not-disclose", compact.as_str()] {
            assert!(!text.contains(private));
        }
        let stored = repository.instance(id).await.unwrap().unwrap();
        assert_eq!(stored.status.is_terminal(), verified.is_some());
        let consumed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM flow_service.flow_nonce_consumptions WHERE flow_instance_id=$1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(consumed, if verified.is_some() { 1 } else { 0 });
        assert!(gateway.observed.load(std::sync::atomic::Ordering::SeqCst) >= 5);
    }
    pool.close().await;
}
fn build_policy(org: &str, id: &str, claim: &str) -> pp::PresentationPolicy {
    let now = Utc::now();
    pp::PresentationPolicy {
        id: Uuid::parse_str(id).unwrap(),
        organization_id: Uuid::parse_str(org).unwrap(),
        name: format!("Synthetic demo requires {claim}"),
        description: Some("Fixed fictional age-20 specimen".into()),
        status: pp::PolicyStatus::Active,
        display_metadata: pp::DisplayMetadata {
            title: "Marty age demonstration".into(),
            description: "Synthetic data only".into(),
            purpose: pp::RequestPurpose::AgeVerification,
            purpose_description: Some(
                "Demonstrate a signed age threshold without date of birth".into(),
            ),
            verifier_name: "Marty".into(),
            verifier_logo_url: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
        },
        required_claims: vec![],
        accepted_credential_types: vec![VCT.into()],
        credential_requirements: vec![pp::CredentialRequirement {
            id: Uuid::from_u128(19),
            credential_template_id: "demo-age".into(),
            display_name: "Synthetic age".into(),
            description: None,
            required: true,
            credential_payload_format: "SD_JWT_VC".into(),
            requested_claims: vec![pp::RequestedClaim {
                id: Uuid::from_u128(20),
                claim_name: claim.into(),
                display_name: claim.into(),
                description: Some("Present the issuer-signed age threshold".into()),
                required: true,
                selective_disclosure: true,
                accept_derived: false,
                predicate_spec: None,
                constraints: vec![pp::ClaimConstraint {
                    id: Uuid::from_u128(21),
                    claim_name: claim.into(),
                    constraint_type: pp::ConstraintType::Equals,
                    value: Some(json!(true)),
                    description: Some("The signed age threshold must be true".into()),
                }],
            }],
            trust_profile_id: None,
            max_age_seconds: Some(600),
            require_fresh_issuance: false,
        }],
        alternative_requirements: vec![],
        presentation_proof_required: true,
        trust_profile_id: Some(Uuid::from_u128(22)),
        holder_binding: pp::HolderBinding {
            required: true,
            binding_methods: vec!["DEVICE_KEY".into()],
            proof_profiles: vec!["OID4VP_VERIFIABLE_PRESENTATION".into()],
            proof_freshness: [
                ("challenge_required".into(), true),
                ("audience_binding_required".into(), true),
                ("replay_detection_required".into(), true),
            ]
            .into_iter()
            .collect(),
        },
        freshness: Some(pp::FreshnessPolicy {
            max_age_seconds: Some(600),
            require_not_revoked: true,
            revocation_grace_seconds: Some(60),
        }),
        issuer_constraints: None,
        credential_ranking_strategy: "FIRST_VALID".into(),
        credential_ranking_weights: None,
        purpose: Some("Synthetic age verification".into()),
        compliance_profile_id: None,
        prefer_predicates: false,
        fallback_policy: None,
        supported_circuits: vec![],
        version: 1,
        created_at: now,
        updated_at: now,
    }
}
