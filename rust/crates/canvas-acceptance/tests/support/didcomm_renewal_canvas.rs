//! Real Canvas rows/guard/projection on the existing renewal delivery graph.
//! Source rows and named admission/signing ports are controlled; guard, binding,
//! PostgreSQL materialization, wallet transport and finalizer are real.
use super::*;
use marty_issuance_service::initiation::InitiationTemplate;

async fn seed_canvas(
    pool: &PgPool,
    id: &str,
    source: &str,
    template: &InitiationTemplate,
    stale: bool,
) {
    let app = format!("application-{id}");
    let platform = format!("platform-{id}");
    let binding = format!("binding-{id}");
    let application_template = format!("application-template-{id}");
    let candidate = format!("candidate-{id}");
    let fact = format!("fact-{id}");
    let context = json!({"canvas":{"source":"canvas-lti","canvas_platform_id":platform,"canvas_program_binding_id":binding,"canvas_account_id":platform,"application_template_id":application_template,"credential_template_id":"didcomm-template","lti_subject":"synthetic-learner","canvas_award_candidate_id":candidate}});
    let requirements = json!([{"requirement_id":"score","source":"canvas_rest","fact_type":"canvas.assignment_score","scope":{"course_id":"course","activity_id":"activity"},"pass_rule":{"min_score_percent":80},"required":true}]);
    let credential_snapshot = json!({"id":"didcomm-template","organization_id":ORGANIZATION,"status":"active","credential_type":"OpenBadgeCredential","credential_payload_format":FORMAT,"revocation_profile_id":"didcomm-status","issuer_did":ISSUER,"issuer_algorithm":"EdDSA","vct":"https://issuer.example/credentials/OpenBadgeCredential","wallet_configs":template.wallet_configs,"validity_rules":{"default_validity_days":365,"renewable":true,"renewal_window_days":30},"selective_disclosure_fields":[],"zk_predicate_claims":[]});
    sqlx::query("INSERT INTO issuance_service.application_templates(id,organization_id,credential_template_id,name,status,form_fields,evidence_requirements,claim_collection_rules,required_checks,approval_strategy,application_validity_days,ui_config,notification_config,created_at,updated_at) VALUES($1,$2,'didcomm-template','Synthetic Canvas renewal','active','[]','[]','[]','[]','auto',30,'{}','{}',clock_timestamp(),clock_timestamp())")
      .bind(&application_template).bind(ORGANIZATION).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.canvas_platforms(id,organization_id,canvas_account_id,registration_status,enabled,connection_config,capability_snapshot,config_version,created_at,updated_at) VALUES($1,$2,$1,'installed',true,'{}','{}',1,clock_timestamp(),clock_timestamp())")
      .bind(&platform).bind(ORGANIZATION).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.canvas_program_bindings(id,organization_id,platform_id,application_template_id,credential_template_id,flow_mode,direct_issue_enabled,auto_approve_on_evidence,evidence_requirements,canvas_scope,feature_flags,canvas_credentials,config_version,validated_config_version,readiness_checks,readiness_validated_at,activated_at,credential_template_snapshot,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,'didcomm-template','elevenid_orchestrated_canvas_evidence',false,false,$5,'{}','{}','{}',1,1,'[{\"status\":\"ready\",\"blocking\":true}]',clock_timestamp(),clock_timestamp(),$6,true,clock_timestamp(),clock_timestamp())")
      .bind(&binding).bind(ORGANIZATION).bind(&platform).bind(&application_template).bind(requirements).bind(credential_snapshot).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.applications(id,organization_id,application_template_id,applicant_identifier,form_data,submitted_evidence,status,derived_claims,integration_context,issuance_transaction_id,credential_id,created_at,updated_at,submitted_at,expires_at) VALUES($1,$2,$3,'synthetic','{}','[]','approved','{}',$4,$5,$6,clock_timestamp(),clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '30 days')")
      .bind(&app).bind(ORGANIZATION).bind(application_template).bind(context).bind(format!("source-tx-{id}")).bind(source).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.canvas_award_candidates(id,organization_id,platform_id,binding_id,candidate_key,lti_subject,state,application_id,claimed_credential_id,observed_at,created_at,updated_at) VALUES($1,$2,$3,$4,$1,'synthetic-learner','claimed',$5,$6,clock_timestamp(),clock_timestamp(),clock_timestamp())")
      .bind(candidate).bind(ORGANIZATION).bind(platform).bind(binding).bind(&app).bind(source).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.evidence_facts(id,organization_id,application_id,subject_id,provider,fact_type,scope,assertion,verification,source,requirement_id,logical_key,source_revision,payload_hash,effective_at,observed_at,created_at) VALUES($1,$2,$3,'synthetic-learner','canvas','canvas.assignment_score','{\"course_id\":\"course\",\"activity_id\":\"activity\"}','{\"score_percent\":92}','{\"status\":\"VERIFIED\"}','{\"source\":\"canvas_rest\"}','score','score-head','revision','synthetic-hash',clock_timestamp(),clock_timestamp(),clock_timestamp())")
      .bind(&fact).bind(ORGANIZATION).bind(&app).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.evidence_fact_heads(organization_id,application_id,logical_key,fact_id) VALUES($1,$2,'score-head',$3)")
      .bind(ORGANIZATION).bind(app).bind(&fact).execute(pool).await.unwrap();
    if stale {
        sqlx::query("UPDATE issuance_service.evidence_facts SET observed_at=clock_timestamp()-interval '2 days',effective_at=clock_timestamp()-interval '2 days' WHERE id=$1").bind(fact).execute(pool).await.unwrap();
    }
}

async fn canvas_snapshot(pool: &PgPool, id: &str) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(
      'application',(SELECT to_jsonb(a) FROM issuance_service.applications a WHERE id=$1),
      'candidate',(SELECT to_jsonb(c) FROM issuance_service.canvas_award_candidates c WHERE id=$2),
      'drift',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]') FROM issuance_service.canvas_evidence_sync_targets d WHERE application_id=$1),
      'facts',(SELECT COALESCE(jsonb_agg(to_jsonb(f) ORDER BY id),'[]') FROM issuance_service.evidence_facts f WHERE application_id=$1))")
      .bind(format!("application-{id}")).bind(format!("candidate-{id}")).fetch_one(pool).await.unwrap()
}

pub(super) async fn run(pool: &PgPool) {
    for authenticated in [false, true] {
        for (ordinary, refused, stale, mismatch) in [
            (false, false, false, 0),
            (false, true, false, 0),
            (true, false, false, 0),
            (false, false, true, 0),
            (true, false, false, 1),
            (true, false, false, 2),
        ] {
            let id = format!(
                "cr-{}{}{}{}-{mismatch}",
                u8::from(authenticated),
                u8::from(ordinary),
                u8::from(refused),
                u8::from(stale)
            );
            let graph = DeliveryGraph::start_canvas(
                pool,
                authenticated,
                refused.then_some(Fault::HttpRefused),
            )
            .await;
            let scenario = if ordinary {
                Scenario::OrdinaryThenDirect
            } else {
                Scenario::Automatic
            };
            let source = seed_source(pool, &graph, &id, scenario).await;
            let template = InitiationTemplate {
                credential_type: "OpenBadgeCredential".into(),
                vct: Some("https://issuer.example/credentials/OpenBadgeCredential".into()),
                credential_payload_format: FORMAT.into(),
                revocation_profile_id: Some("didcomm-status".into()),
                issuer_did: Some(ISSUER.into()),
                issuer_algorithm: Some("EdDSA".into()),
                wallet_configs: if ordinary {
                    vec![]
                } else {
                    transaction(&id).wallet_configs
                },
                renewable: true,
                renewal_window_days: 30,
                ..InitiationTemplate::default()
            };
            seed_canvas(pool, &id, &source, &template, stale).await;
            let before = canvas_snapshot(pool, &id).await;
            let source_before = snapshot(pool, &format!("source-tx-{id}")).await;
            let (service, projector, admission) = fresh_initiation::services_with_template(
                graph.repository.clone(),
                graph.delivery.clone(),
                graph.issuer.clone(),
                &id,
                scenario.template(),
                Some(template.clone()),
            );
            let router = credential_renewal::router(CredentialRenewalService::new(
                graph.repository.clone(),
                InitiationHttpService::new(service, projector.clone(), Some(API_KEY)),
                Some(API_KEY),
                admission,
            ));
            let (status, response) = renewal_response(&router, &source).await;
            assert_eq!(status, StatusCode::OK, "{response}");
            let uri = response["credential_offer_uri"].as_str().unwrap();
            let parsed = url::Url::parse(uri).unwrap();
            assert_eq!(parsed.scheme(), "openid-credential-offer");
            let query = parsed.query_pairs().collect::<Vec<_>>();
            assert_eq!(query.len(), 1);
            assert_eq!(query[0].0, "credential_offer");
            assert_eq!(
                serde_json::from_str::<Value>(&query[0].1).unwrap(),
                json!({"credential_issuer":format!("https://issuer.example/org/{ORGANIZATION}"),"credential_configuration_ids":["OpenBadgeCredential#sd-jwt"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":format!("pre-auth-{id}")}}})
            );
            assert_eq!(
                response,
                json!({"source_credential_id":source,"transaction_id":id,"credential_offer_uri":uri,
              "credential_offer_uris":if ordinary {json!({})}else{json!({"didcomm":if stale {format!("didcomm://pending?transaction_id={id}")}else{format!("didcomm://{}",graph.endpoint)}})},
              "credential_offer_labels":if ordinary {json!({})}else{json!({"didcomm":"Synthetic Wallet"})},
              "expires_at":(Utc.timestamp_opt(1_700_000_000,0).single().unwrap()+chrono::Duration::days(7)).to_rfc3339()})
            );
            let after_offer = canvas_snapshot(pool, &id).await;
            assert_eq!(after_offer["application"]["issuance_transaction_id"], id);
            assert_eq!(after_offer["application"]["status"], "approved");
            assert_eq!(after_offer["facts"], before["facts"]);
            if ordinary {
                assert_eq!(after_offer["application"]["credential_id"], source);
                assert_eq!(after_offer["candidate"], before["candidate"]);
                assert_eq!(after_offer["drift"], json!([]));
                assert_eq!(
                    graph.wallet.captures().await,
                    json!({"messages":[],"failures":0})
                );
                if mismatch != 0 {
                    // Valid independently owned FK targets, not orphan rows or
                    // disabled constraints. The guard remains healthy; the atomic
                    // credential projection must reject another association.
                    let alternate = format!("alt-{id}");
                    seed_canvas(pool, &alternate, &source, &template, false).await;
                    let alternate_before = canvas_snapshot(pool, &alternate).await;
                    let statement = if mismatch == 1 {
                        "UPDATE issuance_service.canvas_award_candidates SET application_id=$2 WHERE id=$1"
                    } else {
                        "UPDATE issuance_service.canvas_award_candidates SET binding_id=$2 WHERE id=$1"
                    };
                    let pointer = if mismatch == 1 {
                        "application"
                    } else {
                        "binding"
                    };
                    sqlx::query(statement)
                        .bind(format!("candidate-{id}"))
                        .bind(format!("{pointer}-{alternate}"))
                        .execute(pool)
                        .await
                        .unwrap();
                    let mismatched = canvas_snapshot(pool, &id).await;
                    assert_eq!(
                        direct_response(
                            &DirectEndpoint {
                                router: direct_router(graph.delivery.clone()),
                                gateway: false
                            },
                            &id
                        )
                        .await,
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            json!({"detail":"DIDComm delivery is unavailable"})
                        )
                    );
                    let rejected = snapshot(pool, &id).await;
                    assert_eq!(rejected["transaction"]["status"], "pending");
                    // Actual release_retryably restores pending and clears the claim.
                    assert!(rejected["transaction"]["reserved_credential_id"].is_null());
                    for rows in ["credentials", "deliveries", "events"] {
                        assert_eq!(rejected[rows], json!([]));
                    }
                    assert_eq!(canvas_snapshot(pool, &id).await, mismatched);
                    assert_eq!(canvas_snapshot(pool, &alternate).await, alternate_before);
                    assert_eq!(
                        snapshot(pool, &format!("source-tx-{id}")).await,
                        source_before
                    );
                    assert_eq!(graph.allocations.load(Ordering::SeqCst), 1);
                    assert_eq!(graph.builder.calls.load(Ordering::SeqCst), 1);
                    assert_eq!(
                        graph.wallet.captures().await,
                        json!({"messages":[],"failures":0})
                    );
                    assert!(graph.publications.lock().unwrap().is_empty());
                    sqlx::query(statement)
                        .bind(format!("candidate-{id}"))
                        .bind(format!("{pointer}-{id}"))
                        .execute(pool)
                        .await
                        .unwrap();
                    assert_eq!(canvas_snapshot(pool, &id).await, after_offer);
                }
                assert_eq!(
                    direct_response(
                        &DirectEndpoint {
                            router: direct_router(graph.delivery.clone()),
                            gateway: false
                        },
                        &id
                    )
                    .await
                    .0,
                    StatusCode::OK
                );
            }
            let state = snapshot(pool, &id).await;
            let canvas = canvas_snapshot(pool, &id).await;
            let mut expected_application = before["application"].clone();
            expected_application["issuance_transaction_id"] = json!(id);
            if !stale {
                expected_application["credential_id"] = state["credentials"][0]["id"].clone();
                // Existing apply_canvas_projection writes the issued timestamp,
                // not a normalized/ignored application field.
                expected_application["updated_at"] = state["credentials"][0]["issued_at"].clone();
                assert!(
                    chrono::DateTime::parse_from_rfc3339(
                        expected_application["updated_at"].as_str().unwrap()
                    )
                    .unwrap()
                        >= chrono::DateTime::parse_from_rfc3339(
                            before["application"]["updated_at"].as_str().unwrap()
                        )
                        .unwrap()
                );
            }
            assert_eq!(
                canvas["application"], expected_application,
                "only exact successor association fields may change"
            );
            if stale {
                assert_eq!(state["transaction"]["status"], "pending");
                for rows in ["credentials", "deliveries", "events"] {
                    assert_eq!(state[rows], json!([]));
                }
                assert_eq!(graph.allocations.load(Ordering::SeqCst), 0);
                assert_eq!(graph.builder.calls.load(Ordering::SeqCst), 0);
                assert_eq!(
                    graph.wallet.captures().await,
                    json!({"messages":[],"failures":0})
                );
                assert_eq!(canvas["application"]["credential_id"], source);
                assert_eq!(canvas["candidate"], before["candidate"]);
                assert_eq!(canvas["drift"], json!([]));
                assert_eq!(
                    snapshot(pool, &format!("source-tx-{id}")).await,
                    source_before
                );
            } else {
                assert_eq!(state["transaction"]["status"], "issued");
                let credential = &state["credentials"][0]["id"];
                assert_eq!(&canvas["application"]["credential_id"], credential);
                assert_eq!(&canvas["candidate"]["claimed_credential_id"], credential);
                assert_eq!(canvas["candidate"]["state"], "claimed");
                assert_eq!(
                    state["credentials"][0]["renewed_from_credential_id"],
                    source
                );
                let captured = graph.wallet.captures().await;
                let message =
                    assert_captured_message(&graph, &captured, authenticated, &id, &state);
                if refused {
                    assert_eq!(state["deliveries"][0]["status"], "delivery_unknown");
                    assert_eq!(state["events"], json!([]));
                    assert_eq!(canvas["drift"], json!([]));
                    assert_eq!(
                        snapshot(pool, &format!("source-tx-{id}")).await,
                        source_before
                    );
                } else {
                    assert_eq!(state["deliveries"][0]["status"], "delivered");
                    assert_eq!(
                        state["events"][0]["application_id"],
                        format!("application-{id}")
                    );
                    assert_eq!(canvas["drift"].as_array().unwrap().len(), 1);
                    assert_eq!(
                        &canvas["drift"][0]["metadata"]["claimed_credential_id"],
                        credential
                    );
                    assert_eq!(canvas["drift"][0]["target_type"], "issued_drift");
                    assert_eq!(
                        snapshot(pool, &format!("source-tx-{id}")).await["credentials"][0]
                            ["status"],
                        "revoked"
                    );
                }
                let direct = DirectEndpoint {
                    router: direct_router(graph.delivery.clone()),
                    gateway: false,
                };
                for _ in 0..2 {
                    assert_eq!(
                        direct_response(&direct, &id).await,
                        if refused {
                            (
                                StatusCode::OK,
                                json!({
                                    "transaction_id":id,
                                    "credential_id":credential,
                                    "holder_did":HOLDER,
                                    "service_endpoint":graph.endpoint,
                                    "didcomm_message_id":message,
                                    "status":"delivery_failed",
                                    "error":"HTTP 503"
                                }),
                            )
                        } else {
                            (
                                StatusCode::OK,
                                json!({
                                    "transaction_id":id,
                                    "credential_id":credential,
                                    "holder_did":HOLDER,
                                    "service_endpoint":graph.endpoint,
                                    "didcomm_message_id":message,
                                    "status":"delivered",
                                    "error":null
                                }),
                            )
                        }
                    );
                }
                assert_eq!(graph.wallet.captures().await, captured);
                assert_eq!(canvas_snapshot(pool, &id).await, canvas);
                assert_eq!(snapshot(pool, &id).await, state);
            }
            assert_eq!(canvas["facts"], before["facts"]);
            assert_eq!(
                graph.publications.lock().unwrap().len(),
                usize::from(!stale && !refused)
            );
            graph.peers.close().await;
            graph.wallet.close_verified();
        }
    }
}
