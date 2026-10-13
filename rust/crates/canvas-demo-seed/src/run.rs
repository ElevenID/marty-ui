//! Executes the real Canvas demo seed journey with the shared Rust operations.

use crate::{
    ags_score_payload, application_payload, claim_wallet_credential, demo_scope,
    docker_container_env_value, ensure_canvas_initial_data, install_platform, lookup_transition,
    mint_canvas_admin_token, refresh_platform_jwks, resolve_issuer_context, run_mirror_publish,
    seed_canvas_lms_objects, seed_open_badge_templates, send_signed_ags, upsert_binding,
    upsert_platform, CanonicalWalletProof, CanvasDocker, CanvasRailsConfig, CanvasRestHttp,
    CanvasRunConfig, ConnectorRunConfig, DemoEvidenceConfig, GatewayHttp, GatewaySeedConfig,
    IssuerProfileContext, SeedRunConfig, WalletHttp,
};
use chrono::Utc;
use serde_json::{json, Value};
use std::{collections::HashMap, time::Duration};
use uuid::Uuid;

fn value_id(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) if value.to_string() != "0" => Some(value.to_string()),
        _ => None,
    }
}

fn has_ags_evidence_response(value: &Value) -> bool {
    value.as_object().is_some_and(|fields| !fields.is_empty())
}

fn has_mirror_delivery(value: &Value) -> bool {
    value["publish"]["delivered_count"]
        .as_u64()
        .is_some_and(|count| count > 0)
        && value["publish"]["failed_count"].as_u64().unwrap_or(0) == 0
}

fn env_first(env: &HashMap<String, String>, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        env.get(*name)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

// The preflight accepts presence flags only; no credential value can enter its
// result or the CLI summary through this boundary.
fn validate_disposable_evidence_settings(
    is_disposable: bool,
    evidence_enabled: bool,
    has_evidence_secret: bool,
    ingest_enabled: bool,
) -> Result<(), &'static str> {
    if is_disposable && evidence_enabled && !has_evidence_secret {
        return Err(
            "Disposable Canvas evidence requires an explicit CANVAS_CREDENTIALS_SHARED_SECRET",
        );
    }
    if is_disposable && evidence_enabled && !ingest_enabled {
        return Err(
            "Disposable Canvas evidence requires CANVAS_LEGACY_EVENT_INGEST_ENABLED=true in issuance",
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct JourneyStages {
    application: bool,
    evidence: bool,
    transition: bool,
    wallet: bool,
    mirror: bool,
}

fn validate_requested_journey_completion(
    requested: JourneyStages,
    completed: JourneyStages,
) -> Result<(), &'static str> {
    if requested.application && !completed.application {
        return Err("Canvas application stage did not complete");
    }
    if requested.evidence && (!completed.evidence || !completed.transition) {
        return Err("Canvas evidence or issuance transition did not complete");
    }
    if requested.wallet && !completed.wallet {
        return Err("Canvas wallet claim did not complete");
    }
    if requested.mirror && !completed.mirror {
        return Err("Canvas mirror publish did not complete");
    }
    Ok(())
}

fn admin_scope(env: &HashMap<String, String>) -> Value {
    demo_scope(
        env_first(
            env,
            &["CANVAS_PROGRAM_BINDING_COURSE_ID", "CANVAS_COURSE_ID"],
        )
        .as_deref(),
        env_first(env, &["CANVAS_PROGRAM_BINDING_QUIZ_ID", "CANVAS_QUIZ_ID"]).as_deref(),
        env_first(
            env,
            &[
                "CANVAS_PROGRAM_BINDING_ASSIGNMENT_ID",
                "CANVAS_ASSIGNMENT_ID",
            ],
        )
        .as_deref(),
        env_first(
            env,
            &["CANVAS_PROGRAM_BINDING_MODULE_ID", "CANVAS_MODULE_ID"],
        )
        .as_deref(),
    )
}

async fn wait_for_canvas(base_url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    let url = format!("{}/", base_url.trim_end_matches('/'));
    for attempt in 0..90 {
        if client
            .get(&url)
            .header("Accept", "*/*")
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return true;
        }
        if attempt < 89 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    false
}

async fn seed_lms(
    canvas: &CanvasRunConfig,
    connector: &ConnectorRunConfig,
    platform_id: &str,
) -> Result<Value, String> {
    if !wait_for_canvas(&canvas.api_base_url).await {
        return Err(format!(
            "Canvas did not become reachable at {}",
            canvas.api_base_url
        ));
    }
    let docker = CanvasDocker;
    let rails = CanvasRailsConfig {
        container_name: canvas.container_name.clone(),
        account_id: canvas.account_id.clone(),
        admin_email: canvas.admin_email.clone(),
        admin_password: canvas.admin_password.clone(),
        browser_base_url: canvas.browser_base_url.clone(),
        lti_client_id: connector.lti_client_id.clone(),
        lti_tool_base_url: connector.lti_tool_base_url.clone(),
        display_name: connector.display_name.clone(),
    };
    ensure_canvas_initial_data(&docker, &rails).await?;
    let token = if canvas.admin_token.is_empty() {
        mint_canvas_admin_token(&docker, &rails).await?
    } else {
        canvas.admin_token.clone()
    };
    let rest = CanvasRestHttp::new(token).map_err(|error| format!("{error:?}"))?;
    match seed_canvas_lms_objects(&docker, &rest, canvas, connector, platform_id).await {
        Ok(result) => Ok(result.summary),
        Err(error)
            if error.contains("Canvas REST request failed (401)")
                || error.contains("Canvas REST request failed (403)") =>
        {
            let token = mint_canvas_admin_token(&docker, &rails).await?;
            let rest = CanvasRestHttp::new(token).map_err(|error| format!("{error:?}"))?;
            Ok(
                seed_canvas_lms_objects(&docker, &rest, canvas, connector, platform_id)
                    .await?
                    .summary,
            )
        }
        Err(error) => Err(error),
    }
}

async fn create_demo_application(
    connector: &ConnectorRunConfig,
    cfg: &GatewaySeedConfig,
    demo: &DemoEvidenceConfig,
    canvas_seed: &Value,
    date: &str,
    issuer: &IssuerProfileContext,
) -> Result<Value, String> {
    let payload = application_payload(cfg, demo, canvas_seed, date, issuer);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .post(format!(
            "{}/internal/applications",
            connector.internal_issuance_base_url.trim_end_matches('/')
        ))
        .header("Accept", "application/json")
        .header("X-API-Key", &connector.internal_issuance_api_key)
        .json(&payload)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Demo application create failed ({status})"));
    }
    let body = response.text().await.map_err(|error| error.to_string())?;
    let result: Value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if !result.is_object() || value_id(&result["id"]).is_none() {
        return Err("Demo application create did not return an application payload".into());
    }
    Ok(result)
}

/// Executes the demo journey against the explicitly configured services.
pub async fn run_seed(
    config: &SeedRunConfig,
    env: &HashMap<String, String>,
    database_url: &str,
) -> Result<Value, String> {
    validate_disposable_evidence_settings(
        env.contains_key("CANVAS_DISPOSABLE_PROJECT"),
        config.connector.demo_evidence_event_enabled,
        env_first(env, &["CANVAS_CREDENTIALS_SHARED_SECRET"]).is_some(),
        env_first(env, &["CANVAS_LEGACY_EVENT_INGEST_ENABLED"])
            .is_some_and(|value| value.eq_ignore_ascii_case("true")),
    )?;
    if !env.contains_key("CANVAS_DISPOSABLE_PROJECT")
        && config.connector.demo_evidence_event_enabled
    {
        return Err("Beta Canvas evidence must use the authoritative LTI evidence sync; synthetic AGS score events are available only in the disposable fixture".into());
    }
    let mut connector = config.connector.clone();
    let wallet_proof = if connector.open_badge_scenario_enabled
        && connector.demo_application_seed_enabled
        && connector.demo_evidence_event_enabled
        && connector.demo_wallet_claim_enabled
    {
        let base = env_first(env, &["SIGNING_KEYS_HOLDER_PROOF_BASE_URL"])
            .ok_or("SIGNING_KEYS_HOLDER_PROOF_BASE_URL is required for Canvas wallet claims")?;
        Some(CanonicalWalletProof::new(
            &base,
            &connector.signing_keys_internal_api_key,
            &connector.organization_id,
        )?)
    } else {
        None
    };
    let mut gateway_cfg = GatewaySeedConfig::from(&connector);
    let gateway = GatewayHttp::new(connector.issuance_api_key.clone())?;
    let mut warnings = Vec::<String>::new();
    let issuer_context = if connector.signing_keys_internal_api_key.trim().is_empty() {
        None
    } else {
        let signing = GatewayHttp::new(connector.signing_keys_internal_api_key.clone())?;
        resolve_issuer_context(
            &signing,
            &connector.organization_id,
            &connector.signing_keys_internal_base_url,
            &connector.signing_keys_internal_api_key,
        )
        .await
    };
    let issuer = if connector.open_badge_scenario_enabled {
        Some(IssuerProfileContext::try_from(
            issuer_context.as_ref().ok_or(
                "Canvas Open Badge requires an active issuer profile from the signing registry",
            )?,
        )?)
    } else {
        None
    };
    if connector.open_badge_scenario_enabled {
        seed_open_badge_templates(
            database_url,
            &gateway_cfg,
            &json!({}),
            issuer.as_ref().expect("validated issuer profile"),
        )
        .await?;
    }
    let platform_result = upsert_platform(&gateway, &gateway_cfg, false).await?;
    let mut platform = platform_result.value;
    let mut platform_id =
        value_id(&platform["id"]).ok_or("Canvas platform upsert did not return an ID")?;
    let mut canvas_seed = Value::Null;
    if config.canvas.enabled {
        match seed_lms(&config.canvas, &connector, &platform_id).await {
            Ok(seed) => {
                if value_id(&seed["course"]["id"]).is_none()
                    || value_id(&seed["developer_key"]["client_id"]).is_none()
                    || value_id(&seed["external_tool"]["deployment_id"]).is_none()
                {
                    return Err("Canvas LMS seed did not confirm a course, developer key client ID, and external tool deployment ID".into());
                }
                let client_id = value_id(&seed["developer_key"]["client_id"])
                    .or_else(|| value_id(&platform["lti_client_id"]))
                    .unwrap_or_else(|| connector.lti_client_id.clone());
                let deployment_id = value_id(&seed["external_tool"]["deployment_id"])
                    .or_else(|| value_id(&platform["lti_deployment_id"]))
                    .unwrap_or_else(|| connector.lti_deployment_id.clone());
                connector.lti_client_id = client_id;
                connector.lti_deployment_id = deployment_id;
                gateway_cfg = GatewaySeedConfig::from(&connector);
                platform = upsert_platform(&gateway, &gateway_cfg, true).await?.value;
                platform_id = value_id(&platform["id"]).unwrap_or(platform_id);
                canvas_seed = seed;
            }
            Err(error) => return Err(format!("Canvas LMS seed failed: {error}")),
        }
    }
    let refreshed = refresh_platform_jwks(&gateway, &gateway_cfg, &platform_id).await?;
    platform = refreshed["platform"].clone();
    if config.canvas.enabled {
        platform = install_platform(&gateway, &gateway_cfg, &platform_id).await?;
    }
    if let Some(account_id) = value_id(&platform["canvas_account_id"]) {
        connector.canvas_account_id = account_id;
        gateway_cfg = GatewaySeedConfig::from(&connector);
    }
    let course_id = value_id(&canvas_seed["course"]["id"]);
    let quiz_id = if canvas_seed["quiz"].get("error").is_some() {
        None
    } else {
        value_id(&canvas_seed["quiz"]["id"])
    };
    let seeded_scope = demo_scope(course_id.as_deref(), quiz_id.as_deref(), None, None);
    let mut scope = seeded_scope.as_object().cloned().unwrap_or_default();
    scope.extend(admin_scope(env).as_object().cloned().unwrap_or_default());
    let scope = Value::Object(scope);
    // Signed LTI launches expose course context, while the quiz is an evidence activity.
    let binding_scope = demo_scope(scope["course_id"].as_str(), None, None, None);
    if connector.open_badge_scenario_enabled {
        seed_open_badge_templates(
            database_url,
            &gateway_cfg,
            &scope,
            issuer.as_ref().expect("validated issuer profile"),
        )
        .await?;
    }
    let binding = if connector.program_binding_seed_enabled {
        Some(
            upsert_binding(
                &gateway,
                &gateway_cfg,
                &platform,
                &binding_scope,
                &scope,
                env_first(env, &["CANVAS_PROGRAM_BINDING_ACTIVATE"])
                    .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            )
            .await?
            .value,
        )
    } else {
        None
    };
    let mut application = None;
    let mut evidence = None;
    let mut wallet = None;
    let mut mirror = None;
    let mut transition = None;
    if connector.open_badge_scenario_enabled && connector.demo_application_seed_enabled {
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let demo = DemoEvidenceConfig::from(&config.canvas);
        match create_demo_application(
            &connector,
            &gateway_cfg,
            &demo,
            &canvas_seed,
            &date,
            issuer.as_ref().expect("validated issuer profile"),
        )
        .await
        {
            Ok(created) => {
                let application_id = value_id(&created["id"]).expect("validated application ID");
                application = Some(created);
                if connector.demo_evidence_event_enabled {
                    let secret =
                        env_first(env, &["CANVAS_CREDENTIALS_SHARED_SECRET"]).unwrap_or_default();
                    let secret =
                        if secret.is_empty() && !env.contains_key("CANVAS_DISPOSABLE_PROJECT") {
                            docker_container_env_value(
                                &CanvasDocker,
                                "marty-issuance",
                                "CANVAS_CREDENTIALS_SHARED_SECRET",
                            )
                            .await
                            .trim()
                            .to_owned()
                        } else {
                            secret
                        };
                    if secret.is_empty() {
                        warnings.push("CANVAS_CREDENTIALS_SHARED_SECRET is not set; demo AGS event was not submitted".into());
                    } else {
                        let suffix = Uuid::new_v4().simple().to_string();
                        let payload = ags_score_payload(
                            &gateway_cfg,
                            &demo,
                            &canvas_seed,
                            &application_id,
                            &date,
                            &suffix[..8],
                        );
                        let url = format!(
                            "{}/v1/integrations/canvas/ags/score-events",
                            connector.issuance_base_url.trim_end_matches('/')
                        );
                        match send_signed_ags(&url, &payload, &secret, Utc::now().timestamp()).await
                        {
                            Ok(result) if has_ags_evidence_response(&result) => {
                                evidence = Some(result);
                                match lookup_transition(database_url, &application_id).await {
                                    Ok(found) => transition = found,
                                    Err(error) => warnings
                                        .push(format!("Canvas transition lookup failed: {error}")),
                                }
                                if let Some(transaction_id) =
                                    transition.as_ref().and_then(|value| {
                                        value_id(&value["application"]["issuance_transaction_id"])
                                    })
                                {
                                    if connector.demo_wallet_claim_enabled {
                                        let public_api =
                                            env_first(env, &["PUBLIC_API_URL"]).unwrap_or_default();
                                        match claim_wallet_credential(
                                            &WalletHttp::new(),
                                            wallet_proof.as_ref().expect("validated wallet proof"),
                                            &gateway_cfg,
                                            &public_api,
                                            &transaction_id,
                                        )
                                        .await
                                        {
                                            Ok(result) => {
                                                wallet = Some(result);
                                                if connector.demo_mirror_publish_enabled {
                                                    match run_mirror_publish(&gateway, &gateway_cfg)
                                                        .await
                                                    {
                                                        Ok(result) => mirror = Some(result),
                                                        Err(error) => warnings.push(format!(
                                                            "Canvas mirror publish failed: {error}"
                                                        )),
                                                    }
                                                }
                                                if let Ok(found) =
                                                    lookup_transition(database_url, &application_id)
                                                        .await
                                                {
                                                    transition = found;
                                                }
                                            }
                                            Err(error) => warnings.push(format!(
                                                "Canvas wallet claim failed: {error}"
                                            )),
                                        }
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(error) => {
                                warnings.push(format!("Canvas demo AGS event failed: {error}"))
                            }
                        }
                    }
                }
            }
            Err(error) => warnings.push(format!("Canvas demo application failed: {error}")),
        }
    }
    let application_requested =
        connector.open_badge_scenario_enabled && connector.demo_application_seed_enabled;
    let evidence_requested = application_requested && connector.demo_evidence_event_enabled;
    let wallet_requested = evidence_requested && connector.demo_wallet_claim_enabled;
    let mirror_requested = wallet_requested && connector.demo_mirror_publish_enabled;
    validate_requested_journey_completion(
        JourneyStages {
            application: application_requested,
            evidence: evidence_requested,
            transition: evidence_requested,
            wallet: wallet_requested,
            mirror: mirror_requested,
        },
        JourneyStages {
            application: application.is_some(),
            evidence: evidence.is_some(),
            transition: transition.is_some(),
            wallet: wallet.is_some(),
            mirror: mirror.as_ref().is_some_and(has_mirror_delivery),
        },
    )?;
    Ok(json!({
        "platform": platform,
        "jwks_refreshed": refreshed["refreshed"],
        "canvas_lms": canvas_seed,
        "canvas_scope": scope,
        "binding": binding,
        "issuer_context": issuer_context,
        "application": application,
        "evidence": evidence,
        "wallet": wallet,
        "mirror": mirror,
        "transition": transition,
        "warnings": warnings,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        env_first, has_ags_evidence_response, has_mirror_delivery, run_seed,
        validate_disposable_evidence_settings, validate_requested_journey_completion,
        JourneyStages,
    };
    use crate::build_run_config;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn empty_ags_response_does_not_start_transition_or_wallet_followup() {
        assert!(!has_ags_evidence_response(&serde_json::Value::Null));
        assert!(!has_ags_evidence_response(&json!({})));
        assert!(has_ags_evidence_response(
            &json!({"application_status": "approved"})
        ));
    }

    #[test]
    fn disposable_secret_is_required_before_any_journey_side_effect() {
        let mut env = HashMap::from([(
            "CANVAS_DISPOSABLE_PROJECT".to_owned(),
            "marty-canvas-disposable-local".to_owned(),
        )]);
        let valid = |env: &HashMap<String, String>| {
            validate_disposable_evidence_settings(
                env.contains_key("CANVAS_DISPOSABLE_PROJECT"),
                true,
                env_first(env, &["CANVAS_CREDENTIALS_SHARED_SECRET"]).is_some(),
                env_first(env, &["CANVAS_LEGACY_EVENT_INGEST_ENABLED"])
                    .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            )
        };
        assert!(valid(&env).is_err());
        env.insert("CANVAS_CREDENTIALS_SHARED_SECRET".into(), "  ".into());
        assert!(valid(&env).is_err());
        env.insert(
            "CANVAS_CREDENTIALS_SHARED_SECRET".into(),
            "local-only-secret".into(),
        );
        assert!(valid(&env).is_err());
        env.insert("CANVAS_LEGACY_EVENT_INGEST_ENABLED".into(), "true".into());
        assert!(valid(&env).is_ok());
    }

    #[test]
    fn disposable_full_journey_cannot_report_success_without_requested_evidence() {
        let requested = JourneyStages {
            application: true,
            evidence: true,
            transition: true,
            wallet: true,
            mirror: true,
        };
        let incomplete = JourneyStages {
            application: true,
            evidence: false,
            transition: false,
            wallet: false,
            mirror: false,
        };
        assert!(validate_requested_journey_completion(requested, incomplete).is_err());
        assert!(validate_requested_journey_completion(requested, requested).is_ok());
        let application_only = JourneyStages {
            application: true,
            evidence: false,
            transition: false,
            wallet: false,
            mirror: false,
        };
        assert_eq!(
            validate_requested_journey_completion(application_only, incomplete),
            Ok(())
        );
        assert_eq!(
            validate_requested_journey_completion(
                application_only,
                JourneyStages {
                    application: false,
                    ..incomplete
                }
            ),
            Err("Canvas application stage did not complete")
        );
        assert!(!has_mirror_delivery(
            &json!({"publish": {"delivered_count": 0, "failed_count": 1}})
        ));
        assert!(has_mirror_delivery(
            &json!({"publish": {"delivered_count": 1}})
        ));
    }

    #[tokio::test]
    async fn wallet_proof_service_must_be_configured_before_any_journey_side_effect() {
        let env = HashMap::from([
            ("MARTY_API_KEY".into(), "gateway-key".into()),
            ("ISSUANCE_API_KEY".into(), "issuance-key".into()),
            (
                "ISSUANCE_INTERNAL_API_BASE_URL".into(),
                "http://issuance:8005".into(),
            ),
            ("CANVAS_DEMO_EVIDENCE_EVENT_ENABLED".into(), "true".into()),
            ("CANVAS_DISPOSABLE_PROJECT".into(), "disposable-test".into()),
            (
                "CANVAS_CREDENTIALS_SHARED_SECRET".into(),
                "test-secret".into(),
            ),
            ("CANVAS_LEGACY_EVENT_INGEST_ENABLED".into(), "true".into()),
        ]);
        let config = build_run_config(&env, true, false).unwrap();
        let error = run_seed(&config, &env, "unreachable-database")
            .await
            .unwrap_err();
        assert!(error.contains("SIGNING_KEYS_HOLDER_PROOF_BASE_URL"));
    }

    #[tokio::test]
    async fn beta_rejects_synthetic_ags_before_any_journey_side_effect() {
        let env = HashMap::from([
            ("MARTY_API_KEY".into(), "gateway-key".into()),
            ("ISSUANCE_API_KEY".into(), "issuance-key".into()),
            ("CANVAS_DEMO_EVIDENCE_EVENT_ENABLED".into(), "true".into()),
            (
                "ISSUANCE_INTERNAL_API_BASE_URL".into(),
                "http://issuance:8005".into(),
            ),
        ]);
        let config = build_run_config(&env, true, false).unwrap();
        let error = run_seed(&config, &env, "unreachable-database")
            .await
            .err()
            .unwrap();
        assert!(error.contains("authoritative LTI evidence sync"));
    }
}
