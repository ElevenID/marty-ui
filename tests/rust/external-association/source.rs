// SPDX-License-Identifier: AGPL-3.0-only
// Explicit disposable fixture only. No deployed role or public HTTP claim.
use crate::external_association::{
    inspect_source, mutate_source, AssociationError, ChangeSource, ChangeSourceExpiry,
    SourceInspection, SourceRequest, SourceScope,
};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn restricted_login_source_adapter_preserves_replay_and_live_revocation() {
    assert_eq!(
        std::env::var("EXTERNAL_ASSOCIATION_SOURCE_TEST").as_deref(),
        Ok("synthetic-local-only")
    );
    let port: u16 = std::env::var("EXTERNAL_ASSOCIATION_SOURCE_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let organization = std::env::var("EXTERNAL_ASSOCIATION_SOURCE_ORG")
        .unwrap()
        .parse()
        .unwrap();
    let grant = std::env::var("EXTERNAL_ASSOCIATION_SOURCE_GRANT")
        .unwrap()
        .parse()
        .unwrap();
    let expires_at_ms = std::env::var("EXTERNAL_ASSOCIATION_SOURCE_EXPIRY")
        .unwrap()
        .parse()
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&format!(
            "postgresql://association_runtime:synthetic-association-only@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "association_runtime");
    crate::external_association_startup::verify_storage(&pool)
        .await
        .unwrap();
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "postgresql://postgres:synthetic-only@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
    sqlx::query("DELETE FROM issuance_service.rust_schema_migrations WHERE version='0017_external_associations'").execute(&owner).await.unwrap();
    assert!(crate::external_association_startup::verify_storage(&pool)
        .await
        .is_err());
    sqlx::query(
        "INSERT INTO issuance_service.rust_schema_migrations VALUES('0017_external_associations')",
    )
    .execute(&owner)
    .await
    .unwrap();
    sqlx::raw_sql("REVOKE UPDATE(consent_generation) ON issuance_service.external_association_identities FROM association_runtime;").execute(&owner).await.unwrap();
    assert!(crate::external_association_startup::verify_storage(&pool)
        .await
        .is_err());
    sqlx::raw_sql("GRANT UPDATE(consent_generation) ON issuance_service.external_association_identities TO association_runtime;").execute(&owner).await.unwrap();
    sqlx::raw_sql("ALTER TABLE issuance_service.external_association_challenges DISABLE TRIGGER external_association_challenge_revision;").execute(&owner).await.unwrap();
    assert!(crate::external_association_startup::verify_storage(&pool)
        .await
        .is_err());
    sqlx::raw_sql("ALTER TABLE issuance_service.external_association_challenges ENABLE TRIGGER external_association_challenge_revision;").execute(&owner).await.unwrap();
    sqlx::raw_sql("CREATE ROLE association_shadow LOGIN PASSWORD 'synthetic-shadow-only' SUPERUSER;GRANT association_runtime TO association_shadow;").execute(&owner).await.unwrap();
    let shadow = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE association_runtime")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&format!(
            "postgresql://association_shadow:synthetic-shadow-only@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
    assert!(crate::external_association_startup::verify_storage(&shadow)
        .await
        .is_err());
    shadow.close().await;
    sqlx::raw_sql(
        "REVOKE association_runtime FROM association_shadow;DROP ROLE association_shadow;",
    )
    .execute(&owner)
    .await
    .unwrap();
    crate::external_association_startup::verify_storage(&pool)
        .await
        .unwrap();
    let service_key = "synthetic-gateway-service-key-000000000001";
    assert!(
        crate::external_association_startup::prepare_isolated_router(&owner, None, false, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        crate::external_association_startup::prepare_isolated_router(
            &owner,
            None,
            true,
            Some(service_key)
        )
        .await
        .is_err()
    );
    assert!(
        crate::external_association_startup::prepare_isolated_router(
            &owner,
            Some(&format!(
                "postgresql://postgres:synthetic-only@127.0.0.1:{port}/postgres"
            )),
            true,
            Some(service_key)
        )
        .await
        .is_err()
    );
    assert!(crate::external_association_startup::prepare_isolated_router(&owner,Some(&format!("postgresql://association_runtime:synthetic-association-only@127.0.0.1:{port}/template1")),true,Some(service_key)).await.is_err());
    let isolated = crate::external_association_startup::prepare_isolated_router(
        &owner,
        Some(&format!(
            "postgresql://association_runtime:synthetic-association-only@127.0.0.1:{port}/postgres"
        )),
        true,
        Some(service_key),
    )
    .await
    .unwrap();
    assert!(isolated.is_some());
    drop(isolated);
    owner.close().await;
    let scope = SourceScope {
        organization,
        grant,
        actor: "admin-one",
    };
    let initial = inspect_source(&pool, scope, None).await.unwrap();
    assert!(
        matches!(initial, SourceInspection::Current { record } if record.revision==4 && !record.current && !record.active)
    );
    let operation_id = Uuid::new_v4();
    let mut races = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let pool = pool.clone();
        races.spawn(async move {
            mutate_source(
                &pool,
                scope,
                &SourceRequest::ChangeExpiry(ChangeSourceExpiry {
                    operation_id,
                    expected_revision: 4,
                    expires_at_ms,
                }),
            )
            .await
            .unwrap()
        });
    }
    let first = races.join_next().await.unwrap().unwrap();
    while let Some(value) = races.join_next().await {
        assert_eq!(value.unwrap(), first);
    }
    assert_eq!(first.revision, 5);
    assert!(!first.active);
    assert_eq!(
        inspect_source(&pool, scope, Some(operation_id))
            .await
            .unwrap(),
        SourceInspection::Receipt { receipt: first }
    );
    assert_eq!(
        inspect_source(
            &pool,
            SourceScope {
                actor: "learner-one",
                ..scope
            },
            Some(operation_id)
        )
        .await,
        Err(AssociationError::NotAuthorized)
    );
    let approve_operation = Uuid::new_v4();
    let approval = mutate_source(
        &pool,
        scope,
        &SourceRequest::Approve(ChangeSource {
            operation_id: approve_operation,
            expected_revision: 5,
        }),
    )
    .await
    .unwrap();
    assert!(approval.active);
    assert!(
        matches!(inspect_source(&pool, scope, None).await.unwrap(), SourceInspection::Current { record } if record.revision==6 && record.current)
    );
    let revoked = mutate_source(
        &pool,
        scope,
        &SourceRequest::Revoke(ChangeSource {
            operation_id: Uuid::new_v4(),
            expected_revision: 6,
        }),
    )
    .await
    .unwrap();
    assert_eq!(revoked.revision, 7);
    assert!(!revoked.active);
    assert_eq!(
        mutate_source(
            &pool,
            scope,
            &SourceRequest::Approve(ChangeSource {
                operation_id: approve_operation,
                expected_revision: 5,
            })
        )
        .await
        .unwrap(),
        approval
    );
    assert_eq!(
        inspect_source(&pool, scope, Some(approve_operation))
            .await
            .unwrap(),
        SourceInspection::Receipt { receipt: approval }
    );
    assert!(
        matches!(inspect_source(&pool, scope, None).await.unwrap(), SourceInspection::Current { record } if record.revision==7 && !record.current)
    );
    assert!(
        sqlx::query("UPDATE organization_service.api_keys SET enabled=false")
            .execute(&pool)
            .await
            .is_err()
    );
    use crate::external_association::{
        consent, create_challenge, ChallengeConsent, ConsentAction, CreateChallenge, LearnerScope,
        ProducerScope,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    let producer = ProducerScope {
        organization,
        api_key_id: std::env::var("EXTERNAL_ASSOCIATION_SOURCE_KEY")
            .unwrap()
            .parse()
            .unwrap(),
    };
    mutate_source(
        &pool,
        scope,
        &SourceRequest::Approve(ChangeSource {
            operation_id: Uuid::new_v4(),
            expected_revision: 7,
        }),
    )
    .await
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let challenge_request = CreateChallenge {
        operation_id: Uuid::new_v4(),
        challenge_id: Uuid::new_v4(),
        source_grant_id: grant,
        expected_source_revision: 8,
        binding_id: "binding-rust".into(),
        expected_binding_revision: 1,
        provider_reference: "d".repeat(64),
        provider_revision: 1,
        code_hash: format!("{:x}", Sha256::digest([7_u8; 32])),
        expires_at_ms: now + 120_000,
    };
    let mut challenges = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let request = challenge_request.clone();
        challenges.spawn(async move { create_challenge(&pool, producer, &request).await.unwrap() });
    }
    let created = challenges.join_next().await.unwrap().unwrap();
    while let Some(result) = challenges.join_next().await {
        assert_eq!(result.unwrap(), created);
    }
    assert_eq!(created.phase, "pending");
    let learner = LearnerScope {
        organization,
        user_id: "learner-one",
        challenge_id: created.challenge_id,
    };
    let consent_request = ChallengeConsent {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        code: URL_SAFE_NO_PAD.encode([7_u8; 32]),
    };
    assert_eq!(
        consent(
            &pool,
            LearnerScope {
                user_id: "admin-one",
                ..learner
            },
            ConsentAction::Confirm,
            &consent_request
        )
        .await,
        Err(AssociationError::NotAuthorized)
    );
    let mut consents = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let request = consent_request.clone();
        consents.spawn(async move {
            consent(&pool, learner, ConsentAction::Confirm, &request)
                .await
                .unwrap()
        });
    }
    let confirmed = consents.join_next().await.unwrap().unwrap();
    while let Some(result) = consents.join_next().await {
        assert_eq!(result.unwrap(), confirmed);
    }
    assert_eq!(confirmed.phase, "confirmed");
    let new_operation = ChallengeConsent {
        operation_id: Uuid::new_v4(),
        ..consent_request.clone()
    };
    assert_eq!(
        consent(&pool, learner, ConsentAction::Confirm, &new_operation).await,
        Err(AssociationError::NotAuthorized)
    );
    use crate::external_association::{
        close_challenge, inspect_challenge, recover_unlink, unlink, ChallengeChange,
        ChallengeInspection, ChallengeReader, CloseAction, IdentityScope, UnlinkRecovery,
    };
    let current = inspect_challenge(&pool, ChallengeReader::Learner(learner), None)
        .await
        .unwrap();
    let ChallengeInspection::Current { record } = current else {
        panic!("expected current state")
    };
    assert!(record.current);
    let identity = record.identity.unwrap();
    let identity_scope = IdentityScope {
        organization,
        user_id: "learner-one",
        identity_id: identity.identity_id,
    };
    let producer_current = inspect_challenge(
        &pool,
        ChallengeReader::Producer {
            scope: producer,
            challenge_id: created.challenge_id,
        },
        None,
    )
    .await
    .unwrap();
    assert!(
        matches!(producer_current, ChallengeInspection::Current { record } if record.current && record.subject_id.is_none() && record.application_id.is_none() && record.identity.is_none())
    );
    assert_eq!(
        inspect_challenge(
            &pool,
            ChallengeReader::Learner(learner),
            Some(consent_request.operation_id)
        )
        .await
        .unwrap(),
        ChallengeInspection::Receipt {
            receipt: confirmed.clone()
        }
    );
    assert_eq!(
        inspect_challenge(
            &pool,
            ChallengeReader::Producer {
                scope: producer,
                challenge_id: created.challenge_id
            },
            Some(consent_request.operation_id)
        )
        .await,
        Err(AssociationError::NotAuthorized)
    );
    let old_pending_request = CreateChallenge {
        operation_id: Uuid::new_v4(),
        challenge_id: Uuid::new_v4(),
        code_hash: format!("{:x}", Sha256::digest([8_u8; 32])),
        ..challenge_request.clone()
    };
    create_challenge(&pool, producer, &old_pending_request)
        .await
        .unwrap();
    let unlink_request = ChallengeChange {
        operation_id: Uuid::new_v4(),
        expected_revision: identity.revision,
    };
    let unlinked = unlink(&pool, identity_scope, &unlink_request)
        .await
        .unwrap();
    assert_eq!(
        recover_unlink(&pool, identity_scope, unlink_request.operation_id)
            .await
            .unwrap(),
        UnlinkRecovery::Receipt {
            receipt: unlinked.clone()
        }
    );
    assert_eq!(
        recover_unlink(
            &pool,
            IdentityScope {
                user_id: "admin-one",
                ..identity_scope
            },
            unlink_request.operation_id
        )
        .await,
        Err(AssociationError::NotAuthorized)
    );
    assert!(
        matches!(inspect_challenge(&pool, ChallengeReader::Learner(learner), None).await.unwrap(), ChallengeInspection::Current { record } if !record.current)
    );
    let fresh_request = CreateChallenge {
        operation_id: Uuid::new_v4(),
        challenge_id: Uuid::new_v4(),
        code_hash: format!("{:x}", Sha256::digest([9_u8; 32])),
        ..challenge_request.clone()
    };
    create_challenge(&pool, producer, &fresh_request)
        .await
        .unwrap();
    let fresh_learner = LearnerScope {
        challenge_id: fresh_request.challenge_id,
        ..learner
    };
    assert!(
        matches!(inspect_challenge(&pool, ChallengeReader::Learner(fresh_learner), None).await.unwrap(), ChallengeInspection::Current { record } if !record.current && record.can_relink)
    );
    let relink_request = ChallengeConsent {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        code: URL_SAFE_NO_PAD.encode([9_u8; 32]),
    };
    assert_eq!(
        consent(
            &pool,
            fresh_learner,
            ConsentAction::Confirm,
            &relink_request
        )
        .await,
        Err(AssociationError::NotAuthorized)
    );
    let relinked = consent(
        &pool,
        fresh_learner,
        ConsentAction::Relink {
            expected_identity_revision: unlinked.revision,
        },
        &relink_request,
    )
    .await
    .unwrap();
    assert_eq!(relinked.action, "relink");
    let old_learner = LearnerScope {
        challenge_id: old_pending_request.challenge_id,
        ..learner
    };
    let stale_request = ChallengeConsent {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        code: URL_SAFE_NO_PAD.encode([8_u8; 32]),
    };
    assert_eq!(
        consent(&pool, old_learner, ConsentAction::Confirm, &stale_request).await,
        Err(AssociationError::NotAuthorized)
    );
    assert!(
        matches!(inspect_challenge(&pool, ChallengeReader::Learner(old_learner), None).await.unwrap(), ChallengeInspection::Current { record } if !record.current && !record.can_relink)
    );
    assert_eq!(
        unlink(&pool, identity_scope, &unlink_request)
            .await
            .unwrap(),
        unlinked
    );
    assert!(
        matches!(inspect_challenge(&pool, ChallengeReader::Learner(fresh_learner), None).await.unwrap(), ChallengeInspection::Current { record } if record.current)
    );
    let abandon_request = ChallengeChange {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
    };
    let abandoned = close_challenge(
        &pool,
        producer,
        old_learner.challenge_id,
        CloseAction::Abandon,
        &abandon_request,
    )
    .await
    .unwrap();
    assert_eq!(abandoned.phase, "abandoned");
    assert_eq!(
        inspect_challenge(
            &pool,
            ChallengeReader::Producer {
                scope: producer,
                challenge_id: old_learner.challenge_id
            },
            Some(abandon_request.operation_id)
        )
        .await
        .unwrap(),
        ChallengeInspection::Receipt { receipt: abandoned }
    );
    mutate_source(
        &pool,
        scope,
        &SourceRequest::Revoke(ChangeSource {
            operation_id: Uuid::new_v4(),
            expected_revision: 8,
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        consent(&pool, learner, ConsentAction::Confirm, &consent_request)
            .await
            .unwrap(),
        confirmed
    );
    assert!(
        matches!(inspect_source(&pool, scope, None).await.unwrap(), SourceInspection::Current { record } if !record.current && !record.active && record.revision==9)
    );
    // Actual Core HTTP decoding/authenticated-header boundary over the same
    // restricted PostgreSQL LOGIN. Public session/key authentication is separate.
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        Router,
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;
    const SERVICE: &str = "synthetic-gateway-service-key-000000000001";
    fn http_request(
        path: &str,
        org: Uuid,
        user: Option<&str>,
        key: Option<Uuid>,
        value: Value,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("x-api-key", SERVICE)
            .header("x-organization-id", org.to_string());
        if let Some(user) = user {
            builder = builder.header("x-user-id", user);
        }
        if let Some(key) = key {
            builder = builder.header("x-api-key-id", key.to_string());
        }
        builder
            .body(Body::from(serde_json::to_vec(&value).unwrap()))
            .unwrap()
    }
    async fn http_response(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    let router =
        crate::external_association_http::association_router(pool.clone(), SERVICE.as_bytes())
            .unwrap();
    let source_path =
        format!("/v1/organizations/{organization}/external-association-sources/{grant}");
    let (status, _) = http_response(
        &router,
        http_request(
            &format!("{source_path}/inspect"),
            organization,
            Some("learner-one"),
            None,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, approved) = http_response(
        &router,
        http_request(
            &format!("{source_path}/approve"),
            organization,
            Some("admin-one"),
            None,
            json!({"operation_id":Uuid::new_v4(),"expected_revision":9}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(approved["revision"], 10);
    let http_challenge = Uuid::new_v4();
    let http_create_operation = Uuid::new_v4();
    let producer_path = format!("/v1/identity/association-challenges/{http_challenge}");
    let learner_path = format!(
        "/v1/organizations/{organization}/external-association-challenges/{http_challenge}"
    );
    let code = URL_SAFE_NO_PAD.encode([10_u8; 32]);
    let body = json!({"operation_id":http_create_operation,"challenge_id":http_challenge,"source_grant_id":grant,
        "expected_source_revision":10,"binding_id":"binding-rust","expected_binding_revision":1,
        "provider_reference":"d".repeat(64),"provider_revision":1,"code_hash":format!("{:x}",Sha256::digest([10_u8;32])),"expires_at_ms":now+120_000});
    let (status, pending) = http_response(
        &router,
        http_request(
            &format!("{producer_path}/create"),
            organization,
            None,
            Some(producer.api_key_id),
            body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pending["phase"], "pending");
    let (status, redacted) = http_response(
        &router,
        http_request(
            &format!("{producer_path}/inspect"),
            organization,
            None,
            Some(producer.api_key_id),
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(redacted["record"]["application_id"].is_null());
    assert!(redacted["record"]["subject_id"].is_null());
    let (status, visible) = http_response(
        &router,
        http_request(
            &format!("{learner_path}/inspect"),
            organization,
            Some("learner-one"),
            None,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(visible["record"]["subject_id"], "canonical-subject");
    let http_consent_operation = Uuid::new_v4();
    let body = json!({"operation_id":http_consent_operation,"expected_revision":1,"code":code});
    let (status, _) = http_response(
        &router,
        http_request(
            &format!("{learner_path}/confirm"),
            organization,
            Some("admin-one"),
            None,
            body.clone(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, confirmed_http) = http_response(
        &router,
        http_request(
            &format!("{learner_path}/confirm"),
            organization,
            Some("learner-one"),
            None,
            body.clone(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(confirmed_http["phase"], "confirmed");
    assert!(!confirmed_http.to_string().contains(&code));
    let (status, replayed) = http_response(
        &router,
        http_request(
            &format!("{learner_path}/confirm"),
            organization,
            Some("learner-one"),
            None,
            body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replayed, confirmed_http);
    let (status, recovery) = http_response(
        &router,
        http_request(
            &format!("{learner_path}/receipt"),
            organization,
            Some("learner-one"),
            None,
            json!({"operation_id":http_consent_operation}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(recovery["kind"], "receipt");
    assert_eq!(recovery["receipt"], confirmed_http);
    let (status, _) = http_response(
        &router,
        http_request(
            &format!("{producer_path}/receipt"),
            organization,
            None,
            Some(producer.api_key_id),
            json!({"operation_id":http_consent_operation}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    pool.close().await;
}
