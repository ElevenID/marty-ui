//! Atomic Canvas association scope only. Real application rows and repository,
//! explicitly historical source credentials; no signing/readiness/delivery proof.
use super::*;
use marty_issuance_service::credential::CredentialRepository;

async fn ordinary_blank_link_finalization(fixture: &Fixture) {
    let mut historical_transaction = fixture.transaction();
    historical_transaction.status = CredentialTransactionStatus::Issued;
    fixture.reserve(&historical_transaction).await;
    let historical = fixture.credential(&historical_transaction).await;
    for (stored, projected, accepted) in [
        (None, None, true),
        (Some(""), None, true),
        (Some(" \t "), None, true),
        (None, Some(""), true),
        (Some("meaningful-source"), None, false),
        (Some("meaningful-source"), Some("other-source"), false),
        (Some(" meaningful-source"), Some("meaningful-source"), false),
    ] {
        let mut transaction = fixture.transaction();
        transaction.status = CredentialTransactionStatus::Authorized;
        transaction.renewal_of_credential_id = stored.map(str::to_owned);
        fixture.reserve(&transaction).await;
        let mut credential = historical.clone();
        credential.id = Uuid::new_v4().to_string();
        credential.transaction_id.clone_from(&transaction.id);
        credential.renewed_from_credential_id = projected.map(str::to_owned);
        let claimed = fixture
            .repository
            .claim_for_signing(&transaction, &credential.id)
            .await
            .unwrap()
            .unwrap();
        let before = fixture.snapshot().await;
        let notification_id = format!("notification-renewal-canvas-{}", transaction.id);
        let finalized = fixture
            .repository
            .finalize(&claimed, &credential, &notification_id)
            .await;
        if accepted {
            finalized.unwrap();
            let persisted = fixture
                .repository
                .credential_by_transaction(&transaction.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(persisted.id, credential.id);
            assert_eq!(persisted.credential, credential.credential);
            assert_eq!(persisted.notification_id, notification_id);
            let persisted_link: Option<String> = sqlx::query_scalar("SELECT renewed_from_credential_id FROM issuance_service.issued_credentials WHERE id=$1")
                .bind(&credential.id).fetch_one(&fixture.pool).await.unwrap();
            assert_eq!(persisted_link, credential.renewed_from_credential_id);
        } else {
            assert!(finalized.is_err());
            assert_eq!(
                fixture.snapshot().await,
                before,
                "meaningful lineage mismatch cannot finalize"
            );
        }
    }
}

async fn application(fixture: &Fixture, source: &RenewalSource, canvas: bool) -> String {
    let id = format!("renewal-application-{}", Uuid::new_v4());
    let template = format!("renewal-template-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO issuance_service.application_templates(id,organization_id,credential_template_id,name,status,form_fields,evidence_requirements,claim_collection_rules,required_checks,approval_strategy,application_validity_days,ui_config,notification_config,created_at,updated_at) VALUES($1,$2,$3,'Synthetic renewal','active','[]','[]','[]','[]','auto',30,'{}','{}',clock_timestamp(),clock_timestamp())")
      .bind(&template).bind(&fixture.organization).bind(&source.credential_template_id).execute(&fixture.pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.applications
      (id,organization_id,application_template_id,applicant_identifier,form_data,submitted_evidence,status,derived_claims,integration_context,issuance_transaction_id,credential_id,created_at,updated_at,submitted_at,expires_at)
      VALUES($1,$2,$3,'synthetic', '{}','[]','approved','{}',$4,$5,$6,clock_timestamp(),clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '30 days')")
      .bind(&id).bind(&fixture.organization).bind(template)
      .bind(if canvas { json!({"canvas":{"canvas_platform_id":"synthetic-platform"}}) } else { json!({"generic":true}) })
      .bind(&source.transaction_id).bind(&source.id).execute(&fixture.pool).await.unwrap();
    sqlx::query("UPDATE issuance_service.issuance_transactions SET application_id=$2 WHERE id=$1")
        .bind(&source.transaction_id)
        .bind(&id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    id
}

async fn app(fixture: &Fixture, id: &str) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(a) FROM issuance_service.applications a WHERE id=$1")
        .bind(id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap()
}

async fn pending(fixture: &Fixture) -> CredentialTransaction {
    let transaction = fixture.transaction();
    fixture.reserve(&transaction).await;
    transaction
}

pub(super) async fn run(fixture: &Fixture) {
    ordinary_blank_link_finalization(fixture).await;
    for canvas in [false, true] {
        let source = fixture.source().await;
        let application = application(fixture, &source, canvas).await;
        if !canvas {
            sqlx::query("UPDATE issuance_service.applications SET status='pending' WHERE id=$1")
                .bind(&application)
                .execute(&fixture.pool)
                .await
                .unwrap();
        }
        let before = app(fixture, &application).await;
        let transaction = pending(fixture).await;
        let bound = fixture
            .repository
            .bind_reservation(&transaction, &source, Some(&application))
            .await
            .unwrap();
        assert_eq!(
            bound.renewal_of_credential_id.as_deref(),
            Some(source.id.as_str())
        );
        assert_eq!(bound.application_id.as_deref(), Some(application.as_str()));
        let mut expected = before;
        if canvas {
            expected["issuance_transaction_id"] = json!(transaction.id);
        }
        assert_eq!(app(fixture, &application).await, expected, "only Canvas current transaction advances; source credential pointer/status/history retained");
        assert_eq!(
            fixture
                .repository
                .bind_reservation(&bound, &source, Some(&application))
                .await
                .unwrap(),
            bound
        );
        assert_eq!(app(fixture, &application).await, expected);
        if canvas {
            let other = pending(fixture).await;
            let state = fixture.snapshot().await;
            assert_eq!(
                fixture
                    .repository
                    .bind_reservation(&other, &source, Some(&application))
                    .await
                    .unwrap_err(),
                RenewalRepositoryError::BindingConflict
            );
            assert_eq!(
                fixture.snapshot().await,
                state,
                "losing reservation remains unlinked, not overwritten or deleted"
            );
            assert_eq!(app(fixture, &application).await, expected);
        }
    }
    for mutation in [
        "pending",
        "foreign-tenant",
        "different-current-transaction",
        "different-current-credential",
        "source-application-mismatch",
        "source-transaction-mismatch",
    ] {
        let mut source = fixture.source().await;
        let application = application(fixture, &source, true).await;
        match mutation {
            "pending" => {
                sqlx::query(
                    "UPDATE issuance_service.applications SET status='pending' WHERE id=$1",
                )
                .bind(&application)
                .execute(&fixture.pool)
                .await
                .unwrap();
            }
            "foreign-tenant" => {
                sqlx::query("UPDATE issuance_service.applications SET organization_id='foreign-organization' WHERE id=$1").bind(&application).execute(&fixture.pool).await.unwrap();
            }
            "different-current-transaction" => {
                sqlx::query("UPDATE issuance_service.applications SET issuance_transaction_id='unrelated-current' WHERE id=$1").bind(&application).execute(&fixture.pool).await.unwrap();
            }
            "different-current-credential" => {
                sqlx::query("UPDATE issuance_service.applications SET credential_id='unrelated-current' WHERE id=$1").bind(&application).execute(&fixture.pool).await.unwrap();
            }
            "source-application-mismatch" => {
                sqlx::query("UPDATE issuance_service.issuance_transactions SET application_id='unrelated-application' WHERE id=$1").bind(&source.transaction_id).execute(&fixture.pool).await.unwrap();
            }
            "source-transaction-mismatch" => {
                source.transaction_id = "unrelated-source-transaction".into();
            }
            _ => unreachable!(),
        }
        let transaction = pending(fixture).await;
        let state = fixture.snapshot().await;
        let application_before = app(fixture, &application).await;
        assert_eq!(
            fixture
                .repository
                .bind_reservation(&transaction, &source, Some(&application))
                .await
                .unwrap_err(),
            RenewalRepositoryError::BindingConflict,
            "{mutation}"
        );
        assert_eq!(
            fixture.snapshot().await,
            state,
            "{mutation}: transaction link update rolled back"
        );
        assert_eq!(app(fixture, &application).await, application_before);
    }
    let source = fixture.source().await;
    let application = application(fixture, &source, true).await;
    let first = pending(fixture).await;
    let second = pending(fixture).await;
    let (a, b) = tokio::join!(
        fixture
            .repository
            .bind_reservation(&first, &source, Some(&application)),
        fixture
            .repository
            .bind_reservation(&second, &source, Some(&application)),
    );
    let (winner, loser) = match (a, b) {
        (Ok(winner), Err(error)) | (Err(error), Ok(winner)) => (winner, error),
        _ => panic!("one Canvas successor association must win"),
    };
    assert_eq!(loser, RenewalRepositoryError::BindingConflict);
    assert_eq!(
        app(fixture, &application).await["issuance_transaction_id"],
        winner.id
    );
    let linked:i64 = sqlx::query_scalar("SELECT count(*) FROM issuance_service.issuance_transactions WHERE id=ANY($1) AND renewal_of_credential_id=$2 AND application_id=$3")
      .bind(vec![first.id,second.id]).bind(source.id).bind(application).fetch_one(&fixture.pool).await.unwrap();
    assert_eq!(linked, 1);
}
