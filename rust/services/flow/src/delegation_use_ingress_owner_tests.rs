//! Real Organization access owner/source through authenticated Flow ingress.
//! START/consent/domain and forwarding credentials remain this suite's explicit
//! fixtures; no public deployment or final machine-proof qualification is claimed.
use super::*;
use marty_delegated_authority::OrganizationDelegationUseCommandAuthorizer;
use marty_organization::{
    catalog::seed_system_roles,
    machine_registry::{MachineRegistryDocuments, MachineRegistryService},
    machine_use_access::{
        MachineUseAccessInput, MachineUseAccessOwner, MachineUseAccessSelection,
        MachineUsePermission, PgMachineUseAccessSource,
    },
    postgres::PostgresOrganizationStore,
    ForwardedPrincipal, JoinMechanism, Organization, OrganizationCreate, OrganizationType,
};
use serde_json::Value;

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_ingress_uses_actual_machine_access_and_denies_revocation_during_signing(
) -> TestResult {
    let mut h = Ingress::new_with_actor_type(PrincipalType::MachineIdentity).await?;
    let org = h.f.caller.organization_id();
    let store = PostgresOrganizationStore::new(h.f.pool.clone());
    let user_id = format!("ingress-machine-owner-{}", Uuid::new_v4());
    let human = ForwardedPrincipal::User {
        user_id: user_id.clone(),
    };
    let (mut organization, mut member) = Organization::create(OrganizationCreate {
        name: format!("Actual ingress access {}", Uuid::new_v4()),
        owner_id: user_id,
        org_type: OrganizationType::Enterprise,
        display_name: None,
        description: None,
        join_mechanism: JoinMechanism::Invite,
        requires_approval: false,
        is_discoverable: false,
        now: Utc::now(),
    })?;
    organization.id = org;
    member.organization_id = org;
    store.save_organization(&organization).await?;
    store.save_member(&member).await?;
    let roles = seed_system_roles(&store, org, Utc::now()).await?;
    store
        .set_member_roles(member.id, &[roles["owner"].id])
        .await?;

    let machine = Uuid::new_v4();
    let deployment = Uuid::new_v4();
    let runtime = format!("urn:test:ingress-runtime:{machine}");
    let principal = serde_json::to_value(h.f.caller.actor())?;
    let principal_id = &h.f.caller.actor().id;
    let now = Utc::now();
    let thumb =
        marty_verification::jwk::Jwk::from_json(&h.f.public_key.to_string())?.thumbprint()?;
    let fingerprint = format!("sha256:{}", hex::encode(URL_SAFE_NO_PAD.decode(&thumb)?));
    assert_eq!(
        h.f.fixture.grant.terms.binding.key_thumbprint.as_deref(),
        Some(fingerprint.as_str())
    );
    let key = json!({"basis":"JWK_RFC7638_SHA256","encoding":"BASE64URL_SHA256","value":thumb});
    let audience = "https://ingress-tests.invalid/registered-workload";
    let documents = json!({
        "configuration":{
            "profile":"urn:marty:principal-runtime-binding-configuration:v1","organization_id":org,
            "deployment_profile_id":deployment,"principal":principal,"authentication_source":{"issuer":principal_id,"subject":principal_id},
            "allowed_audiences":[audience],"runtime":{"kind":"MANAGED","instance_ref":runtime,"machine_identity_id":machine,
                "active_key_id":"ingress-machine-key","stored_thumbprint_encoding":"MIP_SHA256_HEX"},
            "expected_key_algorithm":"ES256","expected_key_thumbprint":key,"shared_runtime":false
        },
        "record":{
            "profile":"urn:marty:principal-runtime-binding:v1","organization_id":org,"principal":principal,
            "authentication":{"issuer":principal_id,"subject":principal_id,"audience":audience,"key_algorithm":"ES256","key_thumbprint":key},
            "runtime":{"kind":"MANAGED","instance_ref":runtime,"machine_identity_id":machine}
        },
        "machine":{
            "id":machine,"organization_id":org,"machine_id":principal_id,"display_name":"Actual ingress machine",
            "machine_type":"SECURE_PROCESSING_RUNTIME","status":"ACTIVE",
            "identity_keys":[{"key_id":"ingress-machine-key","thumbprint":fingerprint,"algorithm":"ES256","status":"ACTIVE",
                "public_key_jwk":h.f.public_key,"valid_from":now-Duration::minutes(1),"valid_until":now+Duration::hours(1)}],
            "assignments":{"deployment_profile_id":deployment,"operator_organization_id":org},"credential_ids":[Uuid::new_v4()],"created_at":now-Duration::minutes(1)
        },
        "map":{
            "id":Uuid::new_v4(),"organization_id":org,"name":"Ingress access test MAP","trust_profile_id":Uuid::new_v4(),
            "required_credential_types":["MachineCredential"],"allowed_machine_types":["SECURE_PROCESSING_RUNTIME"],
            "machine_binding":{"binding_methods":["MACHINE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],
                "proof_freshness":{"challenge_required":true,"audience_binding_required":true,"replay_detection_required":true,"max_proof_age_seconds":120}},
            "status":"ACTIVE","created_at":now-Duration::minutes(1)
        }
    });
    MachineRegistryService::new(store.clone())
        .register(
            org,
            &human,
            MachineRegistryDocuments {
                binding_record: serde_json::to_vec(&documents["record"])?,
                binding_configuration: serde_json::to_vec(&documents["configuration"])?,
                machine_identity: serde_json::to_vec(&documents["machine"])?,
                machine_authentication_policy: serde_json::to_vec(&documents["map"])?,
            },
        )
        .await?;
    let owner = MachineUseAccessOwner::new(store);
    let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    owner
        .grant(
            org,
            &human,
            machine,
            MachineUseAccessInput {
                permissions: vec![
                    MachineUsePermission::RetrieveRequest,
                    MachineUsePermission::SubmitProof,
                ],
                valid_from: now - Duration::seconds(1),
                valid_until: now + Duration::hours(1),
            },
        )
        .await?;
    let role = format!("flow_machine_access_reader_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        GRANT USAGE ON SCHEMA organization_service TO {role};
        GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,
            organization_service.machine_registry_entries,organization_service.machine_registry_history,
            organization_service.machine_use_access,organization_service.machine_use_access_history TO {role};"))).execute(&h.f.pool).await?;
    let reader = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(h.f.pool.connect_options().as_ref().clone().username(&role))
        .await?;
    let access = OrganizationDelegationUseCommandAuthorizer::new(PgMachineUseAccessSource::new(
        reader,
        MachineUseAccessSelection::new(org, deployment)?,
    ));
    access.readiness().await?;
    h.app = Arc::new(
        FlowDelegatedUseIngress::new(
            PostgresFlowRepository::new(h.pool.clone()),
            h.providers.clone(),
            Arc::new(access),
            h.f.fixture.configuration.public_base_url.clone(),
            RequestObjectOptions::default(),
        )
        .await?,
    );

    let (_, _, challenge) = h.f.start().await?;
    let response = h
        .router()
        .oneshot(h.request(challenge.challenge_id, None, Duration::seconds(25)))
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response_bytes(response).await)
    );
    let response = h
        .router()
        .oneshot(h.request(challenge.challenge_id, None, Duration::seconds(25)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let request_bytes = response_bytes(response).await;
    let proof = h.f.proof(&challenge);
    let response = h
        .router()
        .oneshot(h.request(
            challenge.challenge_id,
            Some(proof.clone()),
            Duration::seconds(25),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let submission: Value = serde_json::from_slice(&response_bytes(response).await)?;
    assert_eq!(submission["recovered"], false);
    assert_eq!(h.request_signer.calls.load(Ordering::SeqCst), 1);

    // The second request is authorized, then its current right is revoked
    // while real request signing awaits. Fresh recheck must reject persistence.
    // Consume the first signing notice; all fixture waits remain bounded.
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        h.request_signer.started.notified(),
    )
    .await?;
    h.request_signer.delay_ms.store(1000, Ordering::SeqCst);
    let (_, _, second) = h.f.start().await?;
    let router = h.router();
    let request = h.request(second.challenge_id, None, Duration::seconds(25));
    let operation = tokio::spawn(async move { router.oneshot(request).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        h.request_signer.started.notified(),
    )
    .await?;
    owner.revoke(org, &human, machine, 1).await?;
    assert!(
        !operation.is_finished(),
        "revocation commits during the signing wait"
    );
    let response = operation.await??;
    assert!(!response.status().is_success());
    for submitted in [None, Some(proof)] {
        let response = h
            .router()
            .oneshot(h.request(challenge.challenge_id, submitted, Duration::seconds(25)))
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT request_bytes FROM flow_service.delegated_request_results WHERE challenge_id=$1",
    )
    .bind(challenge.challenge_id)
    .fetch_one(&h.f.pool)
    .await?;
    assert_eq!(retained, request_bytes);
    let second_results: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM flow_service.delegated_request_results WHERE challenge_id=$1",
    )
    .bind(second.challenge_id)
    .fetch_one(&h.f.pool)
    .await?;
    assert_eq!(second_results, 0);
    let proofs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM flow_service.delegated_proof_submissions WHERE challenge_id=$1",
    )
    .bind(challenge.challenge_id)
    .fetch_one(&h.f.pool)
    .await?;
    assert_eq!(proofs, 1);
    assert_eq!(h.request_signer.calls.load(Ordering::SeqCst), 2);
    Ok(())
}
