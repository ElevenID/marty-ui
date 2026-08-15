use marty_signing_keys::documents::{
    certificate_storage_key, did_storage_key, jwks_storage_key, slug_storage_key, DocumentError,
    DocumentStore, InspectCertificateRequest, LoadDidRequest, PublishDidRequest, PublishJwkRequest,
    UpdateJwkRequest,
};
use marty_signing_keys::registry::RegistryStore;
use redis::AsyncCommands;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn redis_round_trip_preserves_certificate_jwks_did_and_slug_behavior() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let suffix = Uuid::new_v4().simple().to_string();
    let organization_id = format!("rust-signing-documents-{suffix}");
    let other_organization_id = format!("rust-signing-documents-other-{suffix}");
    let service_id = "svc-a";
    let slug = format!("org-{suffix}");
    let did_id = format!("did:web:issuer.example:orgs:{slug}");
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/document_vectors.json")).unwrap();
    let store = RegistryStore::connect(&redis_url).await.unwrap();
    let documents = DocumentStore::from_connection(store.connection());

    let certificate = documents
        .store_certificate(
            &organization_id,
            service_id,
            InspectCertificateRequest {
                cert_pem: fixture["certificate"]["cert_pem"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                cert_chain_pem: None,
                expected_public_jwk: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(certificate.cert_expires_at, "2035-01-01T00:00:00Z");
    assert_eq!(
        documents
            .certificate_overrides(&organization_id)
            .await
            .unwrap()["services"][service_id]["cert_expires_at"],
        "2035-01-01T00:00:00Z"
    );

    let publication = documents
        .publish_jwk(
            &organization_id,
            service_id,
            PublishJwkRequest {
                jwk: json!({
                    "kty": "EC", "crv": "P-256", "x": "x", "y": "y",
                    "d": "must-not-be-persisted"
                }),
                key_reference: Some("key-a".to_string()),
                cert_pem: None,
                cert_chain_pem: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(publication.key_count, 1);
    assert!(publication.jwk.get("d").is_none());
    assert_eq!(publication.jwk["key_reference"], "key-a");
    assert_eq!(
        documents.jwks(&organization_id).await.unwrap()["keys"][0],
        publication.jwk
    );

    let updated = documents
        .update_jwk(
            &organization_id,
            "key-a",
            UpdateJwkRequest {
                updates: json!({"name": "Issuer key", "d": "ignored"}),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.updated, vec!["name"]);
    assert_eq!(
        documents.jwks(&organization_id).await.unwrap()["keys"][0]["name"],
        "Issuer key"
    );

    let did = documents
        .publish_did(
            &organization_id,
            service_id,
            PublishDidRequest {
                jwk: json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "private"}),
                public_domain: "issuer.example".to_string(),
                did_id: Some(did_id.clone()),
                org_slug: Some(slug.clone()),
                fragment: Some("issuer-key".to_string()),
                key_reference: Some("key-a".to_string()),
                cert_pem: None,
                cert_chain_pem: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(did.did_id, did_id);
    assert!(did.verification_method["publicKeyJwk"].get("d").is_none());
    assert_eq!(
        documents.resolve_slug(&slug).await.unwrap(),
        Some(organization_id.clone())
    );
    assert!(
        documents
            .load_did(
                &organization_id,
                LoadDidRequest {
                    did_id: Some(did_id.clone()),
                    fallback_did: None,
                },
            )
            .await
            .unwrap()
            .found
    );

    let collision = documents
        .publish_did(
            &other_organization_id,
            service_id,
            PublishDidRequest {
                jwk: json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}),
                public_domain: "issuer.example".to_string(),
                did_id: Some(did_id.clone()),
                org_slug: Some(slug.clone()),
                fragment: None,
                key_reference: None,
                cert_pem: None,
                cert_chain_pem: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(collision, DocumentError::Conflict(_)));

    assert!(
        documents
            .delete_jwk(&organization_id, "key-a")
            .await
            .unwrap()
            .removed
    );
    assert!(documents.jwks(&organization_id).await.unwrap()["keys"]
        .as_array()
        .unwrap()
        .is_empty());

    let client = redis::Client::open(redis_url).unwrap();
    let mut connection = client.get_connection_manager().await.unwrap();
    let keys = [
        certificate_storage_key(&organization_id),
        jwks_storage_key(&organization_id),
        did_storage_key(&organization_id, None),
        did_storage_key(&organization_id, Some(&did_id)),
        slug_storage_key(&slug),
        did_storage_key(&other_organization_id, None),
        did_storage_key(&other_organization_id, Some(&did_id)),
    ];
    let _: () = connection.del(&keys).await.unwrap();
}
