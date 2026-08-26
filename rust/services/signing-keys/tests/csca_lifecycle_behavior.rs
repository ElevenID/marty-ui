use chrono::{Duration, Utc};
use marty_crypto::jwk::certificate_pem_to_jwk;
use marty_signing_keys::csca_lifecycle::{
    CscaCertificateStatus, CscaLifecycleDocument, CscaLifecycleError, ImportCscaCertificateRequest,
    ListCscaCertificatesQuery, ListCscaOutboxQuery,
};
use marty_verification::issuance::{CscaAuthority, CscaKeyAlgorithm};
use serde_json::{json, Value};

fn csca_request(country: &str, label: &str) -> ImportCscaCertificateRequest {
    let authority = CscaAuthority::new(country, label, 30).unwrap();
    let cert_pem = authority.cert_pem().unwrap();
    ImportCscaCertificateRequest {
        expected_public_jwk: serde_json::to_value(certificate_pem_to_jwk(&cert_pem).unwrap())
            .unwrap(),
        cert_pem,
        cert_chain_pem: String::new(),
        key_reference: format!("hsm://csca/{}", country.to_lowercase()),
        metadata: json!({"country": country}),
    }
}

#[test]
fn creation_algorithms_match_the_language_neutral_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/csca-capability-behavior.json"
    ))
    .unwrap();
    let supported = CscaKeyAlgorithm::ALL.map(CscaKeyAlgorithm::as_str);
    assert_eq!(
        json!(supported),
        contract["supported_rust_surface"]["emrtd_issuance"]["creation_algorithms"]
    );
}

#[test]
fn lifecycle_preserves_lookup_filter_expiry_and_managed_custody_behavior() {
    let now = Utc::now();
    let mut document = CscaLifecycleDocument::empty("org-a", now);
    let imported = document
        .import("csca-deu-1", csca_request("DEU", "German CSCA"), now)
        .unwrap();

    assert_eq!(imported.status, CscaCertificateStatus::Valid);
    assert!(imported.certificate.subject.contains("German CSCA"));
    assert_eq!(imported.certificate.key_reference, "hsm://csca/deu");
    assert!(!imported.certificate.cert_pem.is_empty());
    assert_eq!(document.revision, 1);
    let issued = document
        .pending_outbox(&ListCscaOutboxQuery::default())
        .unwrap();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].topic, "certificate.issued");
    assert_eq!(issued[0].key, "csca-deu-1");
    assert_eq!(issued[0].payload["organization_id"], "org-a");
    assert_eq!(issued[0].payload["certificate_id"], "csca-deu-1");
    assert!(issued[0].published_at.is_none());
    assert_eq!(
        document.certificate_data("csca-deu-1", now).unwrap(),
        imported.certificate.cert_pem
    );

    let by_subject = document
        .list(
            &ListCscaCertificatesQuery {
                subject: Some("german".to_string()),
                status: Some(CscaCertificateStatus::Valid),
            },
            now,
        )
        .unwrap();
    assert_eq!(by_subject.len(), 1);
    assert!(document
        .list(
            &ListCscaCertificatesQuery {
                subject: Some("missing".to_string()),
                status: None,
            },
            now,
        )
        .unwrap()
        .is_empty());
    assert_eq!(document.expiring(31, now).unwrap().len(), 1);
    assert_eq!(document.expiring(0, now).unwrap().len(), 1);
    assert!(matches!(
        document.expiring(-1, now),
        Err(CscaLifecycleError::Invalid(_))
    ));
    assert_eq!(
        document
            .get("csca-deu-1", now + Duration::days(40))
            .unwrap()
            .status,
        CscaCertificateStatus::Expired
    );
    assert!(matches!(
        document.certificate_data("csca-deu-1", now + Duration::days(40)),
        Err(CscaLifecycleError::Expired(_))
    ));
    let not_before = chrono::DateTime::parse_from_rfc3339(&imported.certificate.not_before)
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(
        document
            .get("csca-deu-1", not_before - Duration::seconds(1))
            .unwrap()
            .status,
        CscaCertificateStatus::NotYetValid
    );
    assert!(matches!(
        document.certificate_data("csca-deu-1", not_before - Duration::seconds(1)),
        Err(CscaLifecycleError::NotYetValid(_))
    ));
}

#[test]
fn revocation_is_idempotent_and_renewal_records_both_sides_of_lineage() {
    let now = Utc::now();
    let mut document = CscaLifecycleDocument::empty("org-a", now);
    document
        .import("csca-deu-1", csca_request("DEU", "German CSCA 1"), now)
        .unwrap();

    let first = document
        .revoke("csca-deu-1", "key compromise", now + Duration::seconds(1))
        .unwrap();
    let second = document
        .revoke(
            "csca-deu-1",
            "replacement reason",
            now + Duration::seconds(2),
        )
        .unwrap();
    assert_eq!(first.certificate.revoked_at, second.certificate.revoked_at);
    assert_eq!(
        second.certificate.revocation_reason.as_deref(),
        Some("key compromise")
    );
    assert_eq!(second.status, CscaCertificateStatus::Revoked);
    assert!(matches!(
        document.certificate_data("csca-deu-1", now + Duration::seconds(2)),
        Err(CscaLifecycleError::Revoked(_))
    ));

    let replacement = document
        .renew(
            "csca-deu-1",
            "csca-deu-2",
            csca_request("DEU", "German CSCA 2"),
            now + Duration::seconds(3),
        )
        .unwrap();
    assert_eq!(
        replacement.certificate.renewed_from.as_deref(),
        Some("csca-deu-1")
    );
    let prior = document.get("csca-deu-1", now).unwrap();
    assert_eq!(
        prior.certificate.revocation_reason.as_deref(),
        Some("SUPERSEDED")
    );
    assert_eq!(prior.certificate.renewed_to.as_deref(), Some("csca-deu-2"));
    assert_eq!(document.revision, 3);
    let events = document
        .pending_outbox(&ListCscaOutboxQuery::default())
        .unwrap();
    let topics: Vec<_> = events.iter().map(|event| event.topic.as_str()).collect();
    assert_eq!(
        topics,
        [
            "certificate.issued",
            "certificate.revoked",
            "certificate.renewed"
        ]
    );
    assert_eq!(events[2].key, "csca-deu-2");
}

#[test]
fn transactional_outbox_acknowledgement_is_idempotent_and_bounded() {
    let now = Utc::now();
    let mut document = CscaLifecycleDocument::empty("org-a", now);
    document
        .import("csca-deu-1", csca_request("DEU", "German CSCA"), now)
        .unwrap();
    let event = document
        .pending_outbox(&ListCscaOutboxQuery { limit: Some(1) })
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let acknowledged = document
        .acknowledge_outbox(&event.event_id, now + Duration::seconds(1))
        .unwrap();
    let revision = document.revision;
    assert!(acknowledged.published_at.is_some());
    assert!(document
        .pending_outbox(&ListCscaOutboxQuery::default())
        .unwrap()
        .is_empty());
    assert_eq!(
        document
            .acknowledge_outbox(&event.event_id, now + Duration::seconds(2))
            .unwrap()
            .published_at,
        acknowledged.published_at
    );
    assert_eq!(document.revision, revision);
    assert!(matches!(
        document.pending_outbox(&ListCscaOutboxQuery { limit: Some(0) }),
        Err(CscaLifecycleError::Invalid(_))
    ));
    assert!(matches!(
        document.acknowledge_outbox("missing", now),
        Err(CscaLifecycleError::OutboxEventNotFound(_))
    ));
}

#[test]
fn malformed_duplicate_and_non_ca_imports_fail_without_mutating_state() {
    let now = Utc::now();
    let mut document = CscaLifecycleDocument::empty("org-a", now);
    document
        .import("csca-deu-1", csca_request("DEU", "German CSCA"), now)
        .unwrap();
    let revision = document.revision;

    assert!(matches!(
        document.import("csca-deu-1", csca_request("DEU", "Duplicate"), now),
        Err(CscaLifecycleError::Conflict(_))
    ));
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/document_vectors.json")).unwrap();
    assert!(matches!(
        document.import(
            "not-a-csca",
            ImportCscaCertificateRequest {
                cert_pem: fixture["certificate"]["cert_pem"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                cert_chain_pem: String::new(),
                key_reference: "hsm://not-a-csca".to_string(),
                expected_public_jwk: serde_json::to_value(
                    certificate_pem_to_jwk(fixture["certificate"]["cert_pem"].as_str().unwrap(),)
                        .unwrap(),
                )
                .unwrap(),
                metadata: Value::Null,
            },
            now,
        ),
        Err(CscaLifecycleError::Invalid(_))
    ));
    assert!(matches!(
        document.import(
            "bad id!",
            ImportCscaCertificateRequest {
                cert_pem: "invalid".to_string(),
                cert_chain_pem: String::new(),
                key_reference: String::new(),
                expected_public_jwk: Value::Null,
                metadata: Value::Null,
            },
            now,
        ),
        Err(CscaLifecycleError::Invalid(_))
    ));
    let mut missing_custody = csca_request("USA", "Missing custody");
    missing_custody.key_reference.clear();
    assert!(matches!(
        document.import("missing-custody", missing_custody, now),
        Err(CscaLifecycleError::Invalid(_))
    ));
    let mut malformed_chain = csca_request("USA", "Malformed chain");
    malformed_chain.cert_chain_pem = "not a certificate chain".to_string();
    assert!(matches!(
        document.import("malformed-chain", malformed_chain, now),
        Err(CscaLifecycleError::Invalid(_))
    ));
    let mut unrelated_chain = csca_request("USA", "Same subject");
    unrelated_chain.cert_chain_pem = csca_request("USA", "Same subject").cert_pem;
    assert!(matches!(
        document.import("unrelated-chain", unrelated_chain, now),
        Err(CscaLifecycleError::Invalid(_))
    ));
    let mut mismatched_key = csca_request("USA", "Mismatched key");
    mismatched_key.expected_public_jwk = csca_request("CAN", "Different key").expected_public_jwk;
    assert!(matches!(
        document.import("mismatched-key", mismatched_key, now),
        Err(CscaLifecycleError::Invalid(_))
    ));
    let mut leaked_key = csca_request("USA", "Leaked key");
    leaked_key.metadata = json!({"secret": "-----BEGIN PRIVATE KEY-----"});
    assert!(matches!(
        document.import("leaked-key", leaked_key, now),
        Err(CscaLifecycleError::Invalid(_))
    ));
    let mut leaked_jwk = csca_request("USA", "Leaked JWK");
    leaked_jwk.metadata = json!({
        "custody": {"kty": "EC", "crv": "P-256", "x": "public", "y": "public", "d": "private"}
    });
    assert!(matches!(
        document.import("leaked-jwk", leaked_jwk, now),
        Err(CscaLifecycleError::Invalid(_))
    ));
    assert_eq!(document.revision, revision);
    assert!(matches!(
        document.get("missing", now),
        Err(CscaLifecycleError::NotFound(_))
    ));
}
