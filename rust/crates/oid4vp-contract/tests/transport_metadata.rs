use marty_oid4vp_contract::{digest_query_document, Oid4vpEvaluationTransportV1, QueryKind};
use serde_json::json;

#[test]
fn transport_is_bounded_and_never_promotes_wallet_metadata_to_evidence() {
    let query = json!({"credentials": [{"id": "member"}]});
    let submission = json!({
        "id": "response-1",
        "definition_id": "definition-1",
        "descriptor_map": [],
        "legacy_extension": true
    });
    let transport = Oid4vpEvaluationTransportV1 {
        query_kind: QueryKind::Dcql,
        query_digest: digest_query_document(&query).unwrap(),
        query_document: query,
        presentation_submission: Some(submission.clone()),
        vp_token_raw: "header.payload.signature".into(),
        verifier_client_id: "redirect_uri:https://verifier.example/submit".into(),
        request_nonce: "nonce-with-at-least-32-bytes-1234567890".into(),
    };
    transport.validate_transport().unwrap();
    assert_eq!(transport.presentation_submission, Some(submission));
    assert!(transport.compatible_presentation_submission().is_err());
    let debug = format!("{transport:?}");
    assert!(!debug.contains("header.payload.signature"));
    assert!(!debug.contains("redirect_uri:"));

    let mut wrong_digest = transport.clone();
    wrong_digest.query_digest = "0".repeat(64);
    assert!(wrong_digest.validate_transport().is_err());

    let mut wrong_kind = transport.clone();
    wrong_kind.query_kind = QueryKind::PresentationExchange;
    assert!(wrong_kind.validate_transport().is_err());

    let mut oversized = transport;
    oversized.presentation_submission = Some(json!({"extension": "x".repeat(1_048_576)}));
    assert!(oversized.validate_transport().is_err());

    let mut no_submission = oversized;
    no_submission.presentation_submission = None;
    assert!(no_submission
        .compatible_presentation_submission()
        .unwrap()
        .is_none());
}
