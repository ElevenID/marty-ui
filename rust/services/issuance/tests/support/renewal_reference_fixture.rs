//! Exact frozen source rows for renewal gates, not a production serializer.
use marty_issuance_service::{
    credential::{CredentialTransaction, CredentialTransactionStatus},
    credential_renewal::RenewalSource,
};
use serde_json::Value;

pub fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../contracts/credential-renewal-python-reference.json"
    ))
    .unwrap()
}

pub fn case<'a>(corpus: &'a Value, name: &str) -> &'a Value {
    corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["case"] == name)
        .unwrap()
}

pub fn snapshot<'a>(corpus: &'a Value, case: &Value, phase: &str) -> &'a Value {
    let digest = case[phase]["$ref"]
        .as_str()
        .unwrap()
        .strip_prefix("#/states/")
        .unwrap();
    &corpus["states"][digest]
}

pub fn source(snapshot: &Value) -> Option<RenewalSource> {
    snapshot["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == "synthetic-source-credential")
        .map(|value| RenewalSource {
            id: value["id"].as_str().unwrap().into(),
            organization_id: value["organization_id"].as_str().unwrap().into(),
            transaction_id: value["transaction_id"].as_str().unwrap().into(),
            credential_template_id: value["credential_template_id"].as_str().unwrap().into(),
            applicant_id: value["applicant_id"].as_str().map(str::to_owned),
            subject_did: value["subject_did"].as_str().map(str::to_owned),
            status: value["status"].as_str().unwrap().into(),
            renewed_to_credential_id: value["renewed_to_credential_id"]
                .as_str()
                .map(str::to_owned),
            expires_at: value["expires_at"]
                .as_str()
                .map(|value| value.parse().unwrap()),
        })
}

pub fn transaction(value: &Value) -> CredentialTransaction {
    CredentialTransaction {
        id: value["id"].as_str().unwrap().to_owned(),
        organization_id: value["organization_id"].as_str().unwrap().to_owned(),
        credential_template_id: value["credential_template_id"].as_str().unwrap().to_owned(),
        pre_authorized_code: value["pre_auth_code"].as_str().unwrap().to_owned(),
        credential_payload_format: value["credential_payload_format"]
            .as_str()
            .unwrap()
            .to_owned(),
        delivery_mode: value["delivery_mode"].as_str().unwrap().to_owned(),
        issuer_mode: value["issuer_mode"].as_str().unwrap().to_owned(),
        revocation_profile_id: value["revocation_profile_id"].as_str().map(str::to_owned),
        renewal_of_credential_id: value["renewal_of_credential_id"]
            .as_str()
            .map(str::to_owned),
        applicant_id: value["applicant_id"].as_str().map(str::to_owned),
        application_id: value["application_id"].as_str().map(str::to_owned),
        subject_did: value["subject_did"].as_str().map(str::to_owned),
        idempotency_key_hash: value["idempotency_key_hash"].as_str().map(str::to_owned),
        idempotency_request_hash: value["idempotency_request_hash"]
            .as_str()
            .map(str::to_owned),
        nonce: value["nonce"].as_str().map(str::to_owned),
        credential_type: value["credential_type"].as_str().map(str::to_owned),
        issuer_profile_id: value["issuer_profile_id"].as_str().map(str::to_owned),
        issuer_did: value["issuer_did_override"].as_str().map(str::to_owned),
        issuer_algorithm: value["issuer_algorithm"].as_str().map(str::to_owned),
        signing_service_id: value["signing_service_id"].as_str().map(str::to_owned),
        reserved_credential_id: value["reserved_credential_id"].as_str().map(str::to_owned),
        oid4vci_client_id: value["oid4vci_client_id"].as_str().map(str::to_owned),
        selective_disclosure_claims: serde_json::from_value(
            value["selective_disclosure_claims"].clone(),
        )
        .unwrap(),
        zk_predicate_claims: serde_json::from_value(value["zk_predicate_claims"].clone()).unwrap(),
        wallet_configs: serde_json::from_value(value["wallet_configs"].clone()).unwrap(),
        validity_days: value["validity_days"].as_i64().unwrap(),
        renewal_window_days: value["renewal_window_days"].as_i64().unwrap(),
        created_at: value["created_at"].as_str().unwrap().parse().unwrap(),
        expires_at: value["expires_at"].as_str().unwrap().parse().unwrap(),
        status: match value["status"].as_str().unwrap() {
            "pending" => CredentialTransactionStatus::Pending,
            "issued" => CredentialTransactionStatus::Issued,
            other => panic!("unsupported frozen fixture status: {other}"),
        },
        claims: value["claims"].as_object().unwrap().clone(),
        renewable: value["renewable"].as_bool().unwrap(),
    }
}
