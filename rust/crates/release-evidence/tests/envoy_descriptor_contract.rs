//! Independent decoding of the shipped descriptor, including google.api.http.
//! These test-only projections use prost's existing protobuf decoder. They are
//! not an operational descriptor parser or a substitute for Envoy validation.
use marty_release_evidence::envoy_config::{DESCRIPTOR, HTTP_PATH, SERVICE};
use prost::Message;
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Message)]
struct DescriptorSet {
    #[prost(message, repeated, tag = "1")]
    files: Vec<File>,
}
#[derive(Clone, PartialEq, Message)]
struct File {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    package: String,
    #[prost(message, repeated, tag = "4")]
    messages: Vec<Descriptor>,
    #[prost(message, repeated, tag = "6")]
    services: Vec<Service>,
}
#[derive(Clone, PartialEq, Message)]
struct Descriptor {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, repeated, tag = "2")]
    fields: Vec<Field>,
}
#[derive(Clone, PartialEq, Message)]
struct Field {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "3")]
    number: i32,
    #[prost(int32, tag = "5")]
    kind: i32,
    #[prost(bool, tag = "17")]
    proto3_optional: bool,
}
#[derive(Clone, PartialEq, Message)]
struct Service {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, repeated, tag = "2")]
    methods: Vec<Method>,
}
#[derive(Clone, PartialEq, Message)]
struct Method {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    input: String,
    #[prost(string, tag = "3")]
    output: String,
    #[prost(message, optional, tag = "4")]
    options: Option<Options>,
    #[prost(bool, tag = "6")]
    server_streaming: bool,
}
#[derive(Clone, PartialEq, Message)]
struct Options {
    #[prost(message, optional, tag = "72295728")]
    http: Option<Http>,
}
#[derive(Clone, PartialEq, Message)]
struct Http {
    #[prost(string, tag = "2")]
    get: String,
    #[prost(string, tag = "4")]
    post: String,
    #[prost(string, tag = "7")]
    body: String,
}

#[test]
fn shipped_descriptor_preserves_exact_initiation_capability_and_all_eleven_siblings() {
    // Reviewed policy transport, credential-template schema, additive auth_time,
    // PolicyEvaluationResponse authentication_diagnostic_json field 14, and
    // optional per-offer lifetime at InitiateIssuanceRequest field 13, and the
    // additive saved-policy revision and managed prerequisite authority fields.
    assert_eq!(
        format!("{:x}", Sha256::digest(DESCRIPTOR)),
        "784e407604510c45a68234a8d8cb84a57e26db297117b4ae37ed4557a3d5ab60"
    );
    let set = DescriptorSet::decode(DESCRIPTOR).unwrap();
    let files: Vec<_> = set
        .files
        .iter()
        .filter(|f| f.package == "marty.ui.issuance.v1")
        .collect();
    assert_eq!(files.len(), 1);
    let file = files[0];
    assert_eq!(file.name, "issuance_service.proto");
    assert_eq!(file.services.len(), 1);
    let service = &file.services[0];
    assert_eq!(format!("{}.{}", file.package, service.name), SERVICE);
    let expected = [
        ("InitiateIssuance", "POST", HTTP_PATH),
        ("ExchangeToken", "POST", "/v1/issuance/token"),
        ("IssueCredential", "POST", "/v1/issuance/credential"),
        ("GetOffer", "GET", "/v1/issuance/offers/{transaction_id}"),
        ("ListTransactions", "GET", "/v1/issuance/transactions"),
        (
            "GetTransaction",
            "GET",
            "/v1/issuance/transactions/{transaction_id}",
        ),
        (
            "RevokeCredential",
            "POST",
            "/v1/issuance/credentials/{credential_id}/revoke",
        ),
        (
            "SuspendCredential",
            "POST",
            "/v1/issuance/credentials/{credential_id}/suspend",
        ),
        (
            "ReinstateCredential",
            "POST",
            "/v1/issuance/credentials/{credential_id}/reinstate",
        ),
        (
            "GetCredentialStatus",
            "GET",
            "/v1/issuance/credentials/{credential_id}/status",
        ),
        ("StreamCredentialEvents", "", ""),
        ("HealthCheck", "GET", "/v1/issuance/health"),
    ];
    assert_eq!(service.methods.len(), expected.len());
    for (method, (name, verb, path)) in service.methods.iter().zip(expected) {
        assert_eq!(method.name, name);
        assert_eq!(method.server_streaming, name == "StreamCredentialEvents");
        let http = method.options.as_ref().and_then(|o| o.http.as_ref());
        if verb.is_empty() {
            assert!(http.is_none());
        } else {
            let http = http.unwrap();
            assert_eq!(
                if verb == "POST" {
                    &http.post
                } else {
                    &http.get
                },
                path
            );
            assert_eq!(http.body, if verb == "POST" { "*" } else { "" });
        }
    }
    assert_eq!(
        service.methods[0].input,
        ".marty.ui.issuance.v1.InitiateIssuanceRequest"
    );
    assert_eq!(
        service.methods[0].output,
        ".marty.ui.issuance.v1.IssuanceResponse"
    );
    for (message, fields) in [
        (
            "InitiateIssuanceRequest",
            vec![
                "organization_id",
                "credential_template_id",
                "applicant_id",
                "subject_did",
                "claims",
                "holder_did",
                "authorized_client_id",
                "application_id",
                "issuer_did",
                "delivery_mode",
                "idempotency_key",
                "claims_json",
                "offer_ttl_seconds",
            ],
        ),
        (
            "IssuanceResponse",
            vec![
                "id",
                "organization_id",
                "credential_template_id",
                "status",
                "credential_offer_uri",
                "credential_offer_uris",
                "credential_offer_labels",
                "pre_auth_code",
                "expires_at",
            ],
        ),
    ] {
        let found: Vec<_> = file.messages.iter().filter(|m| m.name == message).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].fields.len(), fields.len());
        for (index, (field, name)) in found[0].fields.iter().zip(fields).enumerate() {
            assert_eq!(field.name, name);
            assert_eq!(field.number, index as i32 + 1);
            assert_eq!(field.proto3_optional, name == "offer_ttl_seconds");
            assert_eq!(
                field.kind,
                if name == "offer_ttl_seconds" {
                    4 // TYPE_UINT64; existing field types remain unchanged.
                } else if ["claims", "credential_offer_uris", "credential_offer_labels"]
                    .contains(&name)
                {
                    11
                } else {
                    9
                }
            );
        }
    }
}

#[test]
fn managed_prerequisite_fields_are_additive_and_keep_explicit_update_presence() {
    let set = DescriptorSet::decode(DESCRIPTOR).unwrap();
    let file = set
        .files
        .iter()
        .find(|file| file.name == "presentation_policy_service.proto")
        .unwrap();
    for (message, field, number, optional) in [
        (
            "CreatePolicyRequest",
            "prerequisite_evidence_profile",
            10,
            false,
        ),
        ("CreatePolicyRequest", "trust_profile_id", 11, false),
        ("CreatePolicyRequest", "holder_binding_json", 12, false),
        ("CreatePolicyRequest", "freshness_json", 13, false),
        (
            "UpdatePolicyRequest",
            "prerequisite_evidence_profile",
            5,
            true,
        ),
        ("PolicyResponse", "prerequisite_evidence_profile", 14, false),
        (
            "PolicyResponse",
            "credential_authority_snapshot_json",
            15,
            false,
        ),
        (
            "Oid4vpEvaluationTransport",
            "credential_authority_snapshot_json",
            8,
            false,
        ),
    ] {
        let definition = file
            .messages
            .iter()
            .find(|value| value.name == message)
            .unwrap();
        let field = definition
            .fields
            .iter()
            .find(|value| value.name == field)
            .unwrap();
        assert_eq!(field.number, number);
        assert_eq!(field.kind, 9);
        assert_eq!(field.proto3_optional, optional);
    }
}
