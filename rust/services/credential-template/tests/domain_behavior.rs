use std::path::PathBuf;

use marty_credential_template::{
    normalize_payload_format, render_wallet_open_uri, validate_protocol_requirements,
    validate_wallet_inner_uri, CredentialFormat, DeliveryDestinationPolicy, IssuanceProtocol,
    RuntimeEnvironment,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    formats: Vec<FormatCase>,
    invalid_formats: Vec<String>,
    payload_defaults: Vec<PayloadDefaultCase>,
    payload_aliases: Vec<PayloadAliasCase>,
    issuance_protocols: Vec<IssuanceProtocolCase>,
    protocol_requirements: Vec<ProtocolRequirementCase>,
    inner_uris: Vec<InnerUriCase>,
    wallet_links: Vec<WalletLinkCase>,
    delivery_destinations: Vec<DeliveryDestinationCase>,
}

#[derive(Deserialize)]
struct FormatCase {
    input: String,
    canonical: String,
    public_wire: String,
    signing_wire: String,
}

#[derive(Deserialize)]
struct PayloadDefaultCase {
    supported: Vec<String>,
    canonical: String,
}

#[derive(Deserialize)]
struct PayloadAliasCase {
    input: String,
    canonical: String,
}

#[derive(Deserialize)]
struct IssuanceProtocolCase {
    input: String,
    wire: String,
}

#[derive(Deserialize)]
struct ProtocolRequirementCase {
    name: String,
    format: String,
    compliance_profile_id: Option<String>,
    vct: Option<String>,
    doctype: Option<String>,
    accepted: bool,
}

#[derive(Deserialize)]
struct InnerUriCase {
    environment: RuntimeEnvironment,
    uri: String,
    accepted: bool,
}

#[derive(Deserialize)]
struct WalletLinkCase {
    template: String,
    inner_uri: String,
    wallet_id: String,
    platform: Option<String>,
    expected: String,
}

#[derive(Deserialize)]
struct DeliveryDestinationCase {
    name: String,
    policy: DeliveryDestinationPolicy,
    accepted: bool,
}

fn contract() -> Contract {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/credential-template-domain-behavior.json");
    serde_json::from_slice(&std::fs::read(path).expect("credential-template contract"))
        .expect("valid credential-template contract")
}

#[test]
fn credential_format_and_protocol_aliases_are_canonical() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    for case in contract.formats {
        let format = CredentialFormat::parse(&case.input).unwrap_or_else(|error| {
            panic!("{}: {error}", case.input);
        });
        assert_eq!(format.canonical(), case.canonical, "{}", case.input);
        assert_eq!(format.public_wire(), case.public_wire, "{}", case.input);
        assert_eq!(format.signing_wire(), case.signing_wire, "{}", case.input);
    }
    for value in contract.invalid_formats {
        assert!(CredentialFormat::parse(&value).is_err(), "{value}");
    }
    for case in contract.payload_defaults {
        let supported = case
            .supported
            .iter()
            .map(|value| CredentialFormat::parse(value).expect("fixture format"))
            .collect::<Vec<_>>();
        assert_eq!(
            normalize_payload_format(None, &supported)
                .expect("payload default")
                .canonical(),
            case.canonical
        );
    }
    for case in contract.payload_aliases {
        assert_eq!(
            normalize_payload_format(Some(&case.input), &[])
                .expect("payload alias")
                .canonical(),
            case.canonical
        );
    }
    for case in contract.issuance_protocols {
        assert_eq!(
            IssuanceProtocol::parse(Some(&case.input))
                .expect("protocol alias")
                .wire(),
            case.wire
        );
    }
}

#[test]
fn protocol_requirements_fail_closed() {
    for case in contract().protocol_requirements {
        let format = CredentialFormat::parse(&case.format).expect("fixture format");
        let result = validate_protocol_requirements(
            case.compliance_profile_id.as_deref(),
            format,
            case.vct.as_deref(),
            case.doctype.as_deref(),
        );
        assert_eq!(result.is_ok(), case.accepted, "{}: {result:?}", case.name);
    }
}

#[test]
fn wallet_inner_uris_and_routing_preserve_behavior() {
    let contract = contract();
    for case in contract.inner_uris {
        let result = validate_wallet_inner_uri(&case.uri, case.environment);
        assert_eq!(result.is_ok(), case.accepted, "{}: {result:?}", case.uri);
    }
    for case in contract.wallet_links {
        assert_eq!(
            render_wallet_open_uri(
                &case.template,
                &case.inner_uri,
                &case.wallet_id,
                case.platform.as_deref(),
            )
            .expect("wallet routing"),
            case.expected
        );
    }
}

#[test]
fn delivery_destination_policy_is_tenant_safe() {
    for case in contract().delivery_destinations {
        let result = case.policy.validate();
        assert_eq!(result.is_ok(), case.accepted, "{}: {result:?}", case.name);
    }
}
