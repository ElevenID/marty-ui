use std::collections::BTreeMap;

use marty_flow::{FlowCategory, FlowDefinition, FlowType};

#[test]
fn digital_handoff_has_the_frozen_eight_step_sequence() {
    let flow_type = FlowType::PassportDigitalHandoff;
    assert_eq!(
        serde_json::to_value(flow_type).unwrap(),
        "passport_digital_handoff"
    );
    assert_eq!(flow_type.category(), Some(FlowCategory::Issuance));
    assert_eq!(
        flow_type.required_references(),
        &[
            "credential_template_id",
            "application_template_id",
            "delivery_destination_profile_id",
        ]
    );
    assert_eq!(
        flow_type.sequence(),
        &[
            "accept_application",
            "validate_evidence",
            "approval_decision",
            "generate_data_groups",
            "sign_sod",
            "verify_digital_package",
            "seal_handoff_package",
            "handoff_ready",
        ]
    );

    let references = flow_type
        .required_references()
        .iter()
        .map(|key| ((*key).to_owned(), format!("{key}-1")))
        .collect::<BTreeMap<_, _>>();
    let definition =
        FlowDefinition::built_in("organization-1", "Digital handoff", flow_type, references)
            .unwrap();
    assert_eq!(definition.steps.len(), 8);
    assert_eq!(definition.transitions.len(), 7);
    assert!(definition.validate_graph().is_ok());
}

#[test]
fn mip_05_capabilities_do_not_advertise_the_beta_candidate() {
    assert!(!FlowType::public_05().any(|flow_type| flow_type == FlowType::PassportDigitalHandoff));
}
