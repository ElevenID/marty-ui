include!("../../../../services/issuance/tests/support/didcomm_gateway_replay.rs");

#[test]
fn native_selection_is_unchanged_and_legacy_control_changes_only_direct_owner() {
    let contract = GatewayContract::load().unwrap();
    for candidate in [true, false] {
        select_direct(contract.runtime_route_table().unwrap(), candidate);
        select_direct(contract.proxy_route_table().unwrap(), candidate);
    }
}

#[test]
fn initiation_native_selection_is_unchanged_and_legacy_control_changes_only_rewritten_post_owner() {
    let contract = GatewayContract::load().unwrap();
    for candidate in [true, false] {
        select_consumer(
            contract.runtime_route_table().unwrap(),
            candidate,
            Consumer::Initiation,
        );
        select_consumer(
            contract.proxy_route_table().unwrap(),
            candidate,
            Consumer::Initiation,
        );
    }
}
