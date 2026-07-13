"""MIP 0.3 flow capability contract tests."""

from flow.main import _flow_capabilities


def test_flow_capabilities_advertise_mip_v03_fixed_sequences() -> None:
    capabilities = _flow_capabilities()

    assert capabilities["protocol_version"] == "0.3.1"
    assert capabilities["sequences"]["oid4vci_pre_authorized"]
    assert capabilities["sequences"]["oid4vp_presentation"]
    assert capabilities["required_references"]["oid4vp_presentation"]
