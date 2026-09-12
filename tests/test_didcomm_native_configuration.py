"""Native DIDComm Compose ownership guards; no deployment operations."""

from pathlib import Path
from copy import deepcopy
import runpy

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
AUTHCRYPT = "docker-compose.profile.didcomm-native-authcrypt.yml"
CONFORMANCE = "docker-compose.profile.didcomm-native-conformance.yml"


def test_beta_native_inherits_existing_resolver_and_endpoint_policy() -> None:
    base = yaml.safe_load((ROOT / "docker-compose.base.yml").read_text())
    beta = yaml.safe_load((ROOT / "docker-compose.beta.yml").read_text())
    legacy = base["services"]["issuance"]["environment"]
    native = beta["services"]["issuance-native"]["environment"]
    for name in (
        "UNIVERSAL_RESOLVER_URL",
        "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
        "DIDCOMM_ALLOW_PRIVATE_IPS",
    ):
        assert native[name] == legacy[name]
    assert native["DIDCOMM_ALLOW_PRIVATE_IPS"] == "${DIDCOMM_ALLOW_PRIVATE_IPS:-false}"
    assert "DIDCOMM_ENCRYPTION_POLICY_FILE" not in native
    assert "DIDCOMM_TLS_CA_FILE" not in native


def test_native_authcrypt_mount_is_exact_read_only_and_explicit() -> None:
    overlay = yaml.safe_load((ROOT / AUTHCRYPT).read_text())
    assert set(overlay) == {"services"}
    assert set(overlay["services"]) == {"issuance-native"}
    native = overlay["services"]["issuance-native"]
    assert set(native) == {"environment", "volumes"}
    assert native["environment"] == {
        "DIDCOMM_ENCRYPTION_POLICY_FILE": "/run/secrets/didcomm-authcrypt/didcomm-encryption-policy.json"
    }
    assert native["volumes"] == [
        {
            "type": "bind",
            "source": "${DIDCOMM_ENCRYPTION_POLICY_DIR:?set DIDCOMM_ENCRYPTION_POLICY_DIR to an exact policy directory}",
            "target": "/run/secrets/didcomm-authcrypt",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]


def test_native_conformance_trust_and_host_access_are_explicit() -> None:
    overlay = yaml.safe_load((ROOT / CONFORMANCE).read_text())
    assert set(overlay) == {"services"}
    assert set(overlay["services"]) == {"issuance-native"}
    native = overlay["services"]["issuance-native"]
    assert set(native) == {"environment", "volumes", "extra_hosts"}
    assert native["environment"] == {
        "DIDCOMM_TLS_CA_FILE": "/run/secrets/didcomm-conformance-root-ca.pem",
        "DIDCOMM_ALLOW_PRIVATE_IPS": "true",
    }
    assert native["volumes"] == [
        {
            "type": "bind",
            "source": "${OIDF_TLS_CERT_DIR:?set OIDF_TLS_CERT_DIR to generated conformance material}/root-ca.pem",
            "target": "/run/secrets/didcomm-conformance-root-ca.pem",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    assert native["extra_hosts"] == ["host.docker.internal:host-gateway"]


def test_native_profiles_are_not_implicitly_selected_by_release_or_legacy_conformance() -> (
    None
):
    for path in (
        "scripts/conformance_stack.py",
        "docker-compose.base.yml",
        "docker-compose.selfhost.prod.yml",
        "docker-compose.ui-prod.yml",
        "docker-compose.ui-release.yml",
    ):
        source = (ROOT / path).read_text(encoding="utf-8")
        assert AUTHCRYPT not in source
        assert CONFORMANCE not in source
    legacy = yaml.safe_load(
        (ROOT / "docker-compose.profile.didcomm-authcrypt.yml").read_text()
    )
    assert set(legacy["services"]) == {"issuance"}


def test_native_compose_gate_is_required_before_image_builds() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["test-rust-service-images"]
    assert not job.get("continue-on-error", False)
    steps = job["steps"]
    names = [step.get("name", "") for step in steps]
    name = "Verify native DIDComm configuration ownership"
    assert names.count(name) == 1
    index = names.index(name)
    assert steps[index] == {
        "name": name,
        "run": 'python3 scripts/test_didcomm_native_compose.py --compose-command "$RUNNER_TEMP/compose-render-v5.4.0"',
    }
    assert names.index("Verify generated beta application image configuration") < index
    assert index < next(
        i
        for i, step in enumerate(steps)
        if "docker/build-push-action@" in step.get("uses", "")
    )


def test_configured_native_policy_retains_missing_issuer_fail_closed_guard() -> None:
    # Source registration guard only; Rust behavior is qualified by the existing
    # native policy tests, not by this Python assertion.
    source = (ROOT / "rust/services/issuance/src/initiation_didcomm.rs").read_text(
        encoding="utf-8"
    )
    loader = source.split("fn load_active_policy(", 1)[1].split(
        "fn decode_sender_private_key(", 1
    )[0]
    assert "active.ok_or(NativeDidcommError::EncryptionPolicyUnavailable)" in loader
    assert "fn configured_policy_requires_the_active_issuer()" in source


@pytest.mark.parametrize(
    "mutation", ("policy", "source", "writable", "auto-create", "unrelated-service")
)
def test_pairing_and_full_model_guards_reject_configuration_loss(mutation) -> None:
    gate = runpy.run_path(str(ROOT / "scripts/test_didcomm_native_compose.py"))
    previous = {
        "services": {
            "issuance": {
                "environment": {
                    "DIDCOMM_ENCRYPTION_POLICY_FILE": gate["POLICY_TARGET"]
                    + "/didcomm-encryption-policy.json"
                },
                "volumes": [
                    gate["mount"](gate["POLICY_DIRECTORY"], gate["POLICY_TARGET"])
                ],
            },
            "issuance-native": {"environment": {}},
            "gateway": {"environment": {"UNCHANGED": "synthetic"}},
        },
    }
    expected = gate["expected_model"](previous, authcrypt=True, conformance=False)
    gate["assert_native_policy_pairing"](expected)
    actual = deepcopy(expected)
    native = actual["services"]["issuance-native"]
    if mutation == "policy":
        native["environment"].pop("DIDCOMM_ENCRYPTION_POLICY_FILE")
    elif mutation == "source":
        native["volumes"][0]["source"] = "synthetic-wrong-policy-directory"
    elif mutation == "writable":
        native["volumes"][0]["read_only"] = False
    elif mutation == "auto-create":
        native["volumes"][0]["bind"]["create_host_path"] = True
    else:
        actual["services"]["gateway"]["environment"]["UNCHANGED"] = "changed"
    with pytest.raises(AssertionError):
        gate["assert_model"](actual, expected)
    if mutation != "unrelated-service":
        with pytest.raises(gate["DidcommConfigurationError"]):
            gate["assert_native_policy_pairing"](actual)
