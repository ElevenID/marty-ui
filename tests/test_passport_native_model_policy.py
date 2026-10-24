"""Exercise the real native policy and fail-closed Python transport boundary."""
from pathlib import Path
import pytest
import yaml

from scripts import passport_model_policy as policy
from scripts.validate_beta_passport_configuration import contains_credential
from scripts.collect_passport_supported_acceptance import environment_flags, SupportedEvidenceError

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("value,expected", [
    ({"nested": [None, {"synthetic-credential-key": "public"}]}, True),
    ({"nested": [None, "prefix-synthetic-credential-suffix"]}, True),
    ({"nested": [None, 42, False, "public"]}, False),
])
def test_native_scan_retains_nested_key_and_value_detection(value, expected):
    assert contains_credential(value, "synthetic-credential") is expected


@pytest.mark.parametrize("values", [["FLAG=true", "FLAG=false"], ["FLAG=1"], ["FLAG"], []])
def test_native_flags_reject_missing_ambiguous_or_non_boolean(values):
    with pytest.raises(SupportedEvidenceError, match="Missing or ambiguous gateway passport selector"):
        environment_flags(values, "gateway", {"gateway": ("FLAG",)})


def test_native_flags_preserve_false_and_ignore_unrelated_non_strings():
    assert environment_flags([None, "OTHER=1", "FLAG=false"], "gateway", {"gateway": ("FLAG",)}) == {"FLAG": False}


@pytest.mark.parametrize("response", [b"not-json", b"{}", b'{"ok": 1}', b'[]', b'{"ok":true}', b'{"ok":false}'])
def test_unverifiable_native_response_fails_closed(response, monkeypatch):
    monkeypatch.setattr(policy, "operator_bytes", lambda *a, **kw: response)
    with pytest.raises(ValueError, match="could not be verified"):
        policy.evaluate("runtime-flags")


def test_consumer_workflow_prepares_native_policy_before_collecting():
    workflow = yaml.safe_load((ROOT / ".github/workflows/passport-supported-consumer-acceptance.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["collect"]["steps"]
    prepare = next(i for i, step in enumerate(steps) if step.get("name") == "Prepare read-only Rust Passport model policy")
    collect = next(i for i, step in enumerate(steps) if step.get("id") == "collect")
    assert prepare < collect
    command = "bash scripts/ci/prepare-native-model-operator.sh"
    assert steps[prepare]["run"] == command
    helper = (ROOT / "scripts/ci/prepare-native-model-operator.sh").read_text(encoding="utf-8")
    for requirement in ("+1.95.0 build --locked", "marty-deployment-catalog", "--build-identity",
                        "sha256sum", "MARTY_DEPLOY_BIN_SHA256", "MARTY_DEPLOY_SOURCE_SHA", "GITHUB_ENV"):
        assert requirement in helper
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    assert next(step for step in ci["jobs"]["test-release-contracts"]["steps"]
                if step.get("name") == "Prepare Rust KMS operator for release contracts")["run"] == command


def test_native_timeout_remains_a_caller_specific_refusal(monkeypatch):
    import subprocess
    def timeout(*a, **kw):
        raise subprocess.TimeoutExpired("native-policy", 1)
    monkeypatch.setattr(policy, "operator_bytes", timeout)
    with pytest.raises(SupportedEvidenceError, match="could not be verified"):
        policy.evaluate("runtime-flags", error_type=SupportedEvidenceError)


@pytest.mark.parametrize("name,service,expected", [
    ("gateway", {"environment": {"DEDICATED": "synthetic-credential"}}, False),
    ("signing-keys", {"environment": ["DEDICATED=synthetic-credential"]}, False),
    ("auth", {"environment": {"DEDICATED": "synthetic-credential"}}, True),
    ("gateway", {"environment": {"DEDICATED": "synthetic-credential", "OTHER": "synthetic-credential"}}, True),
    ("gateway", {"environment": {"DEDICATED": "synthetic-credential"}, "labels": {"nested": "synthetic-credential"}}, True),
])
def test_native_service_scan_exempts_only_its_owned_environment_binding(name, service, expected):
    from scripts.validate_beta_passport_configuration import service_reuses_credential
    assert service_reuses_credential(name, service, "synthetic-credential", "DEDICATED") is expected
