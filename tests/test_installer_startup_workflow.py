"""The workflow may sign observed startup without promoting incomplete evidence."""
import json
from pathlib import Path
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/installer-acceptance.yml"


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def steps():
    return workflow()["jobs"]["prepare-candidate-grant"]["steps"]


def named(name):
    return next(step for step in steps() if step.get("name") == name)


def python_block(step):
    return step["run"].split("python - <<'PY'\n", 1)[1].split("\nPY", 1)[0]


def test_startup_is_an_explicit_result_and_incomplete_execution_still_fails():
    value = workflow()
    trigger = value.get("on", value.get(True))["workflow_dispatch"]["inputs"]
    assert trigger["execute"]["default"] is False
    result = trigger["execution_result"]
    assert result["required"] is True and result["type"] == "choice"
    assert result["default"] == "incomplete-checkpoint"
    assert result["options"] == ["incomplete-checkpoint", "startup-observation"]
    context = named("Authenticate the original nightly build and current acceptance invocation")
    assert "os.environ['EXECUTION_RESULT'] != 'startup-observation' or os.environ['EXECUTE'] == 'true'" in context["run"]
    refusal = named("Refuse incomplete execution as installed acceptance")
    assert refusal["if"] == "inputs.execute && inputs.execution_result == 'incomplete-checkpoint'"
    assert "exit 1" in refusal["run"]
    assert "continue-on-error" not in value["jobs"]["prepare-candidate-grant"]


def test_startup_validates_actual_payload_before_signing_and_uses_distinct_artifact():
    all_steps = steps()
    receive = named("Receive actual signed-scope startup payload during this invocation")
    sign = named("Sign distinct startup observation only")
    attest = next(step for step in all_steps if step.get("id") == "startup_provenance")
    verify = named("Verify startup signature and exact invocation proof")
    archive = named("Archive startup observation and authenticated transport evidence")
    summary = named("Record startup observation boundary")
    indexes = [all_steps.index(step) for step in (receive, sign, attest, verify, archive, summary)]
    assert indexes == sorted(indexes) and len(set(indexes)) == len(indexes)
    for step in (receive, sign, attest, verify, summary):
        assert step["if"] == "inputs.execute && inputs.execution_result == 'startup-observation'"
        assert not step.get("continue-on-error", False)
    assert "installer_acceptance_return.py receive-startup-payload" in receive["run"]
    for argument in ("--assets", "--gh", "--cosign", "--controller-user-id", "--harness-source-sha", "--run-attempt"):
        assert argument in receive["run"]
    assert "verify-startup-return" not in receive["run"]
    assert "p.verify_subject(subject,proof" in verify["run"]
    assert archive["with"]["name"] == "installer-startup-observation-${{ github.run_id }}-${{ github.run_attempt }}"
    assert "installer-startup-observation.json" in attest["with"]["subject-path"]
    assert "Ready=false" in summary["run"] and "completed successfully" in summary["run"]
    assert not any(step.get("with", {}).get("name", "").startswith("installer-acceptance-") for step in all_steps)


def test_embedded_workflow_python_remains_parseable():
    for step in steps():
        if "python - <<'PY'\n" in step.get("run", ""):
            compile(python_block(step), f"{WORKFLOW}:{step.get('name')}", "exec")


@pytest.mark.parametrize("mode", ["incomplete-checkpoint", "startup-observation"])
@pytest.mark.parametrize("source", ["managed-ca", "production", "staging", "no-alias", "absent"])
def test_real_hosting_input_preflight_requires_public_production_alias_for_startup(tmp_path, monkeypatch, mode, source):
    cases = json.loads((ROOT / "rust/crates/deployment-catalog/tests/fixtures/installer-candidate-hosting-v2.json").read_text())
    selected = next(case for case in cases if
        json.loads(case["hosting_input"])["tls"]["certificate_source"] == ("managed-ca" if source == "managed-ca" else "acme")
        and (source == "managed-ca" or json.loads(case["hosting_input"])["tls"]["acme"]["environment"] == ("staging" if source == "staging" else "production")))
    raw = selected["hosting_input"]
    if source == "no-alias":
        value = json.loads(raw)
        value.pop("public_entry_origin", None)
        raw = json.dumps(value)
    if source == "absent":
        raw = ""
    output = tmp_path / "installer-staged-grant" / "grant"
    output.mkdir(parents=True, mode=0o700)
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("HOSTING_INPUT", raw)
    monkeypatch.setenv("ACME_STAGING_ROOTS", selected["staging_roots"] if source == "staging" else "")
    monkeypatch.setenv("EXECUTION_RESULT", mode)
    block = python_block(named("Verify exact candidate payloads and issue an unsigned short-lived authorization"))
    admitted = mode == "incomplete-checkpoint" or source == "production"
    if admitted:
        exec(compile(block, str(WORKFLOW), "exec"), {"__name__": "workflow_test"})
        assert (output / "hosting-input.json").exists() == bool(raw)
    else:
        with pytest.raises(ValueError):
            exec(compile(block, str(WORKFLOW), "exec"), {"__name__": "workflow_test"})
        assert not any(output.iterdir())
