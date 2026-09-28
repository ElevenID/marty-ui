"""The full workflow records progress but cannot upgrade partial beta proof."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys

import pytest
import yaml

from scripts.collect_passport_beta_acceptance import EvidenceError
from scripts.probe_passport_beta_chain import ChainProbeError
from scripts.run_passport_beta_acceptance import run
from tests.test_probe_passport_beta_chain import plan as certificate_plan


def report(*, ready: bool = True) -> dict:
    return {
        "schema": "marty.passport-beta-acceptance/v1", "status": "blocked",
        "release": {"signed_manifest_verified": ready, "source_commit": "a" * 40},
        "deployment": {"release_version": "1.1.999", "provider_mode": "simulator"},
        "physical_claim": "not_claimed",
        "runtime_images": {"gateway": {"image_id": "sha256:" + "b" * 64}},
        "probes": {"capabilities_http": {"verified": ready},
                   "sod_signature": {"verified": False, "evidence": None},
                   "nine_route_gateway_flow": {"verified": False, "evidence": None},
                   "physical_claim_boundary": {"verified": True, "evidence": {
                       "physical_claim": "not_claimed", "booklet_verified": False}},
                   "production_isolation": {"verified": False, "evidence": None}},
    }


def test_keeps_partial_acceptance_blocked_after_actual_probe_functions() -> None:
    calls = []

    def collect(*args: object, **kwargs: object) -> dict:
        calls.append("collect")
        return report()

    def snapshot() -> dict:
        calls.append("snapshot")
        return {"sha256": "c" * 64, "container_counts": {"marty-selfhost-prod": 24}}

    def drain() -> dict:
        calls.append("drain")
        return {"verified": True, "evidence": {"in_flight_jobs": 0, "legacy_or_unknown_artifacts": 0}}

    def lifecycle(*args: object, on_submission) -> dict:
        calls.append("lifecycle")
        on_submission("org-a", "source-job", "bureau-job", "f" * 64)
        return {"verified": True, "evidence": {"routes": [], "sod_signature_verified": True,
                                                "sod_sha256": "f" * 64}}

    def routing(*args: object) -> dict:
        calls.append("routing")
        return {"verified": True, "evidence": {"native_selectors": True,
                                               "webhook_owner": "issuance-native"}}

    def flow(owner: str) -> dict:
        calls.append("flow")
        assert owner == "issuance-native"
        return {"verified": True, "evidence": {"unsigned_webhook_http_status": 422,
                                               "unsigned_webhook_owner": owner,
                                               "signature_denial_verified": True}}

    def chain(*args: object, on_dsc_material) -> dict:
        calls.append("chain")
        on_dsc_material("b" * 64, "c" * 64)
        return {"verified": True, "evidence": {"dsc_certificate_sha256": "b" * 64}}

    receipt_arguments = []

    def material_receipt(*args: object) -> dict:
        receipt_arguments.append(args)
        return {"verified": True, "evidence": {"tenant_and_job_binding": True}}

    plan = certificate_plan()
    result = run(Path("beta-artifacts"), {"organization_id": plan["organization_id"],
                                              "issuer_did": plan["dsc"]["dsc_issuer_did"]}, "a" * 32,
                 collector=collect, attestor=lambda *args: True, snapshot=snapshot,
                 drain=drain, lifecycle=lifecycle, routing=routing, flow=flow,
                 certificate_plan=plan, csca_session="csca-session",
                 dsc_session="dsc-session", chain=chain,
                 material_receipt=material_receipt)
    assert calls == ["collect", "routing", "snapshot", "drain", "chain", "flow", "lifecycle", "snapshot", "drain", "collect", "routing"]
    assert result["status"] == "blocked"
    assert result["probes"]["legacy_drain"]["verified"] is True
    assert result["probes"]["production_continuity_during_probe"]["verified"] is True
    assert result["probes"]["production_isolation"]["verified"] is False
    assert result["probes"]["nine_route_gateway_flow"]["verified"] is False
    assert result["probes"]["sod_signature"]["verified"] is True
    assert result["probes"]["simulator_material_receipt"]["verified"] is True
    assert receipt_arguments == [("org-a", "source-job", "bureau-job", "f" * 64,
                                  "b" * 64, "c" * 64, b"a" * 32)]
    assert "source-job" not in str(result) and "bureau-job" not in str(result)
    assert result["probes"]["nine_route_gateway_flow"]["evidence"]["missing"] == [
        "signed_simulator_webhook", "executed_simulator_flow",
    ]
    assert result["probes"]["physical_claim_boundary"]["verified"] is True
    assert result["physical_claim"] == "not_claimed"


def test_missing_governed_chain_inputs_block_before_beta_mutation() -> None:
    with pytest.raises(EvidenceError, match="ceremony inputs are incomplete"):
        run(
            Path("beta-artifacts"), {"organization_id": "org-a"}, "a" * 32,
            collector=lambda *args, **kwargs: report(),
            snapshot=lambda: pytest.fail("Production snapshot must wait for chain inputs"),
            drain=lambda: pytest.fail("Beta drain must wait for chain inputs"),
            flow=lambda *args: pytest.fail("Flow probe must wait for chain inputs"),
            lifecycle=lambda *args: pytest.fail("Passport lifecycle must wait for chain inputs"),
        )


def test_does_not_mutate_beta_before_signed_release_and_managed_capability() -> None:
    calls = []

    def collect(*args: object, **kwargs: object) -> dict:
        calls.append("collect")
        return report(ready=False)

    with pytest.raises(EvidenceError):
        run(Path("beta-artifacts"), {}, "a" * 32, collector=collect,
            snapshot=lambda: calls.append("snapshot"),
            drain=lambda: calls.append("drain"),
            lifecycle=lambda *args: calls.append("lifecycle"))
    assert calls == ["collect"]


@pytest.mark.parametrize("mutation", ["physical_provider", "mixed_ingress", "physical_claim"])
def test_simulator_boundary_fails_before_beta_mutation(mutation: str) -> None:
    collected = report()
    if mutation == "physical_provider":
        collected["deployment"]["provider_mode"] = "physical"
    elif mutation == "mixed_ingress":
        collected["provider_ingress_runtime_image"] = {"image_id": "sha256:" + "b" * 64}
    else:
        collected["physical_claim"] = "verified"
    with pytest.raises(EvidenceError):
        run(
            Path("beta-artifacts"), {}, "a" * 32,
            collector=lambda *args, **kwargs: collected,
            snapshot=lambda: pytest.fail("production snapshot should not start"),
            drain=lambda: pytest.fail("beta drain should not start"),
            lifecycle=lambda *args: pytest.fail("application lifecycle should not start"),
        )


def test_governed_chain_runs_with_complete_inputs_and_stays_blocked() -> None:
    calls = []

    def collect(*args: object, **kwargs: object) -> dict:
        calls.append("collect")
        result = report()
        result["probes"]["managed_csca_dsc_chain"] = {"verified": False, "evidence": None}
        return result

    def chain(plan: dict, csca: str, dsc: str, *, on_dsc_material) -> dict:
        calls.append("chain")
        assert (plan, csca, dsc) == (certificate_plan(), "csca-session", "dsc-session")
        on_dsc_material("b" * 64, "c" * 64)
        return {"verified": True, "evidence": {"csca_certificate_sha256": "b" * 64,
                                               "dsc_certificate_sha256": "b" * 64}}

    def lifecycle(*args: object, on_submission) -> dict:
        calls.append("lifecycle")
        assert "chain" in calls
        on_submission("org-a", "source-job", "bureau-job", "f" * 64)
        return {"verified": True, "evidence": {"routes": [],
                                                "sod_signature_verified": True,
                                                "sod_sha256": "f" * 64}}

    result = run(
        Path("beta-artifacts"), {"organization_id": "org-a", "issuer_did": certificate_plan()["dsc"]["dsc_issuer_did"]}, "a" * 32,
        collector=collect, snapshot=lambda: {"sha256": "c" * 64, "container_counts": {}},
        drain=lambda: {"verified": True, "evidence": {"in_flight_jobs": 0}},
        lifecycle=lifecycle,
        routing=lambda *args: {"verified": True, "evidence": {"native_selectors": True,
                                                               "webhook_owner": "issuance-native"}},
        flow=lambda owner: {"verified": True, "evidence": {"unsigned_webhook_http_status": 422,
                                                           "unsigned_webhook_owner": owner,
                                                           "signature_denial_verified": True}},
        certificate_plan=certificate_plan(), csca_session="csca-session",
        dsc_session="dsc-session", chain=chain,
        material_receipt=lambda *args: {"verified": True, "evidence": {"tenant_and_job_binding": True}},
    )
    assert calls == ["collect", "chain", "lifecycle", "collect"]
    assert result["probes"]["managed_csca_dsc_chain"]["verified"] is True
    assert result["probes"]["sod_signature"]["verified"] is True
    assert result["status"] == "blocked"


def test_failed_governed_chain_cannot_create_a_passport_job() -> None:
    with pytest.raises(EvidenceError, match="chain did not verify"):
        run(
            Path("beta-artifacts"),
            {"organization_id": "org-a", "issuer_did": certificate_plan()["dsc"]["dsc_issuer_did"]},
            "a" * 32,
            collector=lambda *args, **kwargs: report(),
            snapshot=lambda: {"sha256": "c" * 64, "container_counts": {}},
            drain=lambda: {"verified": True, "evidence": {"in_flight_jobs": 0}},
            routing=lambda *args: {"verified": True, "evidence": {"webhook_owner": "issuance-native"}},
            chain=lambda *args, **kwargs: {"verified": False, "evidence": None},
            flow=lambda *args: pytest.fail("Flow probe must wait for the selected chain"),
            lifecycle=lambda *args: pytest.fail("Passport lifecycle must wait for the selected chain"),
            certificate_plan=certificate_plan(),
            csca_session="csca-session", dsc_session="dsc-session",
        )


def test_incomplete_governed_chain_inputs_fail_closed_before_ceremony() -> None:
    with pytest.raises(EvidenceError, match="inputs are incomplete"):
        run(
            Path("beta-artifacts"), {}, "a" * 32,
            collector=lambda *args, **kwargs: report(),
            snapshot=lambda: pytest.fail("production snapshot should not start"),
            drain=lambda: {"verified": True, "evidence": {}},
            lifecycle=lambda *args: pytest.fail("application lifecycle should not start"),
            certificate_plan={"organization_id": "beta"},
            chain=lambda *args: pytest.fail("certificate ceremony should not start"),
        )


@pytest.mark.parametrize("field,bad_value", [
    ("validity_days", "30"), ("validity_days", True), ("validity_days", 91),
    ("country", "CA"), ("country", "us"), ("organization", "X" * 65),
    ("common_name", "bad,name"),
])
def test_malformed_dsc_plan_prevents_any_beta_mutation(field: str, bad_value: object) -> None:
    value = certificate_plan()
    value["dsc"][field] = bad_value
    with pytest.raises(ChainProbeError):
        run(
            Path("beta-artifacts"), {}, "a" * 32,
            collector=lambda *args, **kwargs: report(),
            snapshot=lambda: pytest.fail("production snapshot should not start"),
            drain=lambda: pytest.fail("beta drain should not start"),
            lifecycle=lambda *args: pytest.fail("application lifecycle should not start"),
            certificate_plan=value, csca_session="sessionId=csca", dsc_session="sessionId=dsc",
            chain=lambda *args: pytest.fail("certificate ceremony should not start"),
        )


def test_certificate_plan_must_match_application_before_mutation() -> None:
    with pytest.raises(EvidenceError, match="does not match"):
        run(
            Path("beta-artifacts"), {"organization_id": "other", "issuer_did": "did:web:other"}, "a" * 32,
            collector=lambda *args, **kwargs: report(),
            snapshot=lambda: pytest.fail("production snapshot should not start"),
            drain=lambda: pytest.fail("beta drain should not start"),
            lifecycle=lambda *args: pytest.fail("application lifecycle should not start"),
            certificate_plan=certificate_plan(), csca_session="sessionId=csca", dsc_session="sessionId=dsc",
            chain=lambda *args: pytest.fail("certificate ceremony should not start"),
        )


def test_dsc_lifetime_must_fit_csca_before_any_beta_mutation() -> None:
    value = certificate_plan()
    value["csca"]["validity_days"] = value["dsc"]["validity_days"]
    with pytest.raises(ChainProbeError, match="does not fit"):
        run(
            Path("beta-artifacts"), {}, "a" * 32,
            collector=lambda *args, **kwargs: report(),
            snapshot=lambda: pytest.fail("production snapshot should not start"),
            drain=lambda: pytest.fail("beta drain should not start"),
            lifecycle=lambda *args: pytest.fail("application lifecycle should not start"),
            certificate_plan=value, csca_session="sessionId=csca", dsc_session="sessionId=dsc",
            chain=lambda *args: pytest.fail("certificate ceremony should not start"),
        )


def test_workflow_artifact_matches_credentials_retirement_receipt_convention() -> None:
    workflow_path = Path(__file__).resolve().parents[1] / ".github/workflows/passport-beta-acceptance.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["beta-passport-evidence"]["steps"]
    probe = next(step for step in steps if step.get("id") == "probe")
    upload = next(step for step in steps if step.get("name") == "Upload sanitized beta evidence")
    environment = workflow["jobs"]["beta-passport-evidence"]["env"]
    assert 'report_file="$report_dir/passport-beta-acceptance-$GITHUB_RUN_ID.json"' in probe["run"]
    assert 'report.get("status") == "accepted"' in probe["run"]
    assert environment["PASSPORT_ACCEPTANCE_CERTIFICATE_PLAN_JSON"] == "${{ secrets.PASSPORT_ACCEPTANCE_CERTIFICATE_PLAN_JSON }}"
    assert environment["PASSPORT_ACCEPTANCE_CSCA_OPERATOR_COOKIE"] == "${{ secrets.PASSPORT_ACCEPTANCE_CSCA_OPERATOR_COOKIE }}"
    assert environment["PASSPORT_ACCEPTANCE_DSC_OPERATOR_COOKIE"] == "${{ secrets.PASSPORT_ACCEPTANCE_DSC_OPERATOR_COOKIE }}"
    assert 'if [[ -z "${!required}" ]]; then' in probe["run"]
    assert '--certificate-plan-file "$certificate_plan_file"' in probe["run"]
    assert upload["with"]["name"] == "passport-beta-acceptance-${{ github.run_id }}"
    assert upload["with"]["path"] == (
        "tests/artifacts/passport-beta-acceptance/"
        "passport-beta-acceptance-${{ github.run_id }}.json"
    )
    assert upload["if"] == "always() && (steps.probe.outcome == 'success' || steps.probe.outcome == 'failure')"
    prerequisite = yaml.safe_load((workflow_path.parent / "passport-beta-prerequisite.yml").read_text(encoding="utf-8"))
    prerequisite_steps = prerequisite["jobs"]["collect"]["steps"]
    prerequisite_upload = next(step for step in prerequisite_steps if step.get("name") == "Upload sanitized blocked prerequisite report")
    assert prerequisite_upload["if"] == "always() && (steps.collect.outcome == 'success' || steps.collect.outcome == 'failure')"


@pytest.mark.parametrize("workflow_name,expected_status", [
    ("passport-beta-acceptance.yml", "accepted"),
    ("passport-beta-prerequisite.yml", "blocked"),
])
def test_workflow_report_gate_survives_python_optimization(
    tmp_path: Path, workflow_name: str, expected_status: str,
) -> None:
    workflow_path = Path(__file__).resolve().parents[1] / ".github/workflows" / workflow_name
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = next(iter(workflow["jobs"].values()))["steps"]
    probe = next(step for step in steps if step.get("id") in {"probe", "collect"})
    match = re.search(r"python3 -c '([^']+)'", probe["run"])
    assert match is not None
    code = match.group(1)
    assert "assert " not in code
    if workflow_name == "passport-beta-acceptance.yml":
        report_path = tmp_path / "report.json"
        args = [str(report_path)]
    else:
        report_path = tmp_path / "tests/artifacts/passport-beta-prerequisite/report.json"
        report_path.parent.mkdir(parents=True)
        args = []
    for status in ("blocked", "accepted"):
        report_path.write_text(json.dumps({"schema": "marty.passport-beta-acceptance/v1", "status": status}))
        result = subprocess.run([sys.executable, "-O", "-c", code, *args], cwd=tmp_path, capture_output=True, text=True)
        assert (result.returncode == 0) is (status == expected_status)
    report_path.write_text(json.dumps({"schema": "wrong", "status": expected_status}))
    result = subprocess.run([sys.executable, "-O", "-c", code, *args], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode != 0
