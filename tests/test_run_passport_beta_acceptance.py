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
from scripts.probe_passport_beta_physical_flow import PhysicalFlowProbeError
from scripts.run_passport_beta_acceptance import run
from scripts.probe_passport_beta_flow import PHYSICAL_STEPS
from tests.test_probe_passport_beta_chain import plan as certificate_plan


def report(*, ready: bool = True) -> dict:
    return {
        "schema": "marty.passport-beta-acceptance/v1", "status": "blocked",
        "release": {"signed_manifest_verified": ready, "source_commit": "a" * 40,
                    "stack_manifest_sha256": "b" * 64},
        "deployment": {"release_version": "1.1.999", "provider_mode": "simulator"},
        "runtime_images": {"gateway": {"image_id": "sha256:" + "b" * 64},
                           "passport-beta-bureau": {"container_id": "c" * 12,
                                                    "oci_reference": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "d" * 64}},
        "probes": {"capabilities_http": {"verified": ready},
                   "sod_signature": {"verified": False, "evidence": None},
                   "nine_route_gateway_flow": {"verified": False, "evidence": None},
                   "physical_booklet_verified": {"verified": False, "evidence": None},
                   "production_isolation": {"verified": False, "evidence": None}},
    }


def accepted_batch() -> dict:
    return {"verified": True, "evidence": {
        "provider_kind": "simulator", "physical_claim": "not_claimed",
        "simulator_marker_verified": True, "callback_receipt_sha256": "e" * 64,
        "native_binding_verified": True, "native_completed_jobs": 2,
        "callback_receipts_sha256": ["e" * 64, "f" * 64],
    }}


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

    def lifecycle(*args: object) -> dict:
        calls.append("lifecycle")
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

    application = {"organization_id": "beta"}
    def batch(*args: object) -> dict:
        calls.append("batch")
        assert args[:2] == (application, "a" * 32)
        return accepted_batch()

    result = run(Path("beta-artifacts"), application, "a" * 32,
                 collector=collect, attestor=lambda *args: True, snapshot=snapshot,
                 drain=drain, lifecycle=lifecycle, routing=routing, flow=flow,
                 batch=batch)
    assert calls == ["collect", "routing", "snapshot", "drain", "flow", "lifecycle", "batch", "snapshot", "drain", "collect", "routing"]
    assert result["status"] == "blocked"
    assert result["probes"]["legacy_drain"]["verified"] is True
    assert result["probes"]["production_continuity_during_probe"]["verified"] is True
    assert result["probes"]["production_isolation"]["verified"] is False
    assert result["probes"]["nine_route_gateway_flow"]["verified"] is False
    assert result["probes"]["sod_signature"]["verified"] is True
    assert result["probes"]["physical_bureau_batch"]["verified"] is True
    assert result["probes"]["signed_bureau_callback"]["verified"] is True
    assert result["physical_claim"] == "not_claimed"
    assert result["probes"]["physical_claim_boundary"]["evidence"]["booklet_verified"] is False
    assert result["probes"]["nine_route_gateway_flow"]["evidence"]["missing"] == ["executed_physical_document_flow"]
    assert result["probes"]["physical_booklet_verified"]["verified"] is False


def test_opt_in_executed_flow_keeps_real_provider_callback_blocked() -> None:
    selected = report()
    selected["release"]["stack_manifest_sha256"] = "b" * 64
    selected["deployment"]["provider_mode"] = "physical"
    plan = {"source_commit": "a" * 40, "stack_manifest_sha256": "b" * 64,
            "organization_id": "org-beta", "flow_definition_id": "flow-physical",
            "physical_document": {"country_code": "USA", "applicant": {"name": "Test"},
                                  "mrz": {"line_1": "P<USA"},
                                  "data_groups": {"DG1": "MQ==", "DG2": "Mg=="}}}
    calls = []

    def physical_flow(flow_plan, release, deployment, session, api_key):
        calls.append("physical")
        assert flow_plan == plan and release == selected["release"]
        assert deployment == selected["deployment"]
        assert session == "operator-session" and api_key == "k" * 32
        return {"verified": True, "evidence": {"signed_provider_callback_verified": False,
                                               "instance_id_sha256": "d" * 64,
                                               "source_commit": "a" * 40,
                                               "stack_manifest_sha256": "b" * 64,
                                               "steps": list(PHYSICAL_STEPS),
                                               "execution_relationship": "separate_job_from_gateway_lifecycle"}}

    result = run(
        Path("beta-artifacts"), {"organization_id": "org-beta"}, "k" * 32,
        collector=lambda *args, **kwargs: selected,
        snapshot=lambda: {"sha256": "c" * 64, "container_counts": {}},
        drain=lambda: {"verified": True, "evidence": {}},
        lifecycle=lambda *args: {"verified": True, "evidence": {"sod_signature_verified": True,
                                                                 "sod_sha256": "f" * 64}},
        routing=lambda *args: {"verified": True, "evidence": {"webhook_owner": "passport-provider-ingress"}},
        flow=lambda owner: {"verified": True, "evidence": {"unsigned_webhook_owner": owner,
                                                           "signature_denial_verified": True}},
        physical_flow_plan=plan, flow_session="operator-session", physical_flow=physical_flow,
        checkout_checker=lambda source: source == "a" * 40 or pytest.fail("source drift"),
    )
    assert calls == ["physical"]
    assert result["status"] == "blocked"
    assert result["probes"]["executed_physical_document_flow"]["verified"] is True
    assert result["probes"]["signed_bureau_callback"]["verified"] is False
    assert result["probes"]["nine_route_gateway_flow"]["verified"] is False
    assert result["probes"]["nine_route_gateway_flow"]["evidence"]["execution_relationship"] == "separate_jobs"
    assert result["probes"]["nine_route_gateway_flow"]["evidence"]["missing"] == [
        "signed_provider_webhook", "unified_job_nine_route_proof",
    ]


def test_invalid_physical_plan_blocks_before_snapshot_or_mutation() -> None:
    with pytest.raises(EvidenceError, match="inputs are incomplete"):
        run(Path("beta-artifacts"), {}, "k" * 32,
            collector=lambda *args, **kwargs: report(),
            snapshot=lambda: pytest.fail("snapshot should not start"),
            drain=lambda: pytest.fail("drain should not start"),
            lifecycle=lambda *args: pytest.fail("lifecycle should not start"),
            physical_flow_plan={}, flow_session=None)


def test_physical_source_checkout_drift_blocks_all_beta_mutation() -> None:
    selected = report()
    selected["release"]["stack_manifest_sha256"] = "b" * 64
    selected["deployment"]["provider_mode"] = "physical"
    plan = {"source_commit": "a" * 40, "stack_manifest_sha256": "b" * 64,
            "organization_id": "org-beta", "flow_definition_id": "flow-physical",
            "physical_document": {"country_code": "USA", "applicant": {"name": "Test"},
                                  "mrz": {"line_1": "P<USA"},
                                  "data_groups": {"DG1": "MQ==", "DG2": "Mg=="}}}

    def drift(source: str) -> None:
        raise PhysicalFlowProbeError("Physical Flow probe source checkout drifted")

    with pytest.raises(PhysicalFlowProbeError, match="checkout drifted"):
        run(Path("beta-artifacts"), {"organization_id": "org-beta"}, "k" * 32,
            collector=lambda *args, **kwargs: selected,
            snapshot=lambda: pytest.fail("production snapshot must not start"),
            drain=lambda: pytest.fail("beta drain must not start"),
            lifecycle=lambda *args: pytest.fail("lifecycle must not start"),
            physical_flow=lambda *args: pytest.fail("Flow must not start"),
            physical_flow_plan=plan, flow_session="operator-session", checkout_checker=drift)


@pytest.mark.parametrize("mutate", [
    lambda p: p["physical_document"]["data_groups"].pop("DG2"),
    lambda p: p["physical_document"]["data_groups"].update(DG2="***"),
    lambda p: p["physical_document"].update(country_code="US"),
    lambda p: p["physical_document"].update(document_type="TD4"),
    lambda p: p["physical_document"].update(mrz={"line_1": 12}),
])
def test_invalid_physical_document_blocks_before_direct_lifecycle(mutate) -> None:
    selected = report()
    selected["release"]["stack_manifest_sha256"] = "b" * 64
    selected["deployment"]["provider_mode"] = "physical"
    plan = {"source_commit": "a" * 40, "stack_manifest_sha256": "b" * 64,
            "organization_id": "org-beta", "flow_definition_id": "flow-physical",
            "physical_document": {"country_code": "USA", "applicant": {}, "mrz": {},
                                  "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}}}
    mutate(plan)
    with pytest.raises(PhysicalFlowProbeError):
        run(Path("beta-artifacts"), {"organization_id": "org-beta"}, "k" * 32,
            collector=lambda *args, **kwargs: selected,
            snapshot=lambda: pytest.fail("snapshot must not start"),
            drain=lambda: pytest.fail("drain must not start"),
            lifecycle=lambda *args: pytest.fail("direct lifecycle must not mutate beta"),
            physical_flow=lambda *args: pytest.fail("physical Flow must not start"),
            physical_flow_plan=plan, flow_session="operator-session",
            checkout_checker=lambda source: pytest.fail("invalid plan must stop first"))


def test_physical_plan_tenant_differs_from_direct_lifecycle_before_mutation() -> None:
    selected = report()
    selected["release"]["stack_manifest_sha256"] = "b" * 64
    selected["deployment"]["provider_mode"] = "physical"
    plan = {"source_commit": "a" * 40, "stack_manifest_sha256": "b" * 64,
            "organization_id": "other-org", "flow_definition_id": "flow-physical",
            "physical_document": {"country_code": "USA", "applicant": {}, "mrz": {},
                                  "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}}}
    with pytest.raises(EvidenceError, match="tenant differ"):
        run(Path("beta-artifacts"), {"organization_id": "org-beta"}, "k" * 32,
            collector=lambda *args, **kwargs: selected,
            snapshot=lambda: pytest.fail("snapshot must not start"),
            drain=lambda: pytest.fail("drain must not start"),
            lifecycle=lambda *args: pytest.fail("direct lifecycle must not mutate beta"),
            physical_flow_plan=plan, flow_session="operator-session",
            checkout_checker=lambda source: pytest.fail("tenant mismatch must stop first"))


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


def test_governed_chain_runs_with_complete_inputs_and_stays_blocked() -> None:
    calls = []

    def collect(*args: object, **kwargs: object) -> dict:
        calls.append("collect")
        result = report()
        result["probes"]["managed_csca_dsc_chain"] = {"verified": False, "evidence": None}
        return result

    def chain(plan: dict, csca: str, dsc: str) -> dict:
        calls.append("chain")
        assert (plan, csca, dsc) == (certificate_plan(), "csca-session", "dsc-session")
        return {"verified": True, "evidence": {"csca_certificate_sha256": "b" * 64}}

    result = run(
        Path("beta-artifacts"), {"organization_id": "org-a", "issuer_did": certificate_plan()["dsc"]["dsc_issuer_did"]}, "a" * 32,
        collector=collect, snapshot=lambda: {"sha256": "c" * 64, "container_counts": {}},
        drain=lambda: {"verified": True, "evidence": {"in_flight_jobs": 0}},
        lifecycle=lambda *args: {"verified": True, "evidence": {"routes": [],
                                                                 "sod_signature_verified": True,
                                                                 "sod_sha256": "f" * 64}},
        routing=lambda *args: {"verified": True, "evidence": {"native_selectors": True,
                                                               "webhook_owner": "issuance-native"}},
        flow=lambda owner: {"verified": True, "evidence": {"unsigned_webhook_http_status": 422,
                                                           "unsigned_webhook_owner": owner,
                                                           "signature_denial_verified": True}},
        batch=lambda *args: accepted_batch(),
        certificate_plan=certificate_plan(), csca_session="csca-session",
        dsc_session="dsc-session", chain=chain,
    )
    assert calls == ["collect", "chain", "collect"]
    assert result["probes"]["managed_csca_dsc_chain"]["verified"] is True
    assert result["probes"]["sod_signature"]["verified"] is True
    assert result["status"] == "blocked"


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
    assert environment["PASSPORT_ACCEPTANCE_PHYSICAL_FLOW_PLAN_JSON"] == "${{ secrets.PASSPORT_ACCEPTANCE_PHYSICAL_FLOW_PLAN_JSON }}"
    assert environment["PASSPORT_ACCEPTANCE_FLOW_OPERATOR_COOKIE"] == "${{ secrets.PASSPORT_ACCEPTANCE_FLOW_OPERATOR_COOKIE }}"
    assert 'certificate_args+=(--certificate-plan-file "$certificate_plan_file")' in probe["run"]
    assert "--certificate-plan-file" in probe["run"]
    assert 'flow_args+=(--physical-flow-plan-file "$physical_flow_plan_file")' in probe["run"]
    assert 'chmod 600 "$physical_flow_plan_file"' in probe["run"]
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
