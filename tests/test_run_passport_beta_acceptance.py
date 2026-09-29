"""The full workflow records progress but cannot upgrade partial beta proof."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.collect_passport_beta_acceptance import EvidenceError
from scripts.probe_passport_beta_chain import ChainProbeError
from scripts.probe_passport_beta_batch import _identity_commit
from scripts.probe_passport_beta_flow import PHYSICAL_STEPS
from scripts.probe_passport_beta_native_batch import NativeBatchProbeError
from scripts.run_passport_beta_acceptance import run
from tests.test_probe_passport_beta_chain import plan as certificate_plan


def report(*, ready: bool = True) -> dict:
    return {
        "schema": "marty.passport-beta-acceptance/v1", "status": "blocked",
        "release": {"signed_manifest_verified": ready, "source_commit": "a" * 40,
                    "stack_manifest_sha256": "d" * 64},
        "deployment": {"release_version": "1.1.999", "provider_mode": "simulator"},
        "physical_claim": "not_claimed",
        "runtime_images": {"gateway": {"image_id": "sha256:" + "b" * 64},
                           "issuance-native": {"container_id": "b" * 64},
                           "passport-beta-bureau": {"container_id": "a" * 64,
                               "oci_reference": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "e" * 64}},
        "probes": {"capabilities_http": {"verified": ready},
                   "sod_signature": {"verified": False, "evidence": None},
                   "nine_route_gateway_flow": {"verified": False, "evidence": None},
                   "physical_claim_boundary": {"verified": True, "evidence": {
                       "physical_claim": "not_claimed", "booklet_verified": False}},
                   "production_isolation": {"verified": False, "evidence": None}},
    }


def accepted_batch() -> dict:
    return {"verified": True, "evidence": {
        "provider_kind": "simulator", "physical_claim": "not_claimed",
        "simulator_marker_verified": True, "native_binding_verified": True,
        "native_completed_jobs": 2, "source_commit": "a" * 40,
        "stack_manifest_sha256": "d" * 64,
        "services_oci_reference": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "e" * 64,
        "commitment_scheme": "HMAC-SHA256", "http_status": 202,
        "batch_status": "QUEUED", "request_commitment": "1" * 64,
        "response_commitment": "2" * 64,
        "submitted_job_commitments": ["3" * 64, "4" * 64],
        "returned_jobs": [
            {"source_job_commitment": "3" * 64, "bureau_job_commitment": "5" * 64,
             "status": "SHIPPED"},
            {"source_job_commitment": "4" * 64, "bureau_job_commitment": "6" * 64,
             "status": "SHIPPED"},
        ],
        "callback_receipt_sha256": "7" * 64,
        "callback_receipts_sha256": ["7" * 64, "8" * 64],
    }}


def selected_plan() -> dict:
    selected = certificate_plan()
    return {
        "source_commit": "a" * 40, "stack_manifest_sha256": "d" * 64,
        "organization_id": selected["organization_id"],
        "issuer_did": selected["dsc"]["dsc_issuer_did"],
        "flow_definition_id": "governed-flow",
        "references": {"application_template_id": "app-template",
                       "credential_template_id": "credential-template",
                       "delivery_destination_profile_id": "destination-profile"},
        "physical_document": {"country_code": "USA", "applicant": {"name": "Synthetic"},
                              "mrz": {"line_1": "synthetic"},
                              "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}},
    }


def managed_application(plan: dict | None = None) -> dict:
    selected = certificate_plan() if plan is None else plan
    return {
        "organization_id": selected["organization_id"],
        "issuer_did": selected["dsc"]["dsc_issuer_did"],
        "application_template_id": "app-template",
        "credential_template_id": "credential-template",
        "delivery_destination_profile_id": "destination-profile",
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
        return {"verified": True, "evidence": {
            "dsc_certificate_sha256": "b" * 64,
            "csca_certificate_id": "private-csca-id",
            "dsc_issuer_did_sha256": "e" * 64}}

    receipt_arguments = []

    def material_receipt(*args: object) -> dict:
        receipt_arguments.append(args)
        return {"verified": True, "evidence": {"tenant_and_job_binding": True}}

    def batch(*args: object) -> dict:
        calls.append("batch")
        return accepted_batch()

    plan = certificate_plan()
    result = run(Path("beta-artifacts"), managed_application(plan), "a" * 32,
                 collector=collect, attestor=lambda *args: True, snapshot=snapshot,
                 drain=drain, lifecycle=lifecycle, routing=routing, flow=flow,
                 certificate_plan=plan, csca_session="csca-session",
                 dsc_session="dsc-session", chain=chain,
                 material_receipt=material_receipt, batch=batch)
    assert calls == ["collect", "routing", "snapshot", "drain", "chain", "flow", "lifecycle", "batch", "snapshot", "drain", "collect", "routing"]
    assert result["status"] == "blocked"
    assert result["probes"]["legacy_drain"]["verified"] is True
    assert result["probes"]["production_continuity_during_probe"]["verified"] is True
    assert result["probes"]["production_isolation"]["verified"] is False
    assert result["probes"]["nine_route_gateway_flow"]["verified"] is False
    assert result["probes"]["simulator_batch_diagnostic"] == accepted_batch()
    assert result["probes"]["physical_bureau_batch"]["verified"] is False
    assert result["probes"]["physical_bureau_submission"]["verified"] is False
    assert result["probes"]["signed_bureau_callback"]["verified"] is False
    assert result["probes"]["sod_signature"]["verified"] is True
    assert result["probes"]["simulator_material_receipt"]["verified"] is True
    assert receipt_arguments == [("org-a", "source-job", "bureau-job", "f" * 64,
                                  "b" * 64, "c" * 64, b"a" * 32)]
    assert "source-job" not in str(result) and "bureau-job" not in str(result)
    assert result["probes"]["nine_route_gateway_flow"]["evidence"]["missing"] == [
        "executed_simulator_flow", "selected_flow_in_two_job_batch",
    ]
    assert result["probes"]["physical_claim_boundary"]["verified"] is True
    assert result["physical_claim"] == "not_claimed"


def test_protected_runner_executes_selected_flow_after_chain_and_direct_job(tmp_path: Path) -> None:
    calls = []
    private_state_path = tmp_path / "private" / "pending.json"
    private_handoff_path = tmp_path / "private" / "demo-selected.json"
    selected_bureau = "76a7baef-368a-4722-95a4-df70ea1dfefa"
    selected_source_commitment = _identity_commit("a" * 32, "source-job", "selected-job")
    selected_bureau_commitment = _identity_commit("a" * 32, "bureau-job", selected_bureau)
    direct_source_commitment = _identity_commit("a" * 32, "source-job", "direct-job")
    plan = certificate_plan()
    application = managed_application(plan)
    selected_plan = {"source_commit": "a" * 40, "stack_manifest_sha256": "d" * 64,
                     "organization_id": application["organization_id"],
                     "issuer_did": application["issuer_did"],
                     "flow_definition_id": "governed-flow",
                     "references": {"application_template_id": "app-template",
                                    "credential_template_id": "credential-template",
                                    "delivery_destination_profile_id": "destination-profile"},
                     "physical_document": {"country_code": "USA", "applicant": {"name": "Synthetic"},
                                           "mrz": {"line_1": "synthetic"},
                                           "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}}}

    def chain(*args, on_dsc_material):
        calls.append("chain")
        on_dsc_material("b" * 64, "c" * 64)
        return {"verified": True, "evidence": {"dsc_certificate_sha256": "b" * 64}}

    def lifecycle(*args, on_submission):
        calls.append("lifecycle")
        on_submission(plan["organization_id"], "direct-job", "direct-bureau", "f" * 64)
        base = "/v1/passport/applications/{application_id}"
        routes = [
            {"method": method, "route": route, "http_status": status,
             "job_status": job_status}
            for method, route, status, job_status in [
                ("POST", "/v1/passport/applications", 201, "DRAFT"),
                ("POST", base + "/generate-data-groups", 200, "DATA_GENERATED"),
                ("POST", base + "/generate-sod", 200, "SOD_SIGNED"),
                ("POST", base + "/submit-personalization", 200, "SUBMITTED"),
                ("GET", base + "/production-status", 200, "QUALITY_CHECK"),
                ("POST", base + "/quality-verify", 200, "READY_FOR_ACTIVATION"),
                ("POST", base + "/activate", 200, "ACTIVE"),
            ]]
        return {"verified": True, "evidence": {"sod_signature_verified": True,
                                                "sod_sha256": "f" * 64,
                                                "routes": routes,
                                                "application_input_sha256": "7" * 64,
                                                "job_id_sha256": "8" * 64,
                                                "application_id_sha256": "9" * 64,
                                                "bureau_job_id_sha256": "a" * 64}}

    def receipt(org, source, bureau, sod, dsc_der, dsc_pem, key):
        calls.append(("receipt", source))
        assert (org, dsc_der, dsc_pem, key) == (plan["organization_id"], "b" * 64,
                                               "c" * 64, b"a" * 32)
        return {"verified": True, "evidence": {
            "source_job_id_commitment": _identity_commit("a" * 32, "source-job", source),
            "bureau_job_id_commitment": _identity_commit("a" * 32, "bureau-job", bureau)}}

    def native_batch(*args):
        calls.append("native-batch")
        assert args[3:7] == ("s" * 32, "z" * 32, "b" * 64, "a" * 64)
        assert args[7:12] == ("selected-instance", "selected-app", "selected-job",
                              "e" * 64, "managed-profile")
        assert args[-1] == private_state_path
        private_state_path.write_text("pending", encoding="utf-8")
        return selected_bureau, {"verified": True, "evidence": {
            "provider_kind": "simulator", "physical_claim": "not_claimed",
            "http_status": 202, "batch_status": "QUEUED",
            "selected_flow_in_two_job_batch": True, "native_binding_verified": True,
            "first_accepted_material_verified": True, "companion_native_completed": True,
            "selected_source_job_commitment": selected_source_commitment,
            "selected_bureau_job_commitment": selected_bureau_commitment,
            "companion_source_job_commitment": "6" * 64,
            "companion_bureau_job_commitment": "7" * 64,
            "submitted_job_commitments": [selected_source_commitment, "6" * 64],
            "returned_jobs": [
                {"source_job_commitment": selected_source_commitment,
                 "bureau_job_commitment": selected_bureau_commitment},
                {"source_job_commitment": "6" * 64, "bureau_job_commitment": "7" * 64}],
            "request_commitment": "8" * 64, "response_commitment": "9" * 64,
            "companion_callback_receipt_sha256": "a" * 64,
        }}

    def selected(*args, simulator_container_id, on_submission, on_signed_sod):
        calls.append("selected")
        assert simulator_container_id == "a" * 64
        assert args == ("governed-flow", plan["organization_id"], application["issuer_did"],
                        selected_plan["references"], selected_plan["physical_document"],
                        "governed-cookie", "a" * 32)
        assert on_signed_sod("selected-instance", "selected-app", "selected-job",
                             "e" * 64, "managed-profile") == selected_bureau
        on_submission(plan["organization_id"], "selected-job", selected_bureau, "e" * 64)
        return {"verified": True, "evidence": {"flow_instance_id": "selected-instance",
                                                "flow_id": "governed-flow",
                                                "organization_id": plan["organization_id"],
                                                "application_id": "selected-app",
                                                "job_id": "selected-job", "sod_sha256": "e" * 64,
                                                "bureau_job_id": selected_bureau,
                                                "ordered_steps": list(PHYSICAL_STEPS),
                                                "completed_steps": 9, "physical_claim": "not_claimed",
                                                "source_job_commitment": selected_source_commitment,
                                                "bureau_job_commitment": selected_bureau_commitment,
                                                "callback_receipt_sha256": "5" * 64,
                                                "signed_simulator_callback_verified": True,
                                                "terminal_native_status": "ACTIVE"}}

    result = run(
        Path("beta-artifacts"), application, "a" * 32,
        collector=lambda *args, **kwargs: report(),
        snapshot=lambda: {"sha256": "c" * 64, "container_counts": {}},
        drain=lambda: {"verified": True, "evidence": {"in_flight_jobs": 0}},
        routing=lambda *args: {"verified": True, "evidence": {"webhook_owner": "issuance-native"}},
        flow=lambda owner: {"verified": True, "evidence": {
            "unsigned_webhook_owner": owner, "signature_denial_verified": True}},
        chain=chain, lifecycle=lifecycle, material_receipt=receipt,
        certificate_plan=plan, csca_session="csca-session", dsc_session="dsc-session",
        selected_flow_plan=selected_plan, flow_operator_cookie="governed-cookie",
        selected_flow=selected, native_batch=native_batch,
        native_preflight=lambda *args: calls.append("preflight"),
        native_service_token="s" * 32, native_operator_token="z" * 32,
        private_state_path=private_state_path,
        private_handoff_path=private_handoff_path,
        batch=lambda *args: pytest.fail("Synthetic batch must remain diagnostic"),
        checkout_checker=lambda source: calls.append("checkout"),
    )
    assert calls == ["checkout", "preflight", "chain", "lifecycle", ("receipt", "direct-job"),
                     "selected", "native-batch", ("receipt", "selected-job")]
    assert result["probes"]["selected_physical_flow"]["evidence"] == {
        "sod_sha256": "e" * 64, "ordered_steps": list(PHYSICAL_STEPS),
        "completed_steps": 9, "source_job_commitment": selected_source_commitment,
        "bureau_job_commitment": selected_bureau_commitment,
        "organization_commitment": _identity_commit("a" * 32, "organization", plan["organization_id"]),
        "flow_definition_commitment": _identity_commit("a" * 32, "flow-definition", "governed-flow"),
        "flow_instance_commitment": _identity_commit("a" * 32, "flow-instance", "selected-instance"),
        "application_commitment": _identity_commit("a" * 32, "application", "selected-app"),
        "callback_receipt_sha256": "5" * 64,
        "terminal_native_status": "ACTIVE", "physical_claim": "not_claimed"}
    assert result["probes"]["simulator_material_receipt"]["evidence"]["source_job_id_commitment"] == selected_source_commitment
    assert result["probes"]["sod_signature"]["evidence"] == {
        "sod_sha256": "e" * 64, "native_generate_sod_verified": True,
        "dsc_certificate_sha256": "b" * 64, "source_job_commitment": selected_source_commitment}
    assert result["probes"]["gateway_application_lifecycle"]["evidence"]["source_job_commitment"] == direct_source_commitment
    assert len(result["probes"]["gateway_application_lifecycle"]["evidence"]["routes"]) == 7
    assert "selected-job" not in str(result) and "selected-instance" not in str(result)
    serialized = json.dumps(result)
    assert "private-csca-id" not in serialized
    for key in ("application_input_sha256", "job_id_sha256", "application_id_sha256",
                "bureau_job_id_sha256", "dsc_issuer_did_sha256"):
        assert key not in serialized
    assert result["probes"]["nine_route_gateway_flow"]["verified"] is False
    assert result["probes"]["simulator_batch_diagnostic"]["verified"] is False
    assert result["probes"]["physical_bureau_batch"]["verified"] is True
    assert result["probes"]["physical_bureau_batch"]["evidence"]["selected_flow_in_two_job_batch"] is True
    assert result["probes"]["physical_bureau_submission"]["verified"] is False
    assert not private_state_path.exists()
    handoff = json.loads(private_handoff_path.read_text(encoding="utf-8"))
    assert handoff == {
        "schema": "marty.passport-beta-demo-private/v1",
        "source_commit": "a" * 40, "stack_manifest_sha256": "d" * 64,
        "organization_id": plan["organization_id"],
        "flow_definition_id": "governed-flow", "flow_instance_id": "selected-instance",
        "application_id": "selected-app", "source_job_id": "selected-job",
        "bureau_job_id": selected_bureau,
    }
    assert "selected-app" not in serialized and selected_bureau not in serialized
    assert result["probes"]["signed_bureau_callback"]["verified"] is False
    assert result["probes"]["nine_route_gateway_flow"]["evidence"]["missing"] == [
        "same_job_gateway_route_trace"]
    assert result["status"] == "blocked"


def test_malformed_selected_flow_plan_blocks_before_beta_mutation() -> None:
    plan = certificate_plan()
    with pytest.raises(EvidenceError, match="inputs are incomplete"):
        run(Path("beta-artifacts"),
            {"organization_id": plan["organization_id"], "issuer_did": plan["dsc"]["dsc_issuer_did"]},
            "a" * 32, collector=lambda *args, **kwargs: report(),
            snapshot=lambda: pytest.fail("Production snapshot must wait for Flow input validation"),
            certificate_plan=plan, csca_session="csca-session", dsc_session="dsc-session",
            selected_flow_plan={"flow_definition_id": "governed-flow", "references": {},
                                "physical_document": {}}, flow_operator_cookie="governed-cookie")


def test_native_credential_preflight_blocks_before_ceremony_or_flow_mutation(tmp_path: Path) -> None:
    plan = certificate_plan()
    with pytest.raises(NativeBatchProbeError, match="credentials are rejected"):
        run(
            Path("beta-artifacts"), managed_application(plan), "a" * 32,
            collector=lambda *args, **kwargs: report(),
            certificate_plan=plan, csca_session="csca-session", dsc_session="dsc-session",
            selected_flow_plan=selected_plan(), flow_operator_cookie="governed-cookie",
            native_service_token="s" * 32, native_operator_token="z" * 32,
            private_state_path=tmp_path / "private" / "pending.json",
            private_handoff_path=tmp_path / "private" / "demo-selected.json",
            native_preflight=lambda *args: (_ for _ in ()).throw(
                NativeBatchProbeError("Private credentials are rejected")),
            checkout_checker=lambda source: None,
            snapshot=lambda: pytest.fail("No beta mutation or snapshot after failed auth"),
            chain=lambda *args, **kwargs: pytest.fail("Certificate ceremony must not run"),
        )


@pytest.mark.parametrize("field,value", [
    ("source_commit", "f" * 40),
    ("stack_manifest_sha256", "f" * 64),
    ("organization_id", "other-org"),
    ("issuer_did", "did:web:other"),
])
def test_selected_flow_release_and_identity_drift_block_before_mutation(
    field: str, value: str,
) -> None:
    governed = selected_plan()
    governed[field] = value
    application = {"organization_id": certificate_plan()["organization_id"],
                   "issuer_did": certificate_plan()["dsc"]["dsc_issuer_did"]}
    with pytest.raises(EvidenceError, match="selected Flow inputs are incomplete"):
        run(Path("beta-artifacts"), application, "a" * 32,
            collector=lambda *args, **kwargs: report(),
            certificate_plan=certificate_plan(), csca_session="csca-session",
            dsc_session="dsc-session", selected_flow_plan=governed,
            flow_operator_cookie="governed-cookie",
            snapshot=lambda: pytest.fail("Release drift must stop before snapshot"),
            checkout_checker=lambda source: pytest.fail("Release drift must stop before checkout"))


def test_invalid_selected_physical_document_blocks_before_mutation() -> None:
    governed = selected_plan()
    governed["physical_document"]["data_groups"]["DG2"] = "not base64!"
    with pytest.raises(ValueError, match="data groups are invalid"):
        run(Path("beta-artifacts"), {"organization_id": governed["organization_id"],
                                       "issuer_did": governed["issuer_did"]}, "a" * 32,
            collector=lambda *args, **kwargs: report(),
            certificate_plan=certificate_plan(), csca_session="csca-session",
            dsc_session="dsc-session", selected_flow_plan=governed,
            flow_operator_cookie="governed-cookie",
            snapshot=lambda: pytest.fail("Invalid physical data must stop before snapshot"),
            checkout_checker=lambda source: pytest.fail("Invalid physical data must stop before checkout"))


@pytest.mark.parametrize("profile_change", ["missing", "mismatch"])
def test_application_profiles_match_selected_flow_before_beta_mutation(profile_change: str) -> None:
    governed = selected_plan()
    application = managed_application()
    if profile_change == "missing":
        application.pop("credential_template_id")
        message = "application profile is incomplete"
    else:
        application["credential_template_id"] = "other-template"
        message = "references differ"
    with pytest.raises(EvidenceError, match=message):
        run(Path("beta-artifacts"), application, "a" * 32,
            collector=lambda *args, **kwargs: report(),
            certificate_plan=certificate_plan(), csca_session="csca-session",
            dsc_session="dsc-session", selected_flow_plan=governed,
            flow_operator_cookie="governed-cookie",
            snapshot=lambda: pytest.fail("Profile mismatch must stop before snapshot"),
            checkout_checker=lambda source: None)


@pytest.mark.parametrize("mutation", [
    lambda evidence: evidence.update(source_commit="f" * 40),
    lambda evidence: evidence.update(stack_manifest_sha256="f" * 64),
    lambda evidence: evidence.update(services_oci_reference="ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "f" * 64),
    lambda evidence: evidence.update(http_status=200),
    lambda evidence: evidence.update(submitted_job_commitments=["3" * 64, "3" * 64]),
    lambda evidence: evidence["returned_jobs"][1].update(source_job_commitment="9" * 64),
    lambda evidence: evidence.update(callback_receipts_sha256=["7" * 64]),
])
def test_batch_submission_requires_signed_source_and_two_callback_bindings(mutation) -> None:
    batch_result = accepted_batch()
    mutation(batch_result["evidence"])
    selected = certificate_plan()

    def chain(*args, on_dsc_material):
        on_dsc_material("b" * 64, "c" * 64)
        return {"verified": True, "evidence": {"dsc_certificate_sha256": "b" * 64}}

    def lifecycle(*args, on_submission):
        on_submission(selected["organization_id"], "job", "bureau", "f" * 64)
        return {"verified": True, "evidence": {"sod_signature_verified": True,
                                                "sod_sha256": "f" * 64}}

    with pytest.raises(EvidenceError, match="batch and signed callback receipt"):
        run(Path("beta-artifacts"), managed_application(selected), "a" * 32,
            collector=lambda *args, **kwargs: report(),
            certificate_plan=selected, csca_session="csca-session",
            dsc_session="dsc-session", chain=chain,
            snapshot=lambda: {"sha256": "c" * 64, "container_counts": {}},
            drain=lambda: {"verified": True, "evidence": {"in_flight_jobs": 0}},
            routing=lambda *args: {"verified": True, "evidence": {"webhook_owner": "issuance-native"}},
            flow=lambda owner: {"verified": True, "evidence": {
                "unsigned_webhook_owner": owner, "signature_denial_verified": True}},
            lifecycle=lifecycle,
            material_receipt=lambda *args: {"verified": True, "evidence": {
                "tenant_and_job_binding": True}},
            batch=lambda *args: batch_result)


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
        Path("beta-artifacts"), managed_application(), "a" * 32,
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
        batch=lambda *args: accepted_batch(),
    )
    assert calls == ["collect", "chain", "lifecycle", "collect"]
    assert result["probes"]["managed_csca_dsc_chain"]["verified"] is True
    assert result["probes"]["sod_signature"]["verified"] is True
    assert result["status"] == "blocked"


def test_failed_governed_chain_cannot_create_a_passport_job() -> None:
    with pytest.raises(EvidenceError, match="chain did not verify"):
        run(
            Path("beta-artifacts"),
            managed_application(),
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
    assert '--private-demo-handoff-file "$private_handoff_file"' in probe["run"]
    assert 'passport-beta-demo-selected-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT.json' in probe["run"]
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
        result = subprocess.run([sys.executable, "-O", "-c", code, *args], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert (result.returncode == 0) is (status == expected_status)
    report_path.write_text(json.dumps({"schema": "wrong", "status": expected_status}))
    result = subprocess.run([sys.executable, "-O", "-c", code, *args], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode != 0
