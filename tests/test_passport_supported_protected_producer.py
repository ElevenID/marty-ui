"""Protected Rust producer orders its gates and records only partial evidence."""

from datetime import datetime, timedelta, timezone
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

import pytest
import yaml

from services.passport_disposable_identity import issuer_did
from scripts.check_passport_supported_producer_handoff import HandoffError, verify_handoff
from scripts.passport_supported_infra_images import qualified_images
from scripts.passport_supported_protected_producer import (
    WORKFLOW_NAME, _application, _observe_bound_runtime, produce_disposable_receipt,
)
from scripts.collect_passport_supported_acceptance import COMPOSE_FLAGS, COMPOSE_SERVICES
from scripts.probe_passport_supported_routes import _frozen_routes
from scripts.passport_supported_provisioning_producer import ProducerError, WORKFLOW_REF


NOW = datetime(2026, 9, 28, 17, tzinfo=timezone.utc)
SOURCE = "a" * 40
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64


def flow_receipt() -> dict:
    values = [f"d0000000-0000-4000-8000-{number:012x}" for number in range(1, 8)]
    hashes = [hashlib.sha256(value.encode()).hexdigest() for value in values]
    return {"references": dict(zip((
        "credential_template_id_sha256", "application_template_id_sha256",
        "delivery_destination_profile_id_sha256"), hashes[:3])),
        "flow": dict(zip(("flow_definition_id_sha256", "flow_instance_id_sha256",
                          "native_job_id_sha256", "application_id_sha256"), hashes[3:])),
        "execution": {"nine_steps_verified": True,
                      "six_native_effects_verified": True,
                      "durable_history_verified": True,
                      "restart_resume_verified": True,
                      "bureau_job_id_sha256": "8" * 64,
                      "signed_callback_receipt_sha256": "9" * 64,
                      "sod_sha256": "a" * 64}}


def plan(surface: str) -> dict:
    project = f"marty-passport-acceptance-{surface}-" + uuid.uuid4().hex[:12]
    return {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": surface, "project": project,
        "run_id": "123456", "source_commit": SOURCE,
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=110)).isoformat(),
        "services_reference": SERVICES,
        "migrations_reference": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "c" * 64,
        "infra_images": qualified_images(verify_registry=False),
        "owner_labels": {
            "com.marty.passport.acceptance.owner": "supported-consumer",
            "com.marty.passport.acceptance.run-id": "123456",
            "com.marty.passport.acceptance.source-commit": SOURCE,
            "com.marty.passport.acceptance.services-image": SERVICES,
        },
    }


def certificate(selected: dict, port: int) -> dict:
    import hashlib
    digest = hashlib.sha256(issuer_did(port).encode()).hexdigest()
    return {
        "schema": "marty.passport-supported-disposable-certificate-setup/v1",
        "status": "setup_only", "gateway_operator_authorization_verified": False,
        "project": selected["project"], "source_commit": SOURCE,
        "evidence": {"csca_certificate_id": "csca-disposable-123456",
                     "csca_certificate_sha256": "1" * 64,
                     "dsc_certificate_sha256": "2" * 64,
                     "csca_issuer_did_sha256": digest,
                     "dsc_issuer_did_sha256": digest,
                     "csca_http_status": 200, "dsc_http_status": 200,
                     "chain_verified_by": "openssl-x509-strict"},
    }


@pytest.mark.parametrize("surface", ["base", "selfhost"])
def test_producer_orders_real_gates_and_tears_down(surface: str, tmp_path: Path) -> None:
    selected = plan(surface)
    calls = []
    record = {"project": selected["project"]}

    def run(args, env, timeout):
        calls.append(("run", args))
        assert env["DOCKER_HOST"] == "unix:///var/run/docker.sock"
        if args[:2] == ["docker", "run"]:
            mount = next(value for value in args if value.endswith(",dst=/work/secrets"))
            output = Path(mount.removeprefix("type=bind,src=").removesuffix(
                ",dst=/work/secrets"))
            (output / "bao_token").write_text("hvs.producer-service-token")
            (output / "callback_signer_bao_token").write_text(
                "hvs.producer-callback-token")
        return True

    def setup(*args, **kwargs):
        calls.append(("setup", args))
        return certificate(selected, 29877)

    def live(*args):
        calls.append(("ownership", args))
        return record

    def key(*args, **kwargs):
        calls.append(("key", args))
        return Path(tempfile.gettempdir()) / selected["project"] / "secrets" / "passport_acceptance_api_key"

    def operator_key(*args, **kwargs):
        calls.append(("operator_key", args))
        return (Path(tempfile.gettempdir()) / selected["project"] / "secrets"
                / "passport_acceptance_operator_api_key")

    def prove_flow(*args, **kwargs):
        calls.append(("flow_proof", args))
        assert "inspector" in kwargs
        assert "restart" in kwargs
        return flow_receipt()

    def probe(*args, **kwargs):
        calls.append(("probe", args))
        assert args[2]["issuer_did"] == issuer_did(29877)
        assert set(args[2]["data_groups"]) == {"DG1", "DG2"}
        return {"verified": True, "flow_execution_verified": False,
                "evidence": {"signed_gateway_callback_verified": True,
                             "routes": [{"method": "GET", "route": "synthetic"}] * 9}}

    def complete(*args):
        calls.append(("complete_teardown", args))
        return True

    runtime = {service: {"container_id": service, "image_id": "sha256:" + "d" * 64,
                         "oci_reference": SERVICES, "selectors": {}}
               for service in COMPOSE_SERVICES}
    runtime["edge"] = {"container_id": "edge", "loopback_port": 29877}

    def observe(*args):
        calls.append(("runtime_inventory", args))
        assert args[0] is record
        return runtime

    report = produce_disposable_receipt(
        tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
        {"GITHUB_RUN_ID": "987654"}, 29877, now=NOW,
        deadline_lookup=lambda env: NOW + timedelta(minutes=60),
        verify=lambda *args, **kwargs: selected,
        preflight=lambda *args, **kwargs: selected,
        inspect=lambda args: "", run=run, setup=setup,
        record_live=live, issue_key=key, issue_operator_key=operator_key,
        probe=probe, flow_proof=prove_flow,
        observe_runtime=observe,
        teardown_complete=complete,
        teardown_partial=lambda *args, **kwargs: pytest.fail("unexpected partial teardown"),
    )
    names = [item[0] for item in calls]
    assert (names.index("setup") < names.index("ownership") < names.index("key")
            < names.index("probe") < names.index("operator_key")
            < names.index("flow_proof"))
    assert names.index("flow_proof") < names.index("runtime_inventory") < names.index("complete_teardown")
    assert names[-1] == "complete_teardown"
    commands = [item[1] for item in calls if item[0] == "run"]
    assert commands[0][-9:] == ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "120",
                                "postgres", "redis", "openbao"]
    assert commands[1][:2] == ["docker", "run"]
    if surface == "selfhost":
        assert "selfhost-ceremony.yml" in " ".join(commands[2])
        assert "--force-recreate" in commands[-1]
        assert commands[-1][-2:] == ["gateway", "signing-keys"]
    assert report["status"] == "blocked"
    assert report["rust_routes_verified"] is True
    assert report["signed_gateway_callback_verified"] is True
    assert report["flow_start_verified"] is True
    assert report["flow_execution"] == flow_receipt()
    assert report["flow_execution_verified"] is True
    assert report["rust_restart_resume_verified"] is True
    assert report["producer_run_id"] == "987654"
    assert set(report["runtime_images"]) == set(COMPOSE_SERVICES)
    assert report["runtime_edge"] == runtime["edge"]
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_runtime_inventory_binds_current_owned_container_ids() -> None:
    containers = {service: service for service in (*COMPOSE_SERVICES, "edge")}
    record = {"project": plan("base")["project"], "services_reference": SERVICES,
              "containers": containers}
    runtime = {service: {"container_id": service} for service in COMPOSE_SERVICES}
    runtime["edge"] = {"container_id": "edge", "loopback_port": 29877}
    commands = []

    def inspect(args):
        commands.append(args)
        return ""

    def observe(surface, project, reference, *, runner):
        assert (surface, project, reference) == ("base", record["project"], SERVICES)
        runner(["docker", "ps", "-aq"])
        return runtime

    def proof(*args):
        return {"live_ownership_verified": True}
    assert _observe_bound_runtime(record, "base", 29877, NOW, inspect,
                                  observe=observe, ownership=proof) == runtime
    assert commands == [["ps", "-aq"]]
    for service in ("flow", "edge"):
        invalid = deepcopy(runtime)
        invalid[service] = {**runtime[service], "container_id": "stale"}
        with pytest.raises(ProducerError, match="runtime identity changed"):
            _observe_bound_runtime(record, "base", 29877, NOW, inspect,
                                   observe=lambda *args, **kwargs: invalid,
                                   ownership=proof)
    with pytest.raises(ProducerError, match="edge port changed"):
        _observe_bound_runtime(record, "base", 29878, NOW, inspect,
                               observe=observe, ownership=proof)
    with pytest.raises(ProducerError, match="ownership is unverified"):
        _observe_bound_runtime(record, "base", 29877, NOW, inspect,
                               observe=observe,
                               ownership=lambda *args: {"live_ownership_verified": False})
    with pytest.raises(ProducerError, match="escaped Docker"):
        _observe_bound_runtime(
            record, "base", 29877, NOW, inspect,
            observe=lambda *args, **kwargs: kwargs["runner"](["kubectl", "get", "pods"]),
            ownership=proof,
        )


@pytest.mark.parametrize("complete_result", [True, False])
def test_invalid_route_proof_fails_and_cleans(tmp_path: Path,
                                              complete_result: bool) -> None:
    selected = plan("base")
    partial = []

    def run(args, env, timeout):
        if args[:2] == ["docker", "run"]:
            mount = next(value for value in args if value.endswith(",dst=/work/secrets"))
            output = Path(mount.removeprefix("type=bind,src=").removesuffix(
                ",dst=/work/secrets"))
            (output / "bao_token").write_text("hvs.producer-service-token")
            (output / "callback_signer_bao_token").write_text("hvs.producer-callback-token")
        return True

    with pytest.raises(ProducerError, match="route receipt is invalid"):
        produce_disposable_receipt(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {"GITHUB_RUN_ID": "987654"}, 29877, now=NOW,
            deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: selected,
            inspect=lambda args: "", run=run,
            setup=lambda *args, **kwargs: certificate(selected, 29877),
            record_live=lambda *args: {"project": selected["project"]},
            issue_key=lambda *args, **kwargs: (
                Path(tempfile.gettempdir()) / selected["project"] / "secrets"
                / "passport_acceptance_api_key"),
            probe=lambda *args, **kwargs: {"verified": True,
                "flow_execution_verified": True,
                "evidence": {"signed_gateway_callback_verified": True}},
            teardown_complete=lambda *args: partial.append("complete") or complete_result,
            teardown_partial=lambda *args, **kwargs: partial.append("partial") or True,
        )
    assert partial == (["complete"] if complete_result else ["complete", "partial"])
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_failed_recreate_uses_plan_bound_partial_teardown(tmp_path: Path) -> None:
    selected = plan("base")
    cleanup = []

    def run(args, env, timeout):
        if args[:2] == ["docker", "run"]:
            mount = next(value for value in args if value.endswith(",dst=/work/secrets"))
            output = Path(mount.removeprefix("type=bind,src=").removesuffix(
                ",dst=/work/secrets"))
            (output / "bao_token").write_text("hvs.producer-service-token")
            (output / "callback_signer_bao_token").write_text("hvs.producer-callback-token")
        return True

    def fail_recreate(*args, **kwargs):
        raise ValueError("Disposable Rust service recreation failed")

    def flow_proof(*args, **kwargs):
        return kwargs["restart"]()

    with pytest.raises(ValueError, match="recreation failed"):
        produce_disposable_receipt(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {"GITHUB_RUN_ID": "987654"}, 29877, now=NOW,
            deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: selected,
            inspect=lambda args: "", run=run,
            setup=lambda *args, **kwargs: certificate(selected, 29877),
            record_live=lambda *args: {"project": selected["project"]},
            issue_key=lambda *args, **kwargs: (
                Path(tempfile.gettempdir()) / selected["project"] / "secrets"
                / "passport_acceptance_api_key"),
            issue_operator_key=lambda *args, **kwargs: (
                Path(tempfile.gettempdir()) / selected["project"] / "secrets"
                / "passport_acceptance_operator_api_key"),
            probe=lambda *args, **kwargs: {
                "verified": True, "flow_execution_verified": False,
                "evidence": {"signed_gateway_callback_verified": True}},
            flow_proof=flow_proof, restart_rust=fail_recreate,
            teardown_complete=lambda *args: cleanup.append("complete") or False,
            teardown_partial=lambda *args, **kwargs: cleanup.append("partial") or True,
        )
    assert cleanup == ["complete", "partial"]
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_preflight_rejection_never_starts_docker(tmp_path: Path) -> None:
    selected = plan("base")
    calls = []
    with pytest.raises(ProducerError, match="preflight rejected"):
        produce_disposable_receipt(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {"GITHUB_RUN_ID": "987654"}, 29877, now=NOW,
            deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: (_ for _ in ()).throw(
                ProducerError("preflight rejected")),
            inspect=lambda args: calls.append(args) or "",
            run=lambda *args: calls.append(args) or True,
        )
    assert calls == []
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_hosted_handoff_binds_partial_receipt_to_plan(tmp_path: Path) -> None:
    selected = plan("base")
    plan_path = tmp_path / "plan.json"
    receipt_path = tmp_path / "receipt.json"
    plan_path.write_text(json.dumps(selected))
    statuses = {
        "/v1/passport/applications": "DRAFT",
        "/v1/passport/applications/{application_id}/generate-data-groups": "DATA_GENERATED",
        "/v1/passport/applications/{application_id}/generate-sod": "SOD_SIGNED",
        "/v1/passport/applications/{application_id}/submit-personalization": "SUBMITTED",
        "/v1/passport/applications/{application_id}/production-status": "QUALITY_CHECK",
        "/v1/passport/applications/{application_id}/quality-verify": "READY_FOR_ACTIVATION",
        "/v1/passport/applications/{application_id}/activate": "ACTIVE",
    }
    routes = [{"method": method, "route": path,
               "http_status": (422 if path.endswith("/webhooks/personalization")
                               else 201 if path == "/v1/passport/applications" else 200),
               **({"job_status": statuses[path]} if path in statuses else {}),
               **({"positive_gateway_path_verified": True,
                   "signed_callback_observed_by": "authenticated-private-bureau-receipt"}
                  if path.endswith("/webhooks/personalization") else {})}
              for method, path in sorted(_frozen_routes())]
    application_hash = hashlib.sha256(json.dumps(
        _application(29877), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    runtime = {
        service: {"container_id": f"{index:064x}", "image_id": "sha256:" + "d" * 64,
                  "oci_reference": SERVICES,
                  "selectors": {flag: True for flag in COMPOSE_FLAGS[service]}}
        for index, service in enumerate(COMPOSE_SERVICES, 1)
    }
    receipt = {
        "schema": "marty.passport-supported-rust-producer/v1",
        "status": "blocked", "project": selected["project"], "surface": "base",
        "source_commit": SOURCE, "plan_run_id": "123456", "producer_run_id": "987654",
        "gateway_port": 29877, "physical_claim": "not_claimed",
        "certificate_setup_passed": True, "live_ownership_verified": True,
        "rust_routes_verified": True, "signed_gateway_callback_verified": True,
        "flow_start_verified": True,
        "flow_execution_verified": True, "rust_restart_resume_verified": True,
        "certificate": certificate(selected, 29877),
        "route": {"verified": True, "flow_execution_verified": False,
                  "evidence": {"signed_gateway_callback_verified": True,
                               "signed_callback_path": "simulator-to-gateway-to-native",
                               "physical_claim": "not_claimed",
                               "unsigned_webhook_http_status": 422,
                               "callback_private_status": "QUALITY_CHECK",
                               "application_input_sha256": application_hash,
                               "job_id_sha256": "3" * 64,
                               "application_id_sha256": "4" * 64,
                               "bureau_job_id_sha256": "5" * 64,
                               "callback_bureau_job_id_sha256": "5" * 64,
                               "sod_sha256": "6" * 64,
                               "callback_receipt_sha256": "7" * 64,
                               "sod_signature_verified": True,
                               "routes": routes}},
        "flow_execution": flow_receipt(),
        "runtime_images": runtime,
        "runtime_edge": {"container_id": f"{7:064x}",
                         "oci_reference": selected["infra_images"]["edge"],
                         "loopback_port": 29877},
        "blocker": "Live protected beta acceptance remains unproven",
    }
    receipt_path.write_text(json.dumps(receipt))
    assert verify_handoff(plan_path, receipt_path, SOURCE, "987654",
                          attest=lambda *args: True)["status"] == "blocked"
    for mutation in ("producer_run_id", "signed_gateway_callback_verified",
                     "rust_routes_verified", "project"):
        changed = dict(receipt)
        changed[mutation] = ({"producer_run_id": "wrong", "project": "wrong",
                              "signed_gateway_callback_verified": False,
                              "rust_routes_verified": False}[mutation])
        receipt_path.write_text(json.dumps(changed))
        with pytest.raises(HandoffError):
            verify_handoff(plan_path, receipt_path, SOURCE, "987654",
                           attest=lambda *args: True)

    mutations = [
        ("missing certificate", lambda item: item.pop("certificate")),
        ("foreign certificate", lambda item: item["certificate"].update(
            project="foreign")),
        ("wrong issuer DID", lambda item: item["certificate"]["evidence"].update(
            csca_issuer_did_sha256="8" * 64)),
        ("no SOD signature", lambda item: item["route"]["evidence"].update(
            sod_signature_verified=False)),
        ("missing SOD digest", lambda item: item["route"]["evidence"].pop(
            "sod_sha256")),
        ("wrong application", lambda item: item["route"]["evidence"].update(
            application_input_sha256="8" * 64)),
        ("different bureau job", lambda item: item["route"]["evidence"].update(
            callback_bureau_job_id_sha256="8" * 64)),
        ("no private receipt", lambda item: item["route"]["evidence"].update(
            callback_receipt_sha256="invalid")),
        ("physical claim", lambda item: item.update(physical_claim="booklet-issued")),
        ("route physical claim", lambda item: item["route"]["evidence"].update(
            physical_claim="booklet-issued")),
        ("Gateway claim", lambda item: item["route"]["evidence"]["routes"][-1].update(
            positive_gateway_path_verified=False)),
        ("extra route data", lambda item: item["route"]["evidence"]["routes"][0].update(
            applicant={"name": "private"})),
        ("duplicate create", lambda item: item["route"]["evidence"]["routes"].append(
            deepcopy(next(route for route in item["route"]["evidence"]["routes"]
                          if route["route"] == "/v1/passport/applications")))),
        ("missing lifecycle status", lambda item: item["route"]["evidence"]["routes"]
            [next(index for index, route in enumerate(item["route"]["evidence"]["routes"])
                  if route["route"].endswith("/generate-sod"))].update(
                      job_status="SUBMITTED")),
        ("foreign Flow ID", lambda item: item["flow_execution"]["flow"].update(
            flow_instance_id_sha256="not-a-hash")),
        ("missing durable history", lambda item: item["flow_execution"]
            ["execution"].update(durable_history_verified=False)),
        ("wrong runtime image", lambda item: item["runtime_images"]["flow"].update(
            oci_reference="foreign")),
        ("disabled Rust selector", lambda item: item["runtime_images"]["gateway"]
            ["selectors"].update(PASSPORT_NATIVE_GATEWAY_ENABLED=False)),
        ("duplicate runtime", lambda item: item["runtime_images"]["flow"].update(
            container_id=item["runtime_images"]["gateway"]["container_id"])),
        ("wrong edge port", lambda item: item["runtime_edge"].update(
            loopback_port=29878)),
    ]
    for _, mutate in mutations:
        changed = deepcopy(receipt)
        mutate(changed)
        receipt_path.write_text(json.dumps(changed))
        with pytest.raises(HandoffError):
            verify_handoff(plan_path, receipt_path, SOURCE, "987654",
                           attest=lambda *args: True)


def test_producer_workflow_has_bounded_recovery_and_hosted_attestation() -> None:
    root = Path(__file__).resolve().parents[1] / ".github/workflows"
    workflow = yaml.safe_load((root / "passport-supported-provisioning-producer.yml").read_text())
    assert set(workflow.get("on", workflow.get(True))) == {"workflow_dispatch"}
    job = workflow["jobs"]["producer"]
    assert job["environment"] == "beta-lifecycle"
    assert job["timeout-minutes"] == 60
    assert job["steps"][0]["with"]["persist-credentials"] is False
    prepare, produce, recover, upload = job["steps"][1:]
    assert "and .head_sha == $sha" in prepare["run"]
    assert "2400s" in produce["run"]
    assert "scripts/passport_supported_protected_producer.py" in produce["run"]
    assert recover["if"] == "always() && steps.prepare.outcome == 'success'"
    assert "240s" in recover["run"] and "--recover-only" in recover["run"]
    assert upload["if"] == "steps.produce.outcome == 'success' && steps.recover.outcome == 'success'"
    for step in (prepare, produce, recover):
        assert subprocess.run(["bash", "-n"], input=step["run"].encode(),
                              capture_output=True).returncode == 0
    hosted = yaml.safe_load((root / "passport-supported-provisioning-record.yml").read_text())
    assert hosted["jobs"]["attest-receipt"]["runs-on"] == "ubuntu-latest"
    assert "check_passport_supported_producer_handoff.py" in hosted["jobs"]["attest-receipt"]["steps"][1]["run"]
    assert WORKFLOW_NAME in hosted.get("on", hosted.get(True))["workflow_run"]["workflows"]
    assert WORKFLOW_REF.endswith("passport-supported-provisioning-producer.yml@refs/heads/main")
