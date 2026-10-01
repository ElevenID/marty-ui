"""Read-only production and beta drain probes fail on drift or unsafe rows."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scripts.probe_passport_beta_host import (
    ACTIVE_PHYSICAL_FLOWS_SQL, HostProbeError, assert_production_unchanged, beta_legacy_drain,
    beta_material_receipt, beta_native_route_ownership,
    production_attachment_sha256, production_snapshot,
)
from scripts import probe_passport_beta_host as probe


def runner(*, pending: str = "0", legacy: str = "0", active_flow: str = "0",
           altered: bool = False, stopped_project: bool = False, unhealthy: bool = False):
    commands = []

    def execute(command: list[str]) -> str:
        commands.append(command)
        if command[1] == "ps":
            project = command[command.index("--filter") + 1].split("=")[-1]
            return {"marty-selfhost-prod": "prod-id\nprod-db-id\nprod-ui-id", "marty-selfhost-openbao": "bao-id",
                    "elevenid-beta": "beta-postgres-id"}.get(project, "")
        if command[1] == "inspect":
            container_id = command[2]
            project, service = {
                "prod-id": ("marty-selfhost-prod", "gateway"),
                "prod-db-id": ("marty-selfhost-prod", "postgres"),
                "prod-ui-id": ("marty-selfhost-prod", "ui"),
                "bao-id": ("marty-selfhost-openbao", "openbao"),
                "beta-postgres-id": ("elevenid-beta", "postgres"),
            }[container_id]
            return json.dumps([{ "Id": container_id, "Image": "sha256:" + "a" * 64,
                "Name": "/" + container_id, "Mounts": [],
                "Config": {"Labels": {"com.docker.compose.project": project,
                                      "com.docker.compose.service": service}},
                "State": {"Running": not stopped_project, "Status": "exited" if stopped_project else "running",
                          "Health": {"Status": "unhealthy" if unhealthy else "healthy"},
                          "StartedAt": "changed" if altered and container_id == "prod-id" else "fixed"}}])
        if command[1] == "exec":
            sql = command[-1]
            if "to_regclass" in sql:
                return "t"
            if "status NOT IN" in sql:
                return pending
            if "flow_service.flow_instances AS instance" in sql:
                return active_flow
            return legacy
        raise AssertionError(command)

    return commands, execute


def test_reads_production_identity_without_mutating_it() -> None:
    commands, execute = runner()
    before = production_snapshot(execute)
    after = production_snapshot(execute)
    result = assert_production_unchanged(before, after)
    assert result["verified"] is True
    assert result["evidence"]["scope"] == "acceptance-run-window-only"
    assert result["evidence"]["container_counts"] == {"marty-selfhost-prod": 3,
                                                       "marty-selfhost-openbao": 1}
    assert all(command[1] in ("ps", "inspect") for command in commands)
    _, drifted_execute = runner(altered=True)
    with pytest.raises(HostProbeError, match="changed"):
        assert_production_unchanged(before, production_snapshot(drifted_execute))
    for variant in ({"stopped_project": True}, {"unhealthy": True}):
        _, invalid_execute = runner(**variant)
        with pytest.raises(HostProbeError):
            production_snapshot(invalid_execute)


def test_production_attachment_digest_detects_network_or_port_drift(monkeypatch):
    records = {}
    for index, project in enumerate(probe.PRODUCTION_PROJECTS, 1):
        container_id = f"{index:064x}"
        records[project] = {
            "Id": container_id,
            "Config": {"Labels": {"com.docker.compose.project": project}},
            "NetworkSettings": {"Networks": {"production": {
                "NetworkID": "a" * 64, "Aliases": ["service"],
                "IPAddress": "172.20.0.2"}}},
            "HostConfig": {"PortBindings": {"443/tcp": [{"HostPort": "443"}]}},
        }
    monkeypatch.setattr(probe, "ids", lambda project, _runner: [records[project]["Id"]])
    monkeypatch.setattr(probe, "inspect", lambda container_id, _runner: next(
        record for record in records.values() if record["Id"] == container_id))
    baseline = production_attachment_sha256(lambda _command: "")
    records[probe.PRODUCTION_PROJECTS[0]]["HostConfig"]["PortBindings"]["443/tcp"][0][
        "HostPort"] = "8443"
    assert production_attachment_sha256(lambda _command: "") != baseline


def test_beta_drain_queries_live_table_and_rejects_nonzero_counts() -> None:
    commands, execute = runner()
    result = beta_legacy_drain(execute)
    assert result["verified"] is True
    assert result["evidence"]["in_flight_jobs"] == 0
    assert result["evidence"]["legacy_or_unknown_artifacts"] == 0
    assert result["evidence"]["active_physical_document_flows"] == 0
    assert all(command[1] in ("ps", "inspect", "exec") for command in commands)
    assert all(command[2] == "beta-postgres-id" for command in commands if command[1] == "exec")
    for pending, legacy, active_flow in (("1", "0", "0"), ("0", "1", "0"), ("bad", "0", "0"), ("0", "0", "1")):
        _, unsafe = runner(pending=pending, legacy=legacy, active_flow=active_flow)
        with pytest.raises(HostProbeError):
            beta_legacy_drain(unsafe)


def test_private_material_receipt_binds_first_write_to_exact_tenant_job_and_chain() -> None:
    commands, base = runner()
    organization = "beta-org"
    source = "job'; DROP TABLE issuance_service.passport_beta_bureau_jobs; --"
    bureau = "c3ddfe4d-e67e-473e-a278-c95a27459344"
    digests = ("a" * 64, "b" * 64, "c" * 64)
    expected = [*digests, organization.encode().hex(), source.encode().hex()]

    def execute(command: list[str]) -> str:
        if command[1] != "exec":
            return base(command)
        commands.append(command)
        sql = command[-1]
        actual = re.findall(r"decode\('([0-9a-f]+)', 'hex'\)", sql)
        if actual[:5] != expected or f"'{bureau}'::uuid" not in sql:
            return "0|f|f|f"
        return "1|t|t|t"

    def probe(org: str = organization, job: str = source, bureau_id: str = bureau,
              values: tuple[str, str, str] = digests) -> dict:
        return beta_material_receipt(org, job, bureau_id, *values, b"k" * 32, runner=execute)

    result = probe()
    assert result["verified"] is True
    assert all(result["evidence"][key] is True for key in (
        "tenant_and_job_binding", "first_accepted_sod_der_matches_native",
        "first_accepted_dsc_der_matches_selected_chain",
        "first_accepted_dsc_pem_wire_matches_selected_chain"))
    assert all(raw not in str(result) for raw in (organization, source, bureau, *digests))
    assert source not in commands[-1][-1]
    for changed in ({"org": "foreign-org"}, {"job": "other-job"},
                    {"bureau_id": "70f17506-808d-47e0-9fa0-f8ad2d4a5457"},
                    {"values": (digests[1], digests[0], digests[2])}):
        with pytest.raises(HostProbeError, match="did not match"):
            probe(**changed)

    def legacy(command: list[str]) -> str:
        return "1|f|f|f" if command[1] == "exec" else base(command)

    with pytest.raises(HostProbeError, match="did not match"):
        beta_material_receipt(organization, source, bureau, *digests, b"k" * 32, runner=legacy)
    with pytest.raises(HostProbeError, match="inputs are invalid"):
        beta_material_receipt(organization, source, bureau, *digests, b"short", runner=execute)


def test_material_receipt_commitments_follow_frozen_cross_language_vector() -> None:
    contract = json.loads((Path(__file__).resolve().parents[1] / "contracts/passport-beta-bureau-behavior.json").read_text())
    vector = contract["first_accepted_material_receipt"]["commitment_algorithm"]["test_vector"]
    _, base = runner()

    def accepted(command: list[str]) -> str:
        return "1|t|t|t" if command[1] == "exec" else base(command)

    result = beta_material_receipt("beta-org", vector["source_job_id"], vector["bureau_job_id"],
                                   "a" * 64, "b" * 64, "c" * 64,
                                   vector["key_utf8"].encode(), runner=accepted)
    assert result["evidence"]["source_job_id_commitment"] == vector["source_job_commitment"]
    assert result["evidence"]["bureau_job_id_commitment"] == vector["bureau_job_commitment"]


def test_active_flow_drain_stays_equal_to_beta_cutover_preflight() -> None:
    deploy = (Path(__file__).resolve().parents[1] / "scripts/deploy-local-beta-release.ps1").read_text(encoding="utf-8")
    match = re.search(r"\$activeFlowsSql = @'\s*(.*?)\s*'@", deploy, re.DOTALL)
    assert match is not None
    assert " ".join(match.group(1).split()) == " ".join(ACTIVE_PHYSICAL_FLOWS_SQL.split())


def test_beta_native_route_ownership_projects_only_expected_selectors() -> None:
    images = {service: {"container_id": service, "image_id": "sha256:" + "a" * 64,
                        "oci_reference": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64}
              for service in ("gateway", "flow", "issuance-native", "passport-beta-bureau")}
    configs = {
        "gateway": ["PASSPORT_NATIVE_GATEWAY_ENABLED=true", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED=true",
                    "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED=false", "PASSPORT_PROVIDER_INGRESS_SERVICE_URL="],
        "flow": ["PASSPORT_NATIVE_FLOW_ENABLED=true", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED=true",
                 "ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005"],
        "issuance-native": ["PASSPORT_NATIVE_HTTP_ENABLED=true", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED=true"],
        "passport-beta-bureau": [
            "PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED=true",
            "PASSPORT_BUREAU_CALLBACK_URL=http://gateway:8000/v1/passport/webhooks/personalization",
        ],
    }

    def inspector(container_id: str) -> dict:
        return {"Image": images[container_id]["image_id"],
                "Config": {"Image": images[container_id]["oci_reference"],
                           "Labels": {"com.docker.compose.project": "elevenid-beta",
                                      "com.docker.compose.service": container_id},
                           "Env": [*configs[container_id], "SECRET_KEY=must-never-appear"]},
                "State": {"Running": True, "Status": "running"}}

    result = beta_native_route_ownership(images, inspector=inspector)
    assert result["verified"] is True
    assert result["evidence"]["webhook_owner"] == "issuance-native"
    assert result["evidence"]["simulator_callback_gateway_target"] is True
    assert "SECRET_KEY" not in str(result) and "must-never-appear" not in str(result)
    for service, changed in (("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED=false"),
                             ("flow", "ISSUANCE_NATIVE_SERVICE_URL=http://issuance:8005"),
                             ("issuance-native", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED=false")):
        original = configs[service]
        configs[service] = [item for item in original if item.split("=", 1)[0] != changed.split("=", 1)[0]] + [changed]
        with pytest.raises(HostProbeError):
            beta_native_route_ownership(images, inspector=inspector)
        configs[service] = original
    for changed in (
        "PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED=false",
        "PASSPORT_BUREAU_CALLBACK_URL=http://issuance-native:8005/v1/passport/webhooks/personalization",
    ):
        service = "passport-beta-bureau"
        original = configs[service]
        configs[service] = [item for item in original if item.split("=", 1)[0] != changed.split("=", 1)[0]] + [changed]
        with pytest.raises(HostProbeError, match="bypasses Gateway"):
            beta_native_route_ownership(images, inspector=inspector)
        configs[service] = original
    configs["passport-beta-bureau"].append("PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED=true")
    with pytest.raises(HostProbeError, match="ambiguous"):
        beta_native_route_ownership(images, inspector=inspector)
    configs["passport-beta-bureau"].pop()
    configs["flow"].append("PASSPORT_NATIVE_FLOW_ENABLED=true")
    with pytest.raises(HostProbeError, match="ambiguous"):
        beta_native_route_ownership(images, inspector=inspector)
    configs["flow"].pop()
    configs["gateway"] = [item for item in configs["gateway"] if not item.startswith("PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED=")]
    configs["gateway"].append("PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED=true")
    with pytest.raises(HostProbeError, match="target"):
        beta_native_route_ownership(images, inspector=inspector)
    configs["gateway"] = [item for item in configs["gateway"] if not item.startswith("PASSPORT_PROVIDER_INGRESS_SERVICE_URL=")]
    configs["gateway"].append("PASSPORT_PROVIDER_INGRESS_SERVICE_URL=http://passport-provider-ingress:8021")
    with pytest.raises(HostProbeError, match="absent"):
        beta_native_route_ownership(images, inspector=inspector)
    images["passport-provider-ingress"] = {"container_id": "passport-provider-ingress",
                                          "image_id": images["gateway"]["image_id"],
                                          "oci_reference": images["gateway"]["oci_reference"]}
    configs["passport-provider-ingress"] = []
    provider_image = images["passport-provider-ingress"]
    runtime_images = {key: value for key, value in images.items() if key != "passport-provider-ingress"}
    assert beta_native_route_ownership(runtime_images, provider_image, inspector)["evidence"]["webhook_owner"] == "passport-provider-ingress"
