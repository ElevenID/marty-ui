"""Private signed Credentials route retirement and nonce write proof."""

from __future__ import annotations

import hashlib
import json

import pytest

from scripts import probe_passport_beta_credentials_continuity as proof


OLD = "a" * 64
NEW = "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
POSTGRES = "d" * 64
IMAGE = proof.IMAGE_PREFIX + "e" * 64
NONCE = "n" * 40


def plan():
    return {
        "schema": "marty.passport-beta-aggregate-compose-plan/v1",
        "source_commit": "f" * 40,
        "postgres_container_id": POSTGRES,
        "postgres_system_identifier": "100",
        "database_oid": "200",
        "fence_epoch": "7",
        "migration_set_sha256": "3" * 64,
        "fence_verify_sql_sha256": "4" * 64,
        "issuance_image": IMAGE,
        "old_container_ids_by_service": {"issuance": OLD},
        "service_config_hashes": {"issuance": "1" * 64},
        "recreate_ingress_last": ["nginx-proxy"],
        "restart_ingress_last": [],
    }


def record(name, container, *, running=True, image=IMAGE):
    return {
        "Id": container,
        "Image": IMAGE_ID,
        "Config": {
            "Image": image,
            "Labels": {
                "com.docker.compose.project": "elevenid-beta",
                "com.docker.compose.service": name,
                "com.docker.compose.config-hash": "1" * 64,
            },
        },
        "State": {"Running": running,
                  "Status": "running" if running else "exited",
                  "Health": {"Status": "healthy"}},
    }


def harness(monkeypatch, *, routes=None, hidden_route=None, nonce_row="1",
            ingress_running=False, ui_running=False, image=IMAGE):
    routes = routes or {
        "/v1/issuance/nonce": {"post": {}},
        "/v1/issuance/credential": {"post": {}},
    }
    records = {
        OLD: record("issuance", OLD, running=False),
        NEW: record("issuance", NEW, image=image),
        "2" * 64: record("nginx-proxy", "2" * 64,
                         running=ingress_running),
    }
    ui_id = "5" * 64
    ui = record("ui-prod", ui_id, running=ui_running)
    ui["Config"]["Labels"]["com.docker.compose.project"] = "elevenid-beta-ui"
    records[ui_id] = ui
    monkeypatch.setattr(proof, "ids", lambda project, _runner: [ui_id]
                        if project == "elevenid-beta-ui" else
                        [item for item in records if item != ui_id])
    monkeypatch.setattr(proof, "inspect", lambda candidate, _runner: records[candidate])
    monkeypatch.setattr(proof, "beta_psql", lambda *_args: nonce_row)
    observed = []

    def runner(command):
        observed.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return json.dumps([{"Id": IMAGE_ID, "RepoDigests": [IMAGE]}])
        assert command[:3] == ["docker", "exec", NEW]
        if command[3:5] == ["python", "-c"]:
            result = [
                {"path": "/v1/issuance/nonce", "methods": ["POST"]},
                {"path": "/v1/issuance/credential", "methods": ["POST"]},
            ]
            if hidden_route:
                result.append({"path": hidden_route, "methods": ["GET"]})
            return json.dumps(result)
        path = command[-1]
        if path.endswith("/openapi.json"):
            return json.dumps({"paths": routes}) + "\n200"
        if path.endswith("/v1/passport/capabilities"):
            return json.dumps({"detail": "Not Found"}) + "\n404"
        if path.endswith("/ready"):
            return json.dumps({"status": "ready", "service": "issuance-service"}) + "\n200"
        if path.endswith("/v1/issuance/nonce"):
            return json.dumps({"c_nonce": NONCE}) + "\n200"
        raise AssertionError(path)

    def owner(_plan, *, runner):
        return {"verified": True, "source_commit": _plan["source_commit"],
                "postgres_container_id": POSTGRES, "transition_txid": "42"}

    return runner, owner, observed


def test_private_signed_credentials_proves_absence_and_nonce_write(monkeypatch):
    runner, owner, observed = harness(monkeypatch)
    result = proof.probe(plan(), runner=runner, owner_verifier=owner)
    assert result["removed_python_passport_routes_absent"] is True
    assert result["unrelated_issuance_nonce_write_verified"] is True
    assert result["nonce_sha256"] == hashlib.sha256(NONCE.encode()).hexdigest()
    assert NONCE not in json.dumps(result)
    assert [item[-1] for item in observed if item[:2] == ["docker", "exec"]
            and item[3] == "curl"] == [
        "http://127.0.0.1:8005/openapi.json",
        "http://127.0.0.1:8005/v1/passport/capabilities",
        "http://127.0.0.1:8005/ready",
        "http://127.0.0.1:8005/v1/issuance/nonce",
    ]


def test_rejects_retained_python_passport_route_before_write(monkeypatch):
    routes = {
        "/v1/issuance/nonce": {"post": {}},
        "/v1/issuance/credential": {"post": {}},
        "/v1/passport/capabilities": {"get": {}},
    }
    runner, owner, observed = harness(monkeypatch, routes=routes)
    with pytest.raises(proof.HostProbeError, match="passport route"):
        proof.probe(plan(), runner=runner, owner_verifier=owner)
    assert not any(item[-1].endswith("/nonce") for item in observed)


def test_rejects_hidden_passport_route_before_write(monkeypatch):
    runner, owner, observed = harness(
        monkeypatch, hidden_route="/v1/passport/capabilities")
    with pytest.raises(proof.HostProbeError, match="ASGI registry"):
        proof.probe(plan(), runner=runner, owner_verifier=owner)
    assert not any(item[-1].endswith("/nonce") for item in observed)


def test_rejects_open_ingress_before_write(monkeypatch):
    runner, owner, observed = harness(monkeypatch, ingress_running=True)
    with pytest.raises(proof.HostProbeError, match="ingress"):
        proof.probe(plan(), runner=runner, owner_verifier=owner)
    assert not any(item[-1].endswith("/nonce") for item in observed)


def test_rejects_unsigned_replacement_before_write(monkeypatch):
    runner, owner, observed = harness(monkeypatch, image="local:latest")
    with pytest.raises(proof.HostProbeError, match="signed Compose plan"):
        proof.probe(plan(), runner=runner, owner_verifier=owner)
    assert not any(item[-1].endswith("/nonce") for item in observed)


def test_rejects_unpersisted_nonce(monkeypatch):
    runner, owner, _observed = harness(monkeypatch, nonce_row="0")
    with pytest.raises(proof.HostProbeError, match="not persisted"):
        proof.probe(plan(), runner=runner, owner_verifier=owner)


def prior_receipt():
    return {
        "schema": "marty.passport-beta-credentials-continuity/v1",
        "verified": True,
        "source_commit": "f" * 40,
        "transition_txid": "42",
        "issuance_container_id": NEW,
        "issuance_image": IMAGE,
        "removed_python_passport_routes_absent": True,
        "unrelated_issuance_nonce_write_verified": True,
        "nonce_sha256": "0" * 64,
    }


def test_resume_rechecks_live_credentials_with_running_ingress(monkeypatch):
    runner, owner, observed = harness(monkeypatch, ingress_running=True)
    raw = (json.dumps(prior_receipt(), sort_keys=True) + "\n").encode()
    result = proof.verify_resume(plan(), raw, runner=runner,
                                 owner_verifier=owner)
    assert result["schema"] == "marty.passport-beta-credentials-continuity-resume/v1"
    assert result["prior_receipt_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["source_commit"] == "f" * 40
    assert result["transition_txid"] == "42"
    assert result["issuance_container_id"] == NEW
    assert result["fresh_nonce_sha256"] == hashlib.sha256(NONCE.encode()).hexdigest()
    assert any(item[-1].endswith("/nonce") for item in observed)


def test_resume_rejects_stale_receipt_before_nonce_write(monkeypatch):
    runner, owner, observed = harness(monkeypatch, ingress_running=True)
    prior = prior_receipt()
    prior["transition_txid"] = "41"
    with pytest.raises(proof.HostProbeError, match="prior Credentials|Prior Credentials"):
        proof.verify_resume(plan(), json.dumps(prior).encode(), runner=runner,
                            owner_verifier=owner)
    assert not any(item[-1].endswith("/nonce") for item in observed)


def fenced(_plan, *, runner):
    return {
        "verified": True,
        "source_commit": _plan["source_commit"],
        "postgres_container_id": POSTGRES,
        "postgres_system_identifier": "100",
        "database_oid": "200",
        "fence_epoch": "7",
        "migration_set_sha256": "3" * 64,
    }


def test_pretransition_proves_signed_replacement_before_phase_change(monkeypatch):
    runner, _owner, observed = harness(monkeypatch)
    result = proof.probe_pretransition(plan(), runner=runner,
                                       pretransition_verifier=fenced)
    digest = result.pop("receipt_sha256")
    assert digest == hashlib.sha256(json.dumps(
        result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert result["schema"] == "marty.passport-beta-credentials-pretransition/v1"
    assert result["fence_epoch"] == "7"
    assert result["issuance_container_id"] == NEW
    assert result["removed_python_passport_routes_absent"] is True
    assert result["unrelated_issuance_nonce_write_verified"] is True
    assert any(item[-1].endswith("/nonce") for item in observed)


def test_pretransition_requires_closed_ingress_before_nonce(monkeypatch):
    runner, _owner, observed = harness(monkeypatch, ingress_running=True)
    with pytest.raises(proof.HostProbeError, match="ingress"):
        proof.probe_pretransition(plan(), runner=runner,
                                  pretransition_verifier=fenced)
    assert not any(item[-1].endswith("/nonce") for item in observed)


def test_pretransition_requires_closed_public_ui_before_nonce(monkeypatch):
    runner, _owner, observed = harness(monkeypatch, ui_running=True)
    with pytest.raises(proof.HostProbeError, match="Public beta UI"):
        proof.probe_pretransition(plan(), runner=runner,
                                  pretransition_verifier=fenced)
    assert not any(item[-1].endswith("/nonce") for item in observed)


def test_pretransition_exact_phase_and_native_marker(monkeypatch):
    seen = []
    marker = "|".join(("100", "200", "fully_fenced", "7", "7", "f" * 40,
                       "3" * 64, "true", "false"))
    monkeypatch.setattr(proof, "beta_psql", lambda *_args: marker)
    result = proof.verify_pretransition(
        plan(), runner=lambda _command: "",
        render_verifier=lambda _plan: {"verified": True},
        fence_verifier=lambda intent, _runner: seen.append(intent),
    )
    assert result["verified"] is True
    assert seen[0]["verify_sql_sha256"] == "4" * 64


def test_pretransition_rejects_rust_owner_marker(monkeypatch):
    marker = "|".join(("100", "200", "rust_owner", "7", "7", "f" * 40,
                       "3" * 64, "true", "false"))
    monkeypatch.setattr(proof, "beta_psql", lambda *_args: marker)
    with pytest.raises(proof.HostProbeError, match="database marker"):
        proof.verify_pretransition(
            plan(), runner=lambda _command: "",
            render_verifier=lambda _plan: {"verified": True},
            fence_verifier=lambda _intent, _runner: pytest.fail("fence verifier called"),
        )


def test_pretransition_receipt_check_survives_committed_transition(monkeypatch):
    runner, _owner, _observed = harness(monkeypatch)
    receipt = proof.probe_pretransition(plan(), runner=runner,
                                        pretransition_verifier=fenced)
    raw = (json.dumps(receipt, indent=2) + "\n").encode()
    check = proof.verify_pretransition_receipt(
        plan(), raw, render_verifier=lambda _plan: {"verified": True})
    assert check["schema"] == "marty.passport-beta-credentials-pretransition-check/v1"
    assert check["verified"] is True
    assert check["receipt_file_sha256"] == hashlib.sha256(raw).hexdigest()
    assert check["receipt_sha256"] == receipt["receipt_sha256"]
    assert check["source_commit"] == plan()["source_commit"]
    assert check["postgres_container_id"] == POSTGRES
    assert check["fence_epoch"] == "7"
    assert check["issuance_image"] == IMAGE


def test_pretransition_receipt_check_rejects_tampering(monkeypatch):
    runner, _owner, _observed = harness(monkeypatch)
    receipt = proof.probe_pretransition(plan(), runner=runner,
                                        pretransition_verifier=fenced)
    receipt["nonce_sha256"] = "9" * 64
    with pytest.raises(proof.HostProbeError, match="canonical hash"):
        proof.verify_pretransition_receipt(
            plan(), json.dumps(receipt).encode(),
            render_verifier=lambda _plan: {"verified": True})


def test_pretransition_receipt_check_rejects_changed_plan(monkeypatch):
    runner, _owner, _observed = harness(monkeypatch)
    receipt = proof.probe_pretransition(plan(), runner=runner,
                                        pretransition_verifier=fenced)
    changed = plan()
    changed["issuance_image"] = proof.IMAGE_PREFIX + "a" * 64
    with pytest.raises(proof.HostProbeError, match="signed plan"):
        proof.verify_pretransition_receipt(
            changed, json.dumps(receipt).encode(),
            render_verifier=lambda _plan: {"verified": True})
