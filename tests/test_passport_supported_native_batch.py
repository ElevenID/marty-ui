"""First accepted material must come from the selected disposable database."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess

import pytest

from scripts.passport_supported_native_batch import (
    DisposableMaterialError, exercise_owned_native_batch, read_owned_material_receipt,
)
from scripts import passport_supported_native_batch as adapter
from scripts.probe_passport_beta_host import HostProbeError


NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)
POSTGRES = "a" * 64
SOURCE = "d0000000-0000-4000-8000-000000000001"
BUREAU = "d0000000-0000-4000-8000-000000000002"
RECORD = {"project": "marty-passport-acceptance-base-abcdef",
          "containers": {"postgres": POSTGRES}}


def receipt(*, inspector, ownership):
    return read_owned_material_receipt(
        RECORD, "base", "org-a", SOURCE, BUREAU,
        "1" * 64, "2" * 64, "3" * 64, b"k" * 32,
        inspector=inspector, ownership=ownership, clock=lambda: NOW)


def test_material_query_uses_exact_owned_postgres_and_no_beta_scan() -> None:
    calls = []

    def inspector(args):
        calls.append(args)
        assert args[:4] == ["exec", "--user", "postgres", POSTGRES]
        assert args[4:13] == [
            "psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "marty"]
        assert args[13:16] == ["-d", "marty", "-c"]
        assert SOURCE.encode().hex() in args[-1]
        assert "org-a".encode().hex() in args[-1]
        assert BUREAU in args[-1]
        return "1|t|t|t\n"

    result = receipt(inspector=inspector,
                     ownership=lambda *args: {"live_ownership_verified": True})
    assert result["verified"] is True
    assert result["evidence"]["source"] == "private disposable PostgreSQL"
    assert result["evidence"]["first_accepted_sod_der_matches_native"] is True
    assert len(calls) == 1
    assert SOURCE not in str(result) and BUREAU not in str(result)


def test_material_query_rejects_missing_or_mismatched_first_row() -> None:
    with pytest.raises(HostProbeError, match="did not match"):
        receipt(inspector=lambda args: "0|f|f|f\n",
                ownership=lambda *args: {"live_ownership_verified": True})


def test_material_query_denies_ownership_drift_before_sql() -> None:
    with pytest.raises(DisposableMaterialError, match="ownership changed"):
        receipt(inspector=lambda args: pytest.fail("queried an unowned database"),
                ownership=lambda *args: {"live_ownership_verified": False})


def test_owned_batch_uses_file_backed_bureau_poll_and_keeps_pending_until_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    native, bureau = "a" * 64, "b" * 64
    bureau_job = "d0000000-0000-4000-8000-000000000002"
    root = tmp_path / "marty-passport-acceptance-base-abcdef"
    state_dir = tmp_path / "private-state"
    state_dir.mkdir(mode=0o700)
    pending = state_dir / "pending.json"
    record = {"project": root.name, "disposable_root": str(root),
              "containers": {"issuance-native": native,
                             "passport-beta-bureau": bureau}}
    monkeypatch.setattr(adapter, "_private_key", lambda *args: (root / "api", "api-key"))
    monkeypatch.setattr(adapter, "_operator_key", lambda path, name: name + "-secret")
    calls = []

    def batch(*args, **kwargs):
        assert args[2:5] == (
            "api-key", "grpc_service_token-secret",
            "passport_beta_reconciliation_operator_token-secret")
        assert kwargs["gateway_request"]("POST", "/v1/passport/applications", {},
                                         "api-key") == (202, {"ok": True})
        assert kwargs["private_request"]("native") == (200, {"private": True})
        assert kwargs["simulator_get"](
            bureau, "GET", "/v1/personalization/jobs/" + bureau_job,
        ) == (200, b"", {"status": "SHIPPED"})
        assert args[13]("material") == {"verified": True}
        pending.write_text("private pending state", encoding="utf-8")
        return bureau_job, {"verified": True, "evidence": {"selected_flow_in_two_job_batch": True}}

    def private_request(*args, runner):
        assert runner(["docker", "exec", "-i", native, "curl", "--config", "-"],
                      b"config") == b"private"
        return 200, {"private": True}

    def poll(*args, **kwargs):
        calls.append("file-backed bureau poll")
        assert args[:3] == (record, "base", bureau_job)
        return 200, {"status": "SHIPPED"}

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=b"private")

    selected, proof = exercise_owned_native_batch(
        record, "base", 29877, {}, {}, SOURCE, SOURCE, SOURCE,
        "1" * 64, "2" * 64, "3" * 64, pending, NOW + timedelta(minutes=30),
        inspector=lambda *args: "", ownership=lambda *args: {"live_ownership_verified": True},
        preflight=lambda *args, **kwargs: {
            "native_container_id": native, "native_batch_preflight_verified": True},
        batch=batch,
        gateway_factory=lambda *args, **kwargs: (
            lambda *request: (202, {"ok": True})),
        private_request=private_request, poll=poll,
        material=lambda *args, **kwargs: {"verified": True},
        run=run, clock=lambda: NOW)
    assert selected == bureau_job
    assert proof["final_native_preflight"]["native_container_id"] == native
    assert pending.read_text(encoding="utf-8") == "private pending state"
    assert "file-backed bureau poll" in calls
