"""Cutover snapshots bind fresh probes to the installed fence and old writer."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts import probe_passport_beta_cutover_snapshot as snapshot
from scripts import collect_passport_predeletion_drain as drain
from scripts.probe_passport_beta_host import HostProbeError


POSTGRES = "a" * 64
WRITER = "b" * 64
FENCE = {"schema": "marty.passport-beta-fence-verification/v1",
         "phase": "fully_fenced", "epoch": 4, "functions_md5": {}}


def evidence() -> tuple[dict, dict, dict]:
    observed = {
        "schema": "marty.passport-beta-fence-postinstall-target/v1",
        "observation_sha256": "c" * 64,
        "production_attachments_sha256": "d" * 64,
        "production": {"sha256": "e" * 64},
        "docker": {"context": "desktop-linux", "daemon_id": "synthetic-daemon"},
        "beta": {
            "postgres_system_identifier": "12345", "database_oid": "67890",
            "services": {
                "postgres": {"container_id": POSTGRES},
                "issuance": {"container_id": WRITER, "restart_count": 0,
                             "started_at": "2026-09-29T00:00:00Z",
                             "configured_image": "ghcr.io/elevenid/issuance@sha256:" + "f" * 64},
            },
            "drain": {"verified": True, "evidence": {
                "in_flight_jobs": 0, "legacy_or_unknown_artifacts": 0,
                "active_physical_document_flows": 0,
            }},
        },
    }
    first = {"postgres_container_id": POSTGRES,
             "schema": "marty.passport-beta-fence-direct-probe/v1",
             "method": "postgresql_transaction_rollback",
             "docker_context": "desktop-linux", "docker_daemon_id": "synthetic-daemon",
             "database_uid": "postgresql:12345:67890", "fence_epoch": 4,
             "observation_watermark": 10,
             "observed_at_utc": "2026-09-29T00:00:01.000Z",
             "session_user": "marty", "current_user": "marty",
             "probe_nonce": "a" * 32,
             "rejections": {surface: {"valid_without_fence": True, "sqlstate": "55000",
                         "message": message} for surface, message in snapshot.ERRORS.items()},
             "unrelated_writes": {
                 "issuance_transactions": {"verified": True, "rolled_back": True},
                 "non_passport_flow_definitions": {"verified": True,
                                                   "rolled_back": True},
             }}
    first["receipt_sha256"] = snapshot.digest(first)
    installation = {
        "schema": "marty.passport-beta-fence-installation/v1",
        "postgres_container_id": POSTGRES,
        "postgres_system_identifier": "12345", "database_oid": "67890",
        "fence": FENCE, "direct_database_probe": first,
        "fence_installed_at_utc": "2026-09-29T00:00:00.000Z",
        "source_commit": "a" * 40,
        "approved_target_observation_sha256": "f" * 64,
        "beta_services": observed["beta"]["services"],
        "verify_sql_sha256": hashlib.sha256(b"SELECT 1").hexdigest(),
        "post_install_observation_sha256": "c" * 64,
        "production_snapshot_sha256": "e" * 64,
        "production_attachments_sha256": "d" * 64,
    }
    direct = deepcopy(first)
    direct["observation_watermark"] = 12
    direct["observed_at_utc"] = "2026-09-29T00:00:02.000Z"
    direct["receipt_sha256"] = snapshot.digest({
        key: value for key, value in direct.items() if key != "receipt_sha256"
    })
    return installation, observed, direct


def collect_fixture(
    installation: dict, observed: dict, direct: dict, *,
    total_jobs: str = "0", final: dict | None = None,
) -> dict:
    observations = iter([observed, final if final is not None else observed])

    def psql(sql: str, _runner, container: str) -> str:
        assert container == POSTGRES
        if "pg_get_functiondef" in sql or sql.endswith("SELECT 1"):
            return json.dumps(FENCE)
        if sql == snapshot.ZERO_COUNT_WATERMARK_SQL:
            return total_jobs + "|13|2026-09-29T00:00:03.000Z"
        raise AssertionError(sql)

    return snapshot.collect(
        installation, observer=lambda: next(observations), psql=psql,
        direct_probe=lambda *args, **kwargs: direct,
        runner=lambda command: "unused", verify_sql="SELECT 1",
    )


def test_snapshot_binds_zero_job_beta_to_fresh_write_probe() -> None:
    installation, observed, direct = evidence()
    result = collect_fixture(installation, observed, direct)
    assert result["status"] == "observed"
    assert result["writer_container_id"] == WRITER
    assert result["writer_generation"] == 0
    assert result["installation_receipt_sha256"] == snapshot.digest(installation)
    assert result["fence_installed_at_utc"] == installation["fence_installed_at_utc"]
    assert result["counts"]["unreadable_artifact_count"] == 0
    assert result["observation_watermark"] > direct["observation_watermark"]
    assert result["snapshot_sha256"] == snapshot.digest({
        key: value for key, value in result.items() if key != "snapshot_sha256"
    })


def test_predeletion_drain_projects_same_writer_and_probe() -> None:
    installation, observed, direct = evidence()
    result = collect_fixture(installation, observed, direct)
    report = drain.collect(
        installation, result, installation_file_sha256="1" * 64,
        snapshot_file_sha256="2" * 64, source_commit="a" * 40,
    )
    assert report["status"] == "observed_unattested"
    proof = report["probe"]["evidence"]
    assert proof["legacy_source"]["drain_watermark"] == direct[
        "observation_watermark"]
    assert proof["legacy_source"]["writer_container_id"] == WRITER
    assert proof["passport_write_fence"]["direct_database_probe"] == direct


def test_predeletion_drain_rejects_changed_writer_and_counts() -> None:
    installation, observed, direct = evidence()
    result = collect_fixture(installation, observed, direct)
    result["writer_generation"] = 1
    result["snapshot_sha256"] = snapshot.digest({
        key: value for key, value in result.items() if key != "snapshot_sha256"
    })
    with pytest.raises(HostProbeError, match="writer generation"):
        drain.collect(installation, result, installation_file_sha256="1" * 64,
                      snapshot_file_sha256="2" * 64, source_commit="a" * 40)
    result["writer_generation"] = 0
    result["counts"]["total_job_count"] = 1
    result["snapshot_sha256"] = snapshot.digest({
        key: value for key, value in result.items() if key != "snapshot_sha256"
    })
    with pytest.raises(HostProbeError, match="counts"):
        drain.collect(installation, result, installation_file_sha256="1" * 64,
                      snapshot_file_sha256="2" * 64, source_commit="a" * 40)


def test_predeletion_drain_rejects_changed_installation_binding() -> None:
    installation, observed, direct = evidence()
    result = collect_fixture(installation, observed, direct)
    installation["source_commit"] = "b" * 40
    with pytest.raises(HostProbeError, match="protected fence receipt"):
        drain.collect(installation, result, installation_file_sha256="1" * 64,
                      snapshot_file_sha256="2" * 64, source_commit="a" * 40)


def test_snapshot_rejects_existing_jobs_without_readability_proof() -> None:
    installation, observed, direct = evidence()
    with pytest.raises(HostProbeError, match="individual artifact readability"):
        collect_fixture(installation, observed, direct, total_jobs="1")


def test_snapshot_rejects_same_container_restart_during_probe() -> None:
    installation, observed, direct = evidence()
    changed = deepcopy(observed)
    changed["beta"]["services"]["issuance"]["restart_count"] = 1
    with pytest.raises(HostProbeError, match="inventory changed"):
        collect_fixture(installation, observed, direct, final=changed)


def test_snapshot_rejects_stale_direct_probe() -> None:
    installation, observed, direct = evidence()
    direct["observation_watermark"] = 10
    direct["receipt_sha256"] = snapshot.digest({
        key: value for key, value in direct.items() if key != "receipt_sha256"
    })
    with pytest.raises(HostProbeError, match="Fresh direct beta fence probe"):
        collect_fixture(installation, observed, direct)


def test_snapshot_rejects_fence_timestamp_after_first_probe() -> None:
    installation, observed, direct = evidence()
    installation["fence_installed_at_utc"] = "2026-09-29T00:00:01.000Z"
    with pytest.raises(HostProbeError, match="Installed fence did not precede"):
        collect_fixture(installation, observed, direct)


def test_snapshot_rejects_forged_first_probe_rejection() -> None:
    installation, observed, direct = evidence()
    installation["direct_database_probe"]["rejections"]["physical_document_jobs"]["message"] = "wrong"
    installation["direct_database_probe"]["receipt_sha256"] = snapshot.digest({
        key: value for key, value in installation["direct_database_probe"].items()
        if key != "receipt_sha256"
    })
    with pytest.raises(HostProbeError, match="Direct beta fence probe receipt"):
        collect_fixture(installation, observed, direct)


def test_snapshot_requires_unrelated_writes_in_both_probes() -> None:
    installation, observed, direct = evidence()
    installation["direct_database_probe"]["unrelated_writes"].pop(
        "issuance_transactions")
    installation["direct_database_probe"]["receipt_sha256"] = snapshot.digest({
        key: value for key, value in installation["direct_database_probe"].items()
        if key != "receipt_sha256"
    })
    with pytest.raises(HostProbeError, match="Direct beta fence probe receipt"):
        collect_fixture(installation, observed, direct)

    installation, observed, direct = evidence()
    direct["unrelated_writes"]["non_passport_flow_definitions"]["verified"] = False
    direct["receipt_sha256"] = snapshot.digest({
        key: value for key, value in direct.items() if key != "receipt_sha256"
    })
    with pytest.raises(HostProbeError, match="Direct beta fence probe receipt"):
        collect_fixture(installation, observed, direct)


def test_snapshot_rejects_numeric_unrelated_write_proof() -> None:
    installation, observed, direct = evidence()
    direct["unrelated_writes"]["issuance_transactions"]["verified"] = 1
    direct["receipt_sha256"] = snapshot.digest({
        key: value for key, value in direct.items() if key != "receipt_sha256"
    })
    with pytest.raises(HostProbeError, match="Direct beta fence probe receipt"):
        collect_fixture(installation, observed, direct)


def test_snapshot_rejects_changed_verifier_bytes() -> None:
    installation, observed, direct = evidence()
    installation["verify_sql_sha256"] = "0" * 64
    with pytest.raises(HostProbeError, match="verifier differs"):
        collect_fixture(installation, observed, direct)


def test_zero_count_and_watermark_are_read_together_after_direct_probe() -> None:
    installation, observed, direct = evidence()
    calls: list[str] = []

    def psql(sql: str, _runner, _container: str) -> str:
        if "pg_get_functiondef" in sql or sql.endswith("SELECT 1"):
            calls.append("verify")
            return json.dumps(FENCE)
        assert sql == snapshot.ZERO_COUNT_WATERMARK_SQL
        calls.append("count_with_watermark")
        return "0|13|2026-09-29T00:00:03.000Z"

    def probe(*_args, **_kwargs):
        calls.append("direct_probe")
        return direct

    observations = iter([observed, observed])
    snapshot.collect(installation, observer=lambda: next(observations), psql=psql,
                     direct_probe=probe, runner=lambda _args: "unused",
                     verify_sql="SELECT 1")
    assert calls == ["verify", "direct_probe", "count_with_watermark"]


def test_host_record_uses_os_known_folder_not_programdata_env(monkeypatch) -> None:
    monkeypatch.setenv("ProgramData", "C:/forged")
    monkeypatch.setattr(snapshot, "os", SimpleNamespace(name="nt"))

    def known_folder(_hwnd, folder, _token, _flags, buffer):
        assert folder == 35
        buffer.value = "C:/trusted-program-data"
        return 0

    monkeypatch.setattr(snapshot.ctypes, "windll", SimpleNamespace(
        shell32=SimpleNamespace(SHGetFolderPathW=known_folder)), raising=False)
    assert snapshot.host_fence_marker() == snapshot.Path(
        "C:/trusted-program-data/ElevenID-Marty-elevenid-beta-passport-fence.pending")


def test_wsl_host_record_resolves_windows_known_folder(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ProgramData", "C:/forged")
    monkeypatch.setattr(snapshot, "os", SimpleNamespace(
        name="posix", uname=lambda: SimpleNamespace(release="6.6.0-microsoft-standard-WSL2")))
    powershell = tmp_path / "powershell.exe"
    wslpath = tmp_path / "wslpath"
    powershell.touch()
    wslpath.touch()
    monkeypatch.setattr(snapshot, "WSL_POWERSHELL", str(powershell))
    monkeypatch.setattr(snapshot, "WSL_PATH", str(wslpath))
    commands: list[list[str]] = []

    def runner(command: list[str]) -> str:
        commands.append(command)
        return "D:\\SystemData" if command[0] == str(powershell) else "/mnt/d/SystemData"

    assert snapshot.host_fence_marker(runner) == snapshot.Path(
        "/mnt/d/SystemData/ElevenID-Marty-elevenid-beta-passport-fence.pending")
    assert commands[0][0] == str(powershell)
    assert commands[1] == [str(wslpath), "-u", "D:\\SystemData"]


def test_wsl_receipt_path_maps_installer_windows_path(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(snapshot, "os", SimpleNamespace(name="posix"))
    wslpath = tmp_path / "wslpath"
    wslpath.touch()
    monkeypatch.setattr(snapshot, "WSL_PATH", str(wslpath))
    commands: list[list[str]] = []

    def runner(command: list[str]) -> str:
        commands.append(command)
        return "/mnt/d/evidence/fence.json"

    assert snapshot.host_receipt_path("D:\\evidence\\fence.json", runner) == snapshot.Path(
        "/mnt/d/evidence/fence.json")
    assert commands == [[str(wslpath), "-u", "D:\\evidence\\fence.json"]]
