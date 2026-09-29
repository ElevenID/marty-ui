"""Cutover snapshots bind fresh probes to the installed fence and old writer."""

from __future__ import annotations

from copy import deepcopy
import json

import pytest

from scripts import probe_passport_beta_cutover_snapshot as snapshot
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
             "database_uid": "postgresql:12345:67890", "fence_epoch": 4,
             "observation_watermark": 10,
             "observed_at_utc": "2026-09-29T00:00:01.000Z"}
    first["receipt_sha256"] = snapshot.digest(first)
    installation = {
        "schema": "marty.passport-beta-fence-installation/v1",
        "postgres_container_id": POSTGRES,
        "postgres_system_identifier": "12345", "database_oid": "67890",
        "fence": FENCE, "direct_database_probe": first,
        "post_install_observation_sha256": "c" * 64,
        "production_snapshot_sha256": "e" * 64,
        "production_attachments_sha256": "d" * 64,
    }
    direct = {
        "schema": "marty.passport-beta-fence-direct-probe/v1",
        "database_uid": "postgresql:12345:67890", "fence_epoch": 4,
        "observation_watermark": 12,
        "observed_at_utc": "2026-09-29T00:00:02.000Z",
        "rejections": {"physical_document_jobs": {"sqlstate": "55000"}},
    }
    direct["receipt_sha256"] = snapshot.digest(direct)
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
        if "count(*) FROM issuance_service.physical_document_jobs" in sql:
            return total_jobs
        if sql == snapshot.WATERMARK_SQL:
            return "13|2026-09-29T00:00:03.000Z"
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
    assert result["counts"]["unreadable_artifact_count"] == 0
    assert result["observation_watermark"] > direct["observation_watermark"]
    assert result["snapshot_sha256"] == snapshot.digest({
        key: value for key, value in result.items() if key != "snapshot_sha256"
    })


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
