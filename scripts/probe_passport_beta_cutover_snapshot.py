#!/usr/bin/env python3
"""Read-only, source-bound beta passport snapshot after the scoped fence.

This is a component of the later protected predeletion/final producers. It
does not by itself qualify Python deletion or claim Rust acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

try:
    from .probe_passport_beta_fence_target import observe_fenced
    from .probe_passport_beta_fence_direct_writes import probe_direct_writes
    from .probe_passport_beta_host import HostProbeError, beta_psql, run
except ImportError:
    from probe_passport_beta_fence_target import observe_fenced
    from probe_passport_beta_fence_direct_writes import probe_direct_writes
    from probe_passport_beta_host import HostProbeError, beta_psql, run


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts/sql/passport-beta-fence-verify.sql"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"[0-9]+\Z")
OCI_DIGEST = re.compile(r".+@(sha256:[0-9a-f]{64})\Z")
OBSERVED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z"
)
WATERMARK_SQL = (
    "SELECT txid_current()::text || '|' || "
    "to_char(clock_timestamp() AT TIME ZONE 'UTC', "
    "'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def collect(
    installation: dict[str, Any],
    *,
    observer: Callable[[], dict[str, Any]] = observe_fenced,
    psql: Callable[[str, Callable[[list[str]], str], str], str] = beta_psql,
    direct_probe: Callable[..., dict[str, Any]] = probe_direct_writes,
    runner: Callable[[list[str]], str] = run,
    verify_sql: str | None = None,
) -> dict[str, Any]:
    """Bind a fresh drain/probe to the exact installation and old generation."""
    require(isinstance(installation, dict)
            and installation.get("schema") == "marty.passport-beta-fence-installation/v1",
            "Protected fence installation receipt is invalid")
    postgres = installation.get("postgres_container_id")
    system_id = str(installation.get("postgres_system_identifier", ""))
    database_oid = str(installation.get("database_oid", ""))
    fence = installation.get("fence")
    first_probe = installation.get("direct_database_probe")
    require(isinstance(postgres, str) and SHA256.fullmatch(postgres) is not None
            and DECIMAL.fullmatch(system_id) is not None
            and DECIMAL.fullmatch(database_oid) is not None
            and isinstance(fence, dict)
            and fence.get("schema") == "marty.passport-beta-fence-verification/v1"
            and fence.get("phase") == "fully_fenced"
            and type(fence.get("epoch")) is int and fence["epoch"] > 0
            and isinstance(first_probe, dict)
            and first_probe.get("postgres_container_id") == postgres
            and first_probe.get("database_uid")
                == f"postgresql:{system_id}:{database_oid}"
            and first_probe.get("fence_epoch") == fence["epoch"]
            and type(first_probe.get("observation_watermark")) is int
            and OBSERVED_AT.fullmatch(str(first_probe.get("observed_at_utc"))) is not None
            and first_probe.get("receipt_sha256") == digest({
                key: value for key, value in first_probe.items()
                if key != "receipt_sha256"
            }),
            "Protected fence identity or first write probe is invalid")

    observed = observer()
    require(observed.get("schema") == "marty.passport-beta-fence-postinstall-target/v1"
            and observed.get("observation_sha256")
                == installation.get("post_install_observation_sha256")
            and observed.get("production_attachments_sha256")
                == installation.get("production_attachments_sha256")
            and isinstance(observed.get("production"), dict)
            and observed["production"].get("sha256")
                == installation.get("production_snapshot_sha256"),
            "Beta or production inventory differs from the fence installation")
    beta = observed.get("beta")
    docker = observed.get("docker")
    require(isinstance(beta, dict) and isinstance(docker, dict)
            and beta.get("postgres_system_identifier") == system_id
            and beta.get("database_oid") == database_oid
            and isinstance(beta.get("services"), dict)
            and beta["services"].get("postgres", {}).get("container_id") == postgres
            and isinstance(docker.get("context"), str) and docker["context"]
            and isinstance(docker.get("daemon_id"), str) and docker["daemon_id"],
            "Beta PostgreSQL or Docker identity changed after fence installation")
    writer = beta["services"].get("issuance")
    require(isinstance(writer, dict)
            and isinstance(writer.get("container_id"), str)
            and SHA256.fullmatch(writer["container_id"]) is not None
            and isinstance(writer.get("started_at"), str) and writer["started_at"]
            and type(writer.get("restart_count")) is int
            and writer["restart_count"] >= 0
            and isinstance(writer.get("configured_image"), str),
            "Old beta Python writer generation is invalid")
    image = OCI_DIGEST.fullmatch(writer["configured_image"])
    require(image is not None, "Old beta Python writer image is not immutable")

    sql = verify_sql if verify_sql is not None else VERIFY.read_text(encoding="utf-8")
    session = (
        "SET marty.passport_beta_verified_project = 'elevenid-beta';\n"
        f"SET marty.passport_beta_expected_system_identifier = '{system_id}';\n"
        f"SET marty.passport_beta_expected_database_oid = '{database_oid}';\n"
    )
    try:
        verified = json.loads(psql(session + sql, runner, postgres))
    except (ValueError, OSError) as exc:
        raise HostProbeError("Scoped beta fence verifier failed") from exc
    require(verified == fence, "Scoped beta fence changed since installation")

    total = psql(
        "SELECT count(*) FROM issuance_service.physical_document_jobs",
        runner, postgres,
    )
    require(DECIMAL.fullmatch(total) is not None and int(total) == 0,
            "Existing beta passport jobs require individual artifact readability proof")
    drain = beta.get("drain")
    evidence = drain.get("evidence") if isinstance(drain, dict) else None
    require(drain.get("verified") is True if isinstance(drain, dict) else False,
            "Live beta drain is not verified")
    require(isinstance(evidence, dict)
            and evidence.get("in_flight_jobs") == 0
            and evidence.get("legacy_or_unknown_artifacts") == 0
            and evidence.get("active_physical_document_flows") == 0,
            "Live beta passport jobs or Flows remain")

    fresh_probe = direct_probe(
        postgres,
        expected_docker_context=docker["context"],
        expected_daemon_id=docker["daemon_id"],
        expected_system_identifier=system_id,
        expected_database_oid=database_oid,
        expected_fence_epoch=fence["epoch"],
    )
    require(isinstance(fresh_probe, dict)
            and fresh_probe.get("schema") == "marty.passport-beta-fence-direct-probe/v1"
            and fresh_probe.get("database_uid")
                == f"postgresql:{system_id}:{database_oid}"
            and fresh_probe.get("fence_epoch") == fence["epoch"]
            and type(fresh_probe.get("observation_watermark")) is int
            and fresh_probe["observation_watermark"]
                > first_probe["observation_watermark"]
            and fresh_probe.get("receipt_sha256") == digest({
                key: value for key, value in fresh_probe.items()
                if key != "receipt_sha256"
            }), "Fresh direct beta fence probe is invalid")
    watermark = psql(WATERMARK_SQL, runner, postgres).split("|", 1)
    require(len(watermark) == 2 and DECIMAL.fullmatch(watermark[0]) is not None
            and OBSERVED_AT.fullmatch(watermark[1]) is not None
            and int(watermark[0]) > fresh_probe["observation_watermark"],
            "Beta drain observation watermark is not later than direct write probe")
    final = observer()
    require(final == observed, "Beta or production inventory changed during cutover snapshot")

    database_uid = f"postgresql:{system_id}:{database_oid}"
    result = {
        "schema": "marty.passport-beta-cutover-snapshot/v1",
        "status": "observed",
        "installation_receipt_sha256": digest(installation),
        "database_uid": database_uid,
        "beta_cluster_uid": f"docker:{docker['daemon_id']}",
        "beta_inventory_attestation_sha256": observed["observation_sha256"],
        "writer_deployment_uid": f"elevenid-beta:issuance:{writer['container_id']}",
        "writer_container_id": writer["container_id"],
        "writer_image_digest": image.group(1),
        "writer_started_at": writer["started_at"],
        "writer_generation": writer["restart_count"],
        "fence_epoch": fence["epoch"],
        "fence_verification_sha256": digest(fence),
        "fence_first_probe": first_probe,
        "direct_database_probe": fresh_probe,
        "counts": {
            "total_job_count": 0,
            "nonterminal_job_count": 0,
            "legacy_or_unknown_artifact_count": 0,
            "unreadable_artifact_count": 0,
            "active_passport_flow_count": 0,
        },
        "observation_watermark": int(watermark[0]),
        "observed_at_utc": watermark[1],
        "production_snapshot_sha256": observed["production"]["sha256"],
        "production_attachments_sha256": observed["production_attachments_sha256"],
    }
    result["snapshot_sha256"] = digest(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fence-installation-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        installation = json.loads(args.fence_installation_receipt.read_text(encoding="utf-8"))
        result = collect(installation)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (HostProbeError, OSError, ValueError) as exc:
        raise SystemExit(f"Beta passport cutover snapshot failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
