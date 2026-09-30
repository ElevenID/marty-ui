#!/usr/bin/env python3
"""Read-only beta passport continuity snapshot after the scoped fence.

This is a component of the later protected predeletion/final producers. It
does not authenticate historical installer execution, qualify Python deletion,
or claim Rust acceptance. A protected producer must separately attest the
installation before consuming this observed snapshot for acceptance.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Callable

try:
    from .probe_passport_beta_fence_target import observe_fenced
    from .probe_passport_beta_fence_direct_writes import probe_direct_writes
    from .probe_passport_beta_host import HostProbeError, beta_psql, run
    from .probe_passport_beta_fence_direct_writes import ERRORS
except ImportError:
    from probe_passport_beta_fence_target import observe_fenced
    from probe_passport_beta_fence_direct_writes import probe_direct_writes
    from probe_passport_beta_host import HostProbeError, beta_psql, run
    from probe_passport_beta_fence_direct_writes import ERRORS


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts/sql/passport-beta-fence-verify.sql"
WSL_POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
WSL_PATH = "/usr/bin/wslpath"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
DECIMAL = re.compile(r"[0-9]+\Z")
OCI_DIGEST = re.compile(r".+@(sha256:[0-9a-f]{64})\Z")
OBSERVED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z"
)
ZERO_COUNT_WATERMARK_SQL = (
    "SELECT (SELECT count(*) FROM issuance_service.physical_document_jobs)::text "
    "|| '|' || txid_current()::text || '|' || "
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


def host_fence_marker(
    runner: Callable[[list[str]], str] = run,
) -> Path:
    """Use the same OS known folder as the PowerShell installer, not an env var."""
    if os.name == "nt":
        buffer = ctypes.create_unicode_buffer(32768)
        try:
            status = ctypes.windll.shell32.SHGetFolderPathW(None, 35, None, 0, buffer)
        except (AttributeError, OSError) as exc:
            raise HostProbeError("Windows beta host fence record location is unavailable") from exc
        require(status == 0 and bool(buffer.value),
                "Windows beta host fence record location is unavailable")
        directory = Path(buffer.value)
    else:
        require("microsoft" in os.uname().release.lower(),
                "Beta host fence snapshot requires Windows or WSL")
        require(Path(WSL_POWERSHELL).is_file() and Path(WSL_PATH).is_file(),
                "Pinned WSL beta host bridge is unavailable")
        win_dir = runner([
            WSL_POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
            "[Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)",
        ])
        require(bool(win_dir) and "\n" not in win_dir and "\r" not in win_dir,
                "Windows beta host fence record location is ambiguous")
        linux_dir = runner([WSL_PATH, "-u", win_dir])
        require(bool(linux_dir) and linux_dir.startswith("/")
                and "\n" not in linux_dir and "\r" not in linux_dir,
                "WSL beta host fence record location is invalid")
        directory = Path(linux_dir)
    return directory / "ElevenID-Marty-elevenid-beta-passport-fence.pending"


def host_receipt_path(value: str, runner: Callable[[list[str]], str] = run) -> Path:
    """Map the installer's Windows absolute receipt path into the caller OS."""
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z]:\\[^\r\n]+", value)
            is not None, "Fence host record receipt path is invalid")
    if os.name == "nt":
        return Path(value)
    require(Path(WSL_PATH).is_file(), "Pinned WSL receipt path bridge is unavailable")
    mapped = runner([WSL_PATH, "-u", value])
    require(bool(mapped) and mapped.startswith("/")
            and "\n" not in mapped and "\r" not in mapped,
            "WSL fence receipt path is invalid")
    return Path(mapped)


def validate_direct_probe(probe: dict[str, Any], *, postgres: str,
                          database_uid: str, epoch: int,
                          docker: dict[str, Any]) -> None:
    require(isinstance(probe, dict)
            and probe.get("schema") == "marty.passport-beta-fence-direct-probe/v1"
            and probe.get("method") == "postgresql_transaction_rollback"
            and probe.get("postgres_container_id") == postgres
            and probe.get("database_uid") == database_uid
            and probe.get("fence_epoch") == epoch
            and probe.get("docker_context") == docker.get("context")
            and probe.get("docker_daemon_id") == docker.get("daemon_id")
            and probe.get("session_user") == "marty"
            and probe.get("current_user") == "marty"
            and re.fullmatch(r"[0-9a-f]{32}", str(probe.get("probe_nonce"))) is not None
            and type(probe.get("observation_watermark")) is int
            and probe["observation_watermark"] > 0
            and OBSERVED_AT.fullmatch(str(probe.get("observed_at_utc"))) is not None
            and probe.get("rejections") == {
                surface: {"valid_without_fence": True, "sqlstate": "55000",
                          "message": message}
                for surface, message in ERRORS.items()
            }
            and probe.get("unrelated_writes") == {
                "issuance_transactions": {"verified": True, "rolled_back": True},
                "non_passport_flow_definitions": {"verified": True,
                                                  "rolled_back": True},
            }
            and probe.get("receipt_sha256") == digest({
                key: value for key, value in probe.items()
                if key != "receipt_sha256"
            }), "Direct beta fence probe receipt is invalid")


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
            and isinstance(first_probe, dict),
            "Protected fence identity or first write probe is invalid")
    installed_at = installation.get("fence_installed_at_utc")
    require(isinstance(installed_at, str)
            and OBSERVED_AT.fullmatch(installed_at) is not None
            and isinstance(first_probe.get("observed_at_utc"), str)
            and OBSERVED_AT.fullmatch(first_probe["observed_at_utc"]) is not None
            and installed_at < first_probe["observed_at_utc"],
            "Installed fence did not precede the first direct write probe")

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
    require(installation.get("beta_services") == beta["services"]
            and SHA256.fullmatch(str(installation.get("verify_sql_sha256"))) is not None
            and SHA.fullmatch(str(installation.get("source_commit"))) is not None
            and SHA256.fullmatch(str(installation.get("approved_target_observation_sha256"))) is not None,
            "Protected source or old beta service generation differs from installation")
    validate_direct_probe(first_probe, postgres=postgres,
                          database_uid=f"postgresql:{system_id}:{database_oid}",
                          epoch=fence["epoch"], docker=docker)
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

    sql_bytes = (verify_sql.encode() if verify_sql is not None else VERIFY.read_bytes())
    require(hashlib.sha256(sql_bytes).hexdigest() == installation["verify_sql_sha256"],
            "Protected beta fence verifier differs from installation")
    sql = sql_bytes.decode("utf-8")
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
    validate_direct_probe(fresh_probe, postgres=postgres,
                          database_uid=f"postgresql:{system_id}:{database_oid}",
                          epoch=fence["epoch"], docker=docker)
    require(fresh_probe["observation_watermark"] > first_probe["observation_watermark"],
            "Fresh direct beta fence probe is stale")
    watermark = psql(ZERO_COUNT_WATERMARK_SQL, runner, postgres).split("|", 2)
    require(len(watermark) == 3 and DECIMAL.fullmatch(watermark[0]) is not None
            and int(watermark[0]) == 0,
            "Existing beta passport jobs require individual artifact readability proof")
    require(DECIMAL.fullmatch(watermark[1]) is not None
            and OBSERVED_AT.fullmatch(watermark[2]) is not None
            and int(watermark[1]) > fresh_probe["observation_watermark"],
            "Beta drain observation watermark is not later than direct write probe")
    final = observer()
    require(final == observed, "Beta or production inventory changed during cutover snapshot")

    database_uid = f"postgresql:{system_id}:{database_oid}"
    result = {
        "schema": "marty.passport-beta-cutover-snapshot/v1",
        "status": "observed",
        "installation_provenance": "local_host_continuity_only",
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
        "fence_installed_at_utc": installed_at,
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
        "observation_watermark": int(watermark[1]),
        "observed_at_utc": watermark[2],
        "production_snapshot_sha256": observed["production"]["sha256"],
        "production_attachments_sha256": observed["production_attachments_sha256"],
    }
    result["snapshot_sha256"] = digest(result)
    return result


def main() -> int:
    try:
        from .check_passport_beta_fence_authority import protected_source, protected_file
    except ImportError:
        from check_passport_beta_fence_authority import protected_source, protected_file
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fence-installation-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        head = protected_source(run)
        protected_file("scripts/sql/passport-beta-fence-verify.sql", run)
        protected_file("scripts/probe_passport_beta_cutover_snapshot.py", run)
        protected_file("scripts/probe_passport_beta_fence_target.py", run)
        protected_file("scripts/probe_passport_beta_fence_direct_writes.py", run)
        protected_file("scripts/probe_passport_beta_host.py", run)
        protected_file("deploy-config/passport-beta-fence-approved-target.json", run)
        marker = host_fence_marker()
        record = json.loads(marker.read_text(encoding="utf-8"))
        require(isinstance(record, dict)
                and record.get("schema") == "marty.passport-beta-fence-host-record/v1"
                and isinstance(record.get("receipt_path"), str)
                and host_receipt_path(record["receipt_path"]).resolve()
                    == args.fence_installation_receipt.resolve()
                and record.get("source_commit") == head,
                "Completed protected beta host fence record is invalid")
        receipt_bytes = args.fence_installation_receipt.read_bytes()
        require(hashlib.sha256(receipt_bytes).hexdigest()
                == record.get("receipt_file_sha256"),
                "Fence receipt bytes differ from completed host record")
        installation = json.loads(receipt_bytes)
        approval = json.loads((ROOT / "deploy-config/passport-beta-fence-approved-target.json")
                              .read_text(encoding="utf-8"))
        require(isinstance(installation, dict) and isinstance(approval, dict)
                and installation.get("source_commit") == head
                and installation.get("approved_target_observation_sha256")
                    == record.get("approved_target_observation_sha256")
                    == approval.get("observation_sha256")
                and installation.get("credentials_deletion_head")
                    == approval.get("credentials_deletion_head"),
                "Fence receipt differs from protected host approval")
        result = collect(installation)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (HostProbeError, OSError, ValueError) as exc:
        raise SystemExit(f"Beta passport cutover snapshot failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
