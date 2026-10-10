"""A new signed source may inherit only the same live, fully fenced beta."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from scripts import check_passport_beta_fence_rebind_authority as rebind
from scripts.probe_passport_beta_host import HostProbeError


def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "repo"
    sql = root / "scripts" / "sql" / "fence.sql"
    sql.parent.mkdir(parents=True)
    sql.write_bytes(b"SELECT 1;\n")
    target = tmp_path / "preinstall.json"
    target.write_text('{"observation_sha256":"approved"}\n', encoding="utf-8")
    old = {
        "schema": "marty.passport-beta-fence-installation/v1",
        "source_commit": rebind.PRIOR_SOURCE,
        "verify_sql_sha256": hashlib.sha256(sql.read_bytes()).hexdigest(),
        "approved_target_observation_sha256": "approved",
        "production_snapshot_sha256": "production",
        "production_attachments_sha256": "attachments",
        "beta_services": {"issuance": {"container_id": "old-writer"}},
        "postgres_container_id": "postgres",
        "postgres_system_identifier": "123",
        "database_oid": "456",
        "fence": {"epoch": 17},
        "direct_database_probe": {"observed_at_utc": "prior"},
        "post_install_observation_sha256": "inventory",
    }
    receipt = tmp_path / "old-receipt.json"
    receipt.write_text(json.dumps(old) + "\n", encoding="utf-8")
    monkeypatch.setattr(rebind, "ROOT", root)
    monkeypatch.setattr(rebind, "SQL_FILES", (sql,))
    monkeypatch.setattr(rebind, "VERIFY", sql)
    monkeypatch.setattr(rebind, "check_authority", lambda *args, observer: {
        "source": {"release": rebind.NEXT_RELEASE,
                   "source_commit": "b" * 40,
                   "manifest_sha256": "n" * 64},
        "target_observation_sha256": observer()["observation_sha256"],
        "production_snapshot_sha256": "production",
        "production_attachments_sha256": "attachments",
        "beta_services": old["beta_services"],
        "postgres_container_id": "postgres",
        "postgres_system_identifier": "123",
        "database_oid": "456",
    })
    monkeypatch.setattr(rebind, "manifest_source", lambda *args, **kwargs: {
        "release": rebind.PRIOR_RELEASE, "manifest_sha256": "p" * 64,
    })
    monkeypatch.setattr(rebind, "run", lambda _command: "")
    monkeypatch.setattr(rebind.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(stdout=b"SELECT 1;\n"))
    monkeypatch.setattr(rebind, "collect", lambda installation: {
        "fence_epoch": installation["fence"]["epoch"],
        "production_snapshot_sha256": "production",
        "production_attachments_sha256": "attachments",
        "direct_database_probe": {"observed_at_utc": "fresh"},
        "beta_inventory_attestation_sha256": "inventory",
        "snapshot_sha256": "s" * 64,
        "observed_at_utc": "2026-10-10T18:00:00.000Z",
    })
    return sql, target, receipt


def invoke(target: Path, receipt: Path):
    return rebind.rebind_authority(
        Path("new/stack-manifest.json"), Path("baseline/stack-manifest.json"),
        Path("prior/stack-manifest.json"), target, receipt,
    )


def test_rebind_retains_fence_and_records_new_probe_and_prior_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, target, receipt = prepared(tmp_path, monkeypatch)
    original = receipt.read_bytes()
    result = invoke(target, receipt)
    rebound = result["receipt"]
    assert result["verified"] is True
    assert rebound["source_commit"] == "b" * 40
    assert rebound["fence"]["epoch"] == 17
    assert rebound["direct_database_probe"]["observed_at_utc"] == "fresh"
    assert rebound["rebind"]["prior_receipt_file_sha256"] == hashlib.sha256(
        original
    ).hexdigest()
    assert receipt.read_bytes() == original


def test_rebind_rejects_sql_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sql, target, receipt = prepared(tmp_path, monkeypatch)
    sql.write_bytes(b"SELECT 2;\n")
    with pytest.raises(HostProbeError, match="Fence SQL changed"):
        invoke(target, receipt)


def test_rebind_rejects_changed_production(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, target, receipt = prepared(tmp_path, monkeypatch)
    old = json.loads(receipt.read_text(encoding="utf-8"))
    old["production_snapshot_sha256"] = "different"
    receipt.write_text(json.dumps(old) + "\n", encoding="utf-8")
    with pytest.raises(HostProbeError, match="Prior receipt differs"):
        invoke(target, receipt)


def test_rebind_rejects_repeat_or_untrusted_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sql, target, receipt = prepared(tmp_path, monkeypatch)
    old = json.loads(receipt.read_text(encoding="utf-8"))
    old["rebind"] = {"schema": "already-rebound"}
    receipt.write_text(json.dumps(old), encoding="utf-8")
    with pytest.raises(HostProbeError, match="Completed v1.1.240"):
        invoke(target, receipt)
    inside = sql.parent / "old-receipt.json"
    inside.write_text(json.dumps(old), encoding="utf-8")
    with pytest.raises(HostProbeError, match="outside protected source"):
        invoke(target, inside)


def test_rebind_rejects_failed_fresh_fence_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, target, receipt = prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(rebind, "collect", lambda _installation: (_ for _ in ()).throw(
        HostProbeError("fresh fence probe failed")))
    with pytest.raises(HostProbeError, match="fresh fence probe failed"):
        invoke(target, receipt)


@pytest.mark.skipif(os.name != "nt", reason="Windows atomic host record replacement")
@pytest.mark.parametrize("collision", [False, True])
def test_windows_rebind_record_preserves_old_marker_or_backup(
    tmp_path: Path, collision: bool,
) -> None:
    helper = Path(__file__).resolve().parents[1] / "scripts/beta-passport-fence-rebind-record.ps1"
    harness = tmp_path / "exercise.ps1"
    harness.write_text("""
param([string]$Helper, [string]$Root, [switch]$Collision)
$ErrorActionPreference = 'Stop'
function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
. $Helper
$marker = Join-Path $Root 'marker.json'
$output = Join-Path $Root 'receipt.json'
$old = [Text.Encoding]::UTF8.GetBytes('old-marker')
$new = [Text.Encoding]::UTF8.GetBytes('new-marker')
$receipt = [Text.Encoding]::UTF8.GetBytes('new-receipt')
[IO.File]::WriteAllBytes($marker, $old)
$backup = $marker + '.before-rebind-v11241'
if ($Collision) { [IO.File]::WriteAllText($backup, 'existing-backup') }
try {
    Write-BetaFenceReboundRecord -Output $output -ReceiptBytes $receipt `
        -MarkerPath $marker -MarkerBytes $new -OldMarkerBytes $old
    if ($Collision) { throw 'Expected collision failure' }
} catch {
    if (-not $Collision) { throw }
}
if ($Collision) {
    if ([IO.File]::ReadAllText($marker) -cne 'old-marker' -or
        [IO.File]::ReadAllText($backup) -cne 'existing-backup' -or
        (Test-Path -LiteralPath $output)) { throw 'Collision changed protected record' }
} else {
    if ([IO.File]::ReadAllText($marker) -cne 'new-marker' -or
        [IO.File]::ReadAllText($backup) -cne 'old-marker' -or
        [IO.File]::ReadAllText($output) -cne 'new-receipt') {
        throw 'Atomic replacement or backup differed'
    }
}
""", encoding="utf-8")
    command = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(harness),
        "-Helper", str(helper), "-Root", str(tmp_path),
    ]
    if collision:
        command.append("-Collision")
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
