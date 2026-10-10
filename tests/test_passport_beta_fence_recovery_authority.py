"""Recovery must bind the saved observation and unchanged signed fence SQL."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import check_passport_beta_fence_recovery_authority as recovery
from scripts.probe_passport_beta_host import HostProbeError


def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "repo"
    sql = root / "scripts" / "sql" / "fence.sql"
    sql.parent.mkdir(parents=True)
    sql.write_bytes(b"SELECT 1;\n")
    target = tmp_path / "preinstall.json"
    target.write_bytes(b'{"observation_sha256":"approved"}\n')
    monkeypatch.setattr(recovery, "ROOT", root)
    monkeypatch.setattr(recovery, "SQL_FILES", (sql,))
    monkeypatch.setattr(recovery, "check_authority", lambda *args, observer: {
        "source": {"source_commit": "b" * 40},
        "target_observation_sha256": observer()["observation_sha256"],
    })
    monkeypatch.setattr(recovery, "manifest_source", lambda *args, **kwargs: {
        "release": "marty-ui@1.1.237", "manifest_sha256": "a" * 64,
    })
    monkeypatch.setattr(recovery, "run", lambda command: "")
    monkeypatch.setattr(recovery.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(stdout=b"SELECT 1;\n"))
    return sql, target


def invoke(target: Path):
    return recovery.recovery_authority(
        Path("new/stack-manifest.json"), Path("baseline/stack-manifest.json"),
        Path("prior/stack-manifest.json"), target,
    )


def test_recovery_uses_validated_observation_bytes_for_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, target = prepared(tmp_path, monkeypatch)
    original = target.read_bytes()
    read_bytes = Path.read_bytes
    reads = 0

    def change_after_read(path: Path) -> bytes:
        nonlocal reads
        result = read_bytes(path)
        if path == target:
            reads += 1
            target.write_bytes(b'{"observation_sha256":"altered"}\n')
        return result

    monkeypatch.setattr(Path, "read_bytes", change_after_read)
    result = invoke(target)
    assert reads == 1
    assert result["target_observation_sha256"] == "approved"
    assert result["recovery"]["preinstall_target_file_sha256"] == hashlib.sha256(
        original
    ).hexdigest()
    assert result["recovery"]["compatible_prior_source_commit"] == (
        recovery.COMPATIBLE_PRIOR_SOURCE_COMMIT
    )


def test_recovery_rejects_changed_sql(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sql, target = prepared(tmp_path, monkeypatch)
    sql.write_bytes(b"SELECT 2;\n")
    with pytest.raises(HostProbeError, match="Fence SQL changed"):
        invoke(target)


def test_recovery_rejects_unverified_prior_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, target = prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(recovery, "manifest_source", lambda *args, **kwargs: {
        "release": "marty-ui@1.1.236", "manifest_sha256": "a" * 64,
    })
    with pytest.raises(HostProbeError, match="Compatible prior release"):
        invoke(target)


def test_recovery_rejects_observation_inside_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sql, _ = prepared(tmp_path, monkeypatch)
    target = sql.parent / "untrusted.json"
    target.write_text(json.dumps({"observation_sha256": "approved"}), encoding="utf-8")
    with pytest.raises(HostProbeError, match="outside protected source"):
        invoke(target)
