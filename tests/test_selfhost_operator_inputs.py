"""Shared operator inputs retain file safety and command import compatibility."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import selfhost_operator_inputs as inputs


@pytest.mark.parametrize("reverse", [False, True])
def test_legacy_imports_reexport_helpers_without_running_commands(tmp_path: Path, reverse: bool) -> None:
    owners = {
        "private_file": "activate_selfhost_renewed_secrets",
        "private_empty_or_source": "stage_selfhost_renewed_secrets",
        "write_private": "provision_selfhost_renewal_identity",
        "snapshot_origin": "provision_selfhost_snapshot_identity",
    }
    # Exercise only the scripts shipped in a bundle, not the full checkout.
    scripts = tmp_path / "bundle" / "scripts"
    scripts.mkdir(parents=True)
    manifest = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text(encoding="utf-8"))
    for asset in manifest["assets"]:
        if asset.startswith("scripts/") and asset.endswith(".py"):
            shutil.copyfile(ROOT / asset, scripts / Path(asset).name)
    working = tmp_path / "run"
    working.mkdir()
    program = """
import importlib, pathlib, subprocess, sys
def forbidden(*args, **kwargs):
    raise AssertionError('import attempted to execute a command')
subprocess.run = subprocess.Popen = forbidden
owners = OWNERS
consumers = [
    'provision_selfhost_audit_identity', 'provision_selfhost_evidence_identity',
    'provision_selfhost_snapshot_identity', 'provision_selfhost_snapshot_rotator',
    'activate_selfhost_renewed_secrets',
]
if REVERSE:
    for name in reversed(consumers):
        importlib.import_module(name)
    for name in reversed(list(owners.values())):
        importlib.import_module(name)
shared = importlib.import_module('selfhost_operator_inputs')
if not REVERSE:
    assert not any(name in sys.modules for name in owners.values())
for name in consumers:
    importlib.import_module(name)
for name, owner in owners.items():
    assert getattr(importlib.import_module(owner), name) is getattr(shared, name)
assert list(pathlib.Path.cwd().iterdir()) == []
""".replace("OWNERS", repr(owners)).replace("REVERSE", repr(reverse))
    result = subprocess.run(
        [sys.executable, "-B", "-c", program], cwd=working,
        env={**os.environ, "PYTHONPATH": str(scripts)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("value", ["", "one\ntwo", "one\rtwo", "x" * 513])
def test_invalid_credentials_do_not_create_files(tmp_path: Path, value: str) -> None:
    target = tmp_path / "credential"
    with pytest.raises(ValueError, match="credential is invalid"):
        inputs.write_private(target, value)
    assert list(tmp_path.iterdir()) == []


def test_writer_is_exclusive_and_supports_policy_receipts(tmp_path: Path) -> None:
    target = tmp_path / "receipt"
    receipt = json.dumps(["policy-" + str(i) for i in range(21)])
    inputs.write_private(target, receipt, max_bytes=4096)
    assert target.read_text(encoding="ascii") == receipt + "\n"
    with pytest.raises(FileExistsError):
        inputs.write_private(target, "replacement")
    assert target.read_text(encoding="ascii") == receipt + "\n"
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert inputs.private_file(target) == receipt + "\n"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX permissions and symlinks")
def test_reader_and_writer_reject_unsafe_files(tmp_path: Path) -> None:
    target = tmp_path / "secret"
    inputs.write_private(target, "synthetic-token")
    link = tmp_path / "linked-secret"
    link.symlink_to(target)
    with pytest.raises(ValueError):
        inputs.private_file(link)
    with pytest.raises(FileExistsError):
        inputs.write_private(link, "replacement")
    assert target.read_text(encoding="ascii") == "synthetic-token\n"
    target.chmod(0o644)
    with pytest.raises(ValueError):
        inputs.private_file(target)
    target.chmod(0o600)
    target.write_text("x" * (64 * 1024 + 1), encoding="ascii")
    with pytest.raises(ValueError):
        inputs.private_file(target)
    with pytest.raises(ValueError):
        inputs.private_file(Path("relative-secret"))


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX private directories")
def test_directory_check_preserves_empty_source_and_symlink_rules(tmp_path: Path) -> None:
    directory = tmp_path / "generation"
    directory.mkdir(mode=0o700)
    assert inputs.private_empty_or_source(directory, empty=True) == directory.resolve()
    (directory / "receipt").write_text("synthetic", encoding="ascii")
    assert inputs.private_empty_or_source(directory, empty=False) == directory.resolve()
    with pytest.raises(ValueError, match="must be empty"):
        inputs.private_empty_or_source(directory, empty=True)
    link = tmp_path / "linked-generation"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError):
        inputs.private_empty_or_source(link, empty=False)
    directory.chmod(0o755)
    with pytest.raises(ValueError, match="owner-private"):
        inputs.private_empty_or_source(directory, empty=False)
    assert (directory / "receipt").read_text(encoding="ascii") == "synthetic"


@pytest.mark.parametrize("origin", [
    "http://127.0.0.1:8200", "https://external.invalid:8200", "https://localhost",
    "https://user@localhost:8200", "https://localhost:8200/v1",
    "https://localhost:8200?token=synthetic", "https://localhost:8200#fragment",
    "https://localhost:invalid",
])
def test_snapshot_origin_rejects_ambiguous_or_nonlocal_authority(origin: str) -> None:
    with pytest.raises(ValueError):
        inputs.snapshot_origin(origin)


@pytest.mark.parametrize("origin", [
    "https://127.0.0.1:8200", "https://localhost:443/", "https://[::1]:8200",
])
def test_snapshot_origin_preserves_loopback_origins(origin: str) -> None:
    assert inputs.snapshot_origin(origin) == origin.rstrip("/")
