"""Keep the local recovery helpers consistent with the authenticated installer.

This is an additional byte-consistency check after the existing installer
signature/provenance verification. It creates no alternate artifact admission.
The Python interpreter and initial operator invocation remain trusted inputs.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import zipfile

import bootstrap_kubernetes_openbao as bootstrap


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "marty.kubernetes-legacy-recovery-sources/v1"
SOURCE_FILES = (
    "deploy-config/catalog/kubernetes-application-tokens.json",
    "deploy-config/catalog/kubernetes-secrets.json",
    "scripts/bootstrap_kubernetes_openbao.py",
    "scripts/build_selfhost_image_lock.py",
    "scripts/inspect_kubernetes_legacy_credentials.py",
    "scripts/installer_acceptance.py",
    "scripts/installer_acceptance_runner.py",
    "scripts/installer_acceptance_startup.py",
    "scripts/installer_acceptance_v2.py",
    "scripts/installer_browser_runtime.py",
    "scripts/installer_candidate_authorize.py",
    "scripts/installer_candidate_controller.py",
    "scripts/installer_candidate_dispatch.py",
    "scripts/installer_candidate_hosting.py",
    "scripts/installer_candidate_rendezvous.py",
    "scripts/installer_host_admission.py",
    "scripts/installer_host_probe.py",
    "scripts/installer_live_tls_probe.py",
    "scripts/installer_release.py",
    "scripts/installer_startup_browser.py",
    "scripts/installer_startup_continuation.py",
    "scripts/installer_startup_observation.py",
    "scripts/installer_startup_process.py",
    "scripts/kubernetes_legacy_recovery_sources.py",
    "scripts/passport_remote_tls.py",
    "scripts/prepare_kubernetes_helm_values.py",
    "scripts/provision_selfhost_disposable_tls.py",
    "scripts/recover_kubernetes_legacy_credentials.py",
    "scripts/release_transaction.py",
    "scripts/reload_kubernetes_legacy_workloads.py",
    "scripts/stack_tag_gate.py",
    "scripts/stage_kubernetes_application_credentials.py",
    "scripts/verify_installer_provenance.py",
)
FILE_LIMIT = 1024 * 1024


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def source_bytes(root: Path, name: str) -> bytes:
    path = root / name
    bootstrap.require(root.is_absolute() and root.resolve() == root and path.resolve() == path,
                      "recovery source path contains an alias or symlink")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        bootstrap.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                          and before.st_mode & 0o022 == 0 and before.st_size <= FILE_LIMIT,
                          "recovery source file custody or size differs")
        raw = stream.read(FILE_LIMIT + 1)
        after, linked = os.fstat(stream.fileno()), path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                              value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    bootstrap.require(len(raw) == before.st_size and identity(before) == identity(after) == identity(linked),
                      "recovery source file changed while reading")
    return raw


def snapshot(*, root: Path = ROOT) -> dict[str, str]:
    result = {}
    for name in SOURCE_FILES:
        if name.startswith("scripts/"):
            module = sys.modules.get(Path(name).stem)
            if module is not None:
                bootstrap.require(Path(getattr(module, "__file__", "")).resolve() == root / name,
                                  "loaded recovery helper comes from a different source directory")
        result[name] = digest(source_bytes(root, name))
    return result


def authenticate(assets: Path, identity: dict, *, root: Path = ROOT) -> dict[str, str]:
    """Identity must be the in-process result of the existing verified prepare()."""
    inventory_raw = bootstrap.read_record(assets / "installer-inventory.json")
    bootstrap.require(digest(inventory_raw) == identity["inventorySha256"],
                      "authenticated recovery inventory changed before source matching")
    inventory = bootstrap.release.decode(inventory_raw)
    name = "prepared-selfhost-bundle.zip"
    matches = [entry for entry in inventory["artifacts"] if entry["name"] == name]
    bootstrap.require(len(matches) == 1, "authenticated recovery bundle inventory is ambiguous")
    maximum = bootstrap.release.ARTIFACT_MAX_BYTES[name]
    with (assets / name).open("rb") as stream:
        raw = stream.read(maximum + 1)
    bootstrap.require(len(raw) <= maximum and digest(raw) == matches[0]["sha256"],
                      "authenticated recovery bundle changed before source matching")
    local = snapshot(root=root)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            for source, expected in local.items():
                selected = [entry for entry in entries if entry.filename == "selfhost-prepared/" + source]
                bootstrap.require(len(selected) == 1, "signed recovery helper or catalog is missing or duplicated")
                entry = selected[0]
                mode = entry.external_attr >> 16
                bootstrap.require(not entry.is_dir() and entry.file_size <= FILE_LIMIT
                                  and not entry.flag_bits & 1 and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                                  and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                                  "signed recovery source entry has an unsupported type or size")
                bootstrap.require(digest(archive.read(entry)) == expected,
                                  "local recovery helper or catalog differs from the authenticated bundle")
    except zipfile.BadZipFile as error:
        raise bootstrap.BootstrapError("signed recovery source archive is invalid") from error
    bootstrap.require(snapshot(root=root) == local, "recovery source changed during artifact matching")
    return local


def recheck(expected: dict[str, str]) -> None:
    bootstrap.require(snapshot() == expected, "authenticated recovery source changed during the operation")
