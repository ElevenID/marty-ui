"""Synthetic checkpoint admission tests; no root, VM, APT or Docker action."""
from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_checkpoint as checkpoint  # noqa: E402


def _archive_rows():
    releases = []
    for pocket in checkpoint.archive.POCKETS:
        releases.append({"pocket": pocket,
                         "base_url": checkpoint.archive.POCKETS[pocket],
                         "inrelease_sha256": "a" * 64,
                         "keyring_sha256": "b" * 64,
                         "signer_fingerprint":
                             checkpoint.archive.ARCHIVE_FINGERPRINT,
                         "date": "2026-10-29T00:00:00+00:00",
                         "valid_until": None})
    packages = []
    for name in checkpoint.archive.TARGETS:
        packages.append({"package": name,
                         "version": checkpoint.archive.EXPECTED_VERSIONS[name],
                         "sha256": "c" * 64, "size": 10,
                         "pocket": "noble", "component": "main"})
    return {"packages": packages, "archive_releases": releases,
            "dpkg_status_sha256": checkpoint.archive.sha(b"status")}


def test_unprivileged_stage_recheck_uses_fixed_signed_inputs():
    expected = _archive_rows()
    calls = []
    def inrelease(path, keyring, pocket, now):
        assert keyring == checkpoint.archive.KEYRING
        assert path.name == pocket + ".inrelease"
        return next(row for row in expected["archive_releases"]
                    if row["pocket"] == pocket), {"signed": True}
    def index(path, hashes, component):
        assert hashes == {"signed": True}
        calls.append((path.name, component))
        return []
    def selected(_rows, package, version):
        return {"package": package, "version": version,
                "sha256": "c" * 64, "size": 10}
    with mock.patch.object(checkpoint.archive.os, "geteuid", return_value=65534), \
         mock.patch.object(checkpoint.archive, "_private_directory"), \
         mock.patch.object(checkpoint.archive, "private_file",
                           return_value=b"status"), \
         mock.patch.object(checkpoint.archive, "verify_inrelease",
                           side_effect=inrelease), \
         mock.patch.object(checkpoint.archive, "verify_index",
                           side_effect=index), \
         mock.patch.object(checkpoint.archive, "select_package",
                           side_effect=selected), \
         mock.patch.object(checkpoint.archive, "verify_deb",
                           side_effect=lambda _path, row: row):
        result = checkpoint.archive.verify_staged_bundle(
            Path("/private/bundle"), Path("/private/status"),
            checkpoint.archive.KEYRING, expected)
    assert len(calls) == (len(checkpoint.archive.POCKETS)
                          * len(checkpoint.archive.COMPONENTS))
    assert result["package_actions_authorized"] is False
    assert result["installation_authorized"] is False
    assert result["packages"] == expected["packages"]


def test_stage_recheck_refuses_wrong_signed_package_bytes():
    expected = _archive_rows()
    with mock.patch.object(checkpoint.archive.os, "geteuid", return_value=65534), \
         mock.patch.object(checkpoint.archive, "_private_directory"), \
         mock.patch.object(checkpoint.archive, "private_file",
                           return_value=b"status"), \
         mock.patch.object(checkpoint.archive, "verify_inrelease",
                           side_effect=lambda _p, _k, pocket, _n:
                           (next(row for row in expected["archive_releases"]
                                 if row["pocket"] == pocket), {})), \
         mock.patch.object(checkpoint.archive, "verify_index", return_value=[]), \
         mock.patch.object(checkpoint.archive, "select_package",
                           return_value={"package": "uidmap",
                                         "version": "wrong", "sha256": "0" * 64,
                                         "size": 10}), \
         mock.patch.object(checkpoint.archive, "verify_deb",
                           return_value={"package": "uidmap",
                                         "version": "wrong", "sha256": "0" * 64,
                                         "size": 10}):
        with pytest.raises(ValueError, match="staged package bytes differ"):
            checkpoint.archive.verify_staged_bundle(
                Path("/private/bundle"), Path("/private/status"),
                checkpoint.archive.KEYRING, expected)


def test_stage_recheck_rejects_root_identity_before_archive_calls():
    with mock.patch.object(checkpoint.archive.os, "geteuid", return_value=0), \
         mock.patch.object(checkpoint.archive, "verify_inrelease") as signature:
        with pytest.raises(ValueError, match="staged archive request invalid"):
            checkpoint.archive.verify_staged_bundle(
                Path("/private/bundle"), Path("/private/status"),
                checkpoint.archive.KEYRING, _archive_rows())
    signature.assert_not_called()


def test_fixed_child_bootstrap_reads_module_and_exact_request():
    code = (b"from pathlib import Path\n"
            b"def verify_staged_bundle(bundle,status,keyring,expected):\n"
            b" assert (bundle.name,status.name,keyring.name)=="
            b"('bundle','status','keyring')\n"
            b" return expected\n")
    expected = {"schema": "synthetic", "package_actions_authorized": False}
    done = subprocess.run(
        [sys.executable, "-I", "-B", "-c", checkpoint.CHILD_BOOTSTRAP,
         "/private/bundle", "/private/status", "/private/keyring"],
        input=code + b"\0" + checkpoint.release.encode(expected),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=True)
    assert json.loads(done.stdout) == expected


@pytest.mark.parametrize("stage_ok", [True, False])
def test_checkpoint_record_follows_two_proofs_and_stage_recheck(tmp_path,
                                                                stage_ok):
    vm = "11111111-2222-4333-8444-555555555555"
    copy_id = "33333333-4444-4555-8666-777777777777"
    module_bytes, controller_bytes = b"module", b"controller"
    result = {"module_sha256": checkpoint.archive.sha(module_bytes),
              "controller_sha256": checkpoint.archive.sha(controller_bytes)}
    result_raw = checkpoint.release.encode(result)
    stop = {"pid": 1777, "start_ticks": "17"}
    stop_raw = checkpoint.release.encode(stop)
    pending = {"intent_sha256": checkpoint.release.digest(stop_raw),
               "boot_id": "22222222-3333-4444-8555-666666666666",
               "disk_device": 4, "disk_inode": 5, "snapshot_bytes": 32}
    pending_raw = checkpoint.release.encode(pending)
    proof_value = {"admission_result_sha256": checkpoint.release.digest(result_raw),
                   "pending_sha256": checkpoint.release.digest(pending_raw),
                   "disk_sha256": "a" * 64,
                   "snapshot_sha256": "a" * 64,
                   "cleanup_result_sha256": "b" * 64}
    class Lease:
        def __enter__(self):
            self.parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
            return self
        def __exit__(self, *_):
            os.close(self.parent)
    def read(_fd, name):
        if name.endswith(checkpoint.admission.RESULT_SUFFIX):
            return result_raw, result
        if name.endswith(checkpoint.proof.stopped.PENDING_SUFFIX):
            return pending_raw, pending
        if name.endswith(checkpoint.proof.stopped.INTENT_SUFFIX):
            return stop_raw, stop
        raise AssertionError(name)
    def source_bytes(path, *_args, **_kwargs):
        return (module_bytes if Path(path) == Path(checkpoint.archive.__file__)
                else controller_bytes)
    def stage(*_args):
        events.append("stage")
        if not stage_ok:
            raise ValueError("synthetic stage refusal")
        return {"schema": "synthetic"}
    events = []
    with mock.patch.object(checkpoint.os, "geteuid", return_value=0), \
         mock.patch.object(checkpoint, "ControllerLease", return_value=Lease()), \
         mock.patch.object(checkpoint.proof, "inspect_proof",
                           side_effect=lambda **_: events.append("proof")
                           or proof_value), \
         mock.patch.object(checkpoint.create, "_read_record", side_effect=read), \
         mock.patch.object(checkpoint.archive, "private_file",
                           side_effect=source_bytes), \
         mock.patch.object(checkpoint, "_stage_recheck", side_effect=stage), \
         mock.patch.object(checkpoint.create, "_write",
                           side_effect=lambda _fd, _name, record:
                           events.append("write") or checkpoint.release.encode(record)):
        if stage_ok:
            record = checkpoint.mint_checkpoint(
                source=tmp_path, registry=tmp_path, runtime_parent=tmp_path,
                vm_id=vm, copy_vm_id=copy_id)
        else:
            with pytest.raises(ValueError, match="synthetic stage refusal"):
                checkpoint.mint_checkpoint(
                    source=tmp_path, registry=tmp_path, runtime_parent=tmp_path,
                    vm_id=vm, copy_vm_id=copy_id)
            assert events == ["proof", "stage"]
            assert list(tmp_path.iterdir()) == []
            return
    assert events == ["proof", "stage", "proof", "write"]
    assert record["package_install_authorized"] is False
    assert record["product_dispatch_authorized"] is False
