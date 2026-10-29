"""Nonroot tests for the dormant, fixed package transfer boundary."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_checkpoint_transfer as subject


def test_guest_script_is_syntactically_closed():
    compile(subject.GUEST_COPY, "<fixed-guest-copy>", "exec")
    assert "install_once" not in subject.GUEST_COPY
    assert "apt-get" not in subject.GUEST_COPY
    assert "docker" not in subject.GUEST_COPY


def test_guest_response_must_bind_exact_manifest(monkeypatch):
    vm_id = str(uuid.uuid4())
    rows = [{"name": "admission.json", "sha256": "a" * 64, "size": 8}]
    monkeypatch.setattr(subject.probe, "_pinned", lambda binding: [])
    monkeypatch.setattr(subject, "_ssh_admin", lambda *args, **kwargs:
                        subject.release.encode({
                            "schema": "elevenid.rootless-package-guest-copy/v1",
                            "vm_id": vm_id,
                            "manifest_sha256": "0" * 64,
                            "files": 1, "mode": "create",
                            "stage_device": 1, "stage_inode": 2,
                            "target_device": 3, "target_inode": 4}))
    with pytest.raises(ValueError, match="guest transfer differs"):
        subject._guest_copy({}, vm_id, rows, "create", 1001)


def test_imported_checkout_module_refused_for_private_source(tmp_path):
    with pytest.raises(ValueError, match="imported source differs"):
        subject._loaded_closure(
            tmp_path,
            {"installer_test_vm_rootless_checkpoint_transfer.py": "a" * 64})


def test_historical_admission_module_drift_refused(tmp_path, monkeypatch):
    module = b"archive-v1"
    controller = b"controller-v1"
    checkpoint = b"checkpoint"
    monkeypatch.setattr(subject.archive, "private_file",
                        lambda path, *_args, **_kwargs:
                        module if path.name.endswith("admission.py")
                        else controller)
    result = {"module_sha256": subject.release.digest(module),
              "controller_sha256": subject.release.digest(controller)}
    binding = {"checkpoint_sha256": subject.release.digest(checkpoint)}
    assert subject._historical_source(tmp_path, result, checkpoint,
                                      binding) == module
    result["controller_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="admitted source differs"):
        subject._historical_source(tmp_path, result, checkpoint, binding)


def test_existing_intent_refuses_before_guest_or_vm_call(tmp_path, monkeypatch):
    vm_id = str(uuid.uuid4())
    copy_id = str(uuid.uuid4())
    (tmp_path / (vm_id + subject.INTENT_SUFFIX)).write_bytes(b"prior")
    marker = []
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)

    class Lease:
        def __enter__(self):
            self.parent = parent
            return self

        def __exit__(self, *_):
            return False

    try:
        monkeypatch.setattr(subject.os, "geteuid", lambda: 0)
        monkeypatch.setattr(subject, "ControllerLease", lambda registry: Lease())
        monkeypatch.setattr(subject.source_admission, "admit", lambda **_:
                            {name: "a" * 64 for name in
                             subject.HOST_MODULES + subject.GUEST_MODULES})
        monkeypatch.setattr(subject, "_loaded_closure", lambda *_: None)
        monkeypatch.setattr(subject.resumed, "bound_resumed",
                            lambda **_: marker.append("VM") or {})
        monkeypatch.setattr(subject, "_ssh_admin",
                            lambda *_args, **_kwargs: marker.append("SSH"))
        with pytest.raises(ValueError, match="already attempted"):
            subject.transfer_once(
                source=tmp_path, registry=tmp_path,
                runtime_parent=tmp_path, source_git=tmp_path,
                source_dir=tmp_path, source_commit="a" * 40,
                vm_id=vm_id, copy_vm_id=copy_id)
        assert marker == []
    finally:
        os.close(parent)
