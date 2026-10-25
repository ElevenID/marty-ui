"""Root-only cloud-init seed transition tests for a disposable guest."""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("VM seeding requires Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_candidate_vm_create as creation
import installer_candidate_vm_runtime as runtime
import installer_candidate_vm_seed as seed
from test_installer_candidate_vm_create import root_trial as root_trial
from test_installer_candidate_vm_runtime import runtime_parent as runtime_parent
from test_installer_candidate_vm_runtime import VM_ID, UID, GID


def _transferred(root_trial, runtime_parent, monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    runtime.transfer(source, registry, parent, runtime_parent,
                     vm_id=VM_ID, uid=UID, gid=GID)
    return source, registry, parent


def test_seed_is_root_controlled_and_read_only_to_vm(root_trial, runtime_parent, monkeypatch):
    source, registry, parent = _transferred(root_trial, runtime_parent, monkeypatch)
    receipt = seed.prepare(source, registry, parent, runtime_parent,
                           vm_id=VM_ID, ssh_port=22022)
    control = registry / f"{VM_ID}.control"
    media = runtime_parent / VM_ID / "seed.iso"
    assert receipt["phase"] == "seeded"
    assert receipt["qualified"] is False and receipt["launch_authorized"] is False
    assert receipt["packages"] == seed.PACKAGES
    assert stat.S_IMODE(control.stat().st_mode) == 0o700
    assert (media.stat().st_uid, media.stat().st_gid) == (0, GID)
    assert stat.S_IMODE(media.stat().st_mode) == 0o440
    assert b"PRIVATE KEY" not in (registry / f"{VM_ID}.seed-receipt.json").read_bytes()
    assert (control / "known_hosts").read_text().startswith("[127.0.0.1]:22022 ssh-ed25519 ")
    assert b"docker-compose-v2" in (control / "user-data").read_bytes()
    schema_check = subprocess.run(["/usr/bin/cloud-init", "schema", "--config-file",
                                   str(control / "user-data")], check=False,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    diagnostic = re.sub(r"[A-Za-z0-9+/=]{32,}", "<redacted>",
                        schema_check.stderr.decode("utf-8", "replace"))
    assert schema_check.returncode == 0, diagnostic[:1200]
    assert subprocess.run(["/usr/bin/setpriv", "--reuid=60000", "--regid=60000",
                           "--clear-groups", "/usr/bin/test", "-r", str(media)],
                          check=False).returncode == 0
    assert subprocess.run(["/usr/bin/setpriv", "--reuid=60000", "--regid=60000",
                           "--clear-groups", "/usr/bin/test", "-r",
                           str(control / "controller_ed25519")],
                          check=False).returncode != 0
    with pytest.raises(FileExistsError):
        seed.prepare(source, registry, parent, runtime_parent,
                     vm_id=VM_ID, ssh_port=22022)


def test_seed_failure_retains_intent_and_no_receipt(root_trial, runtime_parent, monkeypatch):
    source, registry, parent = _transferred(root_trial, runtime_parent, monkeypatch)
    actual_command = seed.command

    def refuse_localds(argv, **kwargs):
        if argv and argv[0] == str(seed.LOCALDS):
            raise OSError("injected cloud-localds failure")
        return actual_command(argv, **kwargs)

    monkeypatch.setattr(seed, "command", refuse_localds)
    with pytest.raises(OSError, match="injected cloud-localds failure"):
        seed.prepare(source, registry, parent, runtime_parent,
                     vm_id=VM_ID, ssh_port=22022)
    assert (registry / f"{VM_ID}.seed-intent.json").is_file()
    assert not (registry / f"{VM_ID}.seed-receipt.json").exists()
    assert (registry / f"{VM_ID}.control" / "user-data").is_file()


def test_schema_rejection_retains_intent_without_media(root_trial, runtime_parent, monkeypatch):
    source, registry, parent = _transferred(root_trial, runtime_parent, monkeypatch)
    actual_command = seed.command

    def refuse_schema(argv, **kwargs):
        if argv and argv[0] == str(seed.CLOUD_INIT):
            raise ValueError("injected cloud-init schema rejection")
        return actual_command(argv, **kwargs)

    monkeypatch.setattr(seed, "command", refuse_schema)
    with pytest.raises(ValueError, match="schema rejection"):
        seed.prepare(source, registry, parent, runtime_parent,
                     vm_id=VM_ID, ssh_port=22022)
    assert (registry / f"{VM_ID}.seed-intent.json").is_file()
    assert not (registry / f"{VM_ID}.seed-receipt.json").exists()
    assert not (runtime_parent / VM_ID / "seed.iso").exists()


def test_seed_replacement_during_handoff_never_completes(root_trial, runtime_parent,
                                                         monkeypatch):
    source, registry, parent = _transferred(root_trial, runtime_parent, monkeypatch)
    actual_chown = seed.os.fchown
    replaced = False

    def replace_after_chown(fd, uid, gid):
        nonlocal replaced
        actual_chown(fd, uid, gid)
        if stat.S_ISREG(os.fstat(fd).st_mode) and not replaced:
            media = runtime_parent / VM_ID / "seed.iso"
            prior = media.with_name("prior-seed.iso")
            media.rename(prior)
            shutil.copyfile(prior, media)
            os.chown(media, 0, GID)
            media.chmod(0o440)
            replaced = True

    monkeypatch.setattr(seed.os, "fchown", replace_after_chown)
    with pytest.raises(ValueError, match="media changed"):
        seed.prepare(source, registry, parent, runtime_parent,
                     vm_id=VM_ID, ssh_port=22022)
    assert replaced
    assert (registry / f"{VM_ID}.seed-intent.json").is_file()
    assert not (registry / f"{VM_ID}.seed-receipt.json").exists()


def test_seed_byte_mutation_never_completes(root_trial, runtime_parent, monkeypatch):
    source, registry, parent = _transferred(root_trial, runtime_parent, monkeypatch)
    actual_chmod = seed.os.fchmod

    def mutate_media(fd, mode):
        actual_chmod(fd, mode)
        if mode == 0o440:
            os.pwrite(fd, b"X", 0)

    monkeypatch.setattr(seed.os, "fchmod", mutate_media)
    with pytest.raises(ValueError, match="media bytes differ"):
        seed.prepare(source, registry, parent, runtime_parent,
                     vm_id=VM_ID, ssh_port=22022)
    assert (registry / f"{VM_ID}.seed-intent.json").is_file()
    assert not (registry / f"{VM_ID}.seed-receipt.json").exists()


def test_key_flush_failure_retains_intent(root_trial, runtime_parent, monkeypatch):
    source, registry, parent = _transferred(root_trial, runtime_parent, monkeypatch)
    actual_fsync = seed.os.fsync

    def refuse_key_flush(fd):
        if os.readlink(f"/proc/self/fd/{fd}").endswith("/controller_ed25519"):
            raise OSError("injected key flush failure")
        return actual_fsync(fd)

    monkeypatch.setattr(seed.os, "fsync", refuse_key_flush)
    with pytest.raises(OSError, match="injected key flush failure"):
        seed.prepare(source, registry, parent, runtime_parent,
                     vm_id=VM_ID, ssh_port=22022)
    assert (registry / f"{VM_ID}.seed-intent.json").is_file()
    assert not (registry / f"{VM_ID}.seed-receipt.json").exists()
