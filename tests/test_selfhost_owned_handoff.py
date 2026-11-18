"""Owner-aware file handoff preserves both credentials on uncertain revocation."""
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest
from scripts import selfhost_operator_inputs as handoff
from scripts.selfhost_native_operator import OperatorCleanupError

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX owner-aware handoff")


@pytest.mark.parametrize("mode", [0o400, 0o444])
def test_owned_writer_preserves_install_owner_exact_bytes_and_mode(tmp_path, mode):
    output = tmp_path / "output"
    handoff.write_owned(output, "synthetic-value", mode, tmp_path.stat())
    assert output.read_bytes() == b"synthetic-value"
    assert stat.S_IMODE(output.stat().st_mode) == mode
    assert (output.stat().st_uid, output.stat().st_gid) == (tmp_path.stat().st_uid, tmp_path.stat().st_gid)
    with pytest.raises(FileExistsError):
        handoff.write_owned(output, "replacement", mode, tmp_path.stat())
    assert output.read_bytes() == b"synthetic-value"


@pytest.mark.parametrize("fault", ["fchown", "fchmod", "fsync", "encode"])
def test_owned_writer_failure_discards_only_its_new_file(tmp_path, monkeypatch, fault):
    existing = tmp_path / "existing"
    existing.write_text("preserve")
    output = tmp_path / "new"
    if fault != "encode":
        def fail(*_):
            raise OSError("synthetic write failure")
        monkeypatch.setattr(handoff.os, fault, fail)
    with pytest.raises((OSError, UnicodeError)):
        handoff.write_owned(output, "\u00e9" if fault == "encode" else "new", 0o400, tmp_path.stat())
    assert not output.exists()
    assert existing.read_text() == "preserve"


@pytest.mark.parametrize("fault", [None, "native", "replace", "directory-fsync", "post-replace-fsync"])
def test_refresh_keeps_both_credentials_until_native_proof_and_replace(tmp_path, monkeypatch, fault):
    token_file = tmp_path / "token"
    token_file.write_text("old")
    pending = tmp_path / "token.new"
    seen = []

    def native(_root, *args, input):
        assert args[:2] == ("operator", "leaf-refresh")
        assert json.loads(input) == {"old_token": "old", "new_token": "new", "operator_token": "operator"}
        assert token_file.read_text() == "old" and pending.read_text() == "new"
        assert stat.S_IMODE(pending.stat().st_mode) == 0o400
        seen.append("native")
        if fault == "native":
            raise OperatorCleanupError("Scoped token refresh requires operator recovery")
        return b""

    monkeypatch.setattr(handoff, "operator_bytes", native)
    if fault == "replace":
        def fail_replace(*_):
            raise OSError("synthetic rename failure")
        monkeypatch.setattr(handoff.os, "replace", fail_replace)
    if fault in ("directory-fsync", "post-replace-fsync"):
        original = os.fsync
        syncs = []
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                syncs.append(fd)
                if fault == "directory-fsync" or len(syncs) == 2:
                    raise OSError("synthetic directory sync failure")
            original(fd)
        monkeypatch.setattr(handoff.os, "fsync", fail_directory)

    def write(path, value, mode):
        handoff.write_owned(path, value, mode, tmp_path.stat())
    bao = SimpleNamespace(endpoint="https://127.0.0.1:18200", ca=Path("public-ca"), token="operator")
    if fault:
        with pytest.raises(OperatorCleanupError):
            handoff.refresh_scoped_token(bao, token_file, "new", write)
        if fault == "post-replace-fsync":
            assert token_file.read_text() == "new" and not pending.exists()
        else:
            assert token_file.read_text() == "old" and pending.read_text() == "new"
        assert seen == ([] if fault == "directory-fsync" else ["native"])
    else:
        handoff.refresh_scoped_token(bao, token_file, "new", write)
        assert token_file.read_text() == "new" and not pending.exists()


@pytest.mark.parametrize("link", [False, True])
def test_preexisting_pending_file_or_symlink_is_never_overwritten(tmp_path, monkeypatch, link):
    token = tmp_path / "token"
    token.write_text("old")
    victim = tmp_path / "victim"
    victim.write_text("preserve")
    pending = tmp_path / "token.new"
    if link:
        pending.symlink_to(victim)
    else:
        pending.write_text("existing")
    monkeypatch.setattr(handoff, "operator_bytes", lambda *_args, **_kw: pytest.fail("revoked before pending refusal"))
    with pytest.raises(ValueError, match="pending"):
        handoff.refresh_scoped_token(None, token, "new", lambda *_: pytest.fail("pending overwritten"))
    assert token.read_text() == "old" and victim.read_text() == "preserve" and pending.is_symlink() is link



def test_refresh_write_failure_never_revokes_original(tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("old")
    monkeypatch.setattr(handoff, "operator_bytes", lambda *_args, **_kw: pytest.fail("revoked before staging"))
    def fail_owner(*_):
        raise OSError("synthetic owner failure")
    monkeypatch.setattr(handoff.os, "fchown", fail_owner)
    def write(path, value, mode):
        handoff.write_owned(path, value, mode, tmp_path.stat())
    with pytest.raises(OSError):
        handoff.refresh_scoped_token(None, token, "new", write)
    assert token.read_text() == "old" and not (tmp_path / "token.new").exists()


def test_private_operator_directory_retains_source_and_permission_boundaries(tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    outside = tmp_path / "private"
    outside.mkdir(mode=0o700)
    assert handoff.private_operator_directory(outside, source) == outside.resolve()
    for candidate in (source, Path("relative")):
        with pytest.raises(ValueError):
            handoff.private_operator_directory(candidate, source)
    outside.chmod(0o755)
    with pytest.raises(ValueError):
        handoff.private_operator_directory(outside, source)
    link = tmp_path / "link"
    link.symlink_to(source, target_is_directory=True)
    with pytest.raises(ValueError):
        handoff.private_operator_directory(link, source)



def test_writer_failure_preserves_a_competing_replacement(tmp_path, monkeypatch):
    output = tmp_path / "output"
    displaced = tmp_path / "our-file"
    victim = tmp_path / "competing"
    victim.write_text("preserve")
    def replace_then_fail(*_):
        output.rename(displaced)
        output.symlink_to(victim)
        raise OSError("synthetic concurrent replacement")
    monkeypatch.setattr(handoff.os, "fchmod", replace_then_fail)
    with pytest.raises(OSError):
        handoff.write_owned(output, "new", 0o400, tmp_path.stat())
    assert output.is_symlink() and victim.read_text() == "preserve"
    assert displaced.read_text() == "new"



def test_writer_metadata_failure_closes_fd_and_preserves_uncertain_path(tmp_path, monkeypatch):
    output = tmp_path / "output"
    real_stat = os.fstat
    seen = []
    def fail(fd):
        seen.append(fd)
        raise OSError("synthetic metadata failure")
    with monkeypatch.context() as scoped_patch:
        scoped_patch.setattr(handoff.os, "fstat", fail)
        with pytest.raises(OperatorCleanupError):
            handoff.write_owned(output, "new", 0o400, tmp_path.stat())
    assert len(seen) == 1 and output.exists()
    with pytest.raises(OSError):
        real_stat(seen[0])
