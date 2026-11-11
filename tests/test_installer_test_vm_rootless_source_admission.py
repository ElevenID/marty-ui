"""Synthetic, nonroot source-closure checks; no controller or VM import."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_source_admission as subject


def _run(*args: str, cwd: Path) -> str:
    return subprocess.check_output(args, cwd=cwd, stderr=subprocess.DEVNULL,
                                   text=True).strip()


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    work = tmp_path / "work"
    work.mkdir()
    _run("git", "init", "-q", str(work), cwd=tmp_path)
    (work / "scripts").mkdir()
    (work / "scripts" / "a.py").write_text("value = 1\n")
    _run("git", "add", "scripts/a.py", cwd=work)
    _run("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-q", "-m", "fixture", cwd=work)
    commit = _run("git", "rev-parse", "HEAD", cwd=work)
    bare = tmp_path / "bare.git"
    _run("git", "clone", "--bare", "-q", str(work), str(bare), cwd=tmp_path)
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    shutil.copyfile(work / "scripts" / "a.py", source / "a.py")
    monkeypatch.setattr(subject.os, "geteuid", lambda: 0)
    # The actual root-owner/ancestor check is exercised only after the source
    # has been copied to a separately admitted root-private runtime snapshot.
    monkeypatch.setattr(subject, "_private_ancestry", lambda _: None)
    monkeypatch.setattr(subject, "_bytes", lambda path: path.read_bytes())
    return bare, commit, source


def test_exact_git_blob_closure(tmp_path, monkeypatch):
    bare, commit, source = _fixture(tmp_path, monkeypatch)
    result = subject.admit(git_dir=bare, commit=commit, source_dir=source)
    assert set(result) == {"a.py"}


def test_changed_or_extra_module_refused(tmp_path, monkeypatch):
    bare, commit, source = _fixture(tmp_path, monkeypatch)
    (source / "a.py").write_text("value = 2\n")
    with pytest.raises(ValueError, match="source admission refused"):
        subject.admit(git_dir=bare, commit=commit, source_dir=source)
    (source / "a.py").write_text("value = 1\n")
    (source / "shadow.py").write_text("import os\n")
    with pytest.raises(ValueError, match="source admission refused"):
        subject.admit(git_dir=bare, commit=commit, source_dir=source)


def test_wrong_commit_refused(tmp_path, monkeypatch):
    bare, commit, source = _fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="source admission refused"):
        subject.admit(git_dir=bare, commit="0" * 40, source_dir=source)
