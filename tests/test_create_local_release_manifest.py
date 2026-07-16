from __future__ import annotations

import json
import subprocess
import tarfile
from pathlib import Path

from scripts.create_local_release_manifest import (
    REPOSITORIES,
    create_manifest,
    release_files,
    verify_manifest,
    worktree_digest,
)


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def make_repo(path: Path, *, content: str = "initial") -> None:
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "Test")
    (path / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (path / "tracked.txt").write_text(content, encoding="utf-8")
    git(path, "add", ".")
    git(path, "commit", "-qm", "initial")


def test_release_files_include_dirty_and_untracked_but_not_ignored(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    make_repo(repo)
    (repo / "tracked.txt").write_text("changed", encoding="utf-8")
    (repo / "untracked.txt").write_text("new", encoding="utf-8")
    (repo / "ignored.txt").write_text("secret", encoding="utf-8")

    files = release_files(repo)

    assert Path("tracked.txt") in files
    assert Path("untracked.txt") in files
    assert Path("ignored.txt") not in files


def test_release_scope_excludes_runtime_state_and_limits_named_contexts(tmp_path: Path) -> None:
    ui = tmp_path / "marty-ui"
    make_repo(ui)
    (ui / ".selfhost-state").mkdir()
    (ui / ".selfhost-state" / "secret.txt").write_text("secret", encoding="utf-8")
    (ui / "tests").mkdir()
    (ui / "tests" / "release-test.py").write_text("pass", encoding="utf-8")

    blog = tmp_path / "marty-blog"
    make_repo(blog)
    (blog / "package.json").write_text("{}", encoding="utf-8")
    (blog / "src").mkdir()
    (blog / "src" / "posts.js").write_text("[]", encoding="utf-8")
    (blog / "public").mkdir()
    (blog / "public" / "large.png").write_bytes(b"not-a-build-input")

    assert Path("tests/release-test.py") in release_files(ui)
    assert Path(".selfhost-state/secret.txt") not in release_files(ui)
    assert release_files(blog) == [Path("package.json"), Path("src/posts.js")]


def test_worktree_digest_changes_with_content_and_file_set(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    make_repo(repo)
    first_files = release_files(repo)
    first = worktree_digest(repo, first_files)

    (repo / "tracked.txt").write_text("changed", encoding="utf-8")
    second = worktree_digest(repo, release_files(repo))
    (repo / "new.txt").write_text("new", encoding="utf-8")
    third = worktree_digest(repo, release_files(repo))

    assert len(first) == 64
    assert len({first, second, third}) == 3


def test_manifest_snapshots_all_coordinated_repositories(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name in REPOSITORIES:
        make_repo(workspace / name, content=name)
        if name == "marty-blog":
            repo = workspace / name
            (repo / "package.json").write_text("{}", encoding="utf-8")
            (repo / "src").mkdir()
            (repo / "src" / "index.js").write_text("export {};", encoding="utf-8")
    output = tmp_path / "manifest.json"
    snapshots = tmp_path / "snapshots"

    manifest = create_manifest(workspace, "mip-0.3.1-local-test", output, snapshots)

    assert manifest["source_kind"] == "local-worktree-snapshot"
    assert manifest["promotion_eligible"] is False
    assert manifest["release_ready"] is False
    assert len(manifest["marty_ui_sha"]) == 40
    assert set(manifest["repositories"]) == set(REPOSITORIES)
    assert json.loads(output.read_text(encoding="utf-8"))["mip_version"] == "0.3.1"
    for name, record in manifest["repositories"].items():
        snapshot = snapshots / record["snapshot"]
        assert snapshot.is_file()
        with tarfile.open(snapshot, "r:gz") as archive:
            assert archive.getnames()

    verified = verify_manifest(workspace, output)
    assert set(verified) == set(REPOSITORIES)


def test_manifest_verification_rejects_worktree_drift(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name in REPOSITORIES:
        make_repo(workspace / name, content=name)
        if name == "marty-blog":
            repo = workspace / name
            (repo / "package.json").write_text("{}", encoding="utf-8")
            (repo / "src").mkdir()
            (repo / "src" / "index.js").write_text("export {};", encoding="utf-8")
    output = tmp_path / "manifest.json"
    create_manifest(workspace, "mip-0.3.1-local-test", output, tmp_path / "snapshots")

    (workspace / "marty-ui" / "tracked.txt").write_text("drift", encoding="utf-8")

    try:
        verify_manifest(workspace, output)
    except RuntimeError as exc:
        assert str(exc) == "Worktree changed after snapshot: marty-ui"
    else:
        raise AssertionError("Expected worktree drift to fail verification")
