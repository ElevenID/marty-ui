from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

SOURCE = Path(__file__).parents[1] / "scripts" / "release_source_authority.py"
SPEC = importlib.util.spec_from_file_location("release_source_authority", SOURCE)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                          text=True, timeout=10).stdout.strip()


def write(root: Path, name: str, data: bytes) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def commit(root: Path, message: str) -> str:
    git(root, "add", "--all")
    git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str]:
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.name", "Source policy fixture")
    git(tmp_path, "config", "user.email", "fixture@example.invalid")
    git(tmp_path, "config", "core.autocrlf", "false")
    write(tmp_path, MODULE.POLICY_PATH, MODULE.policy_bytes())
    write(tmp_path, "scripts/release_source_authority.py", SOURCE.read_bytes())
    write(tmp_path, "scripts/imported_policy.py", b"POLICY = 'original'\n")
    write(tmp_path, ".github/workflows/publisher.yml", b"permissions: {}\n")
    write(tmp_path, "release/stack-lock.json", b'{"release":"1"}\n')
    return tmp_path, commit(tmp_path, "Admit future source policy")


def test_keeps_candidate_immutable_while_application_and_version_advance(repository) -> None:
    root, source = repository
    expected = MODULE.require_compatible_source(source, source, source, repository=root)
    write(root, "ui/index.ts", b"export const next = true;\n")
    executable = commit(root, "Unrelated application change")
    write(root, "release/stack-lock.json", b'{"release":"2"}\n')
    main = commit(root, "Next candidate version")
    assert MODULE.require_compatible_source(source, executable, main, repository=root) == expected


@pytest.mark.parametrize("name", ["scripts/imported_policy.py", ".github/workflows/publisher.yml",
                                  "release/revocation.json", "requirements-services.txt", ".gitattributes",
                                  "rust/Cargo.lock", "rust/Cargo.toml", "rust/.cargo/config.toml",
                                  "rust-toolchain.toml", "rust/crates/release-evidence/src/official_cli.rs",
                                  "rust/crates/oid4vp-contract/src/lib.rs"])
def test_rejects_release_program_policy_or_dependency_drift(repository, name) -> None:
    root, source = repository
    write(root, name, b"changed\n")
    main = commit(root, "Change release authority")
    with pytest.raises(MODULE.SourceAuthorityError, match="program or policy changed"):
        MODULE.require_compatible_source(source, main, main, repository=root)


def test_policy_revocation_and_restoration_cannot_revive_old_candidate(repository) -> None:
    root, source = repository
    original = (root / MODULE.POLICY_PATH).read_bytes()
    write(root, MODULE.POLICY_PATH, b'{"schema":"revoked"}\n')
    commit(root, "Revoke authority")
    write(root, MODULE.POLICY_PATH, original)
    main = commit(root, "Restore policy for new sources")
    with pytest.raises(MODULE.SourceAuthorityError, match="program or policy changed"):
        MODULE.require_compatible_source(source, main, main, repository=root)


@pytest.mark.parametrize("fault", ["absent", "foreign"])
def test_historical_sources_do_not_gain_new_authority(repository, fault) -> None:
    root, _ = repository
    if fault == "absent":
        (root / MODULE.POLICY_PATH).unlink()
    else:
        write(root, MODULE.POLICY_PATH, b'{"schema":"marty.immutable-source-authority/v0"}\n')
    old = commit(root, "Historical unsupported source")
    with pytest.raises(MODULE.SourceAuthorityError, match="policy is absent|unsupported source policy"):
        MODULE.require_compatible_source(old, old, old, repository=root)


def test_rejects_nonancestor_executable_and_main_rewind(repository) -> None:
    root, source = repository
    git(root, "checkout", "-b", "candidate")
    write(root, "ui/candidate.ts", b"candidate\n")
    candidate = commit(root, "Candidate")
    git(root, "checkout", "main")
    write(root, "ui/main.ts", b"main\n")
    main = commit(root, "Independent main")
    with pytest.raises(MODULE.SourceAuthorityError):
        MODULE.require_compatible_source(candidate, candidate, main, repository=root)
    with pytest.raises(MODULE.SourceAuthorityError):
        MODULE.require_compatible_source(candidate, source, candidate, repository=root)


def test_rejects_mode_changes_even_when_blob_bytes_match(repository) -> None:
    root, source = repository
    git(root, "update-index", "--chmod=+x", "scripts/imported_policy.py")
    git(root, "commit", "-m", "Make policy executable")
    main = git(root, "rev-parse", "HEAD")
    with pytest.raises(MODULE.SourceAuthorityError, match="program or policy changed"):
        MODULE.require_compatible_source(source, main, main, repository=root)


def test_archive_attributes_cannot_hide_executable_inputs(repository) -> None:
    root, _ = repository
    write(root, ".gitattributes", b"scripts/imported_policy.py export-ignore\n")
    source = commit(root, "Attempt to hide release input")
    with pytest.raises(MODULE.SourceAuthorityError, match="archive omits"):
        MODULE.require_compatible_source(source, source, source, repository=root)


@pytest.mark.parametrize("fault", ["replace", "graft", "shallow"])
def test_rejects_incomplete_or_overridden_history(repository, fault, tmp_path) -> None:
    root, source = repository
    if fault == "replace":
        write(root, "ui/next.ts", b"next\n")
        next_source = commit(root, "Next")
        git(root, "replace", source, next_source)
    elif fault == "graft":
        write(root, ".git/info/grafts", source.encode() + b"\n")
    else:
        write(root, ".git/shallow", source.encode() + b"\n")
    with pytest.raises(MODULE.SourceAuthorityError, match="replace|grafts|complete"):
        MODULE.require_compatible_source(source, source, source, repository=root)
