from __future__ import annotations

import importlib.util
import subprocess
import sys
from importlib import import_module
from datetime import datetime, timedelta, timezone
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
                                  "rust/crates/oid4vp-contract/src/lib.rs", "config/envoy/proto_descriptor.pb",
                                  "rust/.gitattributes", "rust/crates/.gitattributes", "config/.gitattributes"])
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


@pytest.mark.parametrize("change", ["eligibility", "component", "schema"])
def test_version_preparation_cannot_hide_eligibility_or_component_pin_changes(repository, change) -> None:
    root, _ = repository
    original = {"release": "marty-ui@1.2.3", "release_state": "eligible",
                "schema": "marty.stack-lock/v1", "components": [{"version": "1.0.0"}]}
    write(root, "release/stack-lock.json", MODULE.json.dumps(original).encode())
    source = commit(root, "Eligible candidate pins")
    changed = {**original, "release": "marty-ui@1.2.4"}
    if change == "eligibility":
        changed["release_state"] = "blocked"
    elif change == "component":
        changed["components"] = [{"version": "2.0.0"}]
    else:
        changed["schema"] = "foreign"
    write(root, "release/stack-lock.json", MODULE.json.dumps(changed).encode())
    main = commit(root, "Change candidate eligibility or pins")
    with pytest.raises(MODULE.SourceAuthorityError, match="program or policy changed"):
        MODULE.require_compatible_source(source, main, main, repository=root)
    write(root, "release/stack-lock.json", MODULE.json.dumps(original).encode())
    restored = commit(root, "Restore later eligibility")
    with pytest.raises(MODULE.SourceAuthorityError, match="program or policy changed"):
        MODULE.require_compatible_source(source, restored, restored, repository=root)


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


def test_immutable_cache_never_replaces_a_fresh_protected_main_read(repository, monkeypatch) -> None:
    root, source = repository
    h = import_module("scripts.release_tag_handoff")
    monkeypatch.setitem(sys.modules, "release_tag_handoff", h)
    current = [source]
    protected = [True]
    reads, fetches = [], []
    github = h.GitHub()

    def branch(path):
        assert path == f"repos/{h.REPOSITORY}/branches/main"
        reads.append(path)
        return {"name": "main", "protected": protected[0], "commit": {"sha": current[0]}}

    def fetch(*arguments, **kwargs):
        assert "fetch" in arguments and "--no-tags" in arguments
        assert kwargs["repository"] == root
        fetches.append(arguments)

    monkeypatch.setattr(github, "json", branch)
    monkeypatch.setattr(h, "git", fetch)
    verified = set()
    for _ in range(2):
        assert MODULE.authenticated_current(github, source, source, repository=root, verified=verified) == source
    assert len(reads) == 2 and len(fetches) == 1
    write(root, "ui/next.ts", b"next\n")
    current[0] = commit(root, "Unrelated protected-main advance")
    assert MODULE.authenticated_current(github, source, source, repository=root, verified=verified) == current[0]
    assert len(reads) == 3 and len(fetches) == 2
    protected[0] = False
    with pytest.raises(h.HandoffError, match="authenticated protected main"):
        MODULE.authenticated_current(github, source, source, repository=root, verified=verified)
    assert len(fetches) == 2


def test_current_main_policy_change_is_not_covered_by_cached_old_main(repository, monkeypatch) -> None:
    root, source = repository
    h = import_module("scripts.release_tag_handoff")
    monkeypatch.setitem(sys.modules, "release_tag_handoff", h)
    write(root, "config/envoy/proto_descriptor.pb", b"changed-native-build-input")
    main = commit(root, "Change native authority input")
    github = h.GitHub()
    monkeypatch.setattr(github, "json", lambda _: {"name": "main", "protected": True, "commit": {"sha": main}})
    monkeypatch.setattr(h, "git", lambda *args, **kwargs: None)
    verified = {(source, source, source)}
    with pytest.raises(MODULE.SourceAuthorityError, match="program or policy changed"):
        MODULE.authenticated_current(github, source, source, repository=root, verified=verified)
    assert verified == {(source, source, source)}


def test_reads_stack_lock_from_immutable_candidate_instead_of_new_executable(repository) -> None:
    root, source = repository
    expected = (root / "release/stack-lock.json").read_bytes()
    write(root, "release/stack-lock.json", b'{"release":"next"}\n')
    commit(root, "Advance the executor's candidate version")
    assert MODULE.stack_lock_bytes(source, repository=root) == expected


def test_policy_digest_binds_clean_program_bytes_but_allows_application_and_lock_advance(
    repository, monkeypatch,
) -> None:
    root, _ = repository
    monkeypatch.syspath_prepend(str(SOURCE.parent))
    candidate = import_module("stable_publication_candidate")
    write(root, candidate.POLICY_PATH, candidate.h.encoded(candidate.POLICY))
    commit(root, "Bind supported publication policy")
    digest = candidate.policy_digest(root)
    write(root, "ui/next.ts", b"next application\n")
    write(root, "release/stack-lock.json", b'{"release":"next"}\n')
    commit(root, "Unrelated application and candidate-version advance")
    assert candidate.policy_digest(root) == digest
    write(root, "scripts/imported_policy.py", b"changed authority\n")
    with pytest.raises(ValueError):
        candidate.policy_digest(root)
    commit(root, "Reviewed program change requires a new candidate")
    assert candidate.policy_digest(root) != digest


@pytest.mark.parametrize("mutation", [None, "id", "path", "event", "branch", "source", "rerun", "repository"])
def test_operator_run_keeps_actual_executor_identity_and_real_candidate_history(
    repository, monkeypatch, mutation,
) -> None:
    root, source = repository
    h = import_module("scripts.release_tag_handoff")
    write(root, "ui/operator.ts", b"operator admission\n")
    executable = commit(root, "Advance main before operator dispatch")
    write(root, "ui/later.ts", b"later application\n")
    main = commit(root, "Advance main while original operator is queued")
    record = {"id": 123, "path": h.OPERATOR_WORKFLOW, "event": "workflow_dispatch",
              "head_branch": "main", "head_sha": executable, "run_attempt": 1,
              "repository": {"id": h.REPOSITORY_ID, "full_name": h.REPOSITORY},
              "status": "in_progress", "conclusion": None}
    changes = {"id": {"id": 124}, "path": {"path": "foreign"}, "event": {"event": "pull_request"},
               "branch": {"head_branch": "feature"}, "source": {"head_sha": "f" * 40},
               "rerun": {"run_attempt": 2}, "repository": {"repository": None}}
    record.update(changes.get(mutation, {}))
    github = h.GitHub(deadline=datetime.now(timezone.utc) + timedelta(seconds=60))
    reads = []
    def read(path):
        reads.append(path)
        if path.endswith("/branches/main"):
            return {"name": "main", "protected": True, "commit": {"sha": main}}
        assert path == f"repos/{h.REPOSITORY}/actions/runs/123"
        return record.copy()
    def fetch(*arguments, **kwargs):
        assert "fetch" in arguments and kwargs["repository"] == root
    monkeypatch.setattr(github, "json", read)
    monkeypatch.setattr(h, "git", fetch)
    if mutation:
        with pytest.raises(ValueError):
            h.candidate_run(github, 123, h.OPERATOR_WORKFLOW, source, repository=root)
    else:
        accepted = h.candidate_run(github, 123, h.OPERATOR_WORKFLOW, source, repository=root)
        assert accepted["head_sha"] == executable and executable != source
        h.candidate_main_observations(github, source, executable, executable, main, repository=root)
        with pytest.raises(ValueError):
            h.candidate_main_observations(github, source, executable, main, executable, repository=root)
    assert all("/actions/runs/124" not in path for path in reads)
    assert github.mutations == []
