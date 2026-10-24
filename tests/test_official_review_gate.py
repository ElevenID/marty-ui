from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("official_review_gate", ROOT / "scripts/official_review_gate.py")
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
LANES = ["oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc", "haip", "w3c-v2", "eudi"]


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Transport-only controls: module/candidate/disposition validation is tested
    # with the real Rust implementation in release-evidence/tests/official.rs.
    args = argparse.Namespace(validator=Path("owned-validator"), manifest=tmp_path / "candidate.json",
                              snapshot=tmp_path / "snapshot", authorization=tmp_path / "authorization",
                              output=tmp_path / "gate.json", source="a" * 40, harness="b" * 40,
                              run_id=17, current_attempt=2)
    args.manifest.write_bytes(b"unit-fixture-candidate-only")
    for key, value in {"GITHUB_REPOSITORY": gate.REPOSITORY, "GITHUB_REF": "refs/heads/main",
                       "GITHUB_RUN_ID": "17", "GITHUB_RUN_ATTEMPT": "2"}.items():
        monkeypatch.setenv(key, value)
    calls = []
    plan = json.dumps({"pending": ["transport-unit-fixture-only"], "release_qualified": False}).encode()

    def validator(arguments):
        calls.append(arguments)
        if arguments[1:] == ["--list-lanes"]:
            return json.dumps(LANES).encode()
        if arguments[1] == "--prepare-review":
            return plan
        return b'{"unit_fixture_only":true}'

    monkeypatch.setattr(gate, "command", validator)
    frozen = tmp_path / "frozen"
    frozen.mkdir()
    (frozen / "stack-manifest.json").write_bytes(args.manifest.read_bytes())
    (frozen / "origin-attempt.txt").write_bytes(b"1\n")
    (frozen / "review-request.json").write_bytes(plan)

    class GitHub(gate.GitHub):
        def __init__(self):
            self.calls = []
            self.artifacts = [{"name": "official-review-input-17", "expired": False}]
            self.branch = {"name": "main", "protected": True, "commit": {"sha": "c" * 40}}

        def api(self, path, **kwargs):
            self.calls.append(("api", path, kwargs))
            if path.startswith("actions/"):
                return json.dumps([{"artifacts": self.artifacts}]).encode()
            if path == "branches/main":
                return json.dumps(self.branch).encode()
            return b"protected-main-record-unit-fixture-only"

        def download(self, run_id, name, directory):
            self.calls.append(("download", run_id, name))
            if name == "official-review-input-17":
                shutil.copytree(frozen, directory)
            else:
                directory.mkdir(parents=True)
                (directory / "summary.json").write_bytes(b"transport-unit-fixture-only")

    return args, GitHub(), calls, frozen


def test_gate_only_retry_reuses_origin_attempt_and_never_downloads_a_partial_new_set(fixture) -> None:
    args, github, calls, _ = fixture
    assert gate.snapshot(args, github) is False
    downloads = [call for call in github.calls if call[0] == "download"]
    assert downloads == [("download", 17, "official-review-input-17")]
    assert calls[-1][-2:] == ["1", str(args.snapshot / "official-summaries")]
    gate.qualify(args, github)
    assert args.output.is_file()
    assert ("api", "contents/release/official-reviews/17-1.json?ref=" + "c" * 40, {"raw": True}) in github.calls
    assert calls[-1][1:4] == ["--with-main-review", str(args.authorization / "record.json"), "c" * 40]
    assert calls[-1][-2] == "1"


def test_first_collection_downloads_the_complete_current_set_before_freezing(fixture) -> None:
    args, github, calls, _ = fixture
    github.artifacts = [{"name": f"official-{lane}-17-2", "expired": False} for lane in LANES]
    assert gate.snapshot(args, github) is True
    assert [call[2] for call in github.calls if call[0] == "download"] == [f"official-{lane}-17-2" for lane in LANES]
    assert (args.snapshot / "origin-attempt.txt").read_bytes() == b"2\n"
    assert calls[-1][-2] == "2"


def test_interrupted_snapshot_upload_recovers_the_completed_origin_without_protocol_replay(fixture) -> None:
    args, github, calls, _ = fixture
    github.artifacts = [{"name": f"official-{lane}-17-1", "expired": False} for lane in LANES]
    assert gate.snapshot(args, github) is True
    assert [call[2] for call in github.calls if call[0] == "download"] == [f"official-{lane}-17-1" for lane in LANES]
    assert (args.snapshot / "origin-attempt.txt").read_bytes() == b"1\n"
    assert calls[-1][-2] == "1"


def test_a_newer_partial_collection_cannot_be_hidden_by_an_older_complete_set(fixture) -> None:
    args, github, _, _ = fixture
    github.artifacts = [{"name": f"official-{lane}-17-1", "expired": False} for lane in LANES]
    github.artifacts += [{"name": "official-oid4vp-final-17-2", "expired": False}]
    with pytest.raises(ValueError, match="incomplete"):
        gate.snapshot(args, github)
    assert not args.snapshot.exists()
    assert not any(call[0] == "download" for call in github.calls)


@pytest.mark.parametrize("artifact_change", ["expired", "duplicate", "newer-lane"])
def test_expired_ambiguous_or_newer_evidence_cannot_fall_back_to_an_old_approval(fixture, artifact_change) -> None:
    args, github, _, _ = fixture
    if artifact_change == "expired":
        github.artifacts[0]["expired"] = True
    elif artifact_change == "duplicate":
        github.artifacts += [dict(github.artifacts[0])]
    else:
        github.artifacts += [{"name": "official-oid4vp-final-17-2", "expired": False}]
    with pytest.raises(ValueError):
        gate.snapshot(args, github)
    assert not args.output.exists()
    assert not any(call[0] == "api" and call[1] == "branches/main" for call in github.calls)


@pytest.mark.parametrize("changed", ["manifest", "request", "future-attempt"])
def test_mutated_frozen_inputs_are_rejected_before_loading_authorization(fixture, changed) -> None:
    args, github, _, frozen = fixture
    if changed == "manifest":
        (frozen / "stack-manifest.json").write_bytes(b"other-candidate")
    elif changed == "request":
        (frozen / "review-request.json").write_bytes(b"other-request")
    else:
        (frozen / "origin-attempt.txt").write_bytes(b"3\n")
    with pytest.raises(ValueError):
        gate.snapshot(args, github)
    assert not args.output.exists()


@pytest.mark.parametrize(("key", "value"), [("GITHUB_REPOSITORY", "other/repository"),
                                          ("GITHUB_REF", "refs/heads/feature"),
                                          ("GITHUB_RUN_ID", "18"), ("GITHUB_RUN_ATTEMPT", "1")])
def test_foreign_contexts_fail_before_network_or_filesystem_mutation(fixture, monkeypatch, key, value) -> None:
    args, github, _, _ = fixture
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        gate.snapshot(args, github)
    assert not github.calls and not args.snapshot.exists()


@pytest.mark.parametrize("protected", [False, None, "true"])
def test_only_real_protected_main_can_supply_review_records(fixture, protected) -> None:
    args, github, _, _ = fixture
    gate.snapshot(args, github)
    github.branch["protected"] = protected
    with pytest.raises(ValueError):
        gate.qualify(args, github)
    assert not args.output.exists()
    assert not any(call[0] == "api" and call[1].startswith("contents/") for call in github.calls)


def test_local_forged_record_is_never_used_as_authorization(fixture) -> None:
    args, github, _, _ = fixture
    gate.snapshot(args, github)
    args.authorization.mkdir()
    record = args.authorization / "record.json"
    record.write_bytes(b'{"verdict":"accepted"}')
    with pytest.raises(FileExistsError):
        gate.qualify(args, github)
    assert record.read_bytes() == b'{"verdict":"accepted"}'
    assert not args.output.exists()


def test_github_host_cannot_be_redirected_by_local_defaults(monkeypatch) -> None:
    calls = []
    monkeypatch.setenv("GH_HOST", "untrusted.example")
    monkeypatch.setattr(gate, "command", lambda arguments: calls.append(arguments) or b"[]")
    github = gate.GitHub()
    github.api("branches/main")
    github.download(17, "official-review-input-17", Path("owned-output"))
    assert calls[0][:4] == ["gh", "api", "--hostname", "github.com"]
    assert calls[0][4] == "repos/ElevenID/marty-ui/branches/main"
    assert calls[1][calls[1].index("--repo") + 1] == "https://github.com/ElevenID/marty-ui"
