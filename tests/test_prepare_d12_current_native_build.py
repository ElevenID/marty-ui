"""Source-only refusal controls for the closed current D12 build adapter."""
import json
import hashlib
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import prepare_d12_current_native_build as d12
import scoped_native_build as build

RUN = "12345678-1234-4234-8234-123456789abc"
ENGINE = "engine-control"


def target():
    return {"state": "CREATED_EMPTY_OWNED_TARGET", "volume": d12.D12_PASSPORT_CURRENT.volumes[1],
            "runId": RUN, "engineId": ENGINE, "owner": d12.D12_PASSPORT_CURRENT.owner,
            "emptyReadback": True, "sourceIndependent": True, "consumers": [], "createdAt": "created-control"}


def journal():
    return {"schema": 1, "backend": "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1",
            "desktop": {"engineId": ENGINE, "volumeProof": {"Labels": {"elevenid.run": RUN}}},
            "bootstrapParent": {"supported": True, "synced": True}}


def test_closed_source_and_profile_refuse_old_all29(monkeypatch):
    assert build.build_scope(d12.PROFILE)["roles"] == {
        "flow": "marty-flow", "gateway": "marty-gateway",
        "issuance-native": "marty-issuance-service"}
    assert build.artifact_directory(d12.PROFILE) == "debug"
    monkeypatch.setattr(d12, "exact_file", lambda *_: {
        "schema": "marty.local-official-native-source-export/v1",
        "state": "SOURCE_EXPORTED_NO_COMPILER", "buildProfile": "oid4vc-all-services"})
    with pytest.raises(ValueError, match="D12_SOURCE_EXPORT_CHANGED"):
        # The old all-29 packet cannot be prepared as the current three-role build.
        d12.source_packet(Path("unused.json"), "0" * 64)


def test_current_main_three_role_profile_keeps_old_target_and_source_out():
    scope = build.build_scope(d12.PROFILE)
    assert scope["uiRevision"] == "449ab93ca80d147622ae61283f7d8084f7c62884"
    assert scope["coreRevision"] == "11655e38c2dbf69bfa5bc3c873f80c5fad628723"
    assert scope["roles"] == {"flow": "marty-flow", "gateway": "marty-gateway",
                              "issuance-native": "marty-issuance-service"}
    assert scope["volumes"][1] == "marty-d12-current-main-native-target"
    assert scope["prefix"] == "marty-d12-current-main-"
    with pytest.raises(ValueError, match="D12_FRESH_OWNED_TARGET_REQUIRED"):
        d12.target_input({**target(), "volume": "marty-d12-current-native-target"},
                         run_id=RUN, engine_id=ENGINE)


def tiny_repo(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir()
    def run(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.STDOUT).strip()
    run("init", "-q")
    run("config", "user.name", "D12 Control")
    run("config", "user.email", "d12-control@example.invalid")
    run("remote", "add", "origin", d12.ORIGIN["ui"])
    for name in d12.OPERATORS:
        file = repo / "scripts" / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(("# " + name + "\n").encode())
    run("add", ".")
    run("commit", "-qm", "synthetic source control")
    revision = run("rev-parse", "HEAD").decode()
    # Git for Windows may have a stale WSL primary core.worktree entry.
    run("config", "core.worktree", "/mnt/c/stale-unavailable-checkout")
    return repo, revision


def test_source_git_reader_uses_pinned_repository_metadata(tmp_path):
    repo, revision = tiny_repo(tmp_path)
    assert d12.verified_git(["-C", str(repo), "cat-file", "-t", revision]).strip() == b"commit"
    with pytest.raises(ValueError, match="D12_GIT_SOURCE_COMMAND_CHANGED"):
        d12.verified_git(["show", d12.SOURCE])


def test_bootstrap_stages_git_blobs_not_crlf_checkout_bytes(tmp_path):
    repo, revision = tiny_repo(tmp_path)
    staged = tmp_path / "staged"
    staged.mkdir()
    closure = d12.producer_closure(repo, revision, staged)
    for name in d12.OPERATORS:
        path = staged / name
        raw = d12.git(repo, "show", revision + ":scripts/" + name)
        assert path.read_bytes() == raw and b"\r\n" not in raw
        assert closure[name]["sha256"] == d12.sha(path)
    # A normal Windows checkout may be CRLF; it must never replace Git bytes.
    (repo / "scripts/scoped_native_build.py").write_bytes(b"# scoped_native_build.py\r\n")
    assert (repo / "scripts/scoped_native_build.py").read_bytes() != (staged / "scoped_native_build.py").read_bytes()


def test_fresh_target_and_desktop_journal_scope():
    d12.target_input(target(), run_id=RUN, engine_id=ENGINE)
    d12.journal_input(journal(), run_id=RUN, engine_id=ENGINE)
    for change in ({"volume": "marty-oid4vc-native-d2de-target-20261028"},
                   {"owner": "foreign"}, {"emptyReadback": False},
                   {"consumers": ["foreign"]}, {"runId": "other"}):
        with pytest.raises(ValueError, match="D12_FRESH_OWNED_TARGET_REQUIRED"):
            d12.target_input({**target(), **change}, run_id=RUN, engine_id=ENGINE)
    for change in ({"backend": "UBUNTU_PRIVATE_JOURNAL_V1"},
                   {"desktop": {"engineId": "foreign", "volumeProof": {"Labels": {"elevenid.run": RUN}}}},
                   {"desktop": {"engineId": ENGINE, "volumeProof": {"Labels": {"elevenid.run": "other"}}}}):
        with pytest.raises(ValueError, match="D12_DESKTOP_JOURNAL_REQUIRED"):
            d12.journal_input({**journal(), **change}, run_id=RUN, engine_id=ENGINE)


def test_actual_target_readback_blocks_foreign_or_consumed_volume(monkeypatch, tmp_path):
    proof = target()
    path = tmp_path / "target.json"
    path.write_text(json.dumps(proof))
    monkeypatch.setattr(build, "read_ref", lambda _ref: path)
    row = {"Name": proof["volume"], "Driver": "local", "Scope": "local",
           "CreatedAt": proof["createdAt"],
           "Labels": {"elevenid.owner": proof["owner"], "elevenid.run": RUN}}
    class Helper:
        def __init__(self):
            self.row, self.consumers = row, ""
        def run(self, *args):
            return SimpleNamespace(stdout=json.dumps([self.row]) if "inspect" in args else self.consumers)
    helper = Helper()
    plan = {"targetVolumeReceipt": {"path": str(path), "sha256": "0" * 64},
            "runId": RUN, "engineId": ENGINE}
    build.require_d12_fresh_target(plan, helper)
    helper.row = {**row, "Labels": {"elevenid.owner": "foreign", "elevenid.run": RUN}}
    with pytest.raises(ValueError, match="D12_OWNED_TARGET_CHANGED"):
        build.require_d12_fresh_target(plan, helper)
    helper.row = row
    helper.consumers = "existing-container"
    with pytest.raises(ValueError, match="D12_TARGET_ALREADY_CONSUMED"):
        build.require_d12_fresh_target(plan, helper)


def test_bound_cache_journal_uses_hash_bound_historical_transport(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    cache_private = tmp_path / ".codex/private/cache/source-export"
    cache_private.mkdir(parents=True)
    operators = cache_private / "operator"
    operators.mkdir()
    names = ("scoped_linux_journal.py", "scoped_native_runtime.py",
             "desktop_journal_transport.py")
    blobs = {
        names[0]: b"class LinuxBuildJournal:\n    def __init__(self, private, run, backend):\n        self.private, self.run, self.backend = private, run, backend\n",
        names[1]: (Path(build.__file__).with_name(names[1])).read_bytes(),
        names[2]: b"# historical desktop transport\n",
    }
    for name, blob in blobs.items():
        (operators / name).write_bytes(blob)
    digests = {name: hashlib.sha256(blob).hexdigest() for name, blob in blobs.items()}
    backend = {
        "workerSha256": digests[names[0]], "sharedSha256": digests[names[1]],
        "desktop": {
            "transportSha256": digests[names[2]], "engineId": ENGINE,
            "image": "sha256:image-control",
            "configDirectory": str(cache_private / "docker-config"),
            "volumeName": "marty-d02-journal-" + RUN,
            "volumeProof": {"Labels": {"elevenid.owner": "d02-private-journal",
                                      "elevenid.run": RUN}},
        },
    }
    source = {
        "schema": "marty.d12-current-native-source-export/v1",
        "state": "SOURCE_EXPORTED_NO_COMPILER", "producerRevision": "a" * 40,
        "sources": {"ui": {"repository": str(tmp_path / "source"),
                             "revision": "b" * 40, "tree": "c" * 40,
                             "inventory": {"sha256": "d" * 64}},
                    "core": {"revision": "e" * 40}},
        "operators": {name: {"path": str(operators / name), "sha256": digests[name]}
                      for name in names},
    }
    (cache_private / "source-export-receipt.json").write_text(json.dumps(source))
    cached = {"runId": RUN, "journalBackend": backend, "uiRevision": "b" * 40,
              "uiTree": "c" * 40, "uiInventorySha256": "d" * 64}
    receipt = cache_private / "cargo-cache-receipt.json"
    receipt.write_text(json.dumps(cached))
    bound = {"path": str(receipt), "sha256": build.sha(receipt),
             "bytes": receipt.stat().st_size}
    plan = {"cargoCacheRunId": RUN, "cargoCacheJournalBackend": backend,
            "engineId": ENGINE, "builderImage": "sha256:image-control",
            "coreRevision": "e" * 40,
            "sources": {"ui": {"repository": source["sources"]["ui"]["repository"]}}}
    def pinned_git(args):
        assert args[:3] == ["-C", source["sources"]["ui"]["repository"], "show"]
        assert args[3].startswith(source["producerRevision"] + ":scripts/")
        return blobs[args[3].split(":scripts/")[-1]]
    journal = build.bound_cache_journal(plan, bound, cached, pinned_git)
    assert journal.private == cache_private and journal.run == RUN
    assert journal.backend["desktop"]["transportSha256"] == digests[names[2]]
    with pytest.raises(ValueError, match="D12_CACHE_RECEIPT_PRIVATE_PATH_CHANGED"):
        build.bound_cache_journal(plan, {**bound, "sha256": "0" * 64}, cached, pinned_git)
    wrong_backend = json.loads(json.dumps(backend))
    wrong_backend["desktop"]["transportSha256"] = "0" * 64
    with pytest.raises(ValueError, match="D12_CACHE_OPERATOR_SOURCE_CHANGED"):
        build.bound_cache_journal({**plan, "cargoCacheJournalBackend": wrong_backend}, bound,
                                  {**cached, "journalBackend": wrong_backend}, pinned_git)
    changed_shared = b"# different committed shared runtime\n"
    (operators / names[1]).write_bytes(changed_shared)
    changed_digest = hashlib.sha256(changed_shared).hexdigest()
    source["operators"][names[1]]["sha256"] = changed_digest
    (cache_private / "source-export-receipt.json").write_text(json.dumps(source))
    blobs[names[1]] = changed_shared
    different_backend = json.loads(json.dumps(backend))
    different_backend["sharedSha256"] = changed_digest
    with pytest.raises(ValueError, match="D12_CACHE_LOADED_SHARED_CHANGED"):
        build.bound_cache_journal({**plan, "cargoCacheJournalBackend": different_backend}, bound,
                                  {**cached, "journalBackend": different_backend}, pinned_git)
    foreign = tmp_path / "foreign/source-export"
    foreign.mkdir(parents=True)
    foreign_receipt = foreign / receipt.name
    foreign_receipt.write_bytes(receipt.read_bytes())
    with pytest.raises(ValueError, match="D12_CACHE_PRIVATE_ROOT_CHANGED"):
        build.bound_cache_journal(plan, {"path": str(foreign_receipt),
                                         "sha256": build.sha(foreign_receipt),
                                         "bytes": foreign_receipt.stat().st_size}, cached, pinned_git)
