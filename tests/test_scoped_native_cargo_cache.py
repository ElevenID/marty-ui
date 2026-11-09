"""Portable controls for the exact-lock native Cargo cache boundary."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_native_cargo_cache as subject


SOURCES = {
    "ssi-elevenid": ("234723638447c30f90cf499bce1d6b092f865e9d",
                      "6f86efc1579033e14ff2ad7d115ca0857e16a67f"),
    "isomdl-elevenid": ("1e7ab823e26559dfce2f7e0f1fdf2aa61a936b4f",),
    "marty-core": ("ffa24febcd0fb3fced15da7f28190af6d61ae0f9",),
    "marty-microservices-framework": ("d8b8d8583203c31a1a5cd6b513a6068e6c416b6d",),
    "sd-jwt-rust": ("26bd9cb142a1ab17b11ba2f76c76b40a5ef0e60d",),
}


def source(repo, rev):
    return f"git+https://github.com/ElevenID/{repo}?rev={rev}#{rev}"


def _git_control(*args):
    return subprocess.run(["git", *map(str, args)], check=True, capture_output=True).stdout.decode().strip()


def _tiny_repo(path):
    _git_control("init", "-q", path)
    _git_control("-C", path, "config", "user.email", "test@example.invalid")
    _git_control("-C", path, "config", "user.name", "Cache Test")
    (path / "Cargo.toml").write_text('[package]\nname="tiny"\nversion="0.1.0"\n')
    _git_control("-C", path, "add", "Cargo.toml")
    _git_control("-C", path, "commit", "-qm", "initial")
    return _git_control("-C", path, "rev-parse", "HEAD")


def test_local_object_import_uses_exact_parent_gitlink_and_refuses_dirty_checkout(tmp_path):
    rdf = tmp_path / "rdf-work"
    rdf.mkdir()
    rdf_rev = _tiny_repo(rdf)
    rdf_db = tmp_path / "rdf-dataset-canonicalization-0123456789abcdef"
    _git_control("clone", "-q", "--bare", rdf, rdf_db)
    ssi = tmp_path / "ssi-work"
    ssi.mkdir()
    _tiny_repo(ssi)
    _git_control("-C", ssi, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                 rdf, "crates/rdf/canonicalization")
    _git_control("-C", ssi, "config", "-f", ".gitmodules",
                 "submodule.crates/rdf/canonicalization.url",
                 "https://github.com/w3c-ccg/rdf-dataset-canonicalization")
    _git_control("-C", ssi, "add", ".gitmodules", "crates/rdf/canonicalization")
    _git_control("-C", ssi, "commit", "-qm", "gitlink")
    ssi_rev = _git_control("-C", ssi, "rev-parse", "HEAD")
    ssi_name = "ssi-elevenid-0123456789abcdef"
    ssi_db = tmp_path / ssi_name
    _git_control("clone", "-q", "--bare", ssi, ssi_db)
    core = tmp_path / "core-work"
    core.mkdir()
    core_rev = _tiny_repo(core)
    core_name = "marty-core-0123456789abcdef"
    core_db = tmp_path / core_name
    _git_control("clone", "-q", "--bare", core, core_db)
    checkout = tmp_path / "checkouts" / core_name / core_rev[:7]
    checkout.parent.mkdir(parents=True)
    _git_control("clone", "-q", core_db, checkout)
    _git_control("-C", checkout, "checkout", "-q", "--detach", core_rev)
    lock = (f'[[package]]\nname="core"\nversion="0.1.0"\nsource="{source("marty-core", core_rev)}"\n'
            f'[[package]]\nname="ssi"\nversion="0.1.0"\nsource="{source("ssi-elevenid", ssi_rev)}"\n').encode()
    inputs = {"marty-core@" + core_rev: {"gitDirectory": str(core / ".git"),
               "cargoDbName": core_name, "checkoutDirectory": str(checkout)},
              "ssi-elevenid@" + ssi_rev: {"gitDirectory": str(ssi_db),
               "cargoDbName": ssi_name, "checkoutDirectory": None},
              "rdfGitlink": {"gitDirectory": str(rdf_db),
               "cargoDbName": "rdf-dataset-canonicalization-0123456789abcdef"}}
    proof = subject.verified_local_objects(lock, inputs)
    assert proof["rdfGitlink"]["revision"] == rdf_rev
    assert proof["marty-core@" + core_rev]["bare"] is False
    script = subject.render_fetch_script(hashlib.sha256(lock).hexdigest(),
                                         subject.git_sources(lock), proof).decode()
    assert "CARGO_NET_OFFLINE=false" not in script
    assert script.count("fetch -q --no-tags") == 3
    assert "submodule update --init --recursive" in script
    assert ("/seed/" + core_name + " rev-parse --is-bare-repository)\" = false") in script
    rdf_name = "rdf-dataset-canonicalization-0123456789abcdef"
    assert ("/cargo/git/db/" + rdf_name
            + " rev-parse --is-bare-repository)\" = true") in script
    assert _git_control("--git-dir", rdf / ".git", "rev-parse",
                        "--is-bare-repository") == "false"  # The emitted guard refuses such a destination.
    assert "--network" not in script  # Docker caller owns network-none.
    (checkout / "Cargo.toml").write_text("changed")
    with pytest.raises(ValueError, match="NATIVE_CACHE_CHECKOUT_TRACKED_DRIFT"):
        subject.verified_local_objects(lock, inputs)


def test_local_import_refuses_wrong_source_set_and_tree():
    lock, sources, *_ = setup()
    with pytest.raises(ValueError, match="NATIVE_CACHE_LOCAL_SOURCE_SET_CHANGED"):
        subject.render_fetch_script(hashlib.sha256(lock).hexdigest(), sources, {})
    bad = {key: {"revision": key.split("@", 1)[1],
                 "tree": "not-a-tree", "cargoDbName": key.split("@", 1)[0] + "-0123456789abcdef"}
           for key in sources}
    bad["rdfGitlink"] = {"cargoDbName": "rdf-dataset-canonicalization-0123456789abcdef",
                          "revision": "a" * 40, "tree": "b" * 40,
                          "parentSource": next(key for key in sources if key.startswith("ssi-elevenid@"))}
    with pytest.raises(ValueError, match="NATIVE_CACHE_LOCAL_OBJECT_PROOF_CHANGED"):
        subject.render_fetch_script(hashlib.sha256(lock).hexdigest(), sources, bad)


def lock_fixture():
    parts = ["version = 4"]
    for repo, revisions in SOURCES.items():
        for rev in revisions:
            parts.append(f'[[package]]\nname = "{repo}"\nversion = "0.1.0"\nsource = "{source(repo, rev)}"')
    return ("\n\n".join(parts) + "\n").encode()


def setup():
    lock = lock_fixture()
    sources = subject.git_sources(lock)
    metadata = json.dumps({"packages": [{"source": item} for item in sources.values()]}).encode()
    checkout = {key: {"revision": key.split("@", 1)[1], "tree": "a" * 40,
                      "checkout": "/cargo/git/checkouts/" + key.split("@", 1)[0] + "-1234567890abcdef/" + key.split("@", 1)[1][:7],
                      "clean": True, "submodules": []} for key in sources}
    checkout_bytes = json.dumps(checkout).encode()
    plan = {"sources": {"ui": {"revision": "1" * 40, "tree": "2" * 40,
                               "inventory": {"sha256": "3" * 64}},
                        "core": {"revision": SOURCES["marty-core"][0]}},
            "engineId": "engine-control", "builderImage": "sha256:" + "4" * 64}
    digest = hashlib.sha256(lock).hexdigest()
    receipt = {"state": "LOCKED_FETCH_AND_OFFLINE_READBACK_PASSED", "exitCode": 0,
               "oomKilled": False, "helperRemoved": True, "lockedFetchExitCode": 0,
               "offlineFetchExitCode": 0, "originalLockSha256": digest,
               "beforeLockSha256": digest, "afterLockSha256": digest,
               "finalLockSha256": digest, "gitSources": sources,
               "offlineMetadataGitSources": subject.metadata_git_sources(metadata),
               "checkoutProof": checkout, "checkoutProofSha256": hashlib.sha256(checkout_bytes).hexdigest(),
               "uiRevision": plan["sources"]["ui"]["revision"],
               "uiTree": plan["sources"]["ui"]["tree"],
               "uiInventorySha256": plan["sources"]["ui"]["inventory"]["sha256"],
               "cargoVolume": "ui-canvas-cargo", "cargoVolumeCreatedAt": "created-control",
               "engineId": plan["engineId"], "builderImage": plan["builderImage"],
               "journalBackend": {"backend": "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1",
                                  "desktop": {"engineId": plan["engineId"]}},
               "offlineMetadataSha256": hashlib.sha256(metadata).hexdigest()}
    return lock, sources, metadata, checkout_bytes, plan, receipt


def test_exact_original_lock_and_offline_cache_recipe():
    lock, sources, metadata, checkout, plan, receipt = setup()
    assert len(sources) == 6
    script = subject.render_fetch_script(hashlib.sha256(lock).hexdigest(), sources).decode()
    assert "CARGO_NET_OFFLINE=false cargo fetch --locked" in script
    assert "cargo fetch --offline --locked" in script
    assert "python3 /build/cache_guard.py verify-checkouts" in script
    assert "localize_marty_core_dependencies" not in script
    subject.validate_receipt(plan, receipt, lock, metadata, checkout)


@pytest.mark.parametrize("key,bad", [
    ("gitSources", {}), ("originalLockSha256", "0" * 64),
    ("cargoVolume", "foreign"), ("uiRevision", "0" * 40),
    ("engineId", "foreign"), ("offlineFetchExitCode", 1),
    ("oomKilled", True), ("exitCode", False),
    ("lockedFetchExitCode", False), ("offlineFetchExitCode", False),
])
def test_stale_or_foreign_cache_refused(key, bad):
    lock, _, metadata, checkout, plan, receipt = setup()
    receipt[key] = bad
    with pytest.raises(ValueError, match="NATIVE_CACHE_EXACT_LOCK_READBACK_REQUIRED"):
        subject.validate_receipt(plan, receipt, lock, metadata, checkout)


def test_changed_git_revision_refused():
    lock, _, metadata, checkout, plan, receipt = setup()
    changed = lock.replace(SOURCES["marty-microservices-framework"][0].encode(), b"0" * 40)
    with pytest.raises(ValueError):
        subject.validate_receipt(plan, receipt, changed, metadata, checkout)


def test_unselected_optional_git_source_can_be_absent_from_metadata():
    lock, sources, _, checkout, plan, receipt = setup()
    subset = json.dumps({"packages": [{"source": item} for item in sources.values()
                                      if "sd-jwt-rust" not in item]}).encode()
    receipt["offlineMetadataGitSources"] = subject.metadata_git_sources(subset)
    receipt["offlineMetadataSha256"] = hashlib.sha256(subset).hexdigest()
    subject.validate_receipt(plan, receipt, lock, subset, checkout)


def test_missing_checkout_refused_even_if_metadata_is_valid():
    lock, _, metadata, checkout, plan, receipt = setup()
    partial = json.loads(checkout)
    partial.pop(next(key for key in partial if "marty-microservices-framework" in key))
    reduced = json.dumps(partial).encode()
    receipt["checkoutProof"] = partial
    receipt["checkoutProofSha256"] = hashlib.sha256(reduced).hexdigest()
    with pytest.raises(ValueError):
        subject.validate_receipt(plan, receipt, lock, metadata, reduced)


def test_dirty_checkout_with_same_head_refused(tmp_path):
    root = tmp_path / "checkouts"
    repo = root / "fixture-1234567890abcdef" / "abcdef0"
    repo.mkdir(parents=True)
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.STDOUT).decode().strip()
    git("init", "-q")
    git("config", "user.name", "Cache Control")
    git("config", "user.email", "cache-control@example.invalid")
    tracked = repo / "tracked.txt"
    tracked.write_text("accepted\n")
    git("add", "tracked.txt")
    git("commit", "-qm", "accepted")
    revision = git("rev-parse", "HEAD")
    expected = {"fixture@" + revision: source("fixture", revision)}
    (repo / ".cargo-ok").touch()
    proof = subject.verify_checkout_root(expected, root)
    assert proof["fixture@" + revision]["clean"] is True
    tracked.write_text("mutated\n")
    assert git("rev-parse", "HEAD") == revision
    with pytest.raises(ValueError, match="NATIVE_CACHE_CLEAN_CHECKOUT_MISSING"):
        subject.verify_checkout_root(expected, root)


@pytest.mark.parametrize("census,expected", [
    ("", None), ("5" * 64 + "\n", "NATIVE_CACHE_HELPER_STILL_REGISTERED"),
    ("ERROR", "daemon-error"),
])
def test_retirement_requires_successful_exact_daemon_census(census, expected):
    class Helper:
        def run(self, *args):
            if "info" in args:
                return type("Result", (), {"stdout": "engine-control\n"})()
            assert args[-1] == "id=" + "5" * 64
            if census == "ERROR":
                raise OSError("daemon-error")
            return type("Result", (), {"stdout": census})()
    if expected is None:
        subject.confirm_retired(Helper(), "5" * 64, "engine-control")
    elif expected == "daemon-error":
        with pytest.raises(OSError, match=expected):
            subject.confirm_retired(Helper(), "5" * 64, "engine-control")
    else:
        with pytest.raises(ValueError, match=expected):
            subject.confirm_retired(Helper(), "5" * 64, "engine-control")


def _registry_control_lock(crate: bytes) -> bytes:
    checksum = hashlib.sha256(crate).hexdigest()
    return (f'[[package]]\nname = "strum"\nversion = "0.28.0"\n'
            f'source = "{subject.REGISTRY_SOURCE}"\nchecksum = "{checksum}"\n').encode()


def test_locked_registry_archive_import_reuses_exact_file_without_replacement(tmp_path):
    crate = b"small locked crate control\n"
    lock = _registry_control_lock(crate)
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "strum-0.28.0.crate").write_bytes(crate)
    destination = tmp_path / "cargo/registry/cache" / subject.REGISTRY_CACHE
    first = subject.import_registry_archives(lock, seed, destination, tmp_path / "proof-one.json")
    assert first["copied"] == 1 and first["reused"] == 0
    assert (destination / "strum-0.28.0.crate").read_bytes() == crate
    second = subject.import_registry_archives(lock, seed, destination, tmp_path / "proof-two.json")
    assert second["copied"] == 0 and second["reused"] == 1
    assert (destination / "strum-0.28.0.crate").read_bytes() == crate


def test_locked_registry_archive_refuses_bad_seed_and_existing_mismatch(tmp_path):
    crate = b"locked archive"
    lock = _registry_control_lock(crate)
    seed = tmp_path / "seed"
    seed.mkdir()
    source = seed / "strum-0.28.0.crate"
    source.write_bytes(b"different bytes")
    destination = tmp_path / "cargo/registry/cache" / subject.REGISTRY_CACHE
    with pytest.raises(ValueError, match="NATIVE_CACHE_REGISTRY_ARCHIVE_CHANGED"):
        subject.import_registry_archives(lock, seed, destination, tmp_path / "proof.json")
    assert not destination.exists()
    source.write_bytes(crate)
    destination.mkdir(parents=True)
    target = destination / source.name
    target.write_bytes(b"foreign data")
    with pytest.raises(ValueError, match="NATIVE_CACHE_REGISTRY_EXISTING_MISMATCH"):
        subject.import_registry_archives(lock, seed, destination, tmp_path / "proof.json")
    assert target.read_bytes() == b"foreign data"
    assert not (tmp_path / "proof.json").exists()


def test_existing_registry_proof_refuses_before_cache_directory_creation(tmp_path):
    crate = b"locked archive"
    lock = _registry_control_lock(crate)
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "strum-0.28.0.crate").write_bytes(crate)
    proof = tmp_path / "proof.json"
    proof.write_text("prior attempt")
    destination = tmp_path / "cargo/registry/cache" / subject.REGISTRY_CACHE
    with pytest.raises(ValueError, match="NATIVE_CACHE_REGISTRY_PROOF_ALREADY_EXISTS"):
        subject.import_registry_archives(lock, seed, destination, proof)
    assert not destination.exists() and proof.read_text() == "prior attempt"


def test_local_script_imports_registry_before_offline_fetch_and_networked_default_is_unchanged():
    lock, sources, *_ = setup()
    local = {key: {"revision": key.split("@", 1)[1], "tree": "a" * 40,
                   "cargoDbName": key.split("@", 1)[0] + "-0123456789abcdef",
                   "bare": key.split("@", 1)[0] != "marty-core"} for key in sources}
    local["rdfGitlink"] = {"revision": "b" * 40, "tree": "c" * 40,
                            "cargoDbName": "rdf-dataset-canonicalization-0123456789abcdef",
                            "parentSource": next(key for key in sources if key.startswith("ssi-elevenid@"))}
    script = subject.render_fetch_script(hashlib.sha256(lock).hexdigest(), sources, local).decode()
    assert script.index("import-registry") < script.index("cargo fetch --offline --locked")
    assert "/seed/registry" in script and "CARGO_NET_OFFLINE=false" not in script
    default = subject.render_fetch_script(hashlib.sha256(lock).hexdigest(), sources).decode()
    assert "import-registry" not in default and "CARGO_NET_OFFLINE=false cargo fetch --locked" in default
