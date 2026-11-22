"""Real local Git fixtures for the watcher's credential-free source boundary."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts import passport_watch_git_seed as seed


def git(path, *args):
    env = seed.git_environment(dict(os.environ), local_import=True)
    return subprocess.run(["git", "-C", str(path), *args], env=env, check=True,
                          capture_output=True).stdout.decode().strip()


def commit(path, message):
    git(path, "add", "--all")
    git(path, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", message)
    return git(path, "rev-parse", "HEAD")


@pytest.fixture(scope="module")
def cache_template(tmp_path_factory):
    directory = tmp_path_factory.mktemp("git-seed-template")
    cargo, root = directory / "cargo", directory / "checkout"
    (cargo / "git/db").mkdir(parents=True)
    (root / "rust").mkdir(parents=True)
    rows = []
    rdf = directory / "rdf-work"
    rdf.mkdir()
    git(rdf, "init", "--quiet", "--template=")
    (rdf / "canonicalize.rs").write_text("// exact local RDF fixture\n")
    rdf_rev = commit(rdf, "RDF fixture")
    git(directory, "clone", "--quiet", "--bare", "--no-hardlinks", str(rdf),
        str(cargo / "git/db" / (seed.RDF_REPO + "-" + "f" * 16)))
    for index, repo in enumerate(("isomdl-elevenid", "marty-core", "marty-microservices-framework", "sd-jwt-rust", "ssi-elevenid")):
        work = directory / (repo + "-work")
        work.mkdir()
        git(work, "init", "--quiet", "--template=")
        (work / "history.txt").write_text("outside the shallow boundary\n")
        commit(work, "earlier history")
        (work / "Cargo.toml").write_text(f'[package]\nname = "{repo}"\nversion = "0.1.0"\nedition = "2021"\n')
        (work / "src").mkdir()
        (work / "src/lib.rs").write_text("pub fn fixture() {}\n")
        rev = commit(work, "locked dependency")
        rows.append((repo, rev))
        depth = "1"
        if repo == "ssi-elevenid":
            (work / ".gitmodules").write_text(
                f'[submodule "{seed.RDF_PATH}"]\n\tpath = {seed.RDF_PATH}\n\turl = {seed.RDF_URL}\n')
            git(work, "add", ".gitmodules")
            git(work, "update-index", "--add", "--cacheinfo", f"160000,{rdf_rev},{seed.RDF_PATH}")
            git(work, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "locked RDF gitlink")
            rows.append((repo, git(work, "rev-parse", "HEAD")))
            depth = "2"
        git(directory, "clone", "--quiet", "--bare", "--depth=" + depth, work.as_uri(),
            str(cargo / "git/db" / (repo + "-" + str(index + 1) * 16)))
    lock = 'version = 4\n'
    for index, (repo, revision) in enumerate(rows):
        lock += (f'\n[[package]]\nname = "fixture-{index}"\nversion = "0.1.0"\n'
                 f'source = "git+https://github.com/ElevenID/{repo}?rev={revision}#{revision}"\n')
    lock += ('\n[[package]]\nname = "public-registry-fixture"\nversion = "1.0.0"\n'
             'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + "a" * 64 + '"\n')
    (root / "rust/Cargo.lock").write_text(lock)
    return root, cargo


@pytest.fixture
def inputs(cache_template, tmp_path):
    original_root, original_cargo = cache_template
    root, cargo = tmp_path / "checkout", tmp_path / "cargo"
    shutil.copytree(original_root, root)
    shutil.copytree(original_cargo, cargo)
    return root, cargo, tmp_path / "seed"


def inventory(directory):
    return {path.relative_to(directory).as_posix():
            (path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_mode,
             hashlib.sha256(path.read_bytes()).hexdigest())
            for path in directory.rglob("*") if path.is_file()}


def exported(inputs):
    root, cargo, destination = inputs
    record = seed.export_seed(root, cargo, destination, dict(os.environ))
    return root, cargo, destination, record


def consumer(directory):
    cargo = directory / "consumer"
    (cargo / "git").mkdir(parents=True)
    (cargo / "registry").mkdir()
    return cargo


def test_real_shallow_export_import_preserves_input_and_all_locked_checkouts(inputs, tmp_path):
    root, original, destination = inputs
    before = inventory(original)
    record = seed.export_seed(root, original, destination, dict(os.environ))
    lock = (root / "rust/Cargo.lock").read_bytes()
    checked, digest = seed.checked_seed(destination, lock, root)
    assert checked == record and len(record["sources"]) == 6
    assert any(name.endswith("/shallow") for name in record["files"])
    assert before == inventory(original)
    target = consumer(tmp_path)
    old = os.umask(0o077)
    try:
        seed.import_seed(destination, target, lock, digest, dict(os.environ))
    finally:
        os.umask(old)
    seed.verify_checkouts(record, target, seed.git_environment(dict(os.environ)))
    assert before == inventory(original)
    assert not (target / "credentials.toml").exists()
    for name in {row["cargoDbName"] for row in record["sources"].values()}:
        assert (target / "git/db" / name / "shallow").read_bytes() == (destination / "db" / name / "shallow").read_bytes()


def test_export_never_loads_cache_config_hooks_helpers_or_ambient_git_settings(inputs, tmp_path):
    root, cargo, destination = inputs
    sentinel = tmp_path / "must-not-run"
    attack = f"!touch {sentinel}"
    for db in (cargo / "git/db").iterdir():
        # The configuration-free sender does not even parse this input config.
        (db / "config").write_text("invalid config that Git must never load\n")
        (db / "hooks").mkdir(exist_ok=True)
        hook = db / "hooks/reference-transaction"
        hook.write_text(f"#!/bin/sh\ntouch {sentinel}\n")
        hook.chmod(0o700)
    before = inventory(cargo)
    malicious = dict(os.environ, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="credential.helper",
                     GIT_CONFIG_VALUE_0=attack, GIT_ALTERNATE_OBJECT_DIRECTORIES="/forbidden",
                     GIT_NAMESPACE="foreign", GIT_REPLACE_REF_BASE="refs/foreign/",
                     GIT_OBJECT_DIRECTORY="/forbidden", GIT_SHALLOW_FILE="/forbidden",
                     GIT_TEMPLATE_DIR=str(tmp_path), PRIVATE_FORKS_READ_TOKEN="not-a-real-token")
    seed.export_seed(root, cargo, destination, malicious)
    assert not sentinel.exists() and before == inventory(cargo)
    assert all(path.read_bytes() == seed.BARE_CONFIG for path in destination.glob("db/*/config"))
    assert not any(path.name in ("hooks", "credentials", "credentials.toml") for path in destination.rglob("*"))


@pytest.mark.parametrize("missing", (False, True))
def test_original_promisor_marker_never_exports_or_hydrates_missing_objects(inputs, tmp_path, missing):
    root, cargo, destination = inputs
    db = next((cargo / "git/db").glob("isomdl-*"))
    pack = next((db / "objects/pack").glob("*.pack"))
    pack.with_suffix(".promisor").write_bytes(b"")
    sentinel = tmp_path / "must-not-hydrate"
    (db / "config").write_text(f'[remote "origin"]\n\tpromisor = true\n'
        f'\turl = ext::touch {sentinel}\n[extensions]\n\tpartialClone = origin\n')
    if missing:
        pack.chmod(0o600)
        pack.write_bytes(b"")  # The required commit/tree is no longer in this fixture cache.
    before = inventory(cargo)
    if missing:
        with pytest.raises(seed.GitSeedError):
            seed.export_seed(root, cargo, destination, dict(os.environ))
        assert not destination.exists()
    else:
        record = seed.export_seed(root, cargo, destination, dict(os.environ))
        assert not any(name.endswith(".promisor") for name in record["files"])
    assert not sentinel.exists() and inventory(cargo) == before


@pytest.mark.parametrize("kind", ("alternates", "replacement", "object-symlink", "promisor"))
def test_source_cache_rejects_redirected_or_partial_objects_before_export(inputs, tmp_path, kind):
    root, cargo, destination = inputs
    db = next((cargo / "git/db").glob("isomdl-*"))
    if kind == "alternates":
        (db / "objects/info/alternates").write_text("/forbidden\n")
    elif kind == "replacement":
        (db / "refs/replace").mkdir()
    elif kind == "object-symlink":
        (db / "objects/untrusted").symlink_to(tmp_path / "absent")
    else:
        (db / "objects/pack/foreign.promisor").write_text("untrusted remote")
    with pytest.raises(seed.GitSeedError):
        seed.export_seed(root, cargo, destination, dict(os.environ))
    assert not destination.exists()


@pytest.mark.parametrize("kind", ("extra", "symlink", "hardlink", "public", "config", "wrong-lock", "missing-source", "changed-ref"))
def test_checked_seed_rejects_mutations_even_with_rewritten_inventory(inputs, tmp_path, kind):
    root, _, destination, record = exported(inputs)
    lock = (root / "rust/Cargo.lock").read_bytes()
    name = next(name for name in record["files"] if name.endswith("/config"))
    path = destination / name
    if kind == "extra":
        (destination / "credentials.toml").write_text("not a credential")
    elif kind == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "absent")
    elif kind == "hardlink":
        os.link(path, tmp_path / "linked")
    elif kind == "public":
        path.chmod(0o644)
    elif kind == "config":
        path.write_bytes(seed.BARE_CONFIG + b"[include]\n\tpath = /forbidden\n")
        record["files"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
    elif kind == "wrong-lock":
        lock += b"\n# changed original lock\n"
    elif kind == "missing-source":
        record["sources"].pop(next(iter(record["sources"])))
    elif kind == "changed-ref":
        name = next(name for name in record["files"] if "/refs/heads/" in name)
        path = destination / name
        path.write_text("a" * 40 + "\n")
        record["files"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
    (destination / seed.MANIFEST).write_text(json.dumps(record))
    with pytest.raises(seed.GitSeedError):
        seed.checked_seed(destination, lock, root)


def test_stage_is_private_independent_copy_and_keeps_original_input(inputs, tmp_path):
    root, _, source, _ = exported(inputs)
    before = inventory(source)
    destination = tmp_path / "staged"
    lock = (root / "rust/Cargo.lock").read_bytes()
    digest = seed.stage_seed(source, destination, lock, root)
    assert seed.checked_seed(destination, lock)[1] == digest
    assert before == inventory(source)
    for name in before:
        assert (source / name).stat().st_ino != (destination / name).stat().st_ino


@pytest.mark.parametrize("changed", ("tree", "rdf-parent"))
def test_import_derives_object_identity_instead_of_trusting_seed_claims(inputs, tmp_path, changed):
    root, _, source, record = exported(inputs)
    if changed == "tree":
        next(iter(record["sources"].values()))["tree"] = "a" * 40
    else:
        record["rdfGitlink"]["parentSource"] = next(
            key for key in record["sources"] if key.startswith("ssi-elevenid@")
            and key != record["rdfGitlink"]["parentSource"])
    (source / seed.MANIFEST).write_text(json.dumps(record))
    lock = (root / "rust/Cargo.lock").read_bytes()
    digest = seed.checked_seed(source, lock)[1]
    target = consumer(tmp_path)
    with pytest.raises(seed.GitSeedError, match="tree changed|RDF identity changed"):
        seed.import_seed(source, target, lock, digest, dict(os.environ))
    assert not (target / seed.RECORD).exists()


@pytest.mark.parametrize("limit", ("MAX_FILES", "MAX_BYTES", "MAX_SOURCES"))
def test_export_rejects_oversized_input_before_creating_a_source_transport(inputs, monkeypatch, limit):
    root, cargo, destination = inputs
    monkeypatch.setattr(seed, limit, 1)
    monkeypatch.setattr(seed, "_source_view", lambda *args: pytest.fail("source transport must not start"))
    with pytest.raises(seed.GitSeedError, match="bound"):
        seed.export_seed(root, cargo, destination, dict(os.environ))
    assert not destination.exists()


def test_source_change_between_validation_and_copy_fails_closed(inputs, tmp_path, monkeypatch):
    root, _, source, _ = exported(inputs)
    original_read = seed._read
    reads = 0

    def changed(path, *args, **kwargs):
        nonlocal reads
        value = original_read(path, *args, **kwargs)
        if path == source / seed.MANIFEST:
            reads += 1
            if reads == 2:
                path.write_text(path.read_text() + "\n")
        return value

    monkeypatch.setattr(seed, "_read", changed)
    with pytest.raises(seed.GitSeedError):
        seed.stage_seed(source, tmp_path / "staged", (root / "rust/Cargo.lock").read_bytes(), root)


@pytest.mark.parametrize("kind", ("dirty", "skip-worktree", "untracked", "rdf-drift"))
def test_complete_checkout_proof_rejects_tracked_index_untracked_and_gitlink_drift(inputs, tmp_path, kind):
    root, _, source, record = exported(inputs)
    lock = (root / "rust/Cargo.lock").read_bytes()
    target = consumer(tmp_path)
    old = os.umask(0o077)
    try:
        seed.import_seed(source, target, lock, seed.checked_seed(source, lock)[1], dict(os.environ))
    finally:
        os.umask(old)
    row = next(iter(record["sources"].values()))
    path = target / "git/checkouts" / row["cargoDbName"] / row["revision"][:7]
    if kind == "dirty":
        (path / "src/lib.rs").write_text("unverified changed source\n")
    elif kind == "skip-worktree":
        git(path, "update-index", "--skip-worktree", "src/lib.rs")
    elif kind == "untracked":
        (path / "unverified.rs").write_text("foreign file\n")
    else:
        row = record["sources"][record["rdfGitlink"]["parentSource"]]
        path = target / "git/checkouts" / row["cargoDbName"] / row["revision"][:7] / seed.RDF_PATH
        (path / "canonicalize.rs").write_text("unverified gitlink content\n")
    with pytest.raises(seed.GitSeedError):
        seed.verify_checkouts(record, target, seed.git_environment(dict(os.environ)))


def test_public_registry_environment_denies_all_git_transports_and_ambient_credentials(tmp_path):
    env = seed.cargo_environment({"PATH": os.environ["PATH"], "PRIVATE_FORKS_READ_TOKEN": "not-a-real-token",
        "CARGO_REGISTRIES_CRATES_IO_INDEX": "https://foreign.invalid", "GIT_CONFIG_COUNT": "99",
        "HTTP_PROXY": "http://foreign.invalid"}, tmp_path, offline=False)
    assert env["CARGO_NET_GIT_FETCH_WITH_CLI"] == "true" and env["CARGO_NET_OFFLINE"] == "false"
    assert env["RUSTUP_HOME"] == "/usr/local/rustup"
    assert not any(name in env for name in ("PRIVATE_FORKS_READ_TOKEN", "CARGO_REGISTRIES_CRATES_IO_INDEX", "HTTP_PROXY"))
    for remote in ("https://example.invalid/forbidden.git", "ssh://example.invalid/forbidden.git", str(tmp_path)):
        result = subprocess.run(["git", "ls-remote", remote], env=env, capture_output=True, timeout=10)
        assert result.returncode != 0 and b"not allowed" in result.stderr


def test_cargo_rejects_an_unexpected_toolchain_override(tmp_path):
    with pytest.raises(seed.GitSeedError, match="pinned image toolchain"):
        seed.cargo_environment({"RUSTUP_HOME": "/foreign/rustup"}, tmp_path, offline=False)
