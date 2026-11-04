from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bookworm_key", ROOT / "scripts/ci/bookworm_cache_key.py")
KEY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KEY)


def key_fixture(tmp_path):
    names = ["services/Dockerfile", "rust/Cargo.lock", "rust/Cargo.toml", ".github/workflows/ci.yml",
             "scripts/ci/bookworm_cache_key.py", "scripts/ci/bookworm-cache-env.sh",
             "scripts/ci/install-bookworm-sccache.sh"]
    for name in names:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    return names


@pytest.mark.parametrize("changed", ["services/Dockerfile", "rust/Cargo.lock", "rust/Cargo.toml",
                                     ".github/workflows/ci.yml", "scripts/ci/bookworm-cache-env.sh",
                                     "scripts/ci/install-bookworm-sccache.sh"])
def test_key_binds_compiler_dependencies_profiles_and_recipe(tmp_path, changed):
    key_fixture(tmp_path)
    initial = KEY.cache_key(tmp_path, "canvas", "x86_64")
    path = tmp_path / changed
    if changed == "services/Dockerfile":
        source = path.read_text()
        marker = "FROM rust:1.95-bookworm@sha256:"
        start = source.index(marker) + len(marker)
        path.write_text(source[:start] + "f" * 64 + source[start + 64:])
    else:
        path.write_text(path.read_text() + "\n# changed compiler input\n")
    assert KEY.cache_key(tmp_path, "canvas", "x86_64") != initial


def test_all_scopes_share_trusted_objects_but_architectures_do_not(tmp_path):
    key_fixture(tmp_path)
    keys = {KEY.cache_key(tmp_path, lane, "x86_64") for lane in ("canvas", "worker", "flow", "selfhost")}
    assert len(keys) == 1  # sccache itself keys compiler arguments/features per object.
    assert KEY.cache_key(tmp_path, "canvas", "aarch64") not in keys
    with pytest.raises(ValueError): KEY.cache_key(tmp_path, "contracts", "x86_64")


@pytest.mark.parametrize("cache_exit", [0, 1])
def test_container_wrapper_probes_actual_pinned_compiler_and_falls_back(tmp_path, cache_exit):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    compiler = bindir / "actual-bookworm-rustc"
    compiler.write_text("#!/bin/sh\nprintf 'rustc 1.95.0 (fixture)\\n'\n")
    rustup = bindir / "rustup"
    rustup.write_text(f'#!/bin/sh\ntest "$*" = "which rustc --toolchain 1.95.0" || exit 9\nprintf "%s\\n" "{compiler}"\n')
    cache = bindir / "sccache"
    cache.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" > "{tmp_path / "probe"}"\nexit {cache_exit}\n')
    for path in (compiler, rustup, cache): path.chmod(0o755)
    disk = tmp_path / "cache"
    disk.mkdir()
    env = {**os.environ, "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
           "MARTY_BOOKWORM_SCCACHE": str(cache), "SCCACHE_DIR": str(disk),
           "RUSTC_WRAPPER": "untrusted-host-wrapper", "SCCACHE_GHA_ENABLED": "true",
           "ACTIONS_RUNTIME_TOKEN": "fixture", "SCCACHE_GHA_RUNTIME_TOKEN": "fixture"}
    script = f'. "{ROOT / "scripts/ci/bookworm-cache-env.sh"}"\nprintf "%s\\n%s\\n%s\\n%s\\n" "$RUSTC" "${{RUSTC_WRAPPER:-}}" "${{SCCACHE_GHA_ENABLED:-}}" "${{ACTIONS_RUNTIME_TOKEN:-}}"'
    result = subprocess.run(["sh", "-ceu", script], env=env, capture_output=True, text=True, check=True)
    assert result.stdout.splitlines() == [str(compiler), str(cache) if cache_exit == 0 else "", "", ""]
    assert (tmp_path / "probe").read_text().strip() == f"{compiler} -vV"


def test_workflow_mounts_actual_cache_and_only_trusted_full_runs_publish():
    job = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["test-rust-services"]
    steps = {step.get("name"): step for step in job["steps"]}
    compile = steps["Compile reusable Rust test executables"]["run"]
    assert compile.count('"${bookworm_cache_args[@]}"') == 2
    assert compile.count(". ../scripts/ci/bookworm-cache-env.sh") == 2
    assert compile.count("--network none --read-only") == 2
    assert '--volume "$BOOKWORM_SCCACHE_BIN:/opt/marty-cache/sccache:ro"' in compile
    assert '--volume "$BOOKWORM_CACHE_DIR:/opt/marty-cache/data:rw"' in compile
    assert "SCCACHE_GHA_RUNTIME_TOKEN" not in compile and "ACTIONS_RUNTIME_TOKEN" not in compile
    restore = steps["Restore trusted offline Bookworm compiler objects"]
    save = steps["Save successful trusted-main offline compiler objects"]
    assert "actions/cache/restore@" in restore["uses"]
    assert "actions/cache/save@" in save["uses"]
    assert restore["continue-on-error"] and save["continue-on-error"]
    for restriction in ("success()", "github.repository == 'ElevenID/marty-ui'",
                        "github.ref == 'refs/heads/main'", "github.event_name == 'schedule'",
                        "github.event_name == 'workflow_dispatch'", "matrix.lane == 'canvas'"):
        assert restriction in save["if"]
    assert "pull_request" not in save["if"] and "merge_group" not in save["if"]
    assert job["env"]["SCCACHE_GHA_RW_MODE"] == "READ_ONLY"
    for checksum in ("aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588",
                     "f73a5c39f96bb6ebb89cc7915cf182260d4cbf30765322c5e793d0fe8bd80784"):
        assert checksum in (ROOT / "services/Dockerfile").read_text()
        assert checksum in (ROOT / "scripts/ci/install-bookworm-sccache.sh").read_text()
