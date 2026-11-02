from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def steps():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["test-rust-services"]["steps"]


def named(name):
    return next(step for step in steps() if step.get("name") == name)


def test_selfhost_build_cache_is_retired_before_any_host_acceptance_compilation():
    values = steps()
    builder = next(step for step in values if step.get("id") == "rust_contract_builder")
    assert builder["with"].get("driver", "docker-container") == "docker-container"
    assert "name" not in builder["with"] and "endpoint" not in builder["with"]
    image = named("Build public selfhost image")
    cleanup = named("Retire completed selfhost builder cache")
    assert values.index(builder) < values.index(image) < values.index(cleanup)
    assert values.index(cleanup) < values.index(named("Prepare source-matched Rust execution policy"))
    assert values.index(cleanup) < values.index(named("Compile reusable Rust test executables"))
    assert values.index(named("Compile reusable Rust test executables")) < values.index(named("Prepare public selfhost image loader acceptance"))
    for name in ["Record selfhost disk before public image", "Retire completed selfhost builder cache", "Record selfhost acceptance compile disk"]:
        assert named(name)["if"] == "matrix.lane == 'selfhost'"
    assert cleanup["env"] == {
        "SELFHOST_BUILDER": "${{ steps.rust_contract_builder.outputs.name }}",
        "EXPECTED_SELFHOST_IMAGE": "${{ steps.public_selfhost_image.outputs.imageid }}",
    }
    assert image["with"]["builder"] == cleanup["env"]["SELFHOST_BUILDER"]
    assert "docker system prune" not in cleanup["run"]
    assert "rm " not in cleanup["run"]
    assert 'timeout 120s docker buildx prune --builder "$SELFHOST_BUILDER" --all --force' in cleanup["run"]


def test_public_image_and_acceptance_gates_remain_required_and_unchanged():
    image = named("Build public selfhost image")
    assert image["if"] == "matrix.lane == 'selfhost'"
    assert image["with"]["context"] == "."
    assert image["with"]["file"] == "services/Dockerfile"
    assert image["with"]["load"] is True and image["with"]["push"] is False
    assert image["with"]["tags"] == "marty-selfhost-public:contract"
    assert image["with"]["build-args"].splitlines() == [
        "MARTY_RELEASE_VERSION=ci",
        "MARTY_UI_SHA=${{ github.event.pull_request.head.sha || github.sha }}",
        "SERVICE_NAME=issuance_native",
    ]
    assert "cargo test --locked --offline -p marty-selfhost-acceptance" in named("Compile reusable Rust test executables")["run"]
    assert "cargo build --locked --manifest-path rust/Cargo.toml" in named("Prepare public selfhost image loader acceptance")["run"]
    assert named("Record selfhost disk before public image")["run"].count("timeout 20s du") == 1
    assert "timeout 30s docker buildx du" in named("Retire completed selfhost builder cache")["run"]
    assert "timeout 20s du" in named("Record selfhost acceptance compile disk")["run"]


@pytest.mark.parametrize("mode,success,pruned", [
    ("valid", True, True),
    ("wrong-before", False, False),
    ("wrong-after", False, True),
    ("prune-fails", False, True),
    ("empty-builder", False, False),
    ("shared-builder", False, False),
    ("invalid-expected-image", False, False),
    ("du-unavailable", True, True),
])
def test_actual_cleanup_shell_keeps_image_and_only_prunes_exact_owned_builder(tmp_path, mode, success, pruned):
    # Synthetic command implementations: never invoke a Docker executable.
    bash = Path("C:/Program Files/Git/bin/bash.exe") if os.name == "nt" else Path(shutil.which("bash") or "/bin/bash")
    if not bash.is_file():
        pytest.skip("Bash is required for the workflow shell control")
    (tmp_path / "rust-build-evidence").mkdir()
    log = tmp_path / "calls.txt"
    prelude = r'''set -eu
      docker() {
        printf '%s\n' "$*" >> "$CALLS"
        if [[ "$1 $2" == "image inspect" ]]; then
          n=0; [[ ! -f "$RUNNER_TEMP/reads" ]] || n=$(cat "$RUNNER_TEMP/reads")
          n=$((n+1)); printf '%s' "$n" > "$RUNNER_TEMP/reads"
          if [[ "$MODE" == wrong-before || ( "$MODE" == wrong-after && "$n" == 2 ) ]]; then
            printf 'sha256:%064d\n' 2
          else
            printf '%s\n' "$EXPECTED_SELFHOST_IMAGE"
          fi
        elif [[ "$1 $2" == "buildx prune" ]]; then
          [[ "$MODE" != prune-fails ]]
        elif [[ "$1 $2" == "buildx du" ]]; then
          [[ "$MODE" != du-unavailable ]] || return 7
          printf 'synthetic-owned-cache 1024\n'
        else
          return 99
        fi
      }
      timeout() { shift; "$@"; }
      df() { printf 'synthetic-filesystem 1 1 1\n'; }
    '''
    script = tmp_path / "control.sh"
    script.write_text(prelude + named("Retire completed selfhost builder cache")["run"], encoding="utf-8", newline="\n")
    env = {**os.environ, "RUNNER_TEMP": tmp_path.as_posix(), "GITHUB_WORKSPACE": tmp_path.as_posix(),
           "CALLS": log.as_posix(), "MODE": mode,
           "SELFHOST_BUILDER": "" if mode == "empty-builder" else "default" if mode == "shared-builder" else "builder-11111111-1111-4111-8111-111111111111",
           "EXPECTED_SELFHOST_IMAGE": "bad" if mode == "invalid-expected-image" else "sha256:" + "1" * 64}
    result = subprocess.run([str(bash), script.as_posix()], env=env, capture_output=True, timeout=10)
    assert (result.returncode == 0) is success
    calls = log.read_text().splitlines() if log.exists() else []
    assert any(call.startswith("buildx prune") for call in calls) is pruned
    assert all(call.startswith(("image inspect ", "buildx du --builder builder-11111111-1111-4111-8111-111111111111", "buildx prune --builder builder-11111111-1111-4111-8111-111111111111 --all --force")) for call in calls)
    if success:
        assert sum(call.startswith("image inspect ") for call in calls) == 2
