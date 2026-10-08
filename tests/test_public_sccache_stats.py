"""Public image builds expose numeric compiler-cache evidence only."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILTER = ROOT / "scripts/ci/public-sccache-stats.awk"
MARKER = "MARTY_PUBLIC_SCCACHE_V1 "


def awk_binary() -> str:
    executable = shutil.which("awk")
    if executable:
        return executable
    git_bash_awk = Path("C:/Program Files/Git/usr/bin/awk.exe")
    if git_bash_awk.is_file():
        return str(git_bash_awk)
    pytest.skip("awk is unavailable on this host")


def run_filter(sample: str, phase: str = "release_binaries") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [awk_binary(), "-v", f"phase={phase}", "-f", str(FILTER)],
        input=sample,
        text=True,
        capture_output=True,
        check=False,
    )


def test_public_builder_emits_only_allowlisted_numeric_cache_counters() -> None:
    sample = (
        "Compile requests                    3166\n"
        "Cache hits                          2247\n"
        "Cache hits (Rust)                   1445\n"
        "Cache misses                        810\n"
        "Cache write errors                    0\n"
        "Cache location                  ghac, token=private-value\n"
        "Base directories                /private/workspace\n"
        "Cache hits rate                   100.00 %\n"
    )
    result = run_filter(sample)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(MARKER)
    assert json.loads(result.stdout.removeprefix(MARKER)) == {
        "phase": "release_binaries",
        "counters": {
            "compile_requests": 3166,
            "cache_hits": 2247,
            "cache_hits_rust": 1445,
            "cache_misses": 810,
            "cache_write_errors": 0,
        },
    }
    assert "private" not in result.stdout + result.stderr


def test_missing_counters_or_invalid_phase_emit_no_cache_output() -> None:
    sample = "Cache location  ghac, token=private-value\n"
    result = run_filter(sample)
    assert result.returncode == 0
    assert result.stdout == ""
    assert "private" not in result.stderr

    invalid = run_filter("Cache hits  3\n", phase="private-value")
    assert invalid.returncode != 0
    assert invalid.stdout == ""
    assert "private" not in invalid.stderr


def test_public_builder_contains_and_uses_the_filter_without_new_cache_storage() -> None:
    dockerfile = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    ignore = (ROOT / "services/Dockerfile.dockerignore").read_text(encoding="utf-8")
    wrapper = (ROOT / "scripts/ci/run-public-rust-build.sh").read_text(
        encoding="utf-8"
    )
    assert (
        "COPY --chmod=644 scripts/ci/public-sccache-stats.awk "
        "/usr/local/bin/public-sccache-stats.awk"
    ) in dockerfile
    assert ignore.splitlines().count("!scripts/ci/public-sccache-stats.awk") == 1
    assert "sccache --show-stats 2>/dev/null" in wrapper
    assert "awk -v phase=\"$cache_phase\" -f /usr/local/bin/public-sccache-stats.awk" in wrapper
    assert "sccache --stop-server >/dev/null 2>&1 || true" in wrapper
    assert "trap report_cache_counters EXIT" in wrapper
