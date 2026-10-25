"""Execute early bootstrap refusals; these are not installation/crypto proof."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install.sh"
SHELL = (r"C:\Program Files\Git\usr\bin\sh.exe" if os.name == "nt" else shutil.which("sh"))


def run(args=(), source=None):
    command = [SHELL, str(SCRIPT), *args] if source is None else [SHELL, "-s", "--", *args]
    return subprocess.run(command, input=source, capture_output=True, text=True, timeout=15)


def test_help_does_not_require_docker_or_downloads():
    result = run(["--help"])
    assert result.returncode == 0
    assert "--channel nightly|stable" in result.stdout


@pytest.mark.parametrize("args,reason", [
    (["--version"], "Missing value"),
    (["--channel", "preview"], "Channel must"),
    (["--channel", "stable", "--version", "v1.2.3"], "Choose one"),
    (["--version", "../../attacker"], "Invalid version"),
    (["--version", "v1.2.3?x=y"], "Invalid version"),
    (["--install-dir", "/one", "--install-dir", "/two"], "Repeated"),
    (["--skip-verification"], "Unknown option"),
])
def test_invalid_arguments_refused_before_host_mutation(args, reason):
    result = run(args)
    assert result.returncode != 0
    assert reason in result.stderr


def test_truncated_script_cannot_enter_main():
    source = SCRIPT.read_text()
    definition, invocation = source.rsplit('\nmain "$@" --bootstrap-complete', 1)
    assert invocation.strip() == ""
    # A complete function definition alone is inert. An incomplete final command
    # that still parses (bare main, main with forwarded arguments) must refuse.
    for suffix in ("", "\nmain", '\nmain "$@"', '\nmain "$@" --bootstrap-comp'):
        result = run(source=definition + suffix)
        if suffix:
            assert result.returncode != 0
            assert "Incomplete bootstrap" in result.stderr or "Unknown option" in result.stderr
        else:
            assert result.returncode == 0 and not result.stdout and not result.stderr


def test_no_ambient_verifier_or_unsigned_download_execution():
    source = SCRIPT.read_text()
    assert source.index('"$(digest "$2")" = "$3"') < source.index('chmod 700 "$stage/jq"')
    assert source.index('verify "$stage/marty-deploy"') < source.index('"$stage/marty-deploy" --build-identity')
    assert "--skip-verification" not in source
