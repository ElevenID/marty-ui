"""Synthetic Linux rootless bootstrap boundary; no Docker daemon or network."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "install.sh"
TAG = "v1.2.3-nightly.20261027.42"


@pytest.mark.skipif(os.name != "posix" or not Path("/proc/self/status").exists(),
                    reason="Linux process-status boundary")
def test_rootless_bootstrap_requires_nnp_before_external_commands(tmp_path):
    status = Path("/proc/self/status").read_text()
    if "NoNewPrivs:\t1" in status:
        pytest.skip("test process already has no-new-privileges")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text("#!/bin/sh\necho UNEXPECTED_DOCKER >&2\nexit 91\n")
    docker.chmod(0o700)
    env = {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin"}
    result = subprocess.run(["/bin/sh", str(SCRIPT), "--candidate-test", TAG],
                            env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert "no-new-privileges" in result.stderr
    assert "UNEXPECTED_DOCKER" not in result.stderr


@pytest.mark.skipif(os.name != "posix" or not Path("/proc/self/status").exists(),
                    reason="Linux process-status boundary")
def test_rootless_bootstrap_pins_user_socket_and_isolates_docker_config(tmp_path):
    setpriv = shutil.which("setpriv")
    if setpriv is None:
        pytest.skip("setpriv unavailable")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text('''#!/bin/sh
case "$1:$2" in
    info:--format)
        printf 'OBS_HOST=%s OBS_CONFIG=%s OBS_UNTRUSTED=%s\\n' \
            "$DOCKER_HOST" "$DOCKER_CONFIG" "${MARTY_UNTRUSTED-absent}" >&2
        case "$3" in
            *SecurityOptions*) printf 'name=rootless\\n' ;;
            *ID*) printf 'test-engine\\n' ;;
            *) exit 91 ;;
        esac ;;
    info:|compose:version) exit 0 ;;
    *) exit 91 ;;
esac
''')
    docker.chmod(0o700)
    curl = bin_dir / "curl"
    curl.write_text("#!/bin/sh\necho SYNTHETIC_DOWNLOAD_REFUSED >&2\nexit 91\n")
    curl.chmod(0o700)
    env = {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin",
           "MARTY_UNTRUSTED": "canary", "DOCKER_CONFIG": "/tmp/untrusted-config"}
    env.pop("DOCKER_CONTEXT", None)
    env.pop("DOCKER_HOST", None)
    result = subprocess.run([setpriv, "--no-new-privs", "--inh-caps=-all",
                             "--ambient-caps=-all", "--", "/bin/sh", str(SCRIPT),
                             "--candidate-test", TAG], env=env, capture_output=True,
                            text=True, timeout=15)
    assert result.returncode != 0
    assert "SYNTHETIC_DOWNLOAD_REFUSED" in result.stderr
    assert f"OBS_HOST=unix:///run/user/{os.getuid()}/docker.sock" in result.stderr
    assert "OBS_CONFIG=/tmp/marty-installer." in result.stderr
    assert "OBS_UNTRUSTED=absent" in result.stderr
    assert "/tmp/untrusted-config" not in result.stderr
