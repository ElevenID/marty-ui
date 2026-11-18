"""Synthetic Linux rootless bootstrap boundary; no Docker daemon or network."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "install.sh"
TAG = "v1.2.3-nightly.20261027.42"


@pytest.mark.skipif(os.name != "posix" or not Path("/proc/self/status").exists(),
                    reason="Linux no-new-privileges pipeline")
def test_generated_pipeline_inherits_nnp_and_propagates_fetch_failure(tmp_path, monkeypatch):
    import shlex

    if not Path("/usr/bin/setpriv").is_file():
        pytest.skip("setpriv unavailable")
    monkeypatch.syspath_prepend(str(SCRIPT.parent / "scripts"))
    from package_nightly_installation import nightly_trial_guide

    guide = nightly_trial_guide({"tag": TAG, "source_sha": "a" * 40, "build_run_id": 42})
    command = shlex.split(next(line for line in guide.splitlines()
                              if line.startswith("/usr/bin/setpriv ")))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    evidence = tmp_path / "nnp"
    observe = '''while read -r key value rest; do
    case "$key" in NoNewPrivs:) printf '%s\\n' "$value" >> "$NNP_EVIDENCE" ;; esac
done < /proc/self/status
'''
    (bin_dir / "curl").write_text("#!/bin/sh\n" + observe + "exit 37\n")
    (bin_dir / "sh").write_text("#!/bin/sh\n" + observe +
                                "while IFS= read -r line; do :; done\nexit 0\n")
    for path in bin_dir.iterdir():
        path.chmod(0o700)
    result = subprocess.run(command, env={"PATH": f"{bin_dir}:/usr/bin:/bin",
                                         "NNP_EVIDENCE": str(evidence)},
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 37
    assert evidence.read_text().splitlines() == ["1", "1"]


@pytest.mark.skipif(os.name != "posix" or not Path("/proc/self/status").exists(),
                    reason="Linux process-status boundary")
def test_rootless_bootstrap_requires_nnp_before_external_commands(tmp_path):
    if os.getuid() == 0:
        pytest.skip("requires a non-root Linux test process; UID refusal precedes the NNP check")
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
@pytest.mark.parametrize("check", ["--check-host", "--check-compatibility"])
def test_host_check_does_not_bypass_root_refusal(tmp_path, check):
    if os.getuid() != 0:
        pytest.skip("requires a root process to exercise the root refusal")
    tools = tmp_path / "bin"
    tools.mkdir()
    for name in ("uname", "docker", "curl", "mktemp"):
        executable = tools / name
        executable.write_text("#!/bin/sh\necho UNEXPECTED_TOOL_EXECUTION >&2\nexit 91\n")
        executable.chmod(0o700)
    result = subprocess.run(["/bin/sh", str(SCRIPT), check],
                            env={"PATH": str(tools)}, capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert "regular non-root login without sudo" in result.stderr
    assert "UNEXPECTED_TOOL_EXECUTION" not in result.stderr


@pytest.mark.skipif(os.name != "posix" or not Path("/proc/self/status").exists(),
                    reason="Linux process-status boundary")
@pytest.mark.parametrize("check", [None, "--check-host", "--check-compatibility"])
def test_rootless_bootstrap_pins_user_socket_and_isolates_docker_config(tmp_path, check):
    if os.getuid() == 0:
        pytest.skip("requires a non-root Linux process to exercise the real rootless preflight")
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
    info:) exit 0 ;;
    compose:*) echo EARLY_COMPOSE_PROBE >&2; exit 93 ;;
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
    command = [setpriv, "--no-new-privs", "--inh-caps=-all",
               "--ambient-caps=-all", "--", "/bin/sh", str(SCRIPT),
               "--candidate-test", TAG]
    if check:
        command += [check]
    result = subprocess.run(command, env=env, capture_output=True,
                            text=True, timeout=15)
    if check == "--check-host":
        assert result.returncode == 0, result.stderr
        assert "bootstrap host checks passed" in result.stdout
        assert "Compose, resources, images, release availability, and installation readiness were not checked" in result.stdout
        assert "SYNTHETIC_DOWNLOAD_REFUSED" not in result.stderr
    else:
        assert result.returncode != 0
        assert "SYNTHETIC_DOWNLOAD_REFUSED" in result.stderr
    assert "EARLY_COMPOSE_PROBE" not in result.stderr
    assert f"OBS_HOST=unix:///run/user/{os.getuid()}/docker.sock" in result.stderr
    assert "OBS_CONFIG=/tmp/marty-installer." in result.stderr
    assert "OBS_UNTRUSTED=absent" in result.stderr
    assert "/tmp/untrusted-config" not in result.stderr
    staged_configs = re.findall(r"OBS_CONFIG=(\S+)", result.stderr)
    assert staged_configs
    assert all(not Path(path).exists() for path in staged_configs)
