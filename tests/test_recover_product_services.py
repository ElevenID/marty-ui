"""Recovery cannot mutate website owners after its website lock is released."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import recover_product_services as recovery


def test_actual_compose_active_selection_excludes_website_owners_and_inactive_profiles(tmp_path, monkeypatch):
    monkeypatch.delenv("COMPOSE_PROFILES", raising=False)
    services = {name: {"image": "example.invalid/" + name + "@sha256:" + "1" * 64}
                for name in ("ui", "gateway", "postgres", "edge", "bootstrap")}
    services["gateway"]["depends_on"] = {"postgres": {"condition": "service_started"}}
    services["bootstrap"]["profiles"] = ["one-time-initialization"]
    base = tmp_path / "compose.yml"
    overlay = tmp_path / "website.json"
    base.write_text(yaml.safe_dump({"services": services}))
    websites = {"services": {name: {"image": "example.invalid/website@sha256:" + "2" * 64}
                             for name in ("website-a", "website-b", "website-c")}}
    overlay.write_text(json.dumps(websites))
    invocation = ["--project-name", "recovery-test", "-f", str(base), "-f", str(overlay)]
    mutations = []
    def run(command):
        if command[-2:] == ["config", "--services"]:
            executable = os.environ.get("MARTY_INSTALLER_COMPOSE_EXECUTABLE")
            renderer = [executable, *command[2:]] if executable else command
            active = subprocess.run(renderer, check=True, capture_output=True, text=True).stdout
            # A concurrent locked promotion changes the slot after recovery has
            # read its old model. Only explicit product services may be mutated.
            websites["services"]["website-c"]["image"] = "example.invalid/website@sha256:" + "3" * 64
            overlay.write_text(json.dumps(websites))
            return active
        mutations.append(command)
        return ""
    assert recovery.recover(invocation, runner=run) == ["gateway", "postgres", "ui"]
    assert mutations == [["docker", "compose", *invocation, "up", "-d", "--no-build", "--no-deps", "--wait",
                          "gateway", "postgres", "ui"]]
    assert not set(mutations[0][mutations[0].index("--wait") + 1:]).intersection(recovery.WEBSITE_OWNERS | {"bootstrap"})


@pytest.mark.parametrize("output", ["", "edge\nwebsite-a\nwebsite-b\nwebsite-c\n", "ui\nui\n", "ui\n--all\n",
                                    "ui\nunexpected service\n", "ui\n\n", "ui\n../edge\n"])
def test_failed_or_ambiguous_product_selection_never_falls_back_to_all_service_up(output):
    calls = []
    def run(command):
        calls.append(command)
        return output
    with pytest.raises(ValueError):
        recovery.recover(["-f", "/reviewed/compose.yml"], runner=run)
    assert len(calls) == 1 and calls[0][-2:] == ["config", "--services"]


def test_config_failure_prevents_any_mutation():
    calls = []
    def run(command):
        calls.append(command)
        raise ValueError("config failed")
    with pytest.raises(ValueError, match="config failed"):
        recovery.recover(["-f", "/reviewed/compose.yml"], runner=run)
    assert len(calls) == 1 and "up" not in calls[0]


@pytest.mark.parametrize("arguments", [[], ["-f"], ["--profile", "*", "-f", "/compose.yml"],
                                      ["-f", "/compose.yml", "up", "edge"], ["-f", "--profile"]])
def test_wrapper_cannot_inject_an_action_or_expand_profile_selection(arguments):
    def run(_command):
        pytest.fail("invalid invocation must not reach Docker")
    with pytest.raises(ValueError):
        recovery.recover(arguments, runner=run)


def test_powershell_split_branch_delegates_mutation_to_explicit_product_owner():
    source = (ROOT / "scripts/recover-marty-after-reboot.ps1").read_text()
    start = source.index("Invoke-Step 'Recover product while retaining the selected website overlay'")
    block = source[start:source.index("} elseif", start)]
    assert "'recover_product_services.py') -- @ProductionComposeArgs" in block
    assert "docker compose" not in block


@pytest.mark.parametrize("config_failure", [False, True])
def test_real_cli_argument_boundary_and_config_exit_status(tmp_path, config_failure):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text(f"#!{sys.executable}\n" + """import json, os, sys
from pathlib import Path
if sys.argv[-2:] == ['config', '--services']:
    print('ui\\ngateway\\nedge\\nwebsite-a\\nwebsite-b\\nwebsite-c')
    sys.exit(9 if os.environ.get('MARTY_TEST_CONFIG_FAILURE') == '1' else 0)
Path(os.environ['MARTY_TEST_RECOVERY_LOG']).write_text(json.dumps(sys.argv[1:]))
""")
    docker.chmod(0o755)
    log = tmp_path / "mutations.json"
    compose = tmp_path / "existing-compose.yml"
    result = subprocess.run([sys.executable, str(ROOT / "scripts/recover_product_services.py"), "--",
                             "--project-name", "existing-project", "-f", str(compose)],
                            env={**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                                 "MARTY_TEST_RECOVERY_LOG": str(log),
                                 "MARTY_TEST_CONFIG_FAILURE": "1" if config_failure else "0"},
                            capture_output=True, text=True)
    if config_failure:
        assert result.returncode != 0 and not log.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads(log.read_text()) == ["compose", "--project-name", "existing-project", "-f", str(compose),
                                               "up", "-d", "--no-build", "--no-deps", "--wait", "gateway", "ui"]
