"""Pinned source-bound guest host probe transport; no release admission claim."""
import os
from pathlib import Path
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("root VM host probe transport requires Linux", allow_module_level=True)
if os.geteuid() != 0:
    pytest.skip("root VM host probe custody requires root", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_host_probe as host_probe
import installer_release as release


@pytest.fixture
def pinned(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    key = control / "controller_ed25519"
    hosts = control / "known_hosts"
    key.write_bytes(b"private synthetic key")
    hosts.write_bytes(b"[127.0.0.1]:2222 ssh-ed25519 synthetic")
    key.chmod(0o600)
    hosts.chmod(0o600)
    binding = dict(qualified=False, dispatch_authorized=False, ssh=dict(
        host="127.0.0.1", port=2222, user="installer",
        control_dir=str(control), controller_key_sha256=release.digest(key.read_bytes()),
        known_hosts_sha256=release.digest(hosts.read_bytes())))
    monkeypatch.setattr(host_probe.dispatch, "executable", lambda _path: None)
    selected = []
    def verified(source, name):
        selected.append((source, name))
        return "print('{}')"
    monkeypatch.setattr(host_probe.dispatch, "verified_harness_script", verified)
    return binding, key, selected


def test_host_probe_uses_signed_source_and_pinned_loopback(pinned):
    binding, _, selected = pinned
    calls = []
    raw = b'{"schema":"test"}\n'
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return raw
    assert host_probe.probe(binding, "a" * 40, run=run) == raw
    assert selected == [("a" * 40, "installer_host_probe.py")]
    [(argv, options)] = calls
    assert argv[0] == "/usr/bin/ssh"
    assert argv[-2] == "installer@127.0.0.1"
    assert "HostKeyAlgorithms=ssh-ed25519" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "IdentityAgent=none" in argv
    assert "ProxyCommand=none" in argv
    assert "Port=2222" in argv
    assert "base64.b64decode" in argv[-1]
    assert options["timeout"] == 120 and options["limit"] == 65536
    assert set(options["env"]) == {"HOME", "PATH", "LANG", "LC_ALL"}


@pytest.mark.parametrize("change", ["host", "user", "port", "key_hash"])
def test_host_probe_refuses_changed_selection(pinned, change):
    binding, _, _ = pinned
    if change == "key_hash":
        binding["ssh"]["controller_key_sha256"] = "0" * 64
    else:
        binding["ssh"][change] = {
            "host": "remote.example", "user": "root", "port": True,
        }[change]
    with pytest.raises(ValueError):
        host_probe.probe(binding, "a" * 40,
                         run=lambda *_a, **_k: pytest.fail("SSH must not start"))


def test_host_probe_refuses_changed_key_after_ssh(pinned):
    binding, key, _ = pinned
    def run(_argv, **_kwargs):
        key.write_bytes(b"substituted synthetic key")
        return b'{}\n'
    with pytest.raises(ValueError, match="SSH material changed"):
        host_probe.probe(binding, "a" * 40, run=run)


def test_host_probe_refuses_changed_binding_after_ssh(pinned):
    binding, _, _ = pinned
    def run(_argv, **_kwargs):
        binding["ssh"]["port"] = 2223
        return b'{}\n'
    with pytest.raises(ValueError, match="target binding changed"):
        host_probe.probe(binding, "a" * 40, run=run)


def test_host_probe_refuses_oversized_output(pinned):
    binding, _, _ = pinned
    with pytest.raises(ValueError, match="output invalid"):
        host_probe.probe(binding, "a" * 40,
                         run=lambda *_a, **_k: b"x" * 65537)
