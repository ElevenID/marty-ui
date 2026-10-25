"""Guest bootstrap seams use synthetic bytes and proofs, never release claims."""
import argparse
import os
from pathlib import Path
import sys
import time
import urllib.parse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_public_bootstrap as b
import installer_release as release

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux guest custody contract")


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    base = tmp_path / "dispatch"
    base.mkdir(mode=0o700)
    for name in ("grants", "tools", "inputs"):
        (base / name).mkdir(mode=0o700)
    assets = tmp_path / "assets"
    assets.mkdir(mode=0o700)
    for name in release.ARTIFACTS:
        (assets / name).write_bytes(b"synthetic " + name.encode())
    (assets / "prepared-selfhost-images.json").write_bytes(release.encode(dict(
        schema="marty.selfhost-image-lock/v1", release="marty-ui@1.2.3",
        services={"gateway": "ghcr.io/elevenid/services@sha256:" + "a" * 64},
        openbao_didcomm_image="ghcr.io/elevenid/plugin@sha256:" + "b" * 64)))
    inventory = release.encode(release.inventory(assets, expected_services={"gateway"},
        source_sha="a" * 40, release_tag="v1.2.3", build_run_id=42, build_run_attempt=2))
    run = dict(repository=dict(full_name=release.REPOSITORY), path=release.acceptance.WORKFLOW,
               head_sha="c" * 40, head_branch="main", event="workflow_dispatch",
               status="in_progress", conclusion=None, id=99, run_attempt=3)
    now = int(time.time())
    authorization = release.candidate_authorization(inventory, source_sha="a" * 40,
        release_tag="v1.2.3", build_run_id=42, build_run_attempt=2,
        acceptance_run=run, phase="published", now=now)
    auth = release.encode(authorization)
    context = {key: authorization[key] for key in release.CONTEXT_FIELDS}
    target = dict(guest_id="11111111-1111-4111-8111-111111111111", disk_id="d" * 64,
                  engine_id="engine-12345", installation_id="22222222-2222-4222-8222-222222222222")
    receipt = release.encode(release.controller_consumption(auth, inventory, expected=context,
        **target, consumed_at=now, now=now))
    for name, raw in (("candidate-authorization.json", auth),
                      ("controller-consumption.json", receipt)):
        path = base / "grants" / name
        path.write_bytes(raw)
        path.chmod(0o600)
        for suffix in b.SUFFIXES[1:]:
            proof = path.with_name(name + suffix)
            proof.write_bytes(b"synthetic proof")
            proof.chmod(0o600)
    tools = {}
    for name in b.PINS:
        raw = ("synthetic-" + name).encode()
        path = base / "tools" / name
        path.write_bytes(raw)
        path.chmod(0o700)
        tools[name] = (b.digest(raw), len(raw))
    monkeypatch.setattr(b, "PINS", tools)
    release_assets = {"installer-inventory.json": inventory,
                      "marty-deploy-linux-amd64": (assets / "marty-deploy-linux-amd64").read_bytes()}
    for name in b.ASSETS:
        for suffix in b.SUFFIXES[1:]:
            release_assets[name + suffix] = b"synthetic proof"
    calls = []
    def download(url, output, fd, maximum):
        calls.append(("download", output.name))
        name = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
        b.exclusive(fd, output.parent, output.name, release_assets[name])
    def verify(path, *args):
        calls.append(("verify", path.name))
        return b.private_digest(path, 536870912 if path.name == "marty-deploy-linux-amd64" else 65536)[0]
    monkeypatch.setattr(b, "download", download)
    monkeypatch.setattr(b, "verify", verify)
    options = argparse.Namespace(base=base, grants=base / "grants", tools=base / "tools",
        inputs=base / "inputs", install_dir=tmp_path / "installation",
        source_sha="a" * 40, release_tag="v1.2.3",
        operator_sha256=authorization["operator_sha256"], nonce=authorization["nonce"],
        harness_source_sha="c" * 40, run_id=99, run_attempt=3,
        build_run_id=42, build_run_attempt=2, **target)
    return options, calls, release_assets


def test_public_operator_is_authenticated_before_it_can_be_invoked(candidate):
    options, calls, _ = candidate
    operator = b.bootstrap(options)
    assert operator == options.base / "bootstrap/marty-deploy-linux-amd64"
    assert operator.stat().st_mode & 0o777 == 0o700
    assert calls.index(("verify", "installer-inventory.json")) < calls.index(
        ("download", "marty-deploy-linux-amd64"))
    assert calls.index(("verify", "marty-deploy-linux-amd64")) > calls.index(
        ("download", "marty-deploy-linux-amd64.provenance.jsonl"))
    assert (operator.parent / "intent.json").exists()
    assert (operator.parent / "verified.json").exists()
    assert list(options.inputs.iterdir()) == []
    fd = b.private_directory(options.base)
    try:
        operator_fd = b.authenticated_operator_fd(options, fd, operator)
        os.close(operator_fd)
    finally:
        os.close(fd)
    with pytest.raises(FileExistsError):
        b.bootstrap(options)


@pytest.mark.parametrize("field", ["phase", "operator_sha256", "inventory_sha256", "engine_id", "release_tag"])
def test_wrong_signed_context_never_fetches_or_executes(candidate, field):
    options, calls, _ = candidate
    if field in ("phase", "inventory_sha256"):
        path = options.grants / "candidate-authorization.json"
        changed = release.decode(path.read_bytes())
        changed[field] = "staged" if field == "phase" else "f" * 64
        path.write_bytes(release.encode(changed))
    elif field == "release_tag":
        options.release_tag = "v1.2.4"
    elif field == "engine_id":
        options.engine_id = "wrong-engine"
    else:
        options.operator_sha256 = "f" * 64
    with pytest.raises(ValueError):
        b.bootstrap(options)
    assert not any(kind == "download" for kind, _ in calls)
    assert not (options.base / "bootstrap").exists()


def test_altered_public_operator_preserves_intent_without_success(candidate):
    options, calls, assets = candidate
    assets["marty-deploy-linux-amd64"] = b"substituted operator"
    with pytest.raises(ValueError):
        b.bootstrap(options)
    assert (options.base / "bootstrap/intent.json").exists()
    assert not (options.base / "bootstrap/verified.json").exists()
    assert (options.base / "bootstrap/marty-deploy-linux-amd64").exists()
    assert ("verify", "marty-deploy-linux-amd64") not in calls


def test_interrupted_download_retains_partial_and_refuses_replay(candidate, monkeypatch):
    options, calls, _ = candidate
    original = b.download
    def interrupted(url, output, fd, maximum):
        if output.name == "marty-deploy-linux-amd64":
            b.exclusive(fd, output.parent, output.name, b"partial public bytes")
            raise ValueError("interrupted")
        original(url, output, fd, maximum)
    monkeypatch.setattr(b, "download", interrupted)
    with pytest.raises(ValueError):
        b.bootstrap(options)
    assert (options.base / "bootstrap/intent.json").exists()
    assert (options.base / "bootstrap/marty-deploy-linux-amd64").read_bytes() == b"partial public bytes"
    assert not (options.base / "bootstrap/verified.json").exists()
    with pytest.raises(FileExistsError):
        b.bootstrap(options)


def test_verifier_failure_prevents_public_download(candidate, monkeypatch):
    options, calls, _ = candidate
    monkeypatch.setattr(b, "verify", lambda *args: (_ for _ in ()).throw(ValueError("bad proof")))
    with pytest.raises(ValueError):
        b.bootstrap(options)
    assert not any(kind == "download" for kind, _ in calls)
    assert not (options.base / "bootstrap").exists()


def test_operator_mutation_after_bootstrap_refuses_execution(candidate):
    options, _, _ = candidate
    operator = b.bootstrap(options)
    operator.chmod(0o600)
    operator.write_bytes(b"substituted after verification")
    operator.chmod(0o700)
    fd = b.private_directory(options.base)
    try:
        with pytest.raises(ValueError):
            b.authenticated_operator_fd(options, fd, operator)
    finally:
        os.close(fd)


def test_bounded_verifier_capture_and_process_group_cleanup(tmp_path):
    shell = os.open("/bin/sh", os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            b.bounded_command(["/bin/sh", "-c", "head -c 100000 /dev/zero"],
                executable_fd=shell, env={"PATH": "/usr/bin:/bin"}, cwd=tmp_path, limit=1024)
        marker = tmp_path / "orphan-marker"
        with pytest.raises(ValueError):
            b.bounded_command(["/bin/sh", "-c", f"(sleep 0.5; touch {marker}) & sleep 10"],
                executable_fd=shell, env={"PATH": "/usr/bin:/bin"}, cwd=tmp_path, timeout=0.15)
        time.sleep(0.7)
        assert not marker.exists()
    finally:
        os.close(shell)


def test_native_fetch_must_finish_before_candidate_install(candidate, monkeypatch):
    options, _, _ = candidate
    arguments = []
    for key, value in vars(options).items():
        arguments.extend(["--" + key.replace("_", "-"), str(value)])
    calls = []
    monkeypatch.setattr(b, "bootstrap", lambda _: options.base / "bootstrap/marty-deploy-linux-amd64")
    monkeypatch.setattr(b, "authenticated_operator_fd", lambda *args: os.open("/bin/true", os.O_RDONLY))
    def fetch(argv, **kwargs):
        calls.append(argv[1])
        raise ValueError("native fetch refused")
    monkeypatch.setattr(b, "bounded_command", fetch)
    monkeypatch.setattr(b.os, "execve", lambda *args: calls.append("install-candidate"))
    with pytest.raises(SystemExit):
        b.main(arguments)
    assert calls == ["fetch-published-candidate"]
    def success(argv, **kwargs):
        calls.append(argv[1])
        return b""
    monkeypatch.setattr(b, "bounded_command", success)
    b.main(arguments)
    assert calls[-2:] == ["fetch-published-candidate", "install-candidate"]


@pytest.mark.parametrize("url", [
    "http://github.com/ElevenID/marty-ui/releases/download/v1.2.3/file",
    "https://github.com.evil.example/ElevenID/marty-ui/releases/download/v1.2.3/file",
    "https://user:password@github.com/ElevenID/marty-ui/releases/download/v1.2.3/file",
    "https://github.com:8443/ElevenID/marty-ui/releases/download/v1.2.3/file",
    "https://github.com/login",
    "https://objects.githubusercontent.com/asset#fragment",
])
def test_redirect_allowlist_refuses_untrusted_destinations(url):
    assert not b.allowed(url)


def test_replaced_private_parent_refuses_result(tmp_path):
    tmp_path.chmod(0o700)
    base = tmp_path / "base"
    base.mkdir(mode=0o700)
    fd = b.private_directory(base)
    try:
        b.exclusive(fd, base, "intent.json", b"intent")
        moved = tmp_path / "moved"
        base.rename(moved)
        base.mkdir(mode=0o700)
        with pytest.raises(ValueError):
            b.exclusive(fd, base, "verified.json", b"success")
        assert not (base / "verified.json").exists()
        assert not (moved / "verified.json").exists()
        assert (moved / "intent.json").read_bytes() == b"intent"
    finally:
        os.close(fd)
