"""Native snapshot export preserves rootless custody and the existing recovery format."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import runpy
import ssl
import stat
import subprocess
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
EXPORT = runpy.run_path(str(ROOT / "scripts/export-selfhost-openbao.py"))
TOKEN = "synthetic-scoped-snapshot-token-1234"
POLICY = "selfhost-raft-snapshot-read"


def test_snapshot_export_and_identity_are_packaged() -> None:
    bundle = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text())
    assert {"scripts/provision_selfhost_snapshot_identity.py",
            "scripts/export-selfhost-openbao.py", "SELFHOST_OPENBAO.md"} <= set(bundle["assets"])


@pytest.fixture
def native_snapshot(tmp_path: Path):
    if os.name != "posix":
        pytest.skip("native export requires POSIX private directories")
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    key = state / "tls/listener.key"
    ca = state / "tls/ca.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(ca), "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                    "-addext", "basicConstraints=critical,CA:FALSE"],
                   check=True, capture_output=True)
    (state / "root.token").write_text("root-must-not-be-read")
    (state / "unseal.key").write_text("unseal-must-not-be-read")
    (state / "root.token").chmod(0)
    (state / "unseal.key").chmod(0)
    identity = tmp_path / "identity"
    identity.mkdir(mode=0o700)
    for name in ("snapshot-role-id", "snapshot-secret-id"):
        path = identity / name
        path.write_text("synthetic-credential-1234567890")
        path.chmod(0o600)
    output = tmp_path / "exports"
    output.mkdir(mode=0o700)
    config = tmp_path / "openbao.hcl"
    config.write_text('storage "raft" {}')
    control = {"snapshot": b"synthetic encrypted snapshot" * 10000,
               "auth": {"client_token": TOKEN, "policies": [POLICY], "lease_duration": 3600},
               "snapshot_status": 200, "deny_status": 403, "declared_extra": 0, "seen": []}

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            control["seen"].append((self.command, self.path, self.headers.get("X-Vault-Token")))
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            if self.path == "/v1/auth/selfhost-snapshot/login":
                assert self.headers.get("X-Vault-Token") is None
                assert json.loads(body) == {"role_id": "synthetic-credential-1234567890",
                                            "secret_id": "synthetic-credential-1234567890"}
                status, data = 200, json.dumps({"auth": control["auth"]}).encode()
            elif self.path == "/v1/sys/storage/raft/snapshot":
                assert self.headers.get("X-Vault-Token") == TOKEN
                status, data = control["snapshot_status"], control["snapshot"]
            else:
                assert self.headers.get("X-Vault-Token") == TOKEN
                status, data = control["deny_status"], b"{}"
            self.send_response(status)
            if status == 302:
                self.send_header("Location", f"https://127.0.0.1:{self.server.server_port}/must-not-follow")
            self.send_header("Content-Length", str(len(data) + (control["declared_extra"]
                                                         if self.path == "/v1/sys/storage/raft/snapshot" else 0)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = handle_request
        do_POST = handle_request

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield control, (state, output, config, f"https://127.0.0.1:{server.server_port}", identity)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_archive_never_requires_or_carries_root_and_unseal_files(native_snapshot) -> None:
    import zipfile
    control, args = native_snapshot
    archive = EXPORT["export"](*args)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.namelist() == ["raft.snap", "openbao-selfhost.hcl", "manifest.json"]
        assert bundle.read("raft.snap") == control["snapshot"]
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["format"] == "marty-openbao-raft-snapshot-v2"
        assert manifest["snapshot_sha256"] == hashlib.sha256(control["snapshot"]).hexdigest()
    assert [item[1] for item in control["seen"]] == [
        "/v1/auth/selfhost-snapshot/login", "/v1/transit/keys/foreign-snapshot-probe",
        "/v1/auth/token/create", f"/v1/sys/policies/acl/{POLICY}",
        "/v1/sys/storage/raft/snapshot"]
    assert not list(args[1].glob("*.partial"))
    assert not list(args[1].glob(".*.partial"))


@pytest.mark.parametrize("status", [200, 401, 404, 500])
def test_denials_require_real_403_before_snapshot(native_snapshot, status) -> None:
    control, args = native_snapshot
    control["deny_status"] = status
    with pytest.raises(RuntimeError):
        EXPORT["export"](*args)
    assert all(path != "/v1/sys/storage/raft/snapshot" for _, path, _ in control["seen"])
    assert list(args[1].iterdir()) == []


@pytest.mark.parametrize("field,value", [
    ("policies", [POLICY, "default"]), ("policies", []),
    ("lease_duration", True), ("lease_duration", 3600.0),
    ("lease_duration", 3601), ("lease_duration", 0), ("client_token", "short")])
def test_login_scope_is_strict_before_snapshot(native_snapshot, field, value) -> None:
    control, args = native_snapshot
    control["auth"][field] = value
    with pytest.raises(RuntimeError):
        EXPORT["export"](*args)
    assert len(control["seen"]) == 1
    assert list(args[1].iterdir()) == []


@pytest.mark.parametrize("status,body", [(302, b"redirect"), (500, b"failure"), (200, b"")])
def test_snapshot_failure_cleans_private_partial_and_never_follows_redirect(native_snapshot, status, body) -> None:
    control, args = native_snapshot
    control.update(snapshot_status=status, snapshot=body)
    with pytest.raises(RuntimeError):
        EXPORT["export"](*args)
    assert list(args[1].iterdir()) == []
    assert all(path != "/must-not-follow" for _, path, _ in control["seen"])


@pytest.mark.parametrize("mode", ["directory", "credential", "symlink", "oversized", "fifo"])
def test_private_identity_is_checked_before_login(native_snapshot, mode) -> None:
    control, args = native_snapshot
    identity = args[-1]
    credential = identity / "snapshot-role-id"
    if mode == "directory":
        identity.chmod(0o755)
    elif mode == "credential":
        credential.chmod(0o644)
    elif mode == "oversized":
        credential.write_bytes(b"x" * 65537)
    else:
        credential.unlink()
        if mode == "fifo":
            os.mkfifo(credential, mode=0o600)
        else:
            credential.symlink_to(identity / "snapshot-secret-id")
    with pytest.raises(RuntimeError):
        EXPORT["export"](*args)
    assert control["seen"] == []
    assert list(args[1].iterdir()) == []


def test_snapshot_ignores_operator_proxy_environment(native_snapshot, monkeypatch) -> None:
    _, args = native_snapshot
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    assert EXPORT["export"](*args).is_file()


@pytest.mark.parametrize("mode", ["inside-state", "output-symlink", "ca-symlink", "untrusted-ca", "not-raft"])
def test_snapshot_storage_and_trust_boundaries_fail_before_login(native_snapshot, mode) -> None:
    control, original = native_snapshot
    args = list(original)
    state, output, config, _, _ = args
    if mode == "inside-state":
        output = state / "exports"
        output.mkdir(mode=0o700)
        args[1] = output
    elif mode == "output-symlink":
        linked = output.parent / "export-link"
        linked.symlink_to(output, target_is_directory=True)
        args[1] = linked
    elif mode == "ca-symlink":
        ca = state / "tls/ca.crt"
        original = ca.with_name("public-ca.crt")
        ca.rename(original)
        ca.symlink_to(original)
    elif mode == "untrusted-ca":
        (state / "tls/ca.crt").write_bytes((ROOT / "tests/fixtures/selfhost_ca_issuer_public.pem").read_bytes())
    else:
        config.write_text('storage "file" {}')
    with pytest.raises(RuntimeError):
        EXPORT["export"](*args)
    assert control["seen"] == []
    assert list(output.iterdir()) == []


def test_interrupted_snapshot_never_publishes_an_archive(native_snapshot) -> None:
    control, args = native_snapshot
    control.update(snapshot=b"incomplete", declared_extra=100)
    with pytest.raises(RuntimeError):
        EXPORT["export"](*args)
    assert list(args[1].iterdir()) == []
