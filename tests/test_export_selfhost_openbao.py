"""Security checks for the self-host Raft snapshot exporter."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
from pathlib import Path
import runpy
import sys
import json
import threading
import urllib.request
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
EXPORT = runpy.run_path(str(ROOT / "scripts/export-selfhost-openbao.py"))


def test_snapshot_export_and_identity_are_packaged() -> None:
    bundle = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text())
    assert {"scripts/provision_selfhost_snapshot_identity.py",
            "scripts/export-selfhost-openbao.py", "SELFHOST_OPENBAO.md"} <= set(bundle["assets"])


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com:8200",
        "http://127.0.0.1:8200",
        "http://127.0.0.1:8200/other",
        "http://user:pass@127.0.0.1:8200",
    ],
)
def test_snapshot_origin_must_be_https_loopback(origin: str) -> None:
    with pytest.raises(ValueError):
        EXPORT["snapshot_url"](origin)


def test_snapshot_origin_accepts_https_loopback() -> None:
    assert EXPORT["snapshot_url"]("https://127.0.0.1:8200") == (
        "https://127.0.0.1:8200/v1/sys/storage/raft/snapshot"
    )


def test_archive_never_requires_or_carries_root_and_unseal_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    (state / "tls/ca.crt").write_text("public CA", encoding="ascii")
    config = tmp_path / "openbao.hcl"
    config.write_text('storage "raft" {}', encoding="ascii")
    exports = tmp_path / "exports"
    exports.mkdir(mode=0o700)
    identity = tmp_path / "identity"
    identity.mkdir(mode=0o700)

    def fake_snapshot(_url: str, token: str, output: Path, _ca: Path) -> str:
        assert token == "scoped-snapshot-token"
        snapshot = b"encrypted raft custody state"
        output.write_bytes(snapshot)
        return hashlib.sha256(snapshot).hexdigest()

    monkeypatch.setitem(EXPORT["export"].__globals__, "Bao", lambda *_args: object())
    monkeypatch.setitem(EXPORT["export"].__globals__, "checked_login",
                        lambda *_args: "scoped-snapshot-token")
    monkeypatch.setitem(EXPORT["export"].__globals__, "stream_snapshot", fake_snapshot)
    archive = EXPORT["export"](state, exports, config,
                               "https://127.0.0.1:8200", identity)
    with zipfile.ZipFile(archive) as bundle:
        assert set(bundle.namelist()) == {
            "raft.snap", "openbao-selfhost.hcl", "manifest.json",
        }
        assert bundle.read("raft.snap") == b"encrypted raft custody state"


def test_snapshot_redirect_never_forwards_root_token() -> None:
    forwarded: list[str | None] = []

    class Destination(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            forwarded.append(self.headers.get("X-Vault-Token"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fake snapshot")

        def log_message(self, *_args: object) -> None:
            pass

    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{destination.server_port}/snapshot",
            )
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            pass

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (destination, redirect)
    ]
    try:
        for thread in threads:
            thread.start()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), EXPORT["NoRedirect"]()
        )
        request = urllib.request.Request(
            f"http://127.0.0.1:{redirect.server_port}/snapshot",
            headers={"X-Vault-Token": "sensitive-token"},
        )
        with pytest.raises(RuntimeError, match="redirected"):
            opener.open(request, timeout=5)
        assert forwarded == []
    finally:
        for server in (destination, redirect):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
