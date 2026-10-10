"""Security checks for the self-host Raft snapshot exporter."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import runpy
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXPORT = runpy.run_path(str(ROOT / "scripts/export-selfhost-openbao.py"))


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com:8200",
        "https://127.0.0.1:8200",
        "http://127.0.0.1:8200/other",
        "http://user:pass@127.0.0.1:8200",
    ],
)
def test_snapshot_origin_must_be_plain_loopback(origin: str) -> None:
    with pytest.raises(ValueError):
        EXPORT["snapshot_url"](origin)


def test_snapshot_redirect_never_forwards_root_token(tmp_path: Path) -> None:
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
        with pytest.raises(RuntimeError, match="redirected"):
            EXPORT["stream_snapshot"](
                f"http://127.0.0.1:{redirect.server_port}/snapshot",
                "sensitive-token",
                tmp_path / "raft.snap",
            )
        assert forwarded == []
    finally:
        for server in (destination, redirect):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
