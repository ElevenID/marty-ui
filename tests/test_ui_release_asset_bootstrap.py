from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
HELPER = ROOT / "scripts" / "ci" / "download-verified-ui-release-assets.sh"


def test_every_ui_release_bootstrap_uses_the_verified_retry_helper() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    bootstrap_steps = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("name")
        in {"Bootstrap released UI dependencies", "Install UI dependencies"}
    ]
    assert len(bootstrap_steps) == 4
    for step in bootstrap_steps:
        assert (
            'bash "$GITHUB_WORKSPACE/scripts/ci/download-verified-ui-release-assets.sh"'
            in step["run"]
        )


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="Linux Bash test")
def test_ui_release_download_retries_transient_500_and_still_rejects_wrong_digest(
    tmp_path: Path,
) -> None:
    payloads = {"/api.tgz": b"pinned-api", "/blog.tgz": b"pinned-blog"}
    counts = {path: 0 for path in payloads}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            counts[self.path] += 1
            if counts[self.path] == 1:
                self.send_error(500)
                return
            payload = payloads[self.path]
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        env = os.environ | {
            "RUNNER_TEMP": str(tmp_path),
            "MARTY_API_CORE_URI": f"{base}/api.tgz",
            "MARTY_BLOG_URI": f"{base}/blog.tgz",
            "MARTY_API_CORE_DIGEST": "sha256:" + hashlib.sha256(payloads["/api.tgz"]).hexdigest(),
            "MARTY_BLOG_DIGEST": "sha256:" + hashlib.sha256(payloads["/blog.tgz"]).hexdigest(),
        }
        success = subprocess.run(
            ["bash", str(HELPER)], env=env, capture_output=True, text=True, timeout=30
        )
        assert success.returncode == 0, success.stderr
        assert counts == {"/api.tgz": 2, "/blog.tgz": 2}
        assert (tmp_path / "marty-api-core.tgz").read_bytes() == payloads["/api.tgz"]
        assert (tmp_path / "marty-blog.tgz").read_bytes() == payloads["/blog.tgz"]

        wrong_digest = env | {"MARTY_API_CORE_DIGEST": "sha256:" + "0" * 64}
        rejected = subprocess.run(
            ["bash", str(HELPER)],
            env=wrong_digest,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert rejected.returncode != 0
        assert counts == {"/api.tgz": 3, "/blog.tgz": 2}
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
