from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
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
        (owner, step)
        for owner, job in workflow["jobs"].items()
        for step in job.get("steps", [])
        if step.get("name")
        in {"Bootstrap released UI dependencies", "Install UI dependencies"}
    ]
    assert sorted(owner for owner, _ in bootstrap_steps) == [
        "fast-feedback",
        "test-credential-lifecycle-browser",
        "test-ui",
        "test-website",
    ]
    for _, step in bootstrap_steps:
        assert (
            'bash "$GITHUB_WORKSPACE/scripts/ci/download-verified-ui-release-assets.sh"'
            in step["run"]
        )


@pytest.mark.skipif(
    os.name == "nt" or any(shutil.which(tool) is None for tool in ("bash", "git", "node")),
    reason="Linux Bash, Git and Node test",
)
@pytest.mark.parametrize("outcome", ["success", "install-failure", "unexpected-source-drift"])
def test_application_bootstrap_restores_exact_source_inputs_without_hiding_failures(
    tmp_path: Path, outcome: str
) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    command = next(
        step["run"] for step in workflow["jobs"]["test-website"]["steps"]
        if step.get("name") == "Bootstrap released UI dependencies"
    )
    repository = tmp_path / "repository"
    original = {}
    for relative in (
        "ui/package.json", "ui/package-lock.json", "ui/bun.lock",
        "ui/profiles/application/package.json", "ui/profiles/application/package-lock.json",
        "ui/profiles/application/bun.lock", "ui/scripts/application-dependency-profile.mjs",
        "ui/scripts/application-dependency-profile.test.mjs",
    ):
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        original[relative] = (ROOT / relative).read_bytes()
        target.write_bytes(original[relative])
    (repository / ".gitignore").write_text("ui/node_modules/\n", encoding="utf-8")
    (repository / "ui/extra-source.mjs").write_text("original\n", encoding="utf-8")
    helper = repository / "scripts/ci/download-verified-ui-release-assets.sh"
    helper.parent.mkdir(parents=True)
    helper.write_text(
        'set -euo pipefail\nprintf api > "$RUNNER_TEMP/marty-api-core.tgz"\n'
        'printf blog > "$RUNNER_TEMP/marty-blog.tgz"\n',
        encoding="utf-8",
    )
    for args in (
        ["init", "--quiet"], ["add", "."],
        ["-c", "user.name=CI fixture", "-c", "user.email=ci@example.invalid",
         "commit", "--quiet", "-m", "Exact source inputs"],
    ):
        subprocess.run(["git", *args], cwd=repository, check=True, capture_output=True)
    temporary = tmp_path / "runner-temporary"
    temporary.mkdir()
    executable = tmp_path / "bin/bun"
    executable.parent.mkdir()
    executable.write_text(
        f"#!{sys.executable}\n" + '''import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if args[:3] == ["pm", "pkg", "set"]:
    key, value = args[3].split("=", 1)
    manifest = json.loads(Path("package.json").read_text())
    manifest["dependencies"][key.removeprefix("dependencies.")] = value
    Path("package.json").write_text(json.dumps(manifest))
elif args == ["install"]:
    assert os.environ["PUPPETEER_SKIP_DOWNLOAD"] == "true"
    manifest = json.loads(Path("package.json").read_text())
    for name in ["@elevenid/marty-api-core", "@elevenid/marty-blog"]:
        assert manifest["dependencies"][name].startswith("file:")
    Path("bun.lock").write_text("temporary installation lock\\n")
    Path("node_modules").mkdir()
    Path("node_modules/installed-marker").write_text("installed")
    if os.environ["BOOTSTRAP_TEST_OUTCOME"] == "unexpected-source-drift":
        Path("extra-source.mjs").write_text("unexpected mutation\\n")
    if os.environ["BOOTSTRAP_TEST_OUTCOME"] == "install-failure":
        sys.exit(42)
elif args != ["x", "--no-install", "puppeteer", "browsers", "install"]:
    raise AssertionError(args)
''',
        encoding="utf-8",
    )
    executable.chmod(0o755)
    result = subprocess.run(
        ["bash", "-c", command], cwd=repository / "ui", capture_output=True, text=True,
        timeout=30, env=os.environ | {
            "PATH": str(executable.parent) + os.pathsep + os.environ["PATH"],
            "GITHUB_WORKSPACE": str(repository), "RUNNER_TEMP": str(temporary),
            "BOOTSTRAP_TEST_OUTCOME": outcome,
        },
    )
    assert result.returncode == {"success": 0, "install-failure": 42,
                                 "unexpected-source-drift": 1}[outcome], result.stderr
    for relative, expected in original.items():
        assert (repository / relative).read_bytes() == expected, relative
    assert (repository / "ui/node_modules/installed-marker").read_text() == "installed"
    assert not list(temporary.glob("application-bootstrap-inputs.*"))
    if outcome == "unexpected-source-drift":
        assert (repository / "ui/extra-source.mjs").read_text() == "unexpected mutation\n"
        assert "ui/extra-source.mjs" in result.stdout
    else:
        clean = subprocess.run(
            ["git", "status", "--porcelain"], cwd=repository,
            capture_output=True, text=True, check=True,
        )
        assert clean.stdout == ""
    if outcome == "success":
        profile = subprocess.run(
            ["node", "--test", "--test-name-pattern",
             "committed Bun application profile|coordinated Bun lock root swaps",
             "scripts/application-dependency-profile.test.mjs"],
            cwd=repository / "ui", capture_output=True, text=True, timeout=30,
        )
        assert profile.returncode == 0, profile.stdout + profile.stderr


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
