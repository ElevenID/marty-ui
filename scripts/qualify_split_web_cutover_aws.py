#!/usr/bin/env python3
"""Bounded, unsigned Docker qualification of one exact post-split Marty source.

Run separately from the source checkout. This creates no AWS resources, never
publishes images, and removes only Docker resources carrying this run's label.
Package/export/browser qualification belongs to the separate existing gates.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import unittest
import uuid

import qualify_split_web_aws as common


SCHEMA = "marty.split-web-cutover-host-qualification/v1"
OWNER_LABEL = "io.elevenid.cutover-qualification"
BUN_IMAGE = "oven/bun:1.4.4-alpine@sha256:4cf82f5686b196504fe119db3fcd9185b191f82ece82c40680e597228ec6070a"
NGINX_IMAGE = "nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8"
RELEASE_COMPONENTS = {
    "marty-api-core": ("MARTY_API_CORE", "ElevenID/marty-cli", "elevenid-marty-api-core"),
    "marty-blog": ("MARTY_BLOG", "ElevenID/marty-blog", "elevenid-marty-blog"),
}
require = common.require
capture = common.capture


def git_command(root: Path, env: dict, *arguments: str) -> list[str]:
    executable = shutil.which("git", path=env.get("PATH"))
    require(executable is not None, "Git is required")
    return [executable, "--no-replace-objects", "-c", "core.attributesFile=/dev/null", "-C", str(root), *arguments]


def source_inventory(root: Path, revision: str, env: dict) -> tuple[dict, list[dict]]:
    require(re.fullmatch(r"[a-f0-9]{40}", revision) is not None, "An exact lowercase Git commit is required")
    require(capture(git_command(root, env, "rev-parse", "--show-toplevel"), env) == str(root), "Source must be its checkout root")
    require(capture(git_command(root, env, "cat-file", "-t", revision), env) == "commit", "Source revision must be a commit")
    require(capture(git_command(root, env, "rev-parse", "HEAD"), env) == revision, "Source HEAD differs from the selected commit")
    require(capture(git_command(root, env, "status", "--porcelain=v1", "--untracked-files=all"), env) == "", "Source checkout must be clean")
    tree = capture(git_command(root, env, "rev-parse", revision + "^{tree}"), env)
    records = capture(git_command(root, env, "ls-tree", "-r", "-z", "--full-tree", revision), env)
    inventory = []
    for record in records.split("\0"):
        if not record:
            continue
        header, separator, filename = record.partition("\t")
        require(separator == "\t", "Malformed Git source inventory")
        mode, kind, oid = header.split()
        require(kind == "blob" and mode in {"100644", "100755"} and re.fullmatch(r"[a-f0-9]{40}", oid), "Unsupported source object")
        relative = Path(filename)
        require(not relative.is_absolute() and ".." not in relative.parts and not any(ord(c) < 32 for c in filename), "Unsafe Git path")
        inventory.append({"path": filename, "mode": int(mode[-3:], 8), "blob": oid})
    require(inventory, "Empty source inventory")
    verify_files(root, inventory)
    return {"root": str(root), "commit": revision, "tree": tree, "clean": True,
            "tracked_files": len(inventory), "tracked_blob_bytes_and_modes_verified": True}, inventory


def file_bytes(root: Path, record: dict) -> bytes:
    path = root
    for part in Path(record["path"]).parts:
        path = path / part
        require(not path.is_symlink(), "Source paths cannot contain symbolic links")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == record["mode"], "Source file mode changed: " + record["path"])
    content = path.read_bytes()
    digest = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    require(digest == record["blob"], "Source blob changed: " + record["path"])
    return content


def verify_files(root: Path, inventory: list[dict]) -> None:
    for record in inventory:
        file_bytes(root, record)


def materialize_source(root: Path, destination: Path, inventory: list[dict]) -> None:
    require(not os.path.lexists(destination), "Build snapshot already exists")
    destination.mkdir(mode=0o700)
    for record in inventory:
        content = file_bytes(root, record)
        target = destination / record["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(content)
        target.chmod(record["mode"])


def recipe(root: Path) -> dict:
    dockerfile = (root / "docker/ui.Dockerfile").read_text()
    stages = re.findall(r"^FROM (\S+) AS (\S+)$", dockerfile, re.MULTILINE)
    require(stages == [(BUN_IMAGE, "commerce_extension"), (BUN_IMAGE, "builder"),
                       (NGINX_IMAGE, "runtime-base"), ("runtime-base", "selfhost"),
                       ("selfhost", "console"), ("runtime-base", "application")], "Reviewed UI Docker stages or pinned bases changed")
    require("ARG UI_SURFACE=application" in dockerfile and "ARG UI_VARIANT=public" in dockerfile, "Application defaults changed")
    require(json.loads((root / "ui/package.json").read_text())["packageManager"] == "bun@1.4.4", "Bun package manager pin changed")
    lock = json.loads((root / "release/stack-lock.json").read_text())
    arguments = {}
    selected = []
    for name, (prefix, repository, archive) in RELEASE_COMPONENTS.items():
        rows = [item for item in lock["components"] if item["name"] == name]
        require(len(rows) == 1, "Missing or duplicate released dependency: " + name)
        row = rows[0]
        require(row["repository"] == repository and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", row["version"]), "Dependency source or version changed")
        artifacts = [item for item in row["artifacts"] if item["type"] == "npm"]
        require(len(artifacts) == 1, "Missing or duplicate npm artifact")
        artifact = artifacts[0]
        expected = f"https://github.com/{repository}/releases/download/v{row['version']}/{archive}-{row['version']}.tgz"
        require(artifact["uri"] == expected and re.fullmatch(r"sha256:[a-f0-9]{64}", artifact["digest"]), "Dependency artifact must be exact and hash bound")
        arguments.update({prefix + "_VERSION": row["version"], prefix + "_URI": artifact["uri"], prefix + "_DIGEST": artifact["digest"]})
        selected.append({"name": name, "version": row["version"], "uri": artifact["uri"], "digest": artifact["digest"]})
    return {"dockerfile": common.fingerprint(root / "docker/ui.Dockerfile"), "bases": [BUN_IMAGE, NGINX_IMAGE],
            "release_inputs": selected, "build_arguments": arguments}


def build_arguments(kind: str, revision: str, inputs: dict) -> dict[str, str]:
    require(kind in {"application", "selfhost"}, "Unsupported UI target")
    return {**inputs, "UI_SURFACE": "application", "UI_VARIANT": "public" if kind == "application" else "selfhost",
            "NGINX_CONFIG": "nginx.prod.conf" if kind == "application" else "nginx.spa.conf",
            "SELFHOST_PUBLIC_PROFILE": "full", "MARTY_PRODUCTION_PAGES": "public",
            "MARTY_UI_SHA": revision, "MARTY_RELEASE_VERSION": "cutover-" + revision[:12]}


def route_compatibility(root: Path) -> dict:
    routes = json.loads((root / "contracts/web-surface-routes.json").read_text())
    canonical = json.dumps(routes, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return {"version": routes["schema_version"], "sha256": "sha256:" + hashlib.sha256(canonical).hexdigest()}


def checked_paths(options) -> tuple[Path, Path]:
    root = common.ordinary_path(options.marty_root, exists=True)
    evidence = common.ordinary_path(options.evidence_root, exists=False)
    common.chrome_temporary_directory(evidence)
    runner = Path(__file__).resolve().parents[1]
    for left, right in ((root, evidence), (root, runner), (evidence, runner)):
        require(left != right and left not in right.parents and right not in left.parents, "Runner, source, and evidence roots must be separate")
    return root, evidence


def preflight(options, roots) -> tuple[dict, list[dict], dict, dict]:
    root, evidence = roots
    require(sys.platform == "linux" and platform.machine() == "x86_64", "Linux x86_64 is required")
    require(os.getuid() != 0 and os.getuid() == os.geteuid(), "Use the prepared non-root user")
    require(sys.version_info >= (3, 10), "Python 3.10 or later is required")
    env = common.environment(options, evidence)
    tools = {"python": sys.executable}
    for name in ("docker", "systemd-run", "systemctl", "loginctl", "env"):
        tools[name] = shutil.which(name, path=env.get("PATH"))
        require(tools[name] is not None, "Missing prerequisite: " + name)
    source, inventory = source_inventory(root, options.source_commit, env)
    inputs = recipe(root)
    runtime = Path(env["XDG_RUNTIME_DIR"])
    socket = Path(options.docker_socket)
    require(socket == runtime / "docker.sock" and not runtime.is_symlink(), "Use this user's rootless Docker socket")
    metadata = runtime.stat()
    require(metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077, "Rootless runtime directory must be private")
    metadata = socket.lstat()
    require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o007, "Rootless socket ownership or permissions differ")
    require(capture([tools["systemctl"], "--user", "is-active", "docker.service"], env) == "active", "Rootless Docker service is not active")
    require(capture([tools["loginctl"], "show-user", str(os.getuid()), "--property=Linger", "--value"], env) == "yes", "Prepared user must have linger enabled")
    systemd = capture([tools["systemd-run"], "--version"], env).splitlines()[0]
    require(int(systemd.split()[1]) >= 254, "systemd 254+ is required")
    docker = [tools["docker"], "--host", env["DOCKER_HOST"]]
    info = json.loads(capture(docker + ["info", "--format", "{{json .}}"], env))
    require("name=rootless" in info.get("SecurityOptions", []) and info.get("OSType") == "linux" and info.get("Architecture") in {"amd64", "x86_64"}, "Docker must be rootless Linux amd64")
    require(str(info.get("CgroupVersion")) == "2" and info.get("CgroupDriver") == "systemd", "Rootless Docker needs systemd cgroup v2")
    buildx = capture(docker + ["buildx", "version"], env)
    memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(memory["MemAvailable"].split()[0]) * 1024
    free = min(shutil.disk_usage(evidence.parent).free, shutil.disk_usage(info["DockerRootDir"]).free)
    require(available >= 3 * 1024 ** 3, "Wait for other builds to finish: at least 3 GiB available memory is required")
    require(free >= 8 * 1024 ** 3, "At least 8 GiB free disk is required; this runner never prunes")
    return {"source": source, "recipe": inputs, "tools": {"python": platform.python_version(), "systemd": systemd,
            "docker": info.get("ServerVersion"), "buildx": buildx}, "host": {"uid": os.getuid(), "available_memory_bytes": available,
            "minimum_filesystem_free_bytes": free}, "docker": {"endpoint": env["DOCKER_HOST"], "engine_id": info.get("ID"),
            "rootless": True, "initial_containers": common.container_ids(docker, env)}}, inventory, tools, env


def owner_value(value: str) -> str:
    require(re.fullmatch(r"[a-f0-9]{32}", value) is not None, "Invalid qualification owner")
    return OWNER_LABEL + "=" + value


class OwnedDocker:
    def __init__(self, executable: str, env: dict, owner: str):
        self.command = [executable, "--host", env["DOCKER_HOST"]]
        self.env, self.owner, self.label = env, owner, owner_value(owner)

    def call(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run([*self.command, *args], env=self.env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=45, check=check)

    def owned(self, kind: str, identifier: str) -> bool:
        result = self.call(kind, "inspect", "--format", "{{json .}}", identifier, check=False)
        if result.returncode:
            require("No such" in result.stderr or "not found" in result.stderr.lower(), "Docker ownership lookup failed")
            return False
        value = json.loads(result.stdout)
        labels = value.get("Labels") if kind == "network" else value.get("Config", {}).get("Labels")
        require(isinstance(labels, dict) and labels.get(OWNER_LABEL) == self.owner, "Refusing an unowned Docker resource")
        return True

    def remove(self, kind: str, identifier: str) -> subprocess.CompletedProcess:
        if not self.owned(kind, identifier):
            return subprocess.CompletedProcess([], 0, "", "")
        args = [kind, "rm", *(["--force"] if kind in {"container", "image"} else []), identifier]
        return self.call(*args)

    def identities(self, kind: str) -> list[str]:
        extra = ["--all"] if kind in {"container", "image"} else []
        result = self.call(kind, "ls", *extra, "--quiet", "--no-trunc", "--filter", "label=" + self.label)
        values = sorted(set(result.stdout.splitlines()))
        pattern = r"sha256:[a-f0-9]{64}" if kind == "image" else r"[a-f0-9]{64}"
        require(all(re.fullmatch(pattern, value) for value in values), "Unexpected owned Docker identifier")
        return values

    def cleanup(self, initial: list[str], keep_images: set[str]) -> dict:
        removed = {"container": [], "network": [], "image": []}
        for kind in removed:
            for identifier in self.identities(kind):
                if kind == "image" and identifier in keep_images:
                    continue
                require(kind != "container" or identifier not in initial, "A preexisting container acquired this run's label")
                self.remove(kind, identifier)
                removed[kind].append(identifier)
        require(not self.identities("container") and not self.identities("network"), "Owned diagnostic resources remain")
        return removed

    def fixture(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        """Keep the exact test assertions; add ownership to its Docker transport."""
        arguments = list(args)
        operation = arguments[0]
        if operation == "build":
            tag = arguments[arguments.index("--tag") + 1]
            require(re.fullmatch(r"marty-application-[a-f0-9]{12}-[a-z0-9-]+", tag), "Unexpected fixture image name")
            result = self.call("image", "inspect", tag, check=False)
            require(result.returncode != 0 and ("No such" in result.stderr or "not found" in result.stderr.lower()), "Fixture image already exists or lookup failed")
            arguments[1:1] = ["--label", self.label]
            # Builds can fetch the pinned base; the enclosing systemd unit owns
            # their deadline. Use no generic Docker timeout for this operation.
            return subprocess.run([*self.command, *arguments], env=self.env, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, check=check)
        if operation == "run":
            name = arguments[arguments.index("--name") + 1]
            require(re.fullmatch(r"marty-application-[a-f0-9]{12}-[a-z0-9-]+", name), "Unexpected fixture container name")
            arguments[1:1] = ["--label", self.label, "--memory=192m", "--cpus=0.5", "--pids-limit=128"]
        elif arguments[:2] == ["network", "create"]:
            require(re.fullmatch(r"marty-application-[a-f0-9]{12}", arguments[-1]), "Unexpected fixture network")
            arguments[2:2] = ["--label", self.label]
        elif operation == "rm":
            return self.remove("container", arguments[-1])
        elif arguments[:2] == ["image", "rm"]:
            return self.remove("image", arguments[-1])
        elif arguments[:2] == ["network", "rm"]:
            return self.remove("network", arguments[-1])
        else:
            require(operation in {"info", "inspect", "logs"}, "Unexpected fixture Docker operation")
        return self.call(*arguments, check=check)


def request(port: int, path: str, method: str = "GET") -> tuple[int, dict, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read(8 * 1024 * 1024 + 1)
        require(len(body) <= 8 * 1024 * 1024, "HTTP smoke response exceeded its bound")
        return response.status, {key.lower(): value for key, value in response.getheaders()}, body
    finally:
        connection.close()


def serving_port(docker: OwnedDocker, container: str) -> int:
    ports = json.loads(docker.call("inspect", "--format", "{{json .NetworkSettings.Ports}}", container).stdout)
    rows = ports["80/tcp"]
    require(len(rows) == 1 and rows[0]["HostIp"] == "127.0.0.1", "Smoke port must be loopback only")
    port = int(rows[0]["HostPort"])
    for _ in range(120):
        require(docker.call("inspect", "--format", "{{.State.Running}}", container).stdout.strip() == "true", "Smoke container exited")
        try:
            request(port, "/")
            return port
        except OSError:
            time.sleep(0.25)
    raise ValueError("Smoke container did not serve HTTP")


def image_smoke(evidence: Path, report: dict, docker: OwnedDocker) -> dict:
    revision = report["initial"]["source"]["commit"]
    network = "marty-cutover-" + docker.owner
    docker.call("network", "create", "--label", docker.label, network)
    config = evidence / "gateway.conf"
    config.write_text("server { listen 8000; location /v1/ { default_type application/json; return 401 '{\"fixture\":\"cutover-gateway\"}'; } "
                      "location /api/ { default_type application/json; return 503 '{\"fixture\":\"cutover-gateway\"}'; } "
                      "location = /openapi.json { default_type application/json; return 200 '{\"openapi\":\"3.1.0\"}'; } }\n")
    gateway = network + "-gateway"
    docker.call("run", "--detach", "--label", docker.label, "--name", gateway, "--network", network,
                "--network-alias", "gateway", "--memory=128m", "--cpus=0.25", "--pids-limit=128",
                "--mount", f"type=bind,source={config},target=/etc/nginx/conf.d/default.conf,readonly", NGINX_IMAGE)
    observed = []
    for kind, sections in (("application", None), ("selfhost", "public,console"), ("selfhost", "console")):
        image = (evidence / (kind + ".iid")).read_text().strip()
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", image), "Malformed output image identity")
        require(docker.owned("image", image), "Built image is missing")
        metadata = json.loads(docker.call("image", "inspect", "--format", "{{json .}}", image).stdout)
        labels = metadata["Config"]["Labels"]
        require(labels["org.opencontainers.image.revision"] == revision and labels["org.opencontainers.image.version"] == "cutover-" + revision[:12], "Built image source labels differ")
        require(labels["io.elevenid.ui.audience"] == ("production" if kind == "application" else "customer"), "Image audience changed")
        if kind == "application":
            require(labels.get("io.elevenid.ui.surface") == "application", "Application image surface changed")
        else:
            require(labels.get("io.elevenid.selfhost.public-profile") == "full", "Customer profile changed")
        name = network + "-" + kind + ("-console" if sections == "console" else "")
        arguments = ["run", "--detach", "--label", docker.label, "--name", name, "--network", network,
                     "--publish", "127.0.0.1::80", "--memory=192m", "--cpus=0.5", "--pids-limit=128"]
        if sections:
            arguments += ["--env", "UI_ENABLED_SECTIONS=" + sections]
        docker.call(*arguments, image)
        port = serving_port(docker, name)
        public_enabled = sections != "console"
        routes = []
        for path in ("/", "/login?returnTo=%2Forganizations%3Ftab%3Dcredentials", "/organizations", "/verification"):
            status, headers, body = request(port, path)
            require(status == (200 if public_enabled else 404), "Unexpected application route status: " + path)
            if public_enabled:
                require("text/html" in headers.get("content-type", "") and b"ElevenID" in body and b"Welcome to nginx" not in body, "Application shell is missing")
            routes.append({"path": path, "status": status})
        for path in ("/console", "/console/login", "/console/org/credentials"):
            status, _, body = request(port, path)
            require(status == 200 and b"ElevenID" in body, "Console entry is missing")
            routes.append({"path": path, "status": status})
        for path in ("/robots.txt", "/sitemap.xml", "/sitemap-index.xml", "/sitemap-0.xml", "/assets/missing.js"):
            for method in ("GET", "HEAD"):
                require(request(port, path, method)[0] == 404, "Retired or missing static asset fell through: " + path)
        status, _, runtime = request(port, "/runtime-config.js")
        require(status == 200 and b"window.__MARTY_RUNTIME_CONFIG__" in runtime, "Startup runtime configuration is missing")
        if sections:
            match = re.search(rb"enabled_sections: (\[[^\]]*\])", runtime)
            require(match and json.loads(match[1]) == sections.split(","), "Customer startup section metadata changed")
            require(request(port, "/healthz")[0] == 200, "Customer health endpoint failed")
            status, headers, _ = request(port, "/credentials?from=cutover")
            require(status == 308 and headers.get("location") == "/console/applicant/credentials?from=cutover", "Customer console alias dropped the query")
        status, _, marker_bytes = request(port, "/marty-ui-release.json")
        marker = None
        if public_enabled:
            require(status == 200, "Built release marker is unavailable")
            marker = json.loads(marker_bytes)
            require(marker["marty_ui_sha"] == revision and marker["release_version"] == "cutover-" + revision[:12]
                    and marker["audience"] == ("production" if kind == "application" else "customer")
                    and marker["ui_variant"] == ("public" if kind == "application" else "selfhost"), "Runtime image identity changed")
        else:
            require(status == 404, "Disabled customer public section remains reachable")
        if kind == "application":
            status, _, compatibility = request(port, "/marty-web-routes.json")
            require(status == 200, "Application route compatibility marker is missing")
            compatibility = json.loads(compatibility)
            require(compatibility["surface"] == "application" and compatibility["source_sha"] == revision
                    and compatibility["route_contract"] == route_compatibility(evidence / "source"), "Application route identity changed")
            for path, expected_status in (("/v1/private-fixture", 401), ("/api/failure-fixture", 503)):
                status, _, body = request(port, path)
                require(status == expected_status and json.loads(body)["fixture"] == "cutover-gateway", "API response became an application shell")
        html = request(port, "/console")[2].decode()
        assets = sorted(set(re.findall(r'(?:src|href)="(/assets/[^"?#]+\.(?:js|css))"', html)))
        require(assets, "Built console has no entry assets")
        for path in assets:
            status, headers, body = request(port, path)
            require(status == 200 and body and "text/html" not in headers.get("content-type", ""), "Built entry asset is not served")
        docker.call("exec", name, "sh", "-ec", "for p in robots.txt sitemap.xml sitemap-index.xml blog authors demos images/social images/authors images/demos llms.txt; do test ! -e /usr/share/nginx/html/\"$p\"; done")
        observed.append({"target": kind, "sections": sections, "image": image, "release_marker": marker,
                         "routes": routes, "entry_assets": assets, "marketing_static_files_absent": True})
        docker.remove("container", name)
    return {"status": "passed", "images": observed, "browser_or_auth_journey_executed": False}


def matrix(evidence: Path, docker: OwnedDocker) -> None:
    path = evidence / "source/ui/scripts/test_nginx_application_routes.py"
    specification = importlib.util.spec_from_file_location("cutover_nginx_contract", path)
    require(specification is not None and specification.loader is not None, "Nginx test loader is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    require(module.PINNED_NGINX_IMAGE == NGINX_IMAGE, "Nginx fixture pin changed")
    module.docker = docker.fixture
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    require(result.wasSuccessful() and not result.skipped and result.testsRun == 4, "The complete pinned Nginx matrix must pass without skips")


def stages(evidence: Path, revision: str, inputs: dict, owner: str, tools: dict) -> list[dict]:
    docker, python = tools.get("docker", "docker"), tools.get("python", "python3")
    result = []
    for kind in ("application", "selfhost"):
        argv = [docker, "buildx", "build", "--builder=default", "--load", "--provenance=false", "--platform=linux/amd64",
                "--progress=plain", "--file", "docker/ui.Dockerfile", "--target", kind,
                "--label", owner_value(owner), "--tag", "marty-cutover-" + owner + ":" + kind,
                "--iidfile", str(evidence / (kind + ".iid"))]
        for key, value in sorted(build_arguments(kind, revision, inputs).items()):
            argv += ["--build-arg", key + "=" + value]
        result.append({"name": kind + "-docker-build", "cwd": str(evidence / "source"), "argv": argv + ["."], "maximum_seconds": 3600})
    for name, mode, seconds in (("built-image-http-smoke", "_image-smoke", 600), ("application-customer-nginx-matrix", "_nginx-matrix", 900)):
        result.append({"name": name, "cwd": str(evidence), "argv": [python, str(Path(__file__).resolve()), mode,
                       "--evidence-root", str(evidence)], "maximum_seconds": seconds})
    return result


def worker(mode: str, evidence_value: str) -> int:
    evidence = common.ordinary_path(evidence_value, exists=True)
    report = json.loads((evidence / "qualification.json").read_text())
    require(report["schema"] == SCHEMA and report["status"] == "running", "Worker requires its active qualification report")
    require(report["runner"] == runner_identity(), "Runner changed during qualification")
    require(os.environ.get("DOCKER_HOST") == report["initial"]["docker"]["endpoint"], "Worker Docker endpoint changed")
    docker = OwnedDocker(shutil.which("docker"), dict(os.environ), report["owner"])
    engine = json.loads(docker.call("info", "--format", "{{json .}}").stdout)
    require(engine.get("ID") == report["initial"]["docker"]["engine_id"] and "name=rootless" in engine.get("SecurityOptions", []), "Worker Docker engine changed")
    verify_files(evidence / "source", json.loads((evidence / "source-inventory.json").read_text()))
    if mode == "_image-smoke":
        common.write_json(evidence / "image-smoke.json", image_smoke(evidence, report, docker))
    else:
        matrix(evidence, docker)
    return 0


def runner_identity() -> dict:
    return {"runner": common.fingerprint(Path(__file__).resolve()), "shared_helpers": common.fingerprint(Path(common.__file__).resolve())}


def interrupt_run(_signal, _frame) -> None:
    raise KeyboardInterrupt


def run(options, roots, initial: dict, inventory: list[dict], tools: dict, env: dict) -> dict:
    root, evidence = roots
    temporary = common.chrome_temporary_directory(evidence)
    require(options.deadline_utc is not None, "Run requires an explicit bounded UTC deadline")
    deadline = datetime.strptime(options.deadline_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    require(300 <= deadline - time.time() <= 3 * 3600, "Deadline must be 5 minutes to 3 hours ahead")
    owner = uuid.uuid4().hex
    docker = OwnedDocker(tools["docker"], env, owner)
    require(all(not docker.identities(kind) for kind in ("container", "network", "image")), "Qualification owner already has resources")
    evidence.mkdir(mode=0o700)
    for name in ("logs", "docker-config", "temporary"):
        (evidence / name).mkdir(mode=0o700)
    env = {**env, "TMPDIR": str(temporary), "TMP": str(temporary), "TEMP": str(temporary)}
    docker.env = env
    plan = stages(evidence, options.source_commit, initial["recipe"]["build_arguments"], owner, tools)
    report = {"schema": SCHEMA, "status": "running", "owner": owner, "started_at": common.now(), "deadline_utc": options.deadline_utc,
              "runner": runner_identity(), "initial": initial, "steps": [], "scope": {"unsigned_diagnostic_only": True,
              "registry_published": False, "production_deployed": False, "signed_release_issued": False,
              "full_stack_recovery_qualified": False, "browser_or_auth_journey_executed": False,
              "nginx_test_assertions_unchanged": True, "nginx_transport_owner_labels_added": True}}
    common.write_json(evidence / "qualification.json", report)
    common.write_json(evidence / "plan.json", plan)
    common.write_json(evidence / "source-inventory.json", inventory)
    keep_images = set()
    try:
        materialize_source(root, evidence / "source", inventory)
        for number, stage in enumerate(plan, 1):
            seconds = min(stage["maximum_seconds"], int(deadline - time.time()) - 120)
            require(seconds >= 60, "Deadline reached; no new stage was started")
            unit = "marty-cutover-" + owner[:12] + "-" + str(number) + ".service"
            stdout, stderr = (evidence / "logs" / (stage["name"] + suffix) for suffix in (".stdout.log", ".stderr.log"))
            step = {"name": stage["name"], "unit": unit, "status": "running", "started_at": common.now(),
                    "maximum_seconds": seconds, "stdout": str(stdout.relative_to(evidence)), "stderr": str(stderr.relative_to(evidence))}
            report["steps"].append(step)
            common.write_json(evidence / "qualification.json", report, replace=True)
            print(f"[{number}/{len(plan)}] {stage['name']}", flush=True)
            command = common.systemd_command(stage, unit, env, tools, seconds)
            started = time.monotonic()
            with stdout.open("xb") as out, stderr.open("xb") as err:
                os.chmod(stdout, 0o600)
                os.chmod(stderr, 0o600)
                try:
                    result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=seconds + 75, check=False)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    subprocess.run([tools["systemctl"], "--user", "stop", unit], env=env, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, timeout=45, check=False)
                    raise ValueError("Stage interrupted or its outer deadline expired") from None
            step.update(status="passed" if result.returncode == 0 else "failed", exit_code=result.returncode,
                        elapsed_seconds=round(time.monotonic() - started, 3), finished_at=common.now(),
                        stdout_digest=common.fingerprint(stdout), stderr_digest=common.fingerprint(stderr))
            common.write_json(evidence / "qualification.json", report, replace=True)
            require(result.returncode == 0, "Qualification stage failed: " + stage["name"])
        verify_files(evidence / "source", inventory)
        final_source, _ = source_inventory(root, options.source_commit, env)
        require(final_source == initial["source"] and report["runner"] == runner_identity(), "Source or runner identity changed")
        report.update(status="passed", final_source=final_source)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        report.update(status="failed", failure=str(error) or "Interrupted")
        if report["steps"] and report["steps"][-1]["status"] == "running":
            report["steps"][-1].update(status="failed", finished_at=common.now())
    finally:
        try:
            for kind in ("application", "selfhost"):
                path = evidence / (kind + ".iid")
                if path.is_file():
                    image = path.read_text().strip()
                    try:
                        require(re.fullmatch(r"sha256:[a-f0-9]{64}", image) and docker.owned("image", image), "Output image identity changed")
                        keep_images.add(image)
                    except (ValueError, KeyError, subprocess.SubprocessError) as error:
                        # Invalid output metadata cannot prevent cleanup of this
                        # run's containers and networks.
                        report.update(status="failed", output_identity_failure=str(error))
            report["removed_owned_resources"] = docker.cleanup(initial["docker"]["initial_containers"], keep_images)
            remaining = common.container_ids(docker.command, env)
            require(set(initial["docker"]["initial_containers"]) <= set(remaining), "A preexisting container is missing")
            report.update(existing_container_identities_preserved=True, diagnostic_containers_remaining=False,
                          retained_local_images=sorted(keep_images), unrelated_new_containers=sorted(set(remaining) - set(initial["docker"]["initial_containers"])))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            report.update(status="failed", cleanup_unproven=True, cleanup_failure=str(error))
        report["finished_at"] = common.now()
        common.write_json(evidence / "qualification.json", report, replace=True)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "preflight", "run", "_image-smoke", "_nginx-matrix"))
    parser.add_argument("--marty-root")
    parser.add_argument("--source-commit")
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--docker-socket")
    parser.add_argument("--deadline-utc")
    options = parser.parse_args()
    try:
        if options.mode.startswith("_"):
            return worker(options.mode, options.evidence_root)
        require(options.marty_root is not None and options.source_commit is not None and options.docker_socket is not None, "Source root, exact commit, and Docker socket are required")
        roots = checked_paths(options)
        if options.mode == "plan":
            env = common.environment(options, roots[1])
            source, _ = source_inventory(roots[0], options.source_commit, env)
            inputs = recipe(roots[0])
            print(json.dumps({"schema": SCHEMA, "status": "plan-only", "source": source, "recipe": inputs,
                              "steps": stages(roots[1], options.source_commit, inputs["build_arguments"], "0" * 32, {})}, indent=2))
            return 0
        initial, inventory, tools, env = preflight(options, roots)
        if options.mode == "preflight":
            print(json.dumps({"schema": SCHEMA, "status": "prerequisites-passed", **initial}, indent=2))
            return 0
        signal.signal(signal.SIGTERM, interrupt_run)
        report = run(options, roots, initial, inventory, tools, env)
        print(json.dumps({"status": report["status"], "report": str(roots[1] / "qualification.json"), "failure": report.get("failure")}, indent=2))
        return 0 if report["status"] == "passed" else 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "refused", "reason": str(error)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
