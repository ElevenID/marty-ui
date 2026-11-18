#!/usr/bin/env python3
"""Smoke a prepared local UI image without beta writes or external HTTP calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def docker(*args: str) -> bytes:
    return subprocess.check_output(["docker", *args], stderr=subprocess.PIPE)


def smoke(reference: str, manifest: dict) -> dict:
    if (manifest.get("source_kind") != "local-worktree-snapshot"
            or manifest.get("promotion_eligible") is not False
            or manifest.get("release_ready") is not False):
        raise ValueError("This probe requires a non-promotable local source snapshot")
    marker = {"component": "ui", "release_version": manifest["release_version"],
              "marty_ui_sha": manifest["marty_ui_sha"]}
    image = json.loads(docker("image", "inspect", reference))[0]
    if image["Os"] != "linux" or image["Architecture"] != "amd64":
        raise ValueError("Prepared UI must be Linux/amd64")
    labels = image["Config"].get("Labels") or {}
    if (labels.get("org.opencontainers.image.version") != marker["release_version"]
            or labels.get("org.opencontainers.image.revision") != marker["marty_ui_sha"]):
        raise ValueError("Prepared UI labels differ from the local source snapshot")
    scope = "local-ui-smoke"
    cid = docker("run", "--detach", "--name", "elevenid-local-ui-smoke-" + uuid.uuid4().hex,
                 "--label", "io.elevenid.demo.scope=" + scope, "--read-only", "--cpus", "1",
                 "--memory", "256m", "--tmpfs", "/tmp:rw,nosuid,size=32m",
                 "--tmpfs", "/var/run:rw,nosuid,size=8m", "--tmpfs",
                 "/var/cache/nginx:rw,nosuid,size=32m", "--publish", "127.0.0.1::80",
                 image["Id"]).decode().strip()
    if not re.fullmatch("[0-9a-f]{64}", cid):
        raise ValueError("Docker did not return an exact owned container ID")
    try:
        info = json.loads(docker("inspect", cid))[0]
        if info["Config"]["Labels"].get("io.elevenid.demo.scope") != scope:
            raise ValueError("Temporary UI container ownership differs")
        binding = info["NetworkSettings"]["Ports"]["80/tcp"][0]
        if binding["HostIp"] != "127.0.0.1":
            raise ValueError("UI probe must bind only loopback")
        base = "http://127.0.0.1:" + binding["HostPort"]

        def get(path):
            with urllib.request.urlopen(base + path, timeout=5) as response:
                return response.headers, response.read()

        for _ in range(40):
            try:
                _, html = get("/")
                break
            except (OSError, urllib.error.URLError):
                time.sleep(.2)
        else:
            raise RuntimeError("Local UI failed to start")
        if b"ElevenID" not in html or b"Welcome to nginx" in html:
            raise ValueError("Prepared UI serves the wrong homepage")
        _, console = get("/console/")
        if b"<script" not in console:
            raise ValueError("Prepared UI console shell is missing")
        _, served = get("/marty-ui-release.json")
        if json.loads(served) != marker:
            raise ValueError("Served UI marker differs from the source snapshot")
        scripts = [value.decode() for value in re.findall(rb'<script[^>]+src="([^"]+)"', html)]
        local = [path for path in scripts if path.startswith("/") and not path.startswith("//")]
        if not local:
            raise ValueError("Prepared UI has no local application scripts")
        for path in local:
            headers, _ = get(path)
            if "javascript" not in headers.get("Content-Type", ""):
                raise ValueError("A local application script fell through to another content type")
        try:
            get("/ready")
        except urllib.error.HTTPError as error:
            if error.code != 503 or json.loads(error.read()).get("error") != "readiness_not_proxied":
                raise ValueError("Unexpected UI-only readiness response") from error
        else:
            raise ValueError("UI-only server falsely admitted stack readiness")
        result = {"scope": "LOCAL_UI_COMPONENT_ONLY", "imageId": image["Id"],
                  "servedMarker": marker, "homepage": "PASS", "consoleShell": "PASS",
                  "localScripts": local, "scriptMimeTypes": "PASS", "uiAloneStackReadiness": 503,
                  "productionDemoQualified": False, "betaDeployed": False}
    finally:
        # Only the exact ID created above is eligible for this cleanup.
        current = json.loads(docker("inspect", cid))[0]
        if current["Config"]["Labels"].get("io.elevenid.demo.scope") != scope:
            raise RuntimeError("Refusing cleanup of an unowned container")
        docker("rm", "--force", cid)
    result["ownedTemporaryContainerRemoved"] = True
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = smoke(args.image, json.loads(args.source_manifest.read_text(encoding="utf8")))
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf8")
    print(text)


if __name__ == "__main__":
    main()
