#!/usr/bin/env python3
"""Apply an authenticated website composition to an existing ordinary Compose host.

Only website slots and the existing edge are operated. Product and OpenBao image
pins/configuration must match the recorded installation; changes require explicit
adoption after the product upgrade has completed. This is not a native-installer
upgrade command. Use a trusted checkout of this script, never archive-selected code.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
from urllib.parse import urlsplit
import urllib.request

import package_web_composition as composition
import ui_release as ui
import website_provenance as proof
import website_release as web

SCHEMA = "marty.website-host/v1"
SLOTS = ("website-a", "website-b", "website-c")
PUBLIC_ENV = {"GOOGLE_ANALYTICS_MEASUREMENT_ID", "GOOGLE_ANALYTICS_MEASUREMENT_ID_FILE",
              "GOOGLE_SITE_VERIFICATION", "GOOGLE_SITE_VERIFICATION_FILE", "ORGANIZATION_CREATION_ENABLED"}
PUBLIC_SECRETS = {"google_analytics_measurement_id", "google_site_verification"}
OPENBAO_SERVICES = {"openbao", "openbao-tls-init", "openbao-unseal", "openbao-bootstrap"}


def origin(value: str) -> str:
    parsed = urlsplit(value)
    ui.require(value == value.strip() and not re.search(r"[\x00-\x20\x7f\\]", value)
               and parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and not parsed.password
               and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment,
               "public origin must be an explicit HTTP(S) origin without credentials or a path")
    return value.rstrip("/")


def slot_record(manifest: dict) -> dict:
    website = manifest["website"]
    return {"revision": website["revision"], "image": website["image"], "source_sha": website["source_sha"],
            "release_sha256": website["release_sha256"], "composition_id": manifest["composition_id"]}


def validate_slot(value: dict) -> None:
    web.object_keys(value, {"revision", "image", "source_sha", "release_sha256", "composition_id"}, "website slot")
    ui.require(isinstance(value["revision"], str) and re.fullmatch(r"[0-9a-f]{40}(?:-[0-9a-f]{40})?", value["revision"]),
               "invalid website revision")
    web.full_sha(value["source_sha"])
    ui.require(value["revision"].split("-")[0] == value["source_sha"], "website revision source differs")
    web.object_keys(value["image"], {"uri", "digest", "platform"}, "website slot image")
    ui.require(value["image"]["uri"] in {web.PUBLIC_IMAGE, web.COMMERCE_IMAGE}
               and value["image"]["platform"] == "linux/amd64", "unsupported website slot image")
    ui.require(("-" in value["revision"]) == (value["image"]["uri"] == web.COMMERCE_IMAGE),
               "website revision audience differs")
    for digest in (value["image"]["digest"], value["release_sha256"], value["composition_id"]):
        web.image_digest(digest)


def validate_state(state: dict) -> dict:
    web.object_keys(state, {"schema", "host", "product", "routes", "slots", "active", "previous"}, "website host state")
    ui.require(state["schema"] == SCHEMA and isinstance(state["host"], dict), "unsupported website host state")
    web.route_identity(state["routes"])
    ui.require(isinstance(state["slots"], dict) and 1 <= len(state["slots"]) <= 3
               and set(state["slots"]).issubset(SLOTS), "invalid retained website slots")
    for value in state["slots"].values():
        validate_slot(value)
    ui.require(state["active"] in state["slots"] and (state["previous"] is None or
               state["previous"] in state["slots"] and state["previous"] != state["active"]), "invalid active/previous website")
    web.object_keys(state["product"], {"images", "openbao_didcomm_image", "configuration_sha256"}, "product snapshot")
    ui.require(isinstance(state["product"]["images"], dict) and {"ui", "edge", "gateway"}.issubset(state["product"]["images"]),
               "product service closure differs")
    for image in [*state["product"]["images"].values(), state["product"]["openbao_didcomm_image"]]:
        ui.require(isinstance(image, str) and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", image),
                   "product image is not digest pinned")
    web.image_digest(state["product"]["configuration_sha256"])
    return state


def next_state(previous: dict | None, manifest: dict, routes: dict, host: dict, product: dict) -> dict:
    ui.require(web.route_identity(routes) == manifest["route_contract"], "deployment route identity differs")
    value = slot_record(manifest)
    validate_slot(value)
    if previous:
        validate_state(previous)
        ui.require(previous["host"] == host and previous["product"] == product, "host or product changed; adopt the current product explicitly")
        ui.require(web.route_identity(previous["routes"]) == manifest["route_contract"], "retained website routing contract differs")
        for slot, recorded in previous["slots"].items():
            if recorded["revision"] == value["revision"]:
                ui.require(recorded["image"] == value["image"] and recorded["release_sha256"] == value["release_sha256"],
                           "website revision already belongs to different immutable evidence")
                if slot == previous["active"]:
                    return copy.deepcopy(previous)
        available = next(slot for slot in SLOTS if slot not in {previous["active"], previous["previous"]})
        slots = {**previous["slots"], available: value}
        result = {**copy.deepcopy(previous), "slots": slots, "active": available, "previous": previous["active"]}
    else:
        result = {"schema": SCHEMA, "host": host, "product": product, "routes": routes,
                  "slots": {SLOTS[0]: value}, "active": SLOTS[0], "previous": None}
    return validate_state(result)


def render_routes(state: dict) -> bytes:
    validate_state(state)
    active = state["active"]
    retained = [active] + ([state["previous"]] if state["previous"] else [])
    lines = ["# Authenticated website selection; generated by deploy_website.py."]
    def location(selector: str, slot: str):
        lines.extend([f"location {selector} {{", f"    set $website_upstream {slot}:80;",
                      "    proxy_pass http://$website_upstream;", "    proxy_http_version 1.1;",
                      "    proxy_set_header Host $http_host;", "    proxy_set_header X-Real-IP $remote_addr;",
                      "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                      "    proxy_set_header X-Forwarded-Proto $scheme;", "    proxy_set_header X-Forwarded-Host $http_host;", "}"])
    for slot in retained:
        location("^~ /_website/" + state["slots"][slot]["revision"] + "/", slot)
    location("= /_website/runtime-config.js", active)
    lines.extend(["location ^~ /_website/ {", "    return 404;", "}"])
    website = state["routes"]["website"]
    for path in website["exact_paths"]:
        location("= " + path, active)
    for prefix in website["path_prefixes"]:
        if prefix != "/_website/":
            location("^~ " + prefix, active)
    for pattern in website["filename_patterns"]:
        location("~ " + pattern, active)
    return ("\n".join(lines) + "\n").encode()


def compose_overlay(state: dict, model: dict, routes_directory: Path) -> dict:
    validate_state(state)
    services = model["services"]
    ui.require("ui" in services and "edge" in services and not set(services).intersection(SLOTS), "host service roles conflict")
    application, edge = services["ui"], services["edge"]
    ui.require(not edge.get("depends_on") and "http://127.0.0.1/edge-healthz" in edge.get("healthcheck", {}).get("test", []),
               "host edge has not been upgraded for independent website delivery")
    secrets = [entry for entry in application.get("secrets", []) if
               (entry if isinstance(entry, str) else entry.get("source")) in PUBLIC_SECRETS]
    values = {key: value for key, value in application.get("environment", {}).items() if key in PUBLIC_ENV}
    overlay = {"services": {"edge": {"volumes": [{"type": "bind", "source": str(routes_directory),
                 "target": "/etc/nginx/marty-website", "read_only": True}]}}}
    ui.require(not any(item.get("target") == "/etc/nginx/marty-website" for item in edge.get("volumes", []) if isinstance(item, dict)),
               "base Compose already owns the website route mount")
    for slot, website in state["slots"].items():
        service = {"image": website["image"]["uri"] + "@" + website["image"]["digest"],
                   "restart": "unless-stopped", "mem_limit": "256m", "environment": values, "secrets": secrets,
                   "healthcheck": {"test": ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1:80/healthz"],
                                   "interval": "10s", "timeout": "5s", "retries": 6, "start_period": "5s"}}
        if "networks" in edge:
            service["networks"] = copy.deepcopy(edge["networks"])
        overlay["services"][slot] = service
    return overlay


def verify_overlay_model(original: dict, rendered: dict, state: dict, route_directory: Path) -> None:
    expected = copy.deepcopy(original)
    edge = expected["services"]["edge"]
    volumes = edge.setdefault("volumes", [])
    wanted = {"type": "bind", "source": str(route_directory), "target": "/etc/nginx/marty-website", "read_only": True}
    current = rendered["services"]["edge"].get("volumes", [])
    mount = next((entry for entry in current if entry.get("target") == wanted["target"]), None)
    ui.require(mount is not None and all(mount.get(key) == value for key, value in wanted.items()), "rendered website route mount differs")
    volumes.append(mount)
    actual = copy.deepcopy(rendered)
    for slot, record in state["slots"].items():
        service = actual["services"].pop(slot, None)
        ui.require(service is not None and service.get("image") == record["image"]["uri"] + "@" + record["image"]["digest"]
                   and not service.get("depends_on") and not service.get("ports") and "build" not in service,
                   "rendered website service identity differs")
    ui.require(actual == expected, "website Compose overlay changes product, ingress, networks, or secrets")


def atomic_write(path: Path, payload: bytes | None) -> None:
    if payload is None:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".website-write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


@contextmanager
def host_lock(directory: Path):
    ui.require(not any(path.is_symlink() for path in (directory, *directory.parents)), "website host state must not use symlinks")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        ui.require(directory.stat().st_uid == os.getuid() and not directory.stat().st_mode & 0o077, "website host state must be owner-private")
    lock = directory / "deploy.lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise ValueError("website deployment is locked; confirm the recorded process has stopped before removing a stale deploy.lock") from None
    try:
        (lock / "pid").write_text(str(os.getpid()))
        yield
    finally:
        shutil.rmtree(lock)


class DockerHost:
    def __init__(self, *, stack: Path, project: str, compose_files: list[Path], env_file: Path,
                 openbao_file: Path, openbao_env_file: Path, openbao_project: str,
                 public_origin: str, ca_file: Path | None = None):
        ui.require(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project) and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", openbao_project),
                   "invalid Compose project name")
        self.stack = stack.absolute()
        for path in [*compose_files, env_file, openbao_file, openbao_env_file]:
            proof.verifier.local_file(path.absolute())
        self.files = [path.absolute() for path in compose_files]
        self.environment = env_file.absolute()
        self.openbao_file = openbao_file.absolute()
        self.openbao_environment = openbao_env_file.absolute()
        self.project, self.openbao_project = project, openbao_project
        self.public_origin = origin(public_origin)
        self.ca_file = ca_file.absolute() if ca_file else None
        self.directory = self.stack / ".marty-website"

    def identity(self) -> dict:
        return {"stack_directory": str(self.stack), "project": self.project, "compose_files": [str(path) for path in self.files],
                "env_file": str(self.environment), "openbao_compose_file": str(self.openbao_file),
                "openbao_env_file": str(self.openbao_environment), "openbao_project": self.openbao_project,
                "public_origin": self.public_origin, "ca_file": str(self.ca_file) if self.ca_file else None}

    def run(self, args: list[str], *, timeout: int = 180) -> str:
        result = subprocess.run(args, cwd=self.stack, capture_output=True, text=True, timeout=timeout, check=False)
        ui.require(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024,
                   "Docker operation failed: " + " ".join(arg for arg in args[:3]))
        return result.stdout

    def command(self, *, overlay: Path | None = None, provider: bool = False) -> list[str]:
        files = [self.openbao_file] if provider else [*self.files, *([overlay] if overlay else [])]
        result = ["docker", "compose", "--project-directory", str(self.stack), "--project-name",
                  self.openbao_project if provider else self.project, "--env-file",
                  str(self.openbao_environment if provider else self.environment)]
        return result + [part for path in files for part in ("-f", str(path))]

    def model(self, *, overlay: Path | None = None, provider: bool = False) -> dict:
        return json.loads(self.run(self.command(overlay=overlay, provider=provider) + ["config", "--format", "json"]))

    def inspect_current(self, images: dict, *, provider: bool = False) -> None:
        command = self.command(provider=provider) + ["ps", "--all", "--quiet", *sorted(images)]
        identifiers = self.run(command).split()
        for identifier in identifiers:
            ui.require(re.fullmatch(r"[0-9a-f]{12,64}", identifier), "invalid Compose container identity")
            values = json.loads(self.run(["docker", "inspect", identifier]))
            ui.require(isinstance(values, list) and len(values) == 1, "ambiguous installed container")
            container = values[0]
            labels = container["Config"]["Labels"]
            service = labels.get("com.docker.compose.service")
            ui.require(service in images and labels.get("com.docker.compose.project") ==
                       (self.openbao_project if provider else self.project), "installed container owner differs")
            ui.require(container["Config"]["Image"] == images[service], "installed product image differs from configured digest")
            image = json.loads(self.run(["docker", "image", "inspect", images[service]]))
            ui.require(len(image) == 1 and container["Image"] == image[0]["Id"], "installed product image bytes differ")

    def snapshot(self, expected: dict | None = None) -> tuple[dict, dict]:
        model, provider = self.model(), self.model(provider=True)
        services = model["services"]
        ui.require(not set(services).intersection(SLOTS) and all("build" not in service for service in services.values()),
                   "base Compose must contain only digest-pinned product roles")
        images = {name: service.get("image") for name, service in services.items()}
        for image in images.values():
            ui.require(isinstance(image, str) and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", image),
                       "product image is not digest pinned")
        ui.require(set(provider["services"]) == OPENBAO_SERVICES and all("build" not in service for service in provider["services"].values()),
                   "OpenBao role closure differs")
        bao_images = {name: service.get("image") for name, service in provider["services"].items()}
        ui.require(len(set(bao_images.values())) == 1, "OpenBao image pins differ")
        bao = next(iter(bao_images.values()))
        ui.require(isinstance(bao, str) and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", bao), "OpenBao image is not digest pinned")
        snapshot = {"images": images, "openbao_didcomm_image": bao,
                    "configuration_sha256": ui.digest(ui.canonical({"product": model, "openbao": provider}))}
        if expected:
            ui.require(images == expected["images"] and bao == expected["openbao_didcomm_image"], "current product does not match selected composition")
        self.inspect_current(images)
        self.inspect_current(bao_images, provider=True)
        return snapshot, model

    def stage(self, slot: str, overlay: Path, metadata: dict, *, pull: bool = True) -> None:
        base = self.command(overlay=overlay)
        if pull:
            self.run(base + ["pull", slot], timeout=300)
        self.run(base + ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "90", slot], timeout=150)
        actual = json.loads(self.run(base + ["exec", "-T", slot, "wget", "-qO-", "http://127.0.0.1:80/marty-website-release.json"]))
        ui.require(actual == metadata, "staged website image metadata differs")

    def activate(self, overlay: Path, *, initial: bool = False) -> None:
        base = self.command(overlay=overlay)
        # This also handles an edge stopped during host maintenance. The explicit
        # service and --no-deps never start a product role or gate on its health.
        self.run(base + ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "60", "edge"], timeout=90)
        self.run(base + ["exec", "-T", "edge", "nginx", "-t"])
        self.run(base + ["exec", "-T", "edge", "nginx", "-s", "reload"])

    def stop_candidate(self, slot: str, overlay: Path) -> None:
        self.run(self.command(overlay=overlay) + ["stop", "--timeout", "10", slot])

    def check_public(self, metadata: dict) -> None:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None
        context = ssl.create_default_context(cafile=str(self.ca_file) if self.ca_file else None)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        for path in ("/", "/marty-website-release.json"):
            request = urllib.request.Request(self.public_origin + path, headers={"Cache-Control": "no-cache"})
            with opener.open(request, timeout=15) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                ui.require(response.status == 200 and len(raw) <= 4 * 1024 * 1024
                           and response.headers.get("X-Marty-Website-Revision") == metadata["revision"], "public website revision check failed")
                if path == "/":
                    ui.require("text/html" in response.headers.get("Content-Type", "")
                               and ("/_website/" + metadata["revision"] + "/").encode() in raw, "public website homepage does not reference its revision")
                else:
                    ui.require(json.loads(raw) == metadata, "public website metadata differs")


def remember_receipt(directory: Path, payload: Path, selection: dict) -> None:
    receipt = directory / "receipts" / selection["revision"]
    receipt.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if receipt.exists():
        for name in composition.WEBSITE_FILES:
            proof.verifier.local_file(receipt / name, private=True)
            ui.require(proof.file_digest(receipt / name) == proof.file_digest(payload / name),
                       "website revision receipt already contains different evidence")
    else:
        composition.copy_inputs(payload, composition.WEBSITE_FILES, receipt)


def read_state(directory: Path) -> dict | None:
    path = directory / "state.json"
    return validate_state(proof.read_metadata(path)) if path.exists() else None


def transition(host: DockerHost, current: dict | None, target: dict, model: dict, metadata: dict, *, stage: bool) -> dict:
    directory = host.directory
    routes_directory = directory / "routes"
    routes_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    overlay, routes = directory / "compose.website.json", routes_directory / "active.conf"
    before_overlay = overlay.read_bytes() if overlay.exists() else None
    before_routes = routes.read_bytes() if routes.exists() else None
    journal = {"schema": "marty.website-transaction/v1", "host": host.identity(), "previous_state": current,
               "target_state": target, "previous_overlay": before_overlay.decode() if before_overlay is not None else None,
               "previous_routes": before_routes.decode() if before_routes is not None else None, "candidate": target["active"] if stage else None}
    candidate_overlay = directory / "compose.candidate.json"
    atomic_write(candidate_overlay, ui.canonical(compose_overlay(target, model, routes_directory)))
    try:
        rendered = host.model(overlay=candidate_overlay)
        verify_overlay_model(model, rendered, target, routes_directory)
    except Exception:
        atomic_write(candidate_overlay, None)
        raise
    atomic_write(directory / "transaction.json", ui.canonical(journal))
    committed = False
    try:
        host.stage(target["active"], candidate_overlay, metadata, pull=stage)
        atomic_write(overlay, candidate_overlay.read_bytes())
        atomic_write(routes, render_routes(target))
        host.activate(overlay, initial=current is None)
        host.check_public(metadata)
        actual, _ = host.snapshot()
        ui.require(actual == target["product"], "product changed during website activation")
        atomic_write(directory / "state.json", ui.canonical(target))
        committed = True
        atomic_write(directory / "transaction.json", None)
        atomic_write(candidate_overlay, None)
        return target
    except Exception as original:
        if committed:
            raise ValueError("website activation committed; run --recover to finish transaction cleanup") from original
        try:
            atomic_write(routes, before_routes)
            # A missing prior overlay means the combined application was active.
            atomic_write(overlay, before_overlay if before_overlay is not None else b'{"services":{}}\n')
            host.activate(overlay, initial=current is None)
            if current:
                old = proof.read_metadata(directory / "receipts" / current["slots"][current["active"]]["revision"] / "website-release.json")
                host.check_public(old["image_metadata"])
            if stage:
                host.stop_candidate(target["active"], candidate_overlay)
            atomic_write(directory / "transaction.json", None)
            atomic_write(candidate_overlay, None)
        except Exception as rollback:
            raise ValueError("website activation failed and rollback needs recovery; transaction.json was retained") from rollback
        raise ValueError("website activation failed; previous selection was restored") from original


def apply(host: DockerHost, assets: Path, *, gh: Path, cosign: Path, adopt_current_product: bool = False) -> dict:
    with host_lock(host.directory):
        ui.require(not (host.directory / "transaction.json").exists(), "unfinished website transaction; run --recover first")
        current = read_state(host.directory)
        with composition.verified_package(assets, gh=gh, cosign=cosign) as (manifest, payload):
            actual, model = host.snapshot(manifest)
            routes = web.read(payload / "website/web-surface-routes.json")
            if adopt_current_product:
                ui.require(current is not None and current["host"] == host.identity(), "product adoption requires the existing website host")
                ui.require(web.route_identity(current["routes"]) == manifest["route_contract"], "new product cannot serve the retained website route contract")
                updated = {**current, "product": actual}
                atomic_write(host.directory / "state.json", ui.canonical(updated))
                return updated
            target = next_state(current, manifest, routes, host.identity(), actual)
            metadata = web.read(payload / "website/website-release.json")["image_metadata"]
            remember_receipt(host.directory, payload / "website", slot_record(manifest))
            if target == current:
                host.check_public(metadata)
                return target
            return transition(host, current, target, model, metadata, stage=True)


def rollback(host: DockerHost, *, gh: Path, cosign: Path) -> dict:
    with host_lock(host.directory):
        ui.require(not (host.directory / "transaction.json").exists(), "unfinished website transaction; run --recover first")
        state = read_state(host.directory)
        ui.require(state is not None and state["previous"] is not None and state["host"] == host.identity(), "no previous website for this host")
        actual, model = host.snapshot()
        ui.require(actual == state["product"], "current product changed; adopt the upgraded product before website rollback")
        selected = state["slots"][state["previous"]]
        receipt = host.directory / "receipts" / selected["revision"]
        release = proof.verify_website(receipt, gh=gh, cosign=cosign)
        ui.require(release["image"] == selected["image"] and proof.file_digest(receipt / "website-release.json") == selected["release_sha256"]
                   and release["image_metadata"]["route_contract"] == web.route_identity(state["routes"]), "previous website evidence differs")
        target = {**state, "active": state["previous"], "previous": state["active"]}
        # Restarting the retained slot is safe after a host restart; no product role starts.
        return transition(host, state, target, model, release["image_metadata"], stage=False)


def recover(host: DockerHost, *, gh: Path, cosign: Path) -> dict | None:
    with host_lock(host.directory):
        path = host.directory / "transaction.json"
        ui.require(path.exists(), "no interrupted website transaction exists")
        journal = proof.read_metadata(path)
        web.object_keys(journal, {"schema", "host", "previous_state", "target_state", "previous_overlay", "previous_routes", "candidate"}, "website transaction")
        ui.require(journal["schema"] == "marty.website-transaction/v1" and journal["host"] == host.identity(), "transaction host differs")
        target = validate_state(journal["target_state"])
        current = read_state(host.directory)
        if current == target:
            atomic_write(path, None)
            atomic_write(host.directory / "compose.candidate.json", None)
            return current
        ui.require(current == journal["previous_state"], "website state changed after interrupted transaction")
        actual, _ = host.snapshot()
        ui.require(actual == target["product"], "product changed after interrupted transaction")
        previous = journal["previous_state"]
        release = None
        if previous:
            validate_state(previous)
            selection = previous["slots"][previous["active"]]
            receipt = host.directory / "receipts" / selection["revision"]
            release = proof.verify_website(receipt, gh=gh, cosign=cosign)
            ui.require(proof.file_digest(receipt / "website-release.json") == selection["release_sha256"]
                       and release["image"] == selection["image"], "recovery website evidence differs")
        ui.require(journal["candidate"] is None or journal["candidate"] in SLOTS and
                   (previous is None or journal["candidate"] not in {previous["active"], previous["previous"]}),
                   "recovery candidate overlaps a retained slot")
        overlay = host.directory / "compose.website.json"
        atomic_write(host.directory / "routes/active.conf", None if journal["previous_routes"] is None else journal["previous_routes"].encode())
        atomic_write(overlay, (journal["previous_overlay"] or '{"services":{}}\n').encode())
        host.activate(overlay, initial=previous is None)
        if release:
            host.check_public(release["image_metadata"])
        if journal["candidate"] is not None:
            host.stop_candidate(journal["candidate"], host.directory / "compose.candidate.json")
        atomic_write(path, None)
        atomic_write(host.directory / "compose.candidate.json", None)
        return previous


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-dir", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--compose-file", action="append", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--openbao-compose-file", type=Path, required=True)
    parser.add_argument("--openbao-env-file", type=Path, required=True)
    parser.add_argument("--openbao-project", default="marty-selfhost-openbao")
    parser.add_argument("--public-origin", required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--composition-dir", type=Path)
    parser.add_argument("--gh", type=Path)
    parser.add_argument("--cosign", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--rollback", action="store_true")
    mode.add_argument("--recover", action="store_true")
    mode.add_argument("--adopt-current-product", action="store_true")
    args = parser.parse_args()
    host = DockerHost(stack=args.stack_dir, project=args.project, compose_files=args.compose_file, env_file=args.env_file,
                      openbao_file=args.openbao_compose_file, openbao_env_file=args.openbao_env_file,
                      openbao_project=args.openbao_project, public_origin=args.public_origin, ca_file=args.ca_file)
    ui.require(args.gh is not None and args.cosign is not None, "pinned gh and cosign verifiers are required")
    verifiers = dict(gh=args.gh.absolute(), cosign=args.cosign.absolute())
    if args.recover:
        ui.require(args.composition_dir is None, "recovery uses only the existing transaction")
        result = recover(host, **verifiers)
    else:
        if args.rollback:
            ui.require(args.composition_dir is None, "rollback uses retained original website evidence")
            result = rollback(host, **verifiers)
        else:
            ui.require(args.composition_dir is not None, "verified composition assets are required")
            result = apply(host, args.composition_dir.absolute(), adopt_current_product=args.adopt_current_product, **verifiers)
    print(json.dumps({"active": result["active"] if result else None, "previous": result["previous"] if result else None,
                      "product": result["product"] if result else None}, sort_keys=True))


if __name__ == "__main__":
    main()
