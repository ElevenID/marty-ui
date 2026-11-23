"""Pure website slot, route and Compose models shared by the host owners."""
from __future__ import annotations

import copy
from pathlib import Path
import re

import ui_release as ui
import website_producer_policy as policy
import website_release as web


SCHEMA = "marty.website-host/v1"
SLOTS = ("website-a", "website-b", "website-c")
PUBLIC_ENV = {"GOOGLE_ANALYTICS_MEASUREMENT_ID", "GOOGLE_ANALYTICS_MEASUREMENT_ID_FILE",
              "GOOGLE_SITE_VERIFICATION", "GOOGLE_SITE_VERIFICATION_FILE", "ORGANIZATION_CREATION_ENABLED"}
PUBLIC_SECRETS = {"google_analytics_measurement_id", "google_site_verification"}


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
    policy.image_policy(value["image"]["uri"], role="website")
    ui.require(value["image"]["platform"] == "linux/amd64", "unsupported website slot image")
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


def render_routes(state: dict, *, retained_resources_redirect: bool = False) -> bytes:
    validate_state(state)
    active = state["active"]
    retained = [active] + ([state["previous"]] if state["previous"] else [])
    lines = ["# Authenticated website selection; generated by deploy_website.py."]
    def location(selector: str, slot: str, *, internal_resources: bool = False):
        lines.append(f"location {selector} {{")
        upstream_uri = ""
        if internal_resources:
            lines.append("    internal;")
            upstream_uri = "/resources$is_args$args"
        lines.extend([f"    set $website_upstream {slot}:80;",
                      f"    proxy_pass http://$website_upstream{upstream_uri};", "    proxy_http_version 1.1;",
                      "    proxy_set_header Host $http_host;", "    proxy_set_header X-Real-IP $remote_addr;",
                      "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                      "    proxy_set_header X-Forwarded-Proto $scheme;", "    proxy_set_header X-Forwarded-Host $http_host;", "}"])
    for slot in retained:
        location("^~ /_website/" + state["slots"][slot]["revision"] + "/", slot)
    location("= /_website/runtime-config.js", active)
    lines.extend(["location ^~ /_website/ {", "    return 404;", "}"])
    website = state["routes"]["website"]
    for path in website["exact_paths"]:
        if path == "/resources" and retained_resources_redirect:
            alias = "/_website/.managed-resources"
            lines.append(f"rewrite ^/resources$ {alias} last;")
            location("= " + alias, active, internal_resources=True)
        else:
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
