#!/usr/bin/env python3
"""Derive a self-host image lock from one exact stack transaction and Compose model.

This is an offline identity/closure check, not an image provenance or runtime
qualification. The caller must separately verify and qualify every supplied OCI
digest before publishing the resulting lock.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import release_transaction
import yaml

SCHEMA = "marty.selfhost-image-lock/v1"
SELFHOST_URIS = {
    "ui-selfhost": "ghcr.io/elevenid/marty-ui-oss/ui-selfhost",
    "cloudflared-wrapper": "ghcr.io/elevenid/marty-ui-oss/cloudflared-wrapper",
}
LEGACY_ROLE = re.compile(
    r"^ghcr\.io/elevenid/marty-ui/"
    r"(?P<role>services|db-migrate|ui-selfhost|cloudflared-wrapper):"
    r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$"
)
SOURCE_ROLE = re.compile(
    r"^(?:\$\{SELFHOST_IMAGE_PREFIX:-ghcr\.io/elevenid/marty-ui\}|"
    r"ghcr\.io/elevenid/marty-ui)/"
    r"(?P<role>services|db-migrate|ui-selfhost|cloudflared-wrapper):"
    r"(?:\$\{SELFHOST_IMAGE_TAG:\?SELFHOST_IMAGE_TAG must be set to an immutable release tag\}|"
    r"[^@\s]+)$"
)
EXACT_IMAGE = re.compile(
    r"^[a-z0-9]+(?:-+[a-z0-9]+)*(?:\.[a-z0-9]+(?:-+[a-z0-9]+)*)*"
    r"(?::[0-9]+)?/[a-z0-9]+(?:[._-]+[a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*@sha256:[0-9a-f]{64}$"
)
DEDICATED_SERVICES = {
    "db-migrate": "db-migrate",
    "ui": "ui-selfhost",
    "cloudflared": "cloudflared-wrapper",
    "cloudflared-beta": "cloudflared-wrapper",
}
ISSUANCE_SERVICES = frozenset({"issuance", "issuance-migrations"})


class ImageLockError(ValueError):
    """The proposed lock is incomplete or is not bound to its source."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ImageLockError(message)


def _json_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ImageLockError(f"Cannot read JSON object: {path}") from error
    _require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def _exact_image(value: object, label: str) -> str:
    _require(isinstance(value, str) and EXACT_IMAGE.fullmatch(value) is not None,
             f"{label} must be an exact OCI sha256 reference")
    return value


def _repository(value: str) -> str:
    image = value.split("@", 1)[0]
    if ":" in image.rsplit("/", 1)[-1]:
        image = image.rsplit(":", 1)[0]
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return image
    if "/" not in image:
        return "docker.io/library/" + image
    return "docker.io/" + image


def _compose_services(path: Path) -> dict:
    # Compose's !reset is a merge directive. For ownership analysis only the
    # service names, build presence, and image declarations are needed.
    class ComposeLoader(yaml.SafeLoader):
        pass

    ComposeLoader.add_constructor("!reset", lambda _loader, _node: None)
    try:
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ImageLockError(f"Cannot read Compose source: {path}") from error
    _require(isinstance(document, dict) and isinstance(document.get("services"), dict),
             f"Compose source has no services: {path}")
    services = document["services"]
    _require(all(isinstance(name, str) and isinstance(service, dict)
                 for name, service in services.items()),
             f"Compose source has invalid services: {path}")
    return services


def _ownership(base_compose: Path, override_compose: Path) -> tuple[set[str], dict[str, str]]:
    base = _compose_services(base_compose)
    override = _compose_services(override_compose)
    _require(set(override).issubset(base), "bundle override adds an unknown service")
    roles = {}
    for name, service in override.items():
        image = service.get("image")
        match = SOURCE_ROLE.fullmatch(image) if isinstance(image, str) else None
        _require(match is not None, f"bundle override has no known Marty image role: {name}")
        roles[name] = match.group("role")
    build_services = {name for name, service in base.items() if "build" in service}
    _require(build_services.issubset(roles),
             "bundle override does not replace every source-build service")
    _require(all(roles[name] == DEDICATED_SERVICES.get(name, "services") for name in roles),
             "bundle override changed a Marty service image role")
    _require(set(DEDICATED_SERVICES).issubset(roles),
             "bundle override omits a dedicated Marty image role")
    return set(base), roles


def build_lock(
    *,
    model: dict,
    transaction: dict,
    stack_lock: Path,
    base_compose: Path,
    override_compose: Path,
    source_sha: str,
    claim_run_id: str,
    selfhost_images: dict[str, str],
    external_services: dict[str, str],
) -> dict:
    try:
        claim = release_transaction.validate_resume(
            transaction,
            repository="ElevenID/marty-ui",
            source_sha=source_sha,
            stack_lock=stack_lock,
            claim_run_id=claim_run_id,
        )
    except release_transaction.ReleaseTransactionError as error:
        raise ImageLockError(str(error)) from error
    _require(claim["images"] and claim["state"] in {
        "digests_recorded", "qualified", "promoting", "promoted", "published"
    }, "stack transaction has no recorded image digests")
    source_lock = _json_object(stack_lock)
    _require(source_lock.get("schema") == release_transaction.STACK_LOCK_SCHEMA,
             "source stack lock schema changed")
    _require(source_lock.get("release") == f"marty-ui@{claim['version']}",
             "source stack lock release differs from transaction")
    _require(set(selfhost_images) == set(SELFHOST_URIS),
             "self-host role digests must cover exactly the two missing roles")
    for role, image in selfhost_images.items():
        _exact_image(image, role)
        _require(image.startswith(SELFHOST_URIS[role] + "@"),
                 f"{role} uses the wrong OCI repository")
    _require(isinstance(model.get("services"), dict) and model["services"],
             "Compose model has no services object")
    services: dict = model["services"]
    _require(all(isinstance(name, str) and name for name in services),
             "Compose service name is invalid")
    base_names, roles = _ownership(base_compose, override_compose)
    _require(set(services) == base_names, "rendered Compose service set differs from source")
    _require(ISSUANCE_SERVICES.issubset(services),
             "issuance services are absent from Compose")
    _require(isinstance(external_services, dict), "external image map is invalid")
    resolved: dict[str, str] = {}
    used_external: set[str] = set()
    for name, service in services.items():
        _require(isinstance(service, dict) and "build" not in service,
                 f"{name} is not an image-only Compose service")
        source_image = service.get("image")
        _require(isinstance(source_image, str), f"{name} has no image")
        match = LEGACY_ROLE.fullmatch(source_image)
        role = match.group("role") if match else None
        if name in roles:
            _require(role == roles[name], f"{name} has the wrong source image role")
            _require(match.group("version") == claim["version"],
                     f"{name} source image version differs from transaction")
        elif name in ISSUANCE_SERVICES:
            _require(role is None, f"{name} cannot use a Marty UI image")
        else:
            _require(role is None, f"{name} is not a Marty bundle image role")

        if role == "services":
            image = claim["image_uris"]["services"] + "@" + claim["images"]["services"]["digest"]
        elif role == "db-migrate":
            image = claim["image_uris"]["migrations"] + "@" + claim["images"]["migrations"]["digest"]
        elif role in SELFHOST_URIS:
            image = selfhost_images[role]
        else:
            _require(name in external_services,
                     f"{name} needs an explicit independent image digest")
            image = external_services[name]
            _exact_image(image, name)
            _require(_repository(source_image) == _repository(image),
                     f"{name} independent image repository differs from Compose")
            if "@sha256:" in source_image:
                _require(source_image == image,
                         f"{name} resolved image digest differs from explicit input")
            used_external.add(name)
        resolved[name] = _exact_image(image, name)
    _require(set(external_services) == used_external,
             "external image map has missing or extra Compose service roles")
    _require(resolved["issuance"] == resolved["issuance-migrations"],
             "issuance API and migration images differ")
    return {"schema": SCHEMA, "release": source_lock["release"],
            "services": dict(sorted(resolved.items()))}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-model", required=True, type=Path,
                        help="Exact rendered, image-only Docker Compose JSON model")
    parser.add_argument("--transaction", required=True, type=Path)
    parser.add_argument("--stack-lock", required=True, type=Path)
    parser.add_argument("--base-compose", required=True, type=Path)
    parser.add_argument("--override-compose", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--claim-run-id", required=True)
    parser.add_argument("--selfhost-images", required=True, type=Path,
                        help="JSON object with ui-selfhost and cloudflared-wrapper exact OCI refs")
    parser.add_argument("--external-services", required=True, type=Path,
                        help="JSON service-to-exact-ref map for issuance and infrastructure")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    lock = build_lock(
        model=_json_object(args.compose_model),
        transaction=_json_object(args.transaction),
        stack_lock=args.stack_lock,
        base_compose=args.base_compose,
        override_compose=args.override_compose,
        source_sha=args.source_sha,
        claim_run_id=args.claim_run_id,
        selfhost_images=_json_object(args.selfhost_images),
        external_services=_json_object(args.external_services),
    )
    encoded = json.dumps(lock, sort_keys=True, indent=2) + "\n"
    if args.output.exists():
        _require(args.output.read_text(encoding="utf-8") == encoded,
                 "existing image lock differs; use a new output path")
    else:
        with args.output.open("x", encoding="utf-8") as destination:
            destination.write(encoded)


if __name__ == "__main__":
    main()
