#!/usr/bin/env python3
"""Inspect website composition compatibility under the retained Windows lease.

This command does not deploy or grant production admission. It authenticates the
composition and reads the selected model/container identities without creating
Docker helpers, renewing credentials, initializing OpenBao or writing host state.
Only the existing selection owner can resolve its predecessor/recovery chain.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
import re
import subprocess
import sys

import package_web_composition as composition
import selfhost_windows_product as product
import selfhost_windows_renewal as renewal
import selfhost_windows_selection as selection
import ui_release as ui


SCHEMA = "marty.windows-website-preflight/v1"
WEBSITE_ROLES = frozenset({"website-a", "website-b", "website-c"})
ERROR = "Managed website inspection refused; no deployment was attempted. Preserve the selected owner and its records."


def _identity(items: list[dict], project: str) -> dict:
    """Compare configuration and mounts privately, without requiring readiness."""
    result = {}
    for item in items:
        if renewal._project(item) != project:
            continue
        role = renewal._service(item)
        selection.require(isinstance(role, str) and role not in result
                          and re.fullmatch(r"[0-9a-f]{64}", item["Id"]))
        result[role] = {"id": item["Id"], "image": item["Image"],
                        "configuration": deepcopy(item["Config"]),
                        "mounts": renewal.canonical_mounts(item["Mounts"])}
    return result


def _observe(config: dict, choice: str, values: dict, record: dict) -> tuple[dict, dict]:
    """Read selected identities; do not substitute for native/storage custody.

    The caller already holds the real selection lease and private input handles.
    No helper container or generic recovery/configuration callback is used here.
    """
    selection.require(choice in {"old", "new"})
    docker = renewal.Docker(config["docker_host"], config["engine_id"])
    commands = {side: docker.compose(config["project"], Path(config[prefix + "_env"]), Path(config["compose_file"]))
                for side, prefix in (("old", "current"), ("new", "renewed"))}
    models = {side: docker.json(command[len(docker.prefix):] + ["--profile", "*", "config", "--format", "json"])
              for side, command in commands.items()}
    renewal.checked_models(models["old"], models["new"], Path(config["current_secrets"]),
                           Path(config["renewed_secrets"]), sorted(values["old"]))
    model = models[choice]
    selection.require(not WEBSITE_ROLES.intersection(model["services"]))
    before = docker.containers()
    owned = [item for item in before if renewal._project(item) == config["project"]]
    identity = _identity(owned, config["project"])
    roles = set(identity)
    changing = renewal.owned_roles(model, roles)
    renewal.dependency_layers(model, roles, changing)
    hashes = docker.hashes(commands[choice])
    renewal.checked_live_configuration(owned, hashes, config["tls_init_receipt"])
    prefix = "current" if choice == "old" else "renewed"
    mounts = renewal.checked_secret_mounts(owned, config["project"], Path(config[prefix + "_secrets"]),
        roles, model, path_equal=renewal.windows_mount_path_equal)
    selection.require(mounts > 0 and selection.digest(selection.packed(renewal.data_mounts(owned))) == record["data_sha256"])

    # The completed TLS initializer is retained historical evidence. Its exact
    # receipt was checked above; it is neither compared to a successor image nor
    # restarted. Every other installed role must use its selected digest bytes.
    references = {}
    for role in sorted(roles - product.HISTORICAL_ROLES):
        reference = model["services"][role]["image"]
        selection.require(identity[role]["configuration"]["Image"] == reference)
        if reference not in references:
            rows = docker.json(["image", "inspect", reference])
            selection.require(isinstance(rows, list) and len(rows) == 1
                              and re.fullmatch(r"sha256:[0-9a-f]{64}", rows[0]["Id"]))
            references[reference] = rows[0]["Id"]
        selection.require(identity[role]["image"] == references[reference])

    after = [item for item in docker.containers() if renewal._project(item) == config["project"]]
    selection.require(_identity(after, config["project"]) == identity)
    renewal.checked_live_configuration(after, hashes, config["tls_init_receipt"])
    return model, {"configured_roles": len(model["services"]), "installed_roles": len(roles),
                   "selected_configuration_verified": True, "installed_image_bytes_verified": True,
                   "selected_secret_mounts_verified": True, "recorded_data_mounts_verified": True,
                   "historical_tls_initializer_preserved": True}


def compatibility(model: dict, manifest: dict) -> dict:
    """An inert comparison of already authenticated composition and host inputs."""
    services = model["services"]
    configured = set(services) - product.PROVIDER_ROLES
    expected = set(manifest["images"])
    missing = sorted(expected - configured)
    unexpected = sorted(configured - expected)
    mismatches = sorted(role for role in configured & expected
                        if product.image_identity(services[role]["image"]) != product.image_identity(manifest["images"][role]))
    provider_missing = sorted(product.PROVIDER_ROLES - set(services))
    provider_mismatches = sorted(role for role in product.PROVIDER_ROLES & set(services)
        if product.image_identity(services[role]["image"]) != product.image_identity(manifest["openbao_didcomm_image"]))
    application = services.get("ui", {}).get("image", "")
    application_uri = application.split("@", 1)[0]
    audience = {ui.COMMERCE_IMAGE: "full", ui.PUBLIC_IMAGE: "public"}.get(application_uri)
    audience_matches = audience is not None and audience == manifest["production_pages"]
    edge = services.get("edge", {})
    independent_edge = (not edge.get("depends_on")
                        and "http://127.0.0.1/edge-healthz" in edge.get("healthcheck", {}).get("test", []))
    blockers = []
    if missing or unexpected:
        blockers.append("product_role_closure_differs")
    if mismatches:
        blockers.append("product_image_pins_differ")
    if provider_missing or provider_mismatches:
        blockers.append("openbao_image_pins_differ")
    if not audience_matches:
        blockers.append("website_audience_differs")
    if not independent_edge:
        blockers.append("edge_configuration_is_not_independent")
    return {"composition_matches_selected_product": not blockers,
            "installed_application_audience": audience, "website_audience": manifest["production_pages"],
            "missing_product_roles": missing, "unexpected_product_roles": unexpected,
            "product_image_mismatch_roles": mismatches, "missing_openbao_roles": provider_missing,
            "openbao_image_mismatch_roles": provider_mismatches,
            "independent_edge_configuration": independent_edge,
            "compatibility_blockers": blockers}


def inspect_composition(config: dict, choice: str, values: dict, record: dict, assets: Path, *,
                        gh: Path, cosign: Path, registry_config: Path | None) -> dict:
    """Called only by the active selected-input callback under its project lock."""
    with composition.verified_package(Path(assets).absolute(), gh=Path(gh).absolute(), cosign=Path(cosign).absolute(),
                                      registry_config=registry_config) as (manifest, _payload):
        model, observed = _observe(config, choice, values, record)
        comparison = compatibility(model, manifest)
        return {"schema": SCHEMA, "inspection_completed": True, "project": config["project"],
                "compose_sha256": config["compose_sha256"],
                "resolved_configuration_sha256": selection.digest(selection.packed(model)),
                "selection_sequence": record["sequence"],
                "composition_id": manifest["composition_id"], "website_revision": manifest["website"]["revision"],
                "backend_release_tag": manifest["backend"]["release_tag"],
                "composition_authenticated": True, **observed, **comparison,
                "native_custody_checked": False, "foreign_storage_custody_checked": False,
                "runtime_readiness_checked": False, "mounted_edge_template_checked": False,
                "public_ingress_checked": False, "activation_supported": False, "production_admission": False,
                "remaining_milestones": ["managed_website_transition_and_recovery",
                                         "mounted_edge_template_and_public_ingress_qualification"]}


def check(selection_file: Path, assets: Path, *, gh: Path, cosign: Path,
          registry_config: Path | None = None) -> dict:
    with selection.selected_inputs(Path(selection_file).absolute()) as lease:
        result = lease.check_website_composition(assets, gh=gh, cosign=cosign, registry_config=registry_config)
        result["generation_sequence"] = lease.generation_sequence
        result["selected_inputs_sha256"] = lease.selected_sha256
    # Results become visible only after every lease/input/ancestor exit check.
    return result


def main(argv: list[str] | None = None) -> int:
    class PrivateParser(argparse.ArgumentParser):
        def error(self, _message):
            self.exit(2, ERROR + "\n")

    parser = PrivateParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true", required=True)
    for name in ("selection-file", "composition-dir", "gh", "cosign"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--registry-config", type=Path)
    args = parser.parse_args(argv)
    try:
        result = check(args.selection_file, args.composition_dir, gh=args.gh, cosign=args.cosign,
                       registry_config=args.registry_config)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, RuntimeError, subprocess.SubprocessError):
        sys.stderr.write(ERROR + "\n")
        return 2
    sys.stdout.write(selection.packed(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
