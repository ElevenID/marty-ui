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
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import sys

import package_web_composition as composition
from selfhost_windows_inputs import _held_private_input
import selfhost_windows_product as product
import selfhost_windows_product_journal as product_journal
import selfhost_windows_renewal as renewal
import selfhost_windows_selection as selection
import ui_release as ui
import website_release as web


SCHEMA = "marty.windows-website-preflight/v1"
WEBSITE_ROLES = frozenset({"website-a", "website-b", "website-c"})
ERROR = "Managed website inspection refused; no deployment was attempted. Preserve the selected owner and its records."

ROUTE_TARGET = '/etc/nginx/marty-website'
TEMPLATE_TARGET = '/etc/nginx/conf.d/default.conf.template'
MAX_TEMPLATE_BYTES = 1024*1024


def windows_path(value):
    """A bounded, canonical local-drive spelling; no filesystem qualification."""
    selection.require(isinstance(value, str) and len(value) <= 1024 and not re.search(r'[\x00-\x1f\x7f]', value))
    path = PureWindowsPath(value)
    selection.require(re.fullmatch(r'[A-Z]:', path.drive) and path.is_absolute() and str(path) == value
            and len(path.parts) > 1 and all(part not in {'.', '..'} and ':' not in part
                and part.rstrip(' .') == part and not PureWindowsPath(part).is_reserved()
                for part in path.parts[1:]))
    return path


def path_under_owner(root, value):
    path = windows_path(value)
    selection.require(str(path).startswith(str(root) + '\\'))
    return path


def runtime_bind_source(value):
    """Only the existing documented local-drive Docker Desktop bridge forms."""
    selection.require(isinstance(value, str))
    for prefix in ('/run/desktop/mnt/host/', '/host_mnt/', '/mnt/'):
        if value.startswith(prefix):
            match = re.fullmatch(r'([a-zA-Z])/(.+)', value[len(prefix):])
            selection.require(match is not None)
            value = match[1].upper() + ':\\' + match[2].replace('/', '\\')
            break
    return _local_source(value)


def _local_source(value):
    selection.require(isinstance(value, str) and re.match(r'^[a-zA-Z]:[\\/]', value))
    return windows_path(value[0].upper() + value[1:].replace('/', '\\'))


def _overlaps(target, mount):
    return target == mount or target.startswith(mount.rstrip('/') + '/') or mount.startswith(target + '/')


def _combined_mount_targets(targets):
    selection.require(all(isinstance(target, str) and PurePosixPath(target).root == '/'
                and str(PurePosixPath(target)) == target and '..' not in PurePosixPath(target).parts
                for target in targets))
    selection.require(len(set(targets)) == len(targets))
    selection.require(not any(_overlaps(ROUTE_TARGET, target) for target in targets))
    selection.require(not any(_overlaps(TEMPLATE_TARGET, target) for target in targets if target != TEMPLATE_TARGET))


def combined_edge_binding(before, runtime_mounts, owner_root):
    """Identify the declared and installed template before opening its source."""
    edge = before['services']['edge']
    selection.require(not edge.get('depends_on') and
            'http://127.0.0.1/edge-healthz' in edge.get('healthcheck', {}).get('test', []))
    volumes = edge.get('volumes', [])
    selection.require(type(volumes) is list and all(type(mount) is dict for mount in volumes))
    _combined_mount_targets([mount.get('target') for mount in volumes])
    mounts = [mount for mount in volumes if mount['target'] == TEMPLATE_TARGET]
    selection.require(len(mounts) == 1 and mounts[0].get('type') == 'bind' and mounts[0].get('read_only') is True)
    source = str(_local_source(mounts[0].get('source')))
    path_under_owner(windows_path(owner_root), source)
    _combined_mount_targets([mount['Destination'] for mount in runtime_mounts])
    installed = [mount for mount in runtime_mounts if mount['Destination'] == TEMPLATE_TARGET]
    selection.require(len(installed) == 1 and installed[0]['Type'] == 'bind' and installed[0].get('RW') is False
            and str(runtime_bind_source(installed[0].get('Source'))) == source)
    return {'source': source, 'target': TEMPLATE_TARGET, 'runtime_mount_sha256': selection.digest(selection.packed(installed[0]))}


def edge_template_identity(binding, template):
    """Bind exact template bytes to the combined edge mount identity."""
    selection.require(isinstance(template, bytes) and 0 < len(template) <= MAX_TEMPLATE_BYTES and b'\0' not in template)
    try:
        text = template.decode('utf-8')
    except UnicodeError:
        raise ValueError('Managed website edge template refused') from None
    lines = [line.split('#', 1)[0].strip() for line in text.splitlines()]
    selection.require(lines.count(composition.EDGE_INCLUDE) == 1
            and any(re.fullmatch(r'location\s+=\s+/edge-healthz\s*\{', line) for line in lines))
    return {**binding, 'bytes': len(template), 'sha256': selection.digest(template)}


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


def _observe(config: dict, choice: str, values: dict, record: dict, manifest: dict, *,
             full_standalone: bool, owner_root: Path, held, planning: dict | None):
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
    data = renewal.data_mounts(owned)
    selection.require(mounts > 0 and selection.digest(selection.packed(data)) == record["data_sha256"])

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

    comparison = compatibility(model, manifest)
    edge = plan = None
    if planning is not None:
        selection.require(full_standalone and comparison["composition_matches_selected_product"])
    if full_standalone and comparison["composition_matches_selected_product"]:
        source = held.enter_context(renewal.hold_private_input(Path(config["compose_file"]), max_bytes=2*1024*1024))
        selection.require(selection.digest(source) == config["compose_sha256"])
        installed = data["edge"]["mounts"]
        before_model = selection.decode(source)
        binding = combined_edge_binding(before_model, installed, str(owner_root))
        selection.require(combined_edge_binding(model, installed, str(owner_root)) == binding)
        template = held.enter_context(renewal.hold_private_input(
            Path(binding["source"]), max_bytes=MAX_TEMPLATE_BYTES))
        edge = edge_template_identity(binding, template)
        if planning is not None:
            from selfhost_windows_website_plan import from_observation
            plan = from_observation(before_model, manifest, docker=docker,
                edge_template=template, data_before=data, **planning)

    after = [item for item in docker.containers() if renewal._project(item) == config["project"]]
    selection.require(_identity(after, config["project"]) == identity)
    renewal.checked_live_configuration(after, hashes, config["tls_init_receipt"])
    return model, {**comparison, "configured_roles": len(model["services"]), "installed_roles": len(roles),
                   "selected_configuration_verified": True, "installed_image_bytes_verified": True,
                   "selected_secret_mounts_verified": True, "recorded_data_mounts_verified": True,
                   "historical_tls_initializer_preserved": True}, edge, plan


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


def _hold_plan_proofs(assets, held):
    names = product_journal.ARTIFACTS
    held.enter_context(renewal.hold_storage_namespace(assets))
    held.enter_context(_held_private_input(assets, directory=True))
    def check_inventory():
        selection.require({path.name for path in assets.iterdir()} == names)
    check_inventory()
    held.callback(check_inventory)
    return {name: selection.digest(held.enter_context(renewal.hold_private_input(assets / name,
                max_bytes=256*1024*1024 if name == "web-composition.zip" else 4*1024*1024)))
            for name in sorted(names)}


def inspect_composition(config: dict, choice: str, values: dict, record: dict, assets: Path, *,
                        gh: Path, cosign: Path, registry_config: Path | None,
                        owner_root: Path, held, plan_owner=None, plan_attempt_directory=None) -> dict:
    """Called only by the active selected-input callback under its project lock."""
    assets = Path(assets).absolute()
    selection.require((plan_owner is None) == (plan_attempt_directory is None))
    proof_hashes = _hold_plan_proofs(assets, held) if plan_owner is not None else None
    with composition.verified_package(assets, gh=Path(gh).absolute(), cosign=Path(cosign).absolute(),
                                      registry_config=registry_config) as (manifest, payload):
        release = web.read(payload / "website" / "website-release.json") if manifest["production_pages"] == "full" else None
        full_standalone = release is not None and release["schema"] == web.STANDALONE_FULL_RELEASE_SCHEMA
        planning = None
        if plan_owner is not None:
            selection.require(full_standalone)
            planning = {"anchor": plan_owner, "attempt_directory": plan_attempt_directory,
                        "proof_sha256": proof_hashes, "website_release": release,
                        "routes": web.read(payload / "website" / "web-surface-routes.json")}
        model, observed, edge, plan = _observe(config, choice, values, record, manifest,
            full_standalone=full_standalone, owner_root=owner_root, held=held, planning=planning)
        edge_summary = {name: edge[name] for name in ("sha256", "bytes", "runtime_mount_sha256")} if edge else None
        plan_summary = {name: plan[name] for name in ("schema", "plan_sha256", "states", "proof_sha256")} if plan else None
        return {"schema": SCHEMA, "inspection_completed": True, "project": config["project"],
                "compose_sha256": config["compose_sha256"],
                "resolved_configuration_sha256": selection.digest(selection.packed(model)),
                "selection_sequence": record["sequence"],
                "composition_id": manifest["composition_id"], "website_revision": manifest["website"]["revision"],
                "backend_release_tag": manifest["backend"]["release_tag"],
                "composition_authenticated": True, **observed,
                "native_custody_checked": False, "foreign_storage_custody_checked": False,
                "runtime_readiness_checked": False, "mounted_edge_template_checked": edge is not None,
                "combined_edge_template": edge_summary,
                "transition_plan": plan_summary,
                "public_ingress_checked": False, "activation_supported": False, "production_admission": False,
                "remaining_milestones": ["managed_website_transition_and_recovery",
                                         "edge_runtime_and_public_ingress_qualification"]}


def check(selection_file: Path, assets: Path, *, gh: Path, cosign: Path,
          registry_config: Path | None = None, plan_attempt_directory: Path | None = None) -> dict:
    with selection.selected_inputs(Path(selection_file).absolute()) as lease:
        result = lease.check_website_composition(assets, gh=gh, cosign=cosign,
            registry_config=registry_config, plan_attempt_directory=plan_attempt_directory)
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
    parser.add_argument("--plan-attempt-directory", type=Path)
    args = parser.parse_args(argv)
    try:
        result = check(args.selection_file, args.composition_dir, gh=args.gh, cosign=args.cosign,
                       registry_config=args.registry_config, plan_attempt_directory=args.plan_attempt_directory)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, RuntimeError, subprocess.SubprocessError):
        sys.stderr.write(ERROR + "\n")
        return 2
    sys.stdout.write(selection.packed(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
