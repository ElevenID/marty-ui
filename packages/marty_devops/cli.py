"""CLI for read-only Marty deployment catalog planning."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Sequence

from .catalog import DeploymentCatalog, DeploymentCatalogError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect Marty deployment metadata without executing deployment commands.")
    parser.add_argument("--repo-root", default="", help="Path to the marty-ui repository root.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate", help="Validate deployment catalogs, stacks, and bundle manifests.")

    plan_parser = subparsers.add_parser("plan", help="Render a redacted deployment plan for a stack.")
    plan_parser.add_argument("stack", help="Stack profile name, for example selfhost-production.")
    plan_parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")

    services_parser = subparsers.add_parser("services", help="List service metadata from a stack or group.")
    services_parser.add_argument("stack", nargs="?", help="Stack profile name.")
    services_parser.add_argument("--group", help="Service group name to list instead of a stack.")
    services_parser.add_argument("--running-only", action="store_true", help="Only include services with lifecycle=running when listing a stack.")
    services_parser.add_argument("--include-optional", action="store_true", help="Include stack optional services.")
    services_parser.add_argument(
        "--field",
        default="id",
        choices=["id", "compose_service", "k8s_deployment", "image_name", "service_name_env", "group", "lifecycle"],
        help="Service field to print.",
    )

    secrets_parser = subparsers.add_parser("secrets", help="List required secret metadata for a stack.")
    secrets_parser.add_argument("stack", help="Stack profile name.")
    secrets_parser.add_argument(
        "--field",
        default="id",
        choices=["id", "env", "file_env", "compose_secret", "no_log", "allow_empty", "required_for"],
        help="Secret field to print. Values are never resolved or printed.",
    )

    compose_parser = subparsers.add_parser("compose-command", help="Preview the docker compose command for a stack operation.")
    compose_parser.add_argument("stack", help="Stack profile name.")
    compose_parser.add_argument("operation", help="Operation name from the stack manifest, such as config, up, ps, or logs.")
    compose_parser.add_argument("--json", action="store_true", help="Emit JSON argv instead of shell-quoted text.")

    bundle_parser = subparsers.add_parser("bundle-assets", help="List resolved asset paths for a bundle manifest.")
    bundle_parser.add_argument("bundle", help="Bundle manifest name, for example selfhost.")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve() if args.repo_root else None
    try:
        catalog = DeploymentCatalog.load(repo_root)

        if args.command == "validate":
            print("Deployment catalog validation passed.")
            print(f"stacks={len(catalog.stacks)} services={len(catalog.services)} secrets={len(catalog.secrets)} bundles={len(catalog.bundles)}")
            return 0

        if args.command == "plan":
            plan = catalog.redacted_stack_plan(args.stack)
            if args.json:
                print(json.dumps(plan, indent=2, sort_keys=True))
            else:
                _print_plan(plan)
            return 0

        if args.command == "services":
            if args.group:
                service_ids = catalog.services_for_group(args.group)
            elif args.stack:
                service_ids = (
                    catalog.running_services_for_stack(args.stack, include_optional=args.include_optional)
                    if args.running_only
                    else catalog.expanded_services_for_stack(args.stack, include_optional=args.include_optional)
                )
            else:
                raise DeploymentCatalogError("services requires either a stack argument or --group.")

            for service_id in service_ids:
                print(catalog.service_field(service_id, args.field))
            return 0

        if args.command == "secrets":
            for secret_id in catalog.required_secrets_for_stack(args.stack):
                print(catalog.secret_field(secret_id, args.field))
            return 0

        if args.command == "compose-command":
            command = catalog.compose_command(args.stack, args.operation)
            if args.json:
                print(json.dumps(command, indent=2))
            else:
                print(_shell_join(command))
            return 0

        if args.command == "bundle-assets":
            for asset in catalog.bundle_assets(args.bundle):
                print(asset)
            return 0

    except DeploymentCatalogError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    parser.error(f"Unhandled command: {args.command}")
    return 2


def _print_plan(plan: dict[str, object]) -> None:
    print(f"Stack: {plan['name']}")
    if plan.get("description"):
        print(f"Description: {plan['description']}")
    print(f"Env file: {plan['env_file']}")
    print("Compose files: " + ", ".join(plan.get("compose_files", [])))
    profiles = plan.get("compose_profiles", [])
    print("Compose profiles: " + (", ".join(profiles) if profiles else "<none>"))
    print("Domains: " + ", ".join(plan.get("domains", [])))
    print(f"Artifact profile: {plan['artifact_profile']}")
    print("Deployment targets: " + ", ".join(plan.get("deployment_targets", [])))
    print("Required services:")
    for service_id in plan.get("required_services", []):
        print(f"  - {service_id}")
    print("Running services checked for health:")
    for service_id in plan.get("running_services", []):
        print(f"  - {service_id}")
    print("Required secret names (values redacted):")
    for secret_id in plan.get("required_secret_names", []):
        print(f"  - {secret_id}")


def _shell_join(command: Sequence[str]) -> str:
    if sys.platform.startswith("win"):
        return " ".join(_quote_for_powershell(part) for part in command)
    return shlex.join(command)


def _quote_for_powershell(value: str) -> str:
    if not value or any(char.isspace() for char in value):
        return "'" + value.replace("'", "''") + "'"
    return value


if __name__ == "__main__":
    raise SystemExit(main())
