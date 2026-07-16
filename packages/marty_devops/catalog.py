"""Manifest-driven deployment catalog for Marty DevOps workflows.

The catalog is intentionally read-only for this first implementation slice. It
centralizes service, secret, artifact, stack, and bundle metadata
so Make targets and deployment scripts can gradually stop duplicating those
facts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class DeploymentCatalogError(RuntimeError):
    """Raised when deployment metadata is missing or internally inconsistent."""


@dataclass(frozen=True)
class DeploymentCatalog:
    """Loaded deployment metadata rooted at the marty-ui repository."""

    repo_root: Path
    services: dict[str, Any]
    service_groups: dict[str, list[str]]
    secrets: dict[str, Any]
    artifacts: dict[str, Any]
    stacks: dict[str, Any]
    bundles: dict[str, Any]

    @classmethod
    def load(cls, repo_root: Path | str | None = None) -> "DeploymentCatalog":
        root = Path(repo_root).resolve() if repo_root is not None else _default_repo_root()
        catalog_dir = root / "deploy-config" / "catalog"
        stacks_dir = root / "deploy-config" / "stacks"
        bundles_dir = root / "deploy-config" / "bundles"

        services_payload = _read_json(catalog_dir / "services.json")
        secrets_payload = _read_json(catalog_dir / "secrets.json")
        artifacts_payload = _read_json(catalog_dir / "artifacts.json")

        stacks = _read_named_documents(stacks_dir)
        bundles = _read_named_documents(bundles_dir)

        catalog = cls(
            repo_root=root,
            services=dict(services_payload.get("services", {})),
            service_groups={
                name: list(values)
                for name, values in dict(services_payload.get("groups", {})).items()
            },
            secrets=dict(secrets_payload.get("secrets", {})),
            artifacts=dict(artifacts_payload.get("artifacts", {})),
            stacks=stacks,
            bundles=bundles,
        )
        catalog.validate()
        return catalog

    def validate(self) -> None:
        """Validate references across all deployment metadata files."""

        errors: list[str] = []

        for group_name, service_ids in self.service_groups.items():
            for service_id in service_ids:
                if service_id not in self.services:
                    errors.append(f"service group {group_name!r} references unknown service {service_id!r}")

        for service_id, service in self.services.items():
            group = service.get("group")
            if group and group not in self.service_groups:
                errors.append(f"service {service_id!r} references unknown group {group!r}")

        for secret_id, secret in self.secrets.items():
            for stack_name in secret.get("required_for", []):
                if stack_name not in self.stacks:
                    errors.append(f"secret {secret_id!r} references unknown required_for stack {stack_name!r}")

        for stack_name, stack in self.stacks.items():
            for compose_file in stack.get("compose_files", []):
                if not (self.repo_root / compose_file).exists():
                    errors.append(f"stack {stack_name!r} references missing compose file {compose_file!r}")

            for group_name in stack.get("required_service_groups", []):
                if group_name not in self.service_groups:
                    errors.append(f"stack {stack_name!r} references unknown service group {group_name!r}")

            for service_id in stack.get("required_services", []):
                if service_id not in self.services:
                    errors.append(f"stack {stack_name!r} references unknown service {service_id!r}")

            for service_id in stack.get("optional_services", []):
                if service_id not in self.services:
                    errors.append(f"stack {stack_name!r} references unknown optional service {service_id!r}")

            for secret_id in stack.get("required_secrets", []):
                if secret_id not in self.secrets:
                    errors.append(f"stack {stack_name!r} references unknown secret {secret_id!r}")

            artifact_profile = stack.get("artifact_profile")
            if artifact_profile not in self.artifacts:
                errors.append(f"stack {stack_name!r} references unknown artifact profile {artifact_profile!r}")

            parent_stack = stack.get("parent_stack")
            if parent_stack and parent_stack not in self.stacks:
                errors.append(f"stack {stack_name!r} references unknown parent stack {parent_stack!r}")

        for bundle_name, bundle in self.bundles.items():
            stack_name = bundle.get("stack")
            if stack_name not in self.stacks:
                errors.append(f"bundle {bundle_name!r} references unknown stack {stack_name!r}")

            artifact_profile = bundle.get("artifact_profile")
            if artifact_profile not in self.artifacts:
                errors.append(f"bundle {bundle_name!r} references unknown artifact profile {artifact_profile!r}")

            for asset in bundle.get("assets", []):
                if not (self.repo_root / asset).exists():
                    errors.append(f"bundle {bundle_name!r} references missing asset {asset!r}")

        if errors:
            joined = "\n".join(f"- {error}" for error in errors)
            raise DeploymentCatalogError(f"Deployment catalog validation failed:\n{joined}")

    def stack(self, name: str) -> dict[str, Any]:
        try:
            return self.stacks[name]
        except KeyError as exc:
            raise DeploymentCatalogError(f"Unknown stack: {name}") from exc

    def bundle(self, name: str) -> dict[str, Any]:
        try:
            return self.bundles[name]
        except KeyError as exc:
            raise DeploymentCatalogError(f"Unknown bundle: {name}") from exc

    def expanded_services_for_stack(self, stack_name: str, *, include_optional: bool = False) -> list[str]:
        stack = self.stack(stack_name)
        ordered: list[str] = []
        for group_name in stack.get("required_service_groups", []):
            ordered.extend(self.service_groups.get(group_name, []))
        ordered.extend(stack.get("required_services", []))
        optional_services = set(stack.get("optional_services", []))
        return _dedupe(
            service_id
            for service_id in ordered
            if include_optional or service_id not in optional_services
        )

    def services_for_group(self, group_name: str) -> list[str]:
        try:
            return list(self.service_groups[group_name])
        except KeyError as exc:
            raise DeploymentCatalogError(f"Unknown service group: {group_name}") from exc

    def running_services_for_stack(self, stack_name: str, *, include_optional: bool = False) -> list[str]:
        return [
            service_id
            for service_id in self.expanded_services_for_stack(stack_name, include_optional=include_optional)
            if self.services[service_id].get("lifecycle", "running") == "running"
        ]

    def service_field(self, service_id: str, field: str) -> str:
        try:
            service = self.services[service_id]
        except KeyError as exc:
            raise DeploymentCatalogError(f"Unknown service: {service_id}") from exc

        if field == "id":
            return service_id

        value = service.get(field)
        if value is None:
            return ""
        return str(value)

    def secret(self, secret_id: str) -> dict[str, Any]:
        try:
            return self.secrets[secret_id]
        except KeyError as exc:
            raise DeploymentCatalogError(f"Unknown secret: {secret_id}") from exc

    def required_secrets_for_stack(self, stack_name: str) -> list[str]:
        stack = self.stack(stack_name)
        direct = list(stack.get("required_secrets", []))
        schema_required = [
            secret_id
            for secret_id, secret in self.secrets.items()
            if stack_name in secret.get("required_for", [])
        ]
        return _dedupe([*direct, *schema_required])

    def required_secret_specs_for_stack(self, stack_name: str) -> list[dict[str, Any]]:
        return [
            {"id": secret_id, **self.secret(secret_id)}
            for secret_id in self.required_secrets_for_stack(stack_name)
        ]

    def secret_file_name(self, secret_id: str) -> str:
        secret = self.secret(secret_id)
        return str(secret.get("compose_secret") or secret_id)

    def secret_field(self, secret_id: str, field: str) -> str:
        if field == "id":
            return secret_id

        value = self.secret(secret_id).get(field)
        if isinstance(value, list):
            return ",".join(str(item) for item in value)
        if value is None:
            return ""
        return str(value)

    def compose_command(self, stack_name: str, operation: str) -> list[str]:
        stack = self.stack(stack_name)
        operations = stack.get("operations", {})
        if operation not in operations:
            available = ", ".join(sorted(operations)) or "<none>"
            raise DeploymentCatalogError(
                f"Stack {stack_name!r} does not define operation {operation!r}; available: {available}"
            )

        command = ["docker", "compose", "--env-file", stack["env_file"]]
        for compose_file in stack.get("compose_files", []):
            command.extend(["-f", compose_file])
        for profile in stack.get("compose_profiles", []):
            command.extend(["--profile", profile])
        command.extend(operations[operation])
        return command

    def redacted_stack_plan(self, stack_name: str) -> dict[str, Any]:
        stack = self.stack(stack_name)
        artifact_profile = stack.get("artifact_profile")
        return {
            "name": stack_name,
            "description": stack.get("description", ""),
            "env_file": stack.get("env_file"),
            "compose_files": list(stack.get("compose_files", [])),
            "compose_profiles": list(stack.get("compose_profiles", [])),
            "domains": list(stack.get("domains", [])),
            "required_services": self.expanded_services_for_stack(stack_name),
            "running_services": self.running_services_for_stack(stack_name),
            "required_secret_names": self.required_secrets_for_stack(stack_name),
            "artifact_profile": artifact_profile,
            "deployment_targets": list(stack.get("deployment_targets", [])),
        }

    def bundle_assets(self, bundle_name: str) -> list[Path]:
        bundle = self.bundle(bundle_name)
        return [self.repo_root / asset for asset in bundle.get("assets", [])]


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise DeploymentCatalogError(f"Missing deployment metadata file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DeploymentCatalogError(f"Invalid JSON in deployment metadata file: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise DeploymentCatalogError(f"Deployment metadata file must contain a JSON object: {path}")
    return payload


def _read_named_documents(directory: Path) -> dict[str, Any]:
    documents: dict[str, Any] = {}
    if not directory.exists():
        raise DeploymentCatalogError(f"Missing deployment metadata directory: {directory}")
    for path in sorted(directory.glob("*.json")):
        payload = _read_json(path)
        name = payload.get("name") or path.stem
        if not isinstance(name, str) or not name.strip():
            raise DeploymentCatalogError(f"Deployment metadata document {path} has no valid name")
        documents[name] = payload
    return documents


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        ordered.append(value)
        seen.add(value)
    return ordered
