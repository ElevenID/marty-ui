"""Read-only test adapter for the Rust deployment catalog CLI."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


class CatalogView:
    def __init__(self, root: Path):
        self.root = root
        config = root / "deploy-config"
        self.services = json.loads((config / "catalog/services.json").read_text(encoding="utf-8"))["services"]
        self.service_groups = json.loads((config / "catalog/services.json").read_text(encoding="utf-8"))["groups"]
        self.secrets = json.loads((config / "catalog/secrets.json").read_text(encoding="utf-8"))["secrets"]
        self.artifacts = json.loads((config / "catalog/artifacts.json").read_text(encoding="utf-8"))["artifacts"]
        self.stacks = {document["name"]: document for path in (config / "stacks").glob("*.json") if (document := json.loads(path.read_text(encoding="utf-8")))}
        self.bundles = {document["name"]: document for path in (config / "bundles").glob("*.json") if (document := json.loads(path.read_text(encoding="utf-8")))}

    @classmethod
    def load(cls, root: Path) -> "CatalogView":
        return cls(root)

    def lines(self, *args: str) -> list[str]:
        result = subprocess.run(
            ["cargo", "+1.95.0", "run", "--quiet", "--locked", "--manifest-path", str(self.root / "rust/Cargo.toml"),
             "-p", "marty-deployment-catalog", "--bin", "marty-deploy", "--", "--repo-root", str(self.root), *args],
            check=True, capture_output=True, text=True, cwd=self.root,
        )
        return result.stdout.splitlines()

    def stack(self, name: str) -> dict:
        return self.stacks[name]

    def secret(self, name: str) -> dict:
        return self.secrets[name]

    def running_services_for_stack(self, name: str) -> list[str]:
        return self.lines("services", name, "--running-only")

    def services_for_group(self, name: str) -> list[str]:
        return self.lines("services", "--group", name)

    def service_field(self, name: str, field: str) -> str:
        return self.services[name].get(field, "")

    def required_secrets_for_stack(self, name: str) -> list[str]:
        return self.lines("secrets", name)
