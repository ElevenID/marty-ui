"""Bundle pinned protocol schemas with document-local OpenAPI references."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import posixpath
import re
import subprocess
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "contracts/gateway-public-openapi-schemas.json"


def component_name(path: str) -> str:
    return path.removesuffix(".json").replace("/", "__").replace("-", "_")


def bundle_schemas(
    paths: list[str], read: Callable[[str], dict], revision: str
) -> dict:
    components: dict = {}
    pending = list(paths)
    seen: set[str] = set()

    def rewrite(value, source):
        if isinstance(value, list):
            return [rewrite(item, source) for item in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for field, item in value.items():
            if field in {"$id", "$schema"}:
                continue
            if field != "$ref":
                result[field] = rewrite(item, source)
                continue
            file, _, fragment = item.partition("#")
            target = (
                posixpath.normpath(posixpath.join(posixpath.dirname(source), file))
                if file
                else source
            )
            if not re.fullmatch(r"(?:schemas|enums)/[a-z0-9-]+\.json", target):
                raise ValueError(f"Unsupported schema reference: {source} -> {item}")
            if fragment and not fragment.startswith("/"):
                raise ValueError(f"Unsupported schema anchor: {source} -> {item}")
            pending.append(target)
            result[field] = f"#/components/schemas/{component_name(target)}{fragment}"
        return result

    while pending:
        source = pending.pop()
        if source in seen:
            continue
        if not re.fullmatch(r"(?:schemas|enums)/[a-z0-9-]+\.json", source):
            raise ValueError(f"Invalid schema source: {source}")
        seen.add(source)
        schema = rewrite(read(source), source)
        schema["x-marty-source-schema"] = source
        components[component_name(source)] = schema
    return {"protocol_revision": revision, "schemas": dict(sorted(components.items()))}


def generate(protocol_root: Path) -> dict:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    revision = re.search(r"MARTY_PROTOCOL_REF: ([0-9a-f]{40})", workflow).group(1)
    inventory = json.loads(
        (ROOT / "contracts/gateway-public-dto-shapes.json").read_text()
    )
    paths = [f"schemas/{model['schema']}" for model in inventory["models"]]
    paths.extend(
        f"schemas/{name}.json"
        for name in [
            "application-template",
            "compliance-profile",
            "deployment-profile",
            "revocation-profile",
            "wallet-profile",
            "notification-target",
            "notification-payload",
            "notification-delivery-result",
            "delivery-destination-profile",
        ]
    )

    def read(source):
        completed = subprocess.run(
            ["git", "-C", str(protocol_root), "show", f"{revision}:{source}"],
            capture_output=True,
            check=True,
            text=True,
            encoding="utf-8",
        )
        return json.loads(completed.stdout)

    return bundle_schemas(paths, read, revision)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-root", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = (
        json.dumps(generate(args.protocol_root.resolve()), indent=2, sort_keys=True)
        + "\n"
    )
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            raise SystemExit(
                "Public OpenAPI schema bundle is stale; regenerate from the pinned protocol revision"
            )
        print("Public OpenAPI schema bundle matches the pinned protocol revision.")
    else:
        OUTPUT.write_text(expected, encoding="utf-8")
        print("Generated public OpenAPI schema bundle.")


if __name__ == "__main__":
    main()
