#!/usr/bin/env python3
"""Point pinned Marty Core workspace dependencies at a copied local checkout."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path


CORE_REPOSITORY = "https://github.com/ElevenID/marty-core.git"
CORE_CRATES = {
    "marty-crypto": "marty-crypto",
    "marty-verification": "marty-verification",
    "marty-secure-storage": "marty-secure-storage",
    "marty-oid4vci": "marty-oid4vci",
}


def _render_local_dependency(specification: dict, local_path: str) -> str:
    fields = [f"path = {json.dumps(local_path)}"]
    for key in ("features", "default-features", "optional"):
        if key in specification:
            toml_key = key
            value = specification[key]
            if isinstance(value, list):
                rendered = "[" + ", ".join(json.dumps(item) for item in value) + "]"
            elif isinstance(value, bool):
                rendered = str(value).lower()
            else:
                raise ValueError(f"Unsupported {key} value for local dependency")
            fields.append(f"{toml_key} = {rendered}")
    return "{ " + ", ".join(fields) + " }"


def localize_manifest(manifest_path: Path, core_root: str) -> list[str]:
    original = manifest_path.read_text(encoding="utf-8")
    parsed = tomllib.loads(original)
    dependencies = parsed.get("workspace", {}).get("dependencies", {})
    localized: list[str] = []
    rewritten = original

    for crate, directory in CORE_CRATES.items():
        specification = dependencies.get(crate)
        if specification is None:
            continue
        if not isinstance(specification, dict) or specification.get("git") != CORE_REPOSITORY:
            raise ValueError(f"{crate} must be pinned to {CORE_REPOSITORY} before localization")
        local_path = f"{core_root.rstrip('/')}/{directory}"
        replacement = f"{crate} = {_render_local_dependency(specification, local_path)}"
        pattern = re.compile(rf"(?m)^{re.escape(crate)}\s*=\s*\{{[^\r\n]*\}}\s*$")
        rewritten, count = pattern.subn(replacement, rewritten)
        if count != 1:
            raise ValueError(f"Expected exactly one workspace dependency entry for {crate}, found {count}")
        localized.append(crate)

    if not localized:
        raise ValueError("No Marty Core workspace dependencies were found")
    verified = tomllib.loads(rewritten)
    verified_dependencies = verified["workspace"]["dependencies"]
    for crate in localized:
        if "git" in verified_dependencies[crate] or "path" not in verified_dependencies[crate]:
            raise ValueError(f"Failed to localize {crate}")
    manifest_path.write_text(rewritten, encoding="utf-8")
    return localized


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--core-root", default="../marty-core")
    args = parser.parse_args()
    localized = localize_manifest(args.manifest, args.core_root)
    print("Localized Marty Core dependencies: " + ", ".join(localized))


if __name__ == "__main__":
    main()
