#!/usr/bin/env python3
"""Reuse production runtime stages with separately compiled developer artifacts.

This renders recipes only. It neither builds images nor qualifies source/binaries.
The caller must supply local_binaries/local_assets build contexts and the exact
snapshot release/version arguments, then use the guarded prepared-image rollout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def render(root: Path) -> tuple[dict[str, str], dict[str, list[str]]]:
    services = (root / "services/Dockerfile").read_text(encoding="utf8")
    migrations = (root / "services/Dockerfile.migrations").read_text(encoding="utf8")
    ui = (root / "docker/ui.Dockerfile").read_text(encoding="utf8")
    service_marker = "\nFROM debian:bookworm-slim@"
    migration_marker = "\nFROM docker:29-cli@"
    ui_marker = "\nFROM nginx:"
    for source, marker in [(services, service_marker), (migrations, migration_marker), (ui, ui_marker)]:
        if source.count(marker) != 1:
            raise ValueError("Production runtime stage boundary is ambiguous")
    services = services[services.index(service_marker) + 1:]
    migrations = migrations[migrations.index(migration_marker) + 1:]
    ui = ui[ui.index(ui_marker) + 1:]
    selfhost = "\nFROM runtime-base AS selfhost\n"
    public = "\nFROM runtime-base AS public\n"
    if ui.count(selfhost) != 1 or ui.count(public) != 1:
        raise ValueError("Public UI runtime stage boundary is ambiguous")
    ui = ui[:ui.index(selfhost)] + ui[ui.index(public):]
    bins = {}
    for role, source, builder in [
        ("services", services, "rust-service-builder"),
        ("migrations", migrations, "rust-migration-builder"),
    ]:
        pattern = rf"COPY --from={builder} /build/rust/target/release/([a-z0-9-]+) (/usr/local/bin/[a-z0-9-]+)"
        matches = list(re.finditer(pattern, source))
        if not matches:
            raise ValueError("Production runtime has no recognized executable inputs")
        bins[role] = [match[1] for match in matches]
        for match in matches:
            if match[2] != "/usr/local/bin/" + match[1]:
                raise ValueError("Production runtime renames an executable")
        source = re.sub(pattern, r"COPY --chmod=755 --from=local_binaries /\1 \2", source)
        if role == "services":
            services = source
        else:
            migrations = source
    helper = (root / "scripts/build-rust-service-binaries.sh").read_text(encoding="utf8")
    if set(re.findall(r"--bin ([a-z0-9-]+)", helper)) != set(bins["services"]):
        raise ValueError("Shared service build and runtime executable inventories differ")
    original = "COPY --from=builder /workspace/marty-ui/ui/dist-final /usr/share/nginx/html"
    if ui.count(original) != 1:
        raise ValueError("Public UI asset input is ambiguous")
    ui = ui.replace(original, "COPY --from=local_assets / /usr/share/nginx/html")
    recipes = {"services": services, "migrations": migrations, "ui": ui}
    for source in recipes.values():
        if "--from=builder" in source or "--from=rust-" in source:
            raise ValueError("A compiler stage remains in a runtime recipe")
    return recipes, bins


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve()
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip()
    recipes, bins = render(root)
    args.output.mkdir(parents=True, exist_ok=True)
    files = {}
    for role, text in recipes.items():
        data = ("# syntax=docker/dockerfile:1.7\n" + text).encode()
        path = args.output / (role + ".runtime.Dockerfile")
        if path.exists() and path.read_bytes() != data:
            raise ValueError("Use a new output directory for changed runtime recipes")
        path.write_bytes(data)
        files[role] = {"path": str(path.resolve()), "sha256": hashlib.sha256(data).hexdigest()}
    print(json.dumps({"scope": "RUNTIME_RECIPES_ONLY", "sourceRevision": revision,
                      "dockerfiles": files, "binaries": bins, "imagesBuilt": False}))


if __name__ == "__main__":
    main()
