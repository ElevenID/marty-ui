#!/usr/bin/env python3
"""Resolve independent product build inputs without installing either product."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

PRODUCTS = {
    "marty-server": ("server-v", {"services", "migrations", "openbao-didcomm", "keycloak"}),
    "marty-console": ("console-v", {"ui"}),
}
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
SHA = re.compile(r"[0-9a-f]{40}")


SERVER_RUNTIME_FILES = ('docker/nginx-selfhost.prod.conf.template',
 'docker/init-databases.sh',
 'scripts/nginx-entrypoint-selfhost.sh',
 'scripts/load-openbao-token-and-start.sh',
 'scripts/load-secrets-env.sh',
 'scripts/keycloak-selfhost-start.sh',
 'scripts/setup-keycloak.sh',
 'scripts/setup-keycloak-selfhost-production.sh',
 'config/keycloak/11id-realm.json',
 'config/keycloak/themes/11id/email/html/template.ftl',
 'config/keycloak/themes/11id/email/theme.properties',
 'config/keycloak/themes/11id/login/auth-options.ftl',
 'config/keycloak/themes/11id/login/error.ftl',
 'config/keycloak/themes/11id/login/login-update-password.ftl',
 'config/keycloak/themes/11id/login/login-username.ftl',
 'config/keycloak/themes/11id/login/login.ftl',
 'config/keycloak/themes/11id/login/messages/messages_de.properties',
 'config/keycloak/themes/11id/login/messages/messages_en.properties',
 'config/keycloak/themes/11id/login/messages/messages_es.properties',
 'config/keycloak/themes/11id/login/messages/messages_fr.properties',
 'config/keycloak/themes/11id/login/messages/messages_ja.properties',
 'config/keycloak/themes/11id/login/messages/messages_nl.properties',
 'config/keycloak/themes/11id/login/register.ftl',
 'config/keycloak/themes/11id/login/resources/css/marty.css',
 'config/keycloak/themes/11id/login/resources/img/favicon.ico',
 'config/keycloak/themes/11id/login/template.ftl',
 'config/keycloak/themes/11id/login/theme.properties')
SERVER_RUNTIME_MOUNTS = {'edge': {'/etc/nginx/conf.d/default.conf.template': 'docker/nginx-selfhost.prod.conf.template',
          '/docker-entrypoint.d/40-render-selfhost.sh': 'scripts/nginx-entrypoint-selfhost.sh'},
 'postgres': {'/docker-entrypoint-initdb.d/init-databases.sh': 'docker/init-databases.sh'},
 'issuance': {'/app/load-openbao-token-and-start.sh': 'scripts/load-openbao-token-and-start.sh'},
 'issuance-migrations': {'/app/load-secrets-env.sh': 'scripts/load-secrets-env.sh'},
 'keycloak': {'/opt/keycloak/data/import': 'config/keycloak',
              '/opt/keycloak/themes': 'config/keycloak/themes',
              '/scripts/load-secrets-env.sh': 'scripts/load-secrets-env.sh',
              '/scripts/keycloak-selfhost-start.sh': 'scripts/keycloak-selfhost-start.sh'},
 'keycloak-configurator': {'/scripts/setup-keycloak.sh': 'scripts/setup-keycloak.sh',
                           '/scripts/setup-keycloak-selfhost-production.sh': 'scripts/setup-keycloak-selfhost-production.sh',
                           '/scripts/load-secrets-env.sh': 'scripts/load-secrets-env.sh'}}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source_file(root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and bool(relative), "source path is required")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(), "source path escapes or is missing")
    return path


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_payload(root: Path, relative: str) -> bytes:
    payload = source_file(root, relative).read_bytes()
    if relative.endswith(".sh"):
        payload = payload.replace(b"\r\n", b"\n")
    if relative == "config/keycloak/11id-realm.json":
        realm = json.loads(payload)
        # Production deployment supplies operator identities and client secrets.
        # Never distribute the development realm's seeded accounts/credentials.
        realm.pop("users", None)
        for client in realm.get("clients", []):
            client.pop("secret", None)
        payload = (json.dumps(realm, sort_keys=True, indent=2) + "\n").encode("utf-8")
    return payload


def runtime_inputs(root: Path, product: str) -> list[dict[str, str]]:
    return [{"path": name, "source_sha256": digest(source_file(root, name)),
             "sha256": "sha256:" + hashlib.sha256(runtime_payload(root, name)).hexdigest()}
            for name in SERVER_RUNTIME_FILES] if product == "marty-server" else []


def console_dependencies(root: Path) -> tuple[dict[str, str], str]:
    lock_path = source_file(root, "release/stack-lock.json")
    lock = json.loads(lock_path.read_bytes())
    require(lock.get("schema") == "marty.stack-lock/v1", "console dependency lock schema changed")
    args = {}
    for name, prefix in [("marty-api-core", "MARTY_API_CORE"), ("marty-blog", "MARTY_BLOG")]:
        selected = [item for item in lock["components"] if item.get("name") == name]
        require(len(selected) == 1, "console dependency is missing or duplicated")
        component = selected[0]
        artifacts = [item for item in component["artifacts"] if item.get("type") == "npm"]
        require(len(artifacts) == 1, "console dependency must have one npm artifact")
        artifact = artifacts[0]
        require(VERSION.fullmatch(component["version"]) is not None, "console dependency version is invalid")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]) is not None, "console dependency digest is invalid")
        repository = "ElevenID/marty-cli" if name == "marty-api-core" else "ElevenID/marty-blog"
        expected = f"https://github.com/{repository}/releases/download/v{component['version']}/elevenid-{name}-{component['version']}.tgz"
        require(component["repository"] == repository and artifact["uri"] == expected, "console dependency identity changed")
        args.update({prefix + "_VERSION": component["version"], prefix + "_URI": artifact["uri"], prefix + "_DIGEST": artifact["digest"]})
    return args, digest(lock_path)


def build_plan(root: Path, product: str, source_sha: str) -> dict:
    require(product in PRODUCTS, "unknown product")
    require(isinstance(source_sha, str) and SHA.fullmatch(source_sha) is not None, "source SHA is invalid")
    catalog_path = source_file(root, "release/product-packages.json")
    catalog = json.loads(catalog_path.read_bytes())
    require(set(catalog) == {"schema", "products"} and catalog["schema"] == "marty.product-packages/v1", "package catalog schema changed")
    require(set(catalog["products"]) == set(PRODUCTS), "package catalog products changed")
    spec = catalog["products"][product]
    require(set(spec) == {"version", "tag_prefix", "image_namespace", "api", "images"}, "product fields changed")
    prefix, roles = PRODUCTS[product]
    require(spec["tag_prefix"] == prefix, "product tag namespace changed")
    require(spec["image_namespace"] == "ghcr.io/elevenid/" + product, "product image namespace changed")
    require(set(spec["images"]) == roles, "product image roles changed")
    require(spec["api"] == {"http": "v1", "mip": "0.5.0"}, "declared API contract changed")
    version_source = spec["version"]
    require(set(version_source) == {"path", "json_field"}, "version source fields changed")
    expected_source = ({"path": "release/server-version.txt", "json_field": None} if product == "marty-server"
                       else {"path": "release/console-version.txt", "json_field": None})
    require(version_source == expected_source, "product version source changed")
    version_path = source_file(root, version_source["path"])
    version = (json.loads(version_path.read_bytes())[version_source["json_field"]]
               if version_source["json_field"] else version_path.read_text(encoding="utf-8").strip())
    require(isinstance(version, str) and VERSION.fullmatch(version) is not None, "product version is invalid")
    build_args = {"MARTY_RELEASE_VERSION": version, "MARTY_UI_SHA": source_sha}
    dependency_lock_sha256 = None
    if product == "marty-console":
        dependencies, dependency_lock_sha256 = console_dependencies(root)
        build_args.update(dependencies)
        build_args.update(UI_VARIANT="selfhost", NGINX_CONFIG="nginx.spa.conf", SELFHOST_PUBLIC_PROFILE="full")
    images = []
    for role, image in sorted(spec["images"].items()):
        require(set(image) == {"dockerfile", "target"}, "image fields changed")
        require(isinstance(image["target"], str) and re.fullmatch(r"[a-z0-9-]*", image["target"]) is not None, "build target is invalid")
        dockerfile = source_file(root, image["dockerfile"])
        images.append({
            "role": role, "context": ".", "dockerfile": image["dockerfile"],
            "dockerfile_sha256": digest(dockerfile), "target": image["target"],
            "image": spec["image_namespace"] + "/" + role,
            "version_tag": version, "platform": "linux/amd64",
            "build_args": build_args,
        })
    return {
        "schema": "marty.product-build-plan/v1", "product": product,
        "version": version, "tag": prefix + version,
        "repository": "ElevenID/marty-ui", "source_sha": source_sha,
        "version_source": version_source, "version_source_sha256": digest(version_path),
        "catalog_sha256": digest(catalog_path), "api": spec["api"],
        "dependency_lock_sha256": dependency_lock_sha256,
        "qualification": "unqualified", "images": images, "runtime_files": runtime_inputs(root, product),
    }


def assemble_package(root: Path, plan: dict, images_dir: Path, run_id: str, attempt: str) -> dict:
    """Bind this producer attempt's complete role set; do not qualify payloads."""
    require(isinstance(plan, dict), "build plan must be an object")
    require(plan == build_plan(root, plan.get("product"), plan.get("source_sha")), "frozen build plan differs from source")
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None, "producer run ID is invalid")
    require(re.fullmatch(r"[1-9][0-9]*", attempt) is not None, "producer attempt is invalid")
    expected = {image["role"] + ".json" for image in plan["images"]}
    entries = list(images_dir.iterdir())
    require({path.name for path in entries} == expected, "producer image receipts are incomplete or unexpected")
    require(all(path.is_file() and not path.is_symlink() for path in entries), "producer receipt must be a regular file")
    images = []
    for image in plan["images"]:
        path = images_dir / (image["role"] + ".json")
        require(path.stat().st_size <= 65536, "producer receipt is too large")
        receipt = json.loads(path.read_bytes())
        identity = {
            "product": plan["product"], "version": plan["version"], "source_sha": plan["source_sha"],
            "role": image["role"], "image": image["image"], "run_id": run_id, "run_attempt": attempt,
        }
        require(set(receipt) == set(identity) | {"digest"}, "producer receipt fields changed")
        require(all(receipt[key] == value for key, value in identity.items()), "producer receipt identity differs")
        require(isinstance(receipt["digest"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["digest"]) is not None, "producer image digest is invalid")
        images.append({"role": image["role"], "uri": image["image"], "digest": receipt["digest"], "platform": image["platform"]})
    canonical_plan = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": "marty.product-package/v1", "product": plan["product"], "version": plan["version"],
        "tag": plan["tag"], "source": {"repository": plan["repository"], "commit": plan["source_sha"]},
        "api": plan["api"], "platforms": ["linux/amd64"], "images": images,
        "build_plan_sha256": "sha256:" + hashlib.sha256(canonical_plan).hexdigest(),
        "producer": {"workflow": ".github/workflows/product-packages.yml", "run_id": run_id, "run_attempt": attempt},
        "support_state": "experimental", "qualification": "unqualified",
    }


def write_bundle(root: Path, plan: dict, package: dict, output: Path) -> None:
    """Ship the renderer and its stdlib-only module without a source checkout."""
    require(not output.exists() and not output.is_symlink(), "package bundle directory must be new")
    files = {
        name: source_file(root, name).read_bytes() for name in (
            "scripts/compose_product_packages.py", "scripts/product_package_plan.py",
            "deploy-config/schemas/product-package.schema.json", "docs/INDEPENDENT_PRODUCT_PACKAGES.md", "LICENSE",
        )
    }
    require(plan["runtime_files"] == runtime_inputs(root, package["product"]), "runtime source inputs changed")
    for item in plan["runtime_files"]:
        files["runtime/" + item["path"]] = runtime_payload(root, item["path"])
    if package["product"] == "marty-console":
        files["docker-compose.console.yml"] = source_file(root, "docker-compose.console.yml").read_bytes()
    for name, value in [("build-plan.json", plan), ("product-package.json", package)]:
        files[name] = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    arguments = ("--base resolved-server-base.json --runtime-dir runtime --output server.compose.json" if package["product"] == "marty-server"
                 else "--server-origin https://api.example.com --output console.compose.json")
    readme = (
        f"# {package['product']} {package['version']} candidate\n\n"
        "This producer candidate is experimental and unqualified. Independent release verification is separate.\n\n"
        f"Source revision: https://github.com/{plan['repository']}/tree/{plan['source_sha']}\n\n"
        "Extract the canonical product-package.tar.gz before using runtime files; its Unix shell modes survive workflow artifact ZIP transport. The adjacent .sha256 file covers the archive, and SHA256SUMS inside covers its files.\n\n"
        "The optional renderer requires Python 3.11+ with only its standard library; no repository checkout, UI build or npm installation is needed. "
        "It writes Compose JSON without installing software, starting containers or preparing secrets. The deployment owner supplies the normalized server runtime layout, state/secrets and external image pins. Server container configuration and entrypoint assets are included under runtime/; --runtime-dir explicitly binds those packaged assets instead of checkout paths.\n\n"
        f"```sh\npython scripts/compose_product_packages.py --package product-package.json {arguments}\n```\n\n"
        "The image references are immutable digests. A build receipt or successful render does not establish payload, deployment or product compatibility qualification. "
        "See docs/INDEPENDENT_PRODUCT_PACKAGES.md for the source contracts and limits.\n"
    )
    files["README.md"] = readme.encode("utf-8")
    output.mkdir(parents=True)
    for name, payload in sorted(files.items()):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o755 if path.suffix == ".sh" else 0o644)
    inventory = "".join(hashlib.sha256(payload).hexdigest() + "  " + name + "\n" for name, payload in sorted(files.items()))
    (output / "SHA256SUMS").write_text(inventory, encoding="utf-8", newline="\n")


def write_archive(bundle: Path, output: Path) -> None:
    """Preserve Unix runtime modes through workflow artifact ZIP transport."""
    checksum = output.with_name(output.name + ".sha256")
    require(not output.resolve().is_relative_to(bundle.resolve()), "archive must be outside the bundle")
    require(all(not p.exists() and not p.is_symlink() for p in (output, checksum)), "archive outputs must be new")
    paths = sorted(bundle.rglob("*"))
    require(all(not p.is_symlink() and p.resolve().is_relative_to(bundle.resolve())
                and (p.is_file() or p.is_dir()) for p in paths), "bundle contains an unsupported path")
    with (
        output.open("xb") as raw,
        gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped,
        tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for path in paths:
            info = tarfile.TarInfo(path.relative_to(bundle).as_posix())
            if path.is_dir():
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            else:
                payload = path.read_bytes()
                info.size = len(payload)
                info.mode = 0o755 if path.suffix == ".sh" else 0o644
                archive.addfile(info, io.BytesIO(payload))
    with checksum.open("x", encoding="utf-8", newline="\n") as inventory:
        inventory.write(hashlib.sha256(output.read_bytes()).hexdigest() + "  " + output.name + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", choices=PRODUCTS, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--input-plan", type=Path)
    parser.add_argument("--images-dir", type=Path)
    parser.add_argument("--build-run-id")
    parser.add_argument("--build-run-attempt")
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--archive-output", type=Path)
    args = parser.parse_args()
    require(args.archive_output is None or args.bundle_dir is not None, "archive requires a package bundle")
    plan = build_plan(args.root, args.product, args.source_sha)
    assembly = (args.input_plan, args.images_dir, args.build_run_id, args.build_run_attempt)
    if any(value is not None for value in assembly):
        require(all(value is not None for value in assembly), "all package assembly arguments are required")
        frozen = json.loads(args.input_plan.read_bytes())
        require(frozen == plan, "input plan differs from selected source/product")
        plan = assemble_package(args.root, frozen, args.images_dir, args.build_run_id, args.build_run_attempt)
    if args.bundle_dir is not None:
        require(all(value is not None for value in assembly), "bundle requires complete producer assembly inputs")
        require(args.output.resolve() == (args.bundle_dir / "product-package.json").resolve(), "bundle output must name its product-package.json")
        write_bundle(args.root, frozen, plan, args.bundle_dir)
        if args.archive_output is not None:
            write_archive(args.bundle_dir, args.archive_output)
        return
    args.output.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
