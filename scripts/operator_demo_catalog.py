"""Read the frozen operator demo template without depending on website assets.

The historical manifest retains its original public URLs and publication state.
This catalog verifies operator input bytes; it does not qualify the website's
historical images, a deployment, or recorded demonstrations.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

if __package__:
    from .validate_demo_manifests import validate_manifest
else:
    from validate_demo_manifests import validate_manifest


ROOT = Path(__file__).resolve().parents[1]
CATALOG_DIRECTORY = Path("deploy-config/catalog/operator-demos")
CATALOG_SHA256 = "6c986c85929fcdf586ba37607c319ee3868ca87a100f7f0f7f921b52abd6f0d0"
DEMO_TEMPLATE_PATHS = (
    "deploy-config/catalog/operator-demos/2026.08.0.json",
    "ui/public/demos/manifests/2026.08.0.json",
)
OPERATOR_TEMPLATE_SHA256 = "3859324f5f2fb13dae158b8ff95c1e2261ae69c5ce2ce8806a2e4048e16ca494"


@dataclass(frozen=True)
class OperatorDemoCatalog:
    metadata: dict[str, Any]
    manifest: dict[str, Any]
    template_path: Path
    poster_path: Path


@dataclass(frozen=True)
class ProductDemoTemplate:
    manifest: dict[str, Any]
    template_path: Path
    template_sha256: str
    source_revision: str
    source_path: str


def _require(condition: object, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _require_revision(revision: str) -> None:
    _require(
        isinstance(revision, str) and re.fullmatch(r"[a-f0-9]{40}", revision),
        "SOURCE_COMMIT_SHA_REQUIRED",
    )


def _source_git(repository: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repository), *arguments],
        capture_output=True,
        timeout=30,
        check=True,
    ).stdout


def git_blob(repository: Path, revision: str, filename: str) -> bytes:
    _require_revision(revision)
    content = _source_git(repository, "show", revision + ":" + filename)
    _require(len(content) <= 4 * 1024 * 1024, "SOURCE_BLOB_TOO_LARGE")
    return content


def source_demo_template_input(repository: Path, revision: str) -> tuple[str, bytes]:
    """Select a template from one immutable historical or current product commit.

    Only a successful tree lookup with no matching path permits the historical
    fallback. A missing commit, failed Git operation, unexpected entry or changed
    current snapshot must fail rather than substitute another source or checkout.
    """
    _require_revision(revision)
    _require(_source_git(repository, "cat-file", "-t", revision) == b"commit\n", "SOURCE_REVISION_NOT_COMMIT")
    for filename in DEMO_TEMPLATE_PATHS:
        entry = _source_git(repository, "ls-tree", "--full-tree", "-z", revision, "--", filename)
        if not entry:
            continue
        _require(
            re.fullmatch(rb"100644 blob [a-f0-9]{40}\t" + re.escape(filename.encode()) + rb"\0", entry),
            "SOURCE_DEMO_TEMPLATE_ENTRY_INVALID",
        )
        content = git_blob(repository, revision, filename)
        if filename == DEMO_TEMPLATE_PATHS[0]:
            _require(
                hashlib.sha256(content).hexdigest() == OPERATOR_TEMPLATE_SHA256,
                "SOURCE_DEMO_TEMPLATE_DIGEST_CHANGED",
            )
        # Historical commits may contain an earlier valid edition. Their exact
        # Git-blob/reference equality and schema/binder validation remain intact;
        # the current snapshot cannot redefine a signed historical source input.
        return filename, content
    raise ValueError("SOURCE_DEMO_TEMPLATE_MISSING")


def source_demo_template(repository: Path, revision: str) -> bytes:
    return source_demo_template_input(repository, revision)[1]


def _read(root: Path, relative: Path) -> bytes:
    if relative.is_absolute() or any(part in {".", ".."} for part in relative.parts):
        raise ValueError("Invalid operator demo catalog path")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Operator demo catalog inputs cannot be symbolic links")
    if not current.is_file():
        raise ValueError(f"Operator demo catalog input is missing: {relative}")
    if current.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Operator demo catalog input exceeds its size bound")
    # Git checkouts on Windows may use CRLF; the retained Git blobs use LF.
    return current.read_bytes().replace(b"\r\n", b"\n")


def load_operator_demo_catalog(repository_root: Path = ROOT) -> OperatorDemoCatalog:
    root = repository_root.resolve()
    data = _read(root, CATALOG_DIRECTORY / "catalog.json")
    if hashlib.sha256(data).hexdigest() != CATALOG_SHA256:
        raise ValueError("Reviewed operator demo catalog digest changed")
    metadata = json.loads(data)
    inputs = {}
    for role in ("historical_manifest", "draft_poster"):
        record = metadata[role]
        content = _read(root, CATALOG_DIRECTORY / record["path"])
        if len(content) != record["bytes"] or hashlib.sha256(content).hexdigest() != record["sha256"]:
            raise ValueError(f"Operator demo {role} digest changed")
        inputs[role] = content
    manifest = json.loads(inputs["historical_manifest"])
    validate_manifest(manifest)
    if manifest["stack_version"] != metadata["default_stack_version"]:
        raise ValueError("Operator demo template stack version differs")
    return OperatorDemoCatalog(
        metadata=metadata,
        manifest=manifest,
        template_path=root / CATALOG_DIRECTORY / metadata["historical_manifest"]["path"],
        poster_path=root / CATALOG_DIRECTORY / metadata["draft_poster"]["path"],
    )


def load_operator_demo_template(stack_version: str, repository_root: Path = ROOT) -> dict[str, Any]:
    catalog = load_operator_demo_catalog(repository_root)
    if stack_version != catalog.metadata["default_stack_version"]:
        raise ValueError(f"No reviewed operator demo template for stack {stack_version}")
    return catalog.manifest


def load_product_demo_template(stack_version: str, product_root: Path, revision: str) -> ProductDemoTemplate:
    """Validate the selected checkout file against its exact product commit.

    The caller must also retain its full official-source or local-snapshot
    admission checks. A local snapshot's worktree-derived marker is not its Git
    revision; pass the recorded repository head_sha instead.
    """
    _require_revision(revision)
    root = product_root.resolve()
    actual_head = _source_git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    _require(actual_head == revision, "PRODUCT_CHECKOUT_REVISION_CHANGED")
    filename, content = source_demo_template_input(root, revision)
    _require(_read(root, Path(filename)) == content.replace(b"\r\n", b"\n"), "PRODUCT_DEMO_TEMPLATE_CHANGED")
    if filename == DEMO_TEMPLATE_PATHS[0]:
        load_operator_demo_catalog(root)
    manifest = json.loads(content)
    validate_manifest(manifest)
    _require(manifest["stack_version"] == stack_version, "PRODUCT_DEMO_STACK_VERSION_CHANGED")
    _require(
        manifest["binding_state"] == "PENDING_DEPLOYMENT"
        and manifest["release_ready"] is False and manifest["public_demo_ready"] is False,
        "PRODUCT_DEMO_TEMPLATE_NOT_PENDING",
    )
    return ProductDemoTemplate(
        manifest=manifest, template_path=root / filename,
        template_sha256=hashlib.sha256(content).hexdigest(),
        source_revision=revision, source_path=filename,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--product-root", type=Path)
    parser.add_argument("--product-revision")
    parser.add_argument("--stack-version", required=True)
    args = parser.parse_args()
    if (args.product_root is None) != (args.product_revision is None):
        parser.error("--product-root and --product-revision must be provided together")
    try:
        if args.product_root is not None:
            selected = load_product_demo_template(args.stack_version, args.product_root, args.product_revision)
            print(json.dumps({
                "status": "passed", "scope": "product-template", "stack_version": args.stack_version,
                "template_path": str(selected.template_path), "template_sha256": selected.template_sha256,
                "source": {"repository": "ElevenID/marty-ui", "commit": selected.source_revision},
                "source_path": selected.source_path, "website_assets_verified": False,
            }))
            return 0
        catalog = load_operator_demo_catalog(args.repository_root)
        if args.stack_version != catalog.metadata["default_stack_version"]:
            raise ValueError(f"No reviewed operator demo template for stack {args.stack_version}")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Operator demo catalog validation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "passed", "scope": "operator-inputs", "stack_version": args.stack_version,
        "template_path": str(catalog.template_path),
        "template_sha256": catalog.metadata["historical_manifest"]["sha256"],
        "source": catalog.metadata["source"], "website_assets_verified": False,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
