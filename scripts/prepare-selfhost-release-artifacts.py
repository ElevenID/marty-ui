#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from release_version import ReleaseVersionError, resolve_release_tag


DEFAULT_IMAGE_PREFIX = "ghcr.io/elevenid/marty-ui"
DEFAULT_IMAGES = ["services", "db-migrate", "ui-selfhost", "cloudflared-wrapper"]
PUBLIC_UI_IMAGE = "ui"
DIGEST_PATTERN = re.compile(r"^\s*Digest:\s*(sha256:[0-9a-fA-F]{64})\s*$", re.MULTILINE)
PLATFORM_PATTERN = re.compile(r"^\s*Platform:\s*(\S+)\s*$", re.MULTILINE)


class ReleaseError(RuntimeError):
    pass


@dataclass
class ImageReleaseRecord:
    name: str
    ref: str
    digest: str = ""
    digest_ref: str = ""
    platforms: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    signature: dict[str, Any] = field(
        default_factory=lambda: {
            "signed": False,
            "verified": False,
            "subject": "",
        }
    )


def repo_full_sha(path: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def require_tool(name: str, dry_run: bool) -> None:
    if dry_run:
        return
    if not command_exists(name):
        raise ReleaseError(f"Required tool is missing: {name}")


def run_command(command: list[str], *, dry_run: bool, allow_failure: bool = False) -> int:
    printable = " ".join(command)
    if dry_run:
        print(f"DRY RUN: {printable}")
        return 0

    result = subprocess.run(command)
    if result.returncode and not allow_failure:
        raise ReleaseError(f"Command failed with exit code {result.returncode}: {printable}")
    return result.returncode


def run_command_to_file(command: list[str], output_file: Path, *, dry_run: bool) -> None:
    printable = " ".join(command)
    if dry_run:
        print(f"DRY RUN: {printable} > {output_file}")
        return

    with output_file.open("w", encoding="utf-8", newline="\n") as handle:
        result = subprocess.run(command, stdout=handle, text=True)
    if result.returncode:
        raise ReleaseError(f"Command failed with exit code {result.returncode}: {printable}")


def choose_scan_tool(requested: str, dry_run: bool) -> str:
    if requested != "auto":
        require_tool(requested, dry_run)
        return requested

    if dry_run:
        return "trivy"
    if command_exists("trivy"):
        return "trivy"
    if command_exists("grype"):
        return "grype"
    raise ReleaseError("No scanner found. Install trivy or grype, or run with --dry-run.")


def image_refs(image_prefix: str, tag: str, include_public_ui: bool, skip_cloudflared: bool) -> list[tuple[str, str]]:
    names = list(DEFAULT_IMAGES)
    if skip_cloudflared:
        names.remove("cloudflared-wrapper")
    if include_public_ui:
        names.append(PUBLIC_UI_IMAGE)
    return [(name, f"{image_prefix}/{name}:{tag}") for name in names]


def image_repository_ref(image_ref: str) -> str:
    if "@" in image_ref:
        return image_ref.split("@", 1)[0]
    if ":" not in image_ref.rsplit("/", 1)[-1]:
        return image_ref
    return image_ref.rsplit(":", 1)[0]


def image_digest_ref(image_ref: str, digest: str) -> str:
    if not digest:
        raise ReleaseError(f"Cannot build digest ref for {image_ref}: digest is missing")
    return f"{image_repository_ref(image_ref)}@{digest.lower()}"


def dry_run_digest_ref(image_ref: str) -> str:
    return f"{image_repository_ref(image_ref)}@sha256:<resolved-digest>"


def parse_imagetools_digest(output: str) -> str:
    match = DIGEST_PATTERN.search(output)
    return match.group(1).lower() if match else ""


def parse_imagetools_platforms(output: str) -> list[str]:
    return sorted({match.group(1) for match in PLATFORM_PATTERN.finditer(output)})


def generate_sbom(image_name: str, image_ref: str, output_dir: Path, dry_run: bool) -> Path:
    require_tool("syft", dry_run)
    sbom_dir = output_dir / "sbom"
    if not dry_run:
        sbom_dir.mkdir(parents=True, exist_ok=True)
    output_file = sbom_dir / f"{image_name}.spdx.json"
    run_command(["syft", image_ref, "-o", f"spdx-json={output_file}"], dry_run=dry_run)
    return output_file


def scan_image(
    image_name: str,
    image_ref: str,
    output_dir: Path,
    scan_tool: str,
    dry_run: bool,
    allow_scan_failures: bool,
) -> Path:
    scan_dir = output_dir / "scan"
    if not dry_run:
        scan_dir.mkdir(parents=True, exist_ok=True)

    if scan_tool == "trivy":
        output_file = scan_dir / f"{image_name}.trivy.json"
        command = [
            "trivy",
            "image",
            "--format",
            "json",
            "--output",
            str(output_file),
            "--severity",
            "HIGH,CRITICAL",
            "--exit-code",
            "1",
            image_ref,
        ]
    elif scan_tool == "grype":
        output_file = scan_dir / f"{image_name}.grype.json"
        command = ["grype", image_ref, "-o", "json", "--file", str(output_file), "--fail-on", "high"]
    else:
        raise ReleaseError(f"Unsupported scan tool: {scan_tool}")

    run_command(command, dry_run=dry_run, allow_failure=allow_scan_failures)
    return output_file


def inspect_digest(image_name: str, image_ref: str, output_dir: Path, dry_run: bool) -> tuple[Path, str, list[str]]:
    require_tool("docker", dry_run)
    digest_dir = output_dir / "digests"
    if not dry_run:
        digest_dir.mkdir(parents=True, exist_ok=True)
    output_file = digest_dir / f"{image_name}.imagetools.txt"
    command = ["docker", "buildx", "imagetools", "inspect", image_ref]
    printable = " ".join(command)
    if dry_run:
        print(f"DRY RUN: {printable} > {output_file}")
        return output_file, "", []

    result = subprocess.run(command, capture_output=True, text=True)
    output_file.write_text(result.stdout, encoding="utf-8", newline="\n")
    if result.returncode:
        raise ReleaseError(f"Command failed with exit code {result.returncode}: {printable}\n{result.stderr.strip()}")

    digest = parse_imagetools_digest(result.stdout)
    if not digest:
        raise ReleaseError(f"Could not parse image digest from docker buildx imagetools output for {image_ref}")
    return output_file, digest, parse_imagetools_platforms(result.stdout)


def sign_image(digest_ref: str, cosign_key: str, dry_run: bool) -> None:
    require_tool("cosign", dry_run)
    if not cosign_key:
        raise ReleaseError("--cosign-key or COSIGN_KEY is required when --sign is used")
    if "@sha256:" not in digest_ref and not digest_ref.endswith("@sha256:<resolved-digest>"):
        raise ReleaseError(f"Cosign signing requires an image digest ref, got: {digest_ref}")
    run_command(["cosign", "sign", "--yes", "--key", cosign_key, digest_ref], dry_run=dry_run)


def verify_signature(digest_ref: str, cosign_public_key: str, dry_run: bool) -> None:
    require_tool("cosign", dry_run)
    if not cosign_public_key:
        raise ReleaseError(
            "--cosign-public-key or COSIGN_PUBLIC_KEY is required when --verify-signatures is used"
        )
    if "@sha256:" not in digest_ref and not digest_ref.endswith("@sha256:<resolved-digest>"):
        raise ReleaseError(f"Cosign verification requires an image digest ref, got: {digest_ref}")
    run_command(["cosign", "verify", "--key", cosign_public_key, digest_ref], dry_run=dry_run)


def signature_subject(record: ImageReleaseRecord, dry_run: bool) -> str:
    if record.digest_ref:
        return record.digest_ref
    if dry_run:
        return dry_run_digest_ref(record.ref)
    raise ReleaseError(f"Image digest was not resolved for {record.ref}; run with --inspect-digests or allow automatic digest inspection.")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(output_dir: Path, dry_run: bool) -> Path:
    checksum_file = output_dir / "checksums.sha256"
    if dry_run:
        print(f"DRY RUN: write checksums to {checksum_file}")
        return checksum_file

    files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.name != checksum_file.name
    )

    with checksum_file.open("w", encoding="utf-8", newline="\n") as handle:
        for path in files:
            relative = path.relative_to(output_dir).as_posix()
            handle.write(f"{sha256_file(path)}  {relative}\n")
    return checksum_file


def release_repositories(repo_root: Path, workspace_root: Path) -> dict[str, str]:
    return {
        "marty-ui": repo_full_sha(repo_root),
        "marty-core": repo_full_sha(workspace_root / "marty-core"),
        "marty-credentials": repo_full_sha(workspace_root / "marty-credentials"),
        "longfellow-zk": repo_full_sha(workspace_root / "longfellow-zk"),
        "marty-microservices-framework": repo_full_sha(workspace_root / "marty-microservices-framework"),
    }


def image_record_payload(record: ImageReleaseRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "ref": record.ref,
        "digest": record.digest or None,
        "digest_ref": record.digest_ref or None,
        "platforms": record.platforms,
        "artifacts": record.artifacts,
        "signature": record.signature,
    }


def write_manifest(
    *,
    output_dir: Path,
    tag: str,
    image_prefix: str,
    image_records: list[ImageReleaseRecord],
    actions: dict[str, bool],
    artifacts: dict[str, list[str]],
    repo_root: Path,
    workspace_root: Path,
    dry_run: bool,
) -> Path:
    manifest_file = output_dir / "release-manifest.json"
    payload = {
        "schema_version": 2,
        "release_tag": tag,
        "image_prefix": image_prefix,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "images": [image_record_payload(record) for record in image_records],
        "actions": actions,
        "artifacts": artifacts,
        "repositories": release_repositories(repo_root, workspace_root),
    }

    if dry_run:
        print(f"DRY RUN: write release manifest to {manifest_file}")
        return manifest_file

    manifest_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest_file


def write_release_evidence(
    *,
    output_dir: Path,
    tag: str,
    image_records: list[ImageReleaseRecord],
    repo_root: Path,
    workspace_root: Path,
    dry_run: bool,
) -> Path:
    evidence_file = output_dir / "release-evidence.md"
    if dry_run:
        print(f"DRY RUN: write release evidence to {evidence_file}")
        return evidence_file

    repositories = release_repositories(repo_root, workspace_root)
    lines = [
        f"# Marty self-host release {tag}",
        "",
        "## Images",
        "",
        "| Image | Tag ref | Digest ref | SBOM | Scan | Signed | Verified |",
        "|---|---|---|---|---|---|---|",
    ]
    for record in image_records:
        lines.append(
            "| "
            + " | ".join(
                [
                    record.name,
                    f"`{record.ref}`",
                    f"`{record.digest_ref}`" if record.digest_ref else "not inspected",
                    record.artifacts.get("sbom", ""),
                    record.artifacts.get("scan", ""),
                    "yes" if record.signature.get("signed") else "no",
                    "yes" if record.signature.get("verified") else "no",
                ]
            )
            + " |"
        )

    lines.extend(["", "## Source repositories", ""])
    for repo, sha in repositories.items():
        lines.append(f"- `{repo}`: `{sha}`")

    evidence_file.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8", newline="\n")
    return evidence_file


def relative_artifact(path: Path, output_dir: Path, dry_run: bool) -> str:
    if dry_run:
        return path.as_posix()
    return path.relative_to(output_dir).as_posix()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate local release artifacts for Marty self-host images.",
    )
    parser.add_argument(
        "--tag",
        default="",
        help="Immutable image tag, for example 2026.05.0. Defaults to VERSION in the repo root.",
    )
    parser.add_argument(
        "--version-file",
        default="",
        help="Optional VERSION file path to use when --tag is omitted.",
    )
    parser.add_argument(
        "--image-prefix",
        default=os.environ.get("SELFHOST_IMAGE_PREFIX") or DEFAULT_IMAGE_PREFIX,
        help=f"Image prefix. Default: {DEFAULT_IMAGE_PREFIX}",
    )
    parser.add_argument("--output-dir", default="", help="Release artifact output directory.")
    parser.add_argument("--include-public-ui", action="store_true", help="Include the public ui image.")
    parser.add_argument("--skip-cloudflared", action="store_true", help="Skip cloudflared-wrapper image.")
    parser.add_argument("--sbom", action="store_true", help="Generate Syft SPDX JSON SBOMs.")
    parser.add_argument("--scan", action="store_true", help="Run Trivy or Grype image scans.")
    parser.add_argument(
        "--scan-tool",
        choices=["auto", "trivy", "grype"],
        default="auto",
        help="Scanner to use when --scan is enabled.",
    )
    parser.add_argument(
        "--allow-scan-failures",
        action="store_true",
        help="Record scan output but do not fail on scanner findings.",
    )
    parser.add_argument("--sign", action="store_true", help="Sign images with Cosign.")
    parser.add_argument("--verify-signatures", action="store_true", help="Verify image signatures with Cosign.")
    parser.add_argument(
        "--inspect-digests",
        action="store_true",
        help="Write docker buildx imagetools inspection output for each pushed image.",
    )
    parser.add_argument("--cosign-key", default=os.environ.get("COSIGN_KEY", ""), help="Cosign private key path.")
    parser.add_argument(
        "--cosign-public-key",
        default=os.environ.get("COSIGN_PUBLIC_KEY", ""),
        help="Cosign public key path.",
    )
    parser.add_argument("--no-checksums", action="store_true", help="Do not write checksums.sha256.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running tools or writing files.")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)

    repo_root = Path(__file__).resolve().parents[1]
    workspace_root = repo_root.parent
    version_file = Path(args.version_file).expanduser() if args.version_file else None
    try:
        release_tag = resolve_release_tag(repo_root=repo_root, tag=args.tag, version_file=version_file)
    except ReleaseVersionError as exc:
        raise ReleaseError(str(exc)) from exc

    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else repo_root / "dist" / "releases" / release_tag
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    image_records = [
        ImageReleaseRecord(name=name, ref=ref)
        for name, ref in image_refs(args.image_prefix, release_tag, args.include_public_ui, args.skip_cloudflared)
    ]
    scan_tool = choose_scan_tool(args.scan_tool, args.dry_run) if args.scan else ""
    artifacts: dict[str, list[str]] = {"sbom": [], "scan": [], "digests": [], "signatures": [], "evidence": []}
    digest_resolution_required = args.inspect_digests or args.sign or args.verify_signatures

    print(f"Release tag: {release_tag}")
    print(f"Image prefix: {args.image_prefix}")
    print(f"Output dir: {output_dir}")

    for record in image_records:
        print(f"\n== {record.name}: {record.ref}")
        if args.sbom:
            sbom_artifact = relative_artifact(
                generate_sbom(record.name, record.ref, output_dir, args.dry_run),
                output_dir,
                args.dry_run,
            )
            artifacts["sbom"].append(sbom_artifact)
            record.artifacts["sbom"] = sbom_artifact
        if args.scan:
            scan_artifact = relative_artifact(
                scan_image(
                    record.name,
                    record.ref,
                    output_dir,
                    scan_tool,
                    args.dry_run,
                    args.allow_scan_failures,
                ),
                output_dir,
                args.dry_run,
            )
            artifacts["scan"].append(scan_artifact)
            record.artifacts["scan"] = scan_artifact
        if digest_resolution_required:
            digest_artifact_path, digest, platforms = inspect_digest(record.name, record.ref, output_dir, args.dry_run)
            digest_artifact = relative_artifact(digest_artifact_path, output_dir, args.dry_run)
            artifacts["digests"].append(digest_artifact)
            record.artifacts["digest_inspection"] = digest_artifact
            record.digest = digest
            record.platforms = platforms
            if digest:
                record.digest_ref = image_digest_ref(record.ref, digest)
        if args.sign:
            subject = signature_subject(record, args.dry_run)
            sign_image(subject, args.cosign_key, args.dry_run)
            artifacts["signatures"].append(subject)
            record.signature["signed"] = True
            record.signature["subject"] = subject
        if args.verify_signatures:
            subject = signature_subject(record, args.dry_run)
            verify_signature(subject, args.cosign_public_key, args.dry_run)
            record.signature["verified"] = True
            record.signature["subject"] = subject

    evidence_file = write_release_evidence(
        output_dir=output_dir,
        tag=release_tag,
        image_records=image_records,
        repo_root=repo_root,
        workspace_root=workspace_root,
        dry_run=args.dry_run,
    )
    artifacts["evidence"].append(relative_artifact(evidence_file, output_dir, args.dry_run))

    manifest_file = write_manifest(
        output_dir=output_dir,
        tag=release_tag,
        image_prefix=args.image_prefix,
        image_records=image_records,
        actions={
            "sbom": args.sbom,
            "scan": args.scan,
            "inspect_digests": digest_resolution_required,
            "sign": args.sign,
            "verify_signatures": args.verify_signatures,
        },
        artifacts=artifacts,
        repo_root=repo_root,
        workspace_root=workspace_root,
        dry_run=args.dry_run,
    )
    print(f"\nManifest: {manifest_file}")

    if not args.no_checksums:
        checksum_file = write_checksums(output_dir, args.dry_run)
        print(f"Checksums: {checksum_file}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
