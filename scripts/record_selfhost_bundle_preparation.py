#!/usr/bin/env python3
"""Record an unqualified, exact ZIP/image-lock handoff for later install testing."""

import argparse
import hashlib
import json
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import yaml
from build_selfhost_image_lock import EXACT_IMAGE


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def extract_owned_zip(bundle: zipfile.ZipFile, extracted: Path) -> tuple[str, dict[str, str], set[str]]:
    """Extract bounded regular files after rejecting unsafe or duplicate names."""
    files: dict[str, str] = {}
    directories: set[str] = set()
    directory_modes: dict[str, int] = {}
    roots: set[str] = set()
    total_size = 0
    for member in bundle.infolist():
        path = PurePosixPath(member.filename)
        if (path.is_absolute() or "\\" in member.filename or ":" in member.filename
                or any(part in (".", "..", "") for part in member.filename.rstrip("/").split("/"))):
            raise ValueError("unsafe ZIP member")
        roots.add(path.parts[0])
        kind = stat.S_IFMT(member.external_attr >> 16)
        if kind not in ((0, stat.S_IFDIR) if member.is_dir() else (0, stat.S_IFREG)):
            raise ValueError("special ZIP member")
        mode = stat.S_IMODE(member.external_attr >> 16)
        if not mode:
            mode = 0o755 if member.is_dir() else 0o644
        if (mode & 0o7000 or (member.is_dir() and mode & 0o700 != 0o700)
                or (not member.is_dir() and not mode & 0o400)):
            raise ValueError("unsafe ZIP member permissions")
        target = extracted.joinpath(*path.parts)
        if member.is_dir():
            if member.filename in directories:
                raise ValueError("duplicate ZIP directory")
            directories.add(member.filename)
            directory_modes[member.filename] = mode
            target.mkdir(parents=True, exist_ok=True)
            continue
        if member.filename in files:
            raise ValueError("duplicate ZIP member")
        total_size += member.file_size
        if member.file_size > 64 * 1024 * 1024 or total_size > 256 * 1024 * 1024:
            raise ValueError("ZIP member or bundle exceeds extraction limit")
        target.parent.mkdir(parents=True, exist_ok=True)
        copied = 0
        with bundle.open(member) as source, target.open("xb") as output:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                copied += len(chunk)
                if copied > member.file_size:
                    raise ValueError("ZIP member size changed while extracting")
                output.write(chunk)
        if copied != member.file_size:
            raise ValueError("ZIP member size changed while extracting")
        target.chmod(mode)
        files[member.filename] = file_digest(target)
    if len(roots) != 1:
        raise ValueError("ZIP must have one bundle root")
    for name in sorted(directory_modes, key=lambda value: value.count("/"), reverse=True):
        extracted.joinpath(*PurePosixPath(name).parts).chmod(directory_modes[name])
    return next(iter(roots)), files, directories


def record(archive: Path, lock_path: Path, transaction: Path, source_sha: str, run_id: str) -> dict:
    if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
        raise ValueError("source SHA must be a full lowercase Git commit")
    if not run_id.isdecimal():
        raise ValueError("run ID must be numeric")
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    if lock.get("schema") != "marty.selfhost-image-lock/v1":
        raise ValueError("unsupported image lock")
    plugin = lock.get("openbao_didcomm_image")
    if (not isinstance(plugin, str) or EXACT_IMAGE.fullmatch(plugin) is None
            or not plugin.startswith("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@")):
        raise ValueError("image lock lacks exact OpenBao DIDComm image")
    transaction_bytes = transaction.read_bytes()
    with zipfile.ZipFile(archive) as bundle, tempfile.TemporaryDirectory(prefix="selfhost-fresh-") as scratch:
        extracted = Path(scratch)
        root, files, directories = extract_owned_zip(bundle, extracted)
        embedded_lock = (extracted / root / ".marty-selfhost-images.json").read_bytes()
        if embedded_lock != lock_bytes:
            raise ValueError("embedded image lock differs from prepared lock")
        marker = json.loads((extracted / root / ".marty-selfhost-bundle.json").read_bytes())
        if marker.get("schema") != "marty.selfhost-bundle-files/v1":
            raise ValueError("unsupported bundle inventory")
        expected_directories = {f"{root}/{name}/" if name else f"{root}/"
                                for name in marker["directories"]}
        if directories != expected_directories:
            raise ValueError("ZIP directories differ from owned bundle")
        expected = {f"{root}/{name}": value for name, value in marker["files"].items()}
        actual = {name: file_hash for name, file_hash in files.items()
                  if name != f"{root}/.marty-selfhost-bundle.json"}
        if actual != expected:
            raise ValueError("ZIP inventory differs from owned bundle")
        compose = yaml.safe_load((extracted / root / "docker-compose.yml").read_bytes())
        networks = compose.get("networks", {})
        if not isinstance(networks, dict):
            raise TypeError("ZIP Compose networks are invalid")
        default_network = networks.get("default", {})
        if default_network != {}:
            raise ValueError("ZIP Compose pins or changes the default network")
        volumes = compose.get("volumes", {})
        if not isinstance(volumes, dict):
            raise TypeError("ZIP Compose volumes are invalid")
        if volumes and volumes != {"redis-socket": {}}:
            raise ValueError("ZIP Compose pins or changes the Redis socket volume")
        if "redis" in compose["services"] and volumes != {"redis-socket": {}}:
            raise ValueError("ZIP Compose omits the project-scoped Redis socket volume")
        images = {name: service.get("image") for name, service in compose["services"].items()
                  if "image" in service}
        if images != lock["services"]:
            raise ValueError("ZIP Compose image closure differs from lock")
        openbao_path = extracted / root / "docker-compose.selfhost.openbao.yml"
        if not openbao_path.is_file():
            raise ValueError("ZIP omits pinned OpenBao Compose")
        openbao_compose = yaml.safe_load(openbao_path.read_bytes())
        openbao_services = openbao_compose.get("services") if isinstance(openbao_compose, dict) else None
        if (not isinstance(openbao_services, dict)
                or set(openbao_services) != {"openbao-tls-init", "openbao", "openbao-unseal", "openbao-bootstrap"}
                or any(not isinstance(service, dict) or service.get("image") != plugin
                       or "build" in service for service in openbao_services.values())):
            raise ValueError("ZIP OpenBao Compose image differs from lock")
    return {
        "schema": "marty.selfhost-bundle-preparation/v1",
        "qualification": "unqualified",
        "source_sha": source_sha,
        "run_id": run_id,
        "release": lock["release"],
        "archive_sha256": file_digest(archive),
        "image_lock_sha256": digest(lock_bytes),
        "transaction_sha256": digest(transaction_bytes),
        "images": images,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "source-sha", "run-id", "output"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    result = record(Path(args.archive), Path(args.image_lock), Path(args.transaction),
                    args.source_sha, args.run_id)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
