#!/usr/bin/env python3
"""Seal one original stable CD attempt's already-signed publication bytes.

This data-only checkpoint does not authenticate Actions, verify signatures,
authorize a review, execute an installer, or create a tag. Its trusted callers
must authenticate the original run/artifact and perform the existing release
crypto and protected-main checks. The original 900-second deadline cannot be
refreshed by loading, copying, or reopening an existing output directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

if __package__:
    from .release_review_main import gate_authority, strict_json
    from .release_transaction import REQUIRED_IMAGE_ROLES, validate_claim
else:
    from release_review_main import gate_authority, strict_json
    from release_transaction import REQUIRED_IMAGE_ROLES, validate_claim

SCHEMA = "elevenid.stable-publication-checkpoint/v1"
REPOSITORY = "ElevenID/marty-ui"
WORKFLOW = ".github/workflows/cd.yml"
LIFETIME_SECONDS = 900
SIGNED_SUBJECTS = (
    "stack-manifest.json", "release-transaction.json", "marty-ui-sbom.cdx.json",
    "marty-ui-services-sbom.cdx.json", "marty-ui-migrations-sbom.cdx.json",
    "marty-ui-openbao-didcomm-sbom.cdx.json", "marty-ui-keycloak-sbom.cdx.json",
    "marty-deploy-linux-amd64", "marty-deploy-linux-arm64", "install.sh",
    "installer-inventory.json", "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json",
)
CHECKSUM_NAMES = frozenset(SIGNED_SUBJECTS) | {name + ".sigstore.json" for name in SIGNED_SUBJECTS}
PROVENANCE_NAMES = frozenset(name + ".provenance.jsonl" for name in (
    "install.sh", "marty-deploy-linux-amd64", "installer-inventory.json",
    "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json",
))
ASSET_NAMES = frozenset(CHECKSUM_NAMES | PROVENANCE_NAMES | {"SHA256SUMS"})
CHECKPOINT_FILES = frozenset({"assets/" + name for name in ASSET_NAMES}
                             | {"request.json", "official-interoperability.json"})
MAX_FILE_BYTES = {name: 1024 * 1024 for name in CHECKPOINT_FILES}
MAX_FILE_BYTES.update({"assets/" + name: 64 * 1024 * 1024 for name in SIGNED_SUBJECTS
                       if name.endswith("-sbom.cdx.json")})
MAX_FILE_BYTES.update({"assets/" + name: 64 * 1024 for name in (
    "release-transaction.json", "install.sh", "installer-inventory.json",
    "prepared-selfhost-images.json", "SHA256SUMS",
)})
MAX_FILE_BYTES.update({"assets/marty-deploy-linux-amd64": 512 * 1024 * 1024,
                       "assets/marty-deploy-linux-arm64": 512 * 1024 * 1024,
                       "assets/prepared-selfhost-bundle.zip": 256 * 1024 * 1024,
                       "request.json": 64 * 1024,
                       "official-interoperability.json": 256 * 1024})
MAX_TOTAL_BYTES = 2 * 1024**3
REQUEST_FIELDS = frozenset({"schema", "repository", "source_sha", "claim_run_id", "tag",
    "transaction_id", "run_id", "run_attempt", "origin_attempt", "protected_main_commit",
    "official_gate_sha256", "manifest_sha256", "transaction_sha256", "created_at",
    "not_after", "assets", "authority"})
AUTHORITY_FIELDS = frozenset({"source_sha", "run_id", "origin_attempt", "review_required",
    "protected_main_commit", "record_sha256", "request_sha256", "gate_sha256", "harness_sha",
    "manifest_sha256"})
CAPTURE_NAMES = frozenset({"stack-manifest.json", "release-transaction.json",
                          "installer-inventory.json", "prepared-selfhost-images.json", "SHA256SUMS"})
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
RAW_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
RUN = re.compile(r"[1-9][0-9]{0,15}\Z")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class CheckpointError(ValueError):
    """The original release checkpoint cannot be admitted."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckpointError(message)


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _positive(value: Any) -> bool:
    return type(value) is int and 0 < value < 2**53


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _encode(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def _decode(raw: bytes) -> dict:
    try:
        value = strict_json(raw)
    except (ValueError, RecursionError):
        raise CheckpointError("Checkpoint JSON is malformed") from None
    _require(type(value) is dict, "Checkpoint JSON must be an object")
    return value


def _clock(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    _require(isinstance(now, datetime) and now.tzinfo is not None
             and now.utcoffset() == timedelta(0), "Checkpoint clock must be UTC")
    return now


def _timestamp(value: Any) -> datetime:
    _require(_matches(TIMESTAMP, value), "Checkpoint timestamp is not canonical UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise CheckpointError("Checkpoint timestamp is invalid") from None


def _active(request: dict, now: datetime | None) -> None:
    created, expires = _timestamp(request["created_at"]), _timestamp(request["not_after"])
    _require(expires - created == timedelta(seconds=LIFETIME_SECONDS),
             "Checkpoint deadline must span exactly 900 seconds")
    _require(created <= _clock(now) < expires, "Checkpoint is future or expired")


def validate_request_identity(request: object) -> dict:
    """Validate archived identity without granting publication authority.

    Only a separately authenticated v2 candidate may use historical evidence.
    The v1 loader and CLI still require the active original deadline.
    """
    _require(type(request) is dict and set(request) == REQUEST_FIELDS, "Checkpoint request fields differ")
    _require(request["schema"] == SCHEMA and request["repository"] == REPOSITORY,
             "Checkpoint schema or repository differs")
    _require(_matches(SHA, request["source_sha"]) and _matches(SHA, request["protected_main_commit"])
             and _matches(TAG, request["tag"]) and _matches(RAW_DIGEST, request["transaction_id"])
             and _matches(RUN, request["claim_run_id"]) and int(request["claim_run_id"]) < 2**53
             and _positive(request["run_id"]) and type(request["run_attempt"]) is int
             and request["run_attempt"] == 1 and type(request["origin_attempt"]) is int
             and request["origin_attempt"] == 1, "Checkpoint original candidate identity differs")
    _require(all(_matches(DIGEST, request[key]) for key in
                 ("official_gate_sha256", "manifest_sha256", "transaction_sha256")),
             "Checkpoint evidence digest is invalid")
    assets = request["assets"]
    _require(type(assets) is dict and set(assets) == ASSET_NAMES, "Checkpoint must name exactly 32 assets")
    for name, entry in assets.items():
        _require(type(entry) is dict and set(entry) == {"size", "sha256"}
                 and type(entry["size"]) is int and 0 < entry["size"] <= MAX_FILE_BYTES["assets/" + name]
                 and _matches(DIGEST, entry["sha256"]), "Checkpoint asset entry is invalid")
    _require(sum(entry["size"] for entry in assets.values()) <= MAX_TOTAL_BYTES,
             "Checkpoint assets exceed the expanded size limit")
    _require(assets["stack-manifest.json"]["sha256"] == request["manifest_sha256"]
             and assets["release-transaction.json"]["sha256"] == request["transaction_sha256"],
             "Checkpoint evidence does not match its asset inventory")
    authority = request["authority"]
    _require(type(authority) is dict and set(authority) == AUTHORITY_FIELDS,
             "Checkpoint gate authority fields differ")
    _require(type(authority["review_required"]) is bool and _positive(authority["run_id"])
             and type(authority["origin_attempt"]) is int and authority["origin_attempt"] == 1
             and authority["source_sha"] == request["source_sha"]
             and authority["run_id"] == request["run_id"]
             and authority["protected_main_commit"] == request["protected_main_commit"]
             and authority["gate_sha256"] == request["official_gate_sha256"]
             and authority["manifest_sha256"] == request["manifest_sha256"]
             and _matches(SHA, authority["harness_sha"]), "Checkpoint gate authority identity differs")
    if authority["review_required"]:
        _require(authority["protected_main_commit"] != request["source_sha"]
                 and _matches(DIGEST, authority["record_sha256"])
                 and _matches(DIGEST, authority["request_sha256"]), "Checkpoint accepted review is incomplete")
    else:
        _require(authority["protected_main_commit"] == request["source_sha"]
                 and authority["record_sha256"] is None and authority["request_sha256"] is None,
                 "All-pass checkpoint cannot advance the original source")
    _require(_timestamp(request["not_after"]) - _timestamp(request["created_at"])
             == timedelta(seconds=LIFETIME_SECONDS), "Checkpoint deadline must span exactly 900 seconds")
    return request


def validate_request(request: object, *, now: datetime | None = None) -> dict:
    """Validate the closed request and its active, original fixed deadline."""
    validate_request_identity(request)
    _active(request, now)
    return request


def _fingerprint(value: os.stat_result) -> tuple:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _directory_identity(value: os.stat_result) -> tuple:
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def _open_directory(path: Path) -> int:
    """Walk with no-follow directory descriptors, including every ancestor."""
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class _Directory:
    def __init__(self, path: Path):
        self.path = Path(os.path.abspath(path))
        self.fd = _open_directory(self.path)
        self.identity = _directory_identity(os.fstat(self.fd))
        self.seen: dict[str, tuple] = {}
        if self.identity[3] != os.geteuid() or self.identity[2] & 0o022:
            self.close()
            raise CheckpointError("Checkpoint directory owner or write permissions differ")

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> _Directory:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def unchanged(self) -> None:
        visible = _open_directory(self.path)
        try:
            _require(_directory_identity(os.fstat(self.fd)) == self.identity
                     == _directory_identity(os.fstat(visible)), "Checkpoint directory changed")
        finally:
            os.close(visible)
        for name, expected in self.seen.items():
            _require(_fingerprint(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == expected,
                     "Checkpoint file changed during observation")

    def read(self, name: str, maximum: int, *, capture: bool = True,
             destination: _Directory | None = None, request: dict | None = None,
             now: datetime | None = None) -> tuple[dict, bytes]:
        _require(name not in {"", ".", ".."} and "/" not in name, "Checkpoint filename differs")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        output_fd = -1
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and before.st_uid == os.geteuid() and not before.st_mode & 0o7022
                     and 0 < before.st_size <= maximum, "Checkpoint input type, owner, mode or size differs")
            if destination is not None:
                output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=destination.fd)
                os.fchmod(output_fd, 0o600)
            digest = hashlib.sha256()
            chunks: list[bytes] = []
            size = 0
            while True:
                if request is not None:
                    _active(request, now)
                block = os.read(fd, min(1024 * 1024, maximum + 1 - size))
                if not block:
                    break
                size += len(block)
                _require(size <= maximum, "Checkpoint input grew beyond its size limit")
                digest.update(block)
                if capture:
                    chunks.append(block)
                if output_fd >= 0:
                    view = memoryview(block)
                    while view:
                        written = os.write(output_fd, view)
                        _require(written > 0, "Checkpoint copy was incomplete")
                        view = view[written:]
            _require(size == before.st_size and _fingerprint(os.fstat(fd)) == _fingerprint(before)
                     == _fingerprint(os.stat(name, dir_fd=self.fd, follow_symlinks=False)),
                     "Checkpoint input changed during its bounded read")
            self.seen[name] = _fingerprint(before)
            if output_fd >= 0:
                os.fsync(output_fd)
            return {"size": size, "sha256": "sha256:" + digest.hexdigest()}, b"".join(chunks)
        finally:
            os.close(fd)
            if output_fd >= 0:
                os.close(output_fd)

    def write(self, name: str, raw: bytes) -> None:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                _require(written > 0, "Checkpoint write was incomplete")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)


def _transaction(raw: bytes, *, source_sha: str, tag: str, claim_run_id: str, run_id: int) -> dict:
    try:
        transaction = validate_claim(_decode(raw))
        _require(transaction["source_sha"] == source_sha and transaction["tag"] == tag
                 and transaction["claim_run_id"] == claim_run_id
                 and transaction["state"] == "promoted"
                 and transaction["promoted_roles"] == list(REQUIRED_IMAGE_ROLES)
                 and transaction["publication"] is None and transaction["tombstone"] is None,
                 "Checkpoint transaction is not this candidate's complete promotion")
        _require(all(row["build_run_id"] == str(run_id) for row in transaction["images"].values())
                 and all(row["run_id"] == str(run_id) for row in transaction["gates"].values()),
                 "Checkpoint transaction combines different producer runs")
        preflight = transaction["preflight"]
        _require(preflight["git_tag_absent"] is True and preflight["github_release_absent"] is True
                 and all(value is True for value in preflight["registry_version_tags_absent"].values()),
                 "Checkpoint transaction preflight is not exact boolean evidence")
        return transaction
    except (ValueError, KeyError, TypeError):
        raise CheckpointError("Checkpoint promoted transaction is invalid or foreign") from None


def _validate_payloads(request: dict, captured: dict[str, bytes], gate_bytes: bytes) -> None:
    """Bind data semantics without invoking any artifact or crypto executable."""
    transaction = _transaction(captured["release-transaction.json"], source_sha=request["source_sha"],
                               tag=request["tag"], claim_run_id=request["claim_run_id"], run_id=request["run_id"])
    try:
        authority = gate_authority(gate_bytes, transaction, run_id=request["run_id"], current_attempt=1)
        _require(transaction["transaction_id"] == request["transaction_id"]
                 and authority == request["authority"]
                 and _digest(gate_bytes) == request["official_gate_sha256"],
                 "Checkpoint gate or transaction identity differs")
        manifest = _decode(captured["stack-manifest.json"])
        _require(set(manifest) == {"schema", "release", "generated_at", "components"}
                 and manifest["schema"] == "marty.stack/v1"
                 and manifest["release"] == "marty-ui@" + request["tag"][1:]
                 and isinstance(manifest["generated_at"], str)
                 and isinstance(manifest["components"], list), "Checkpoint product manifest differs")
        product = [row for row in manifest["components"] if type(row) is dict and row.get("name") == "marty-ui"]
        _require(len(product) == 1, "Checkpoint product manifest lacks its unique product")
        product = product[0]
        expected_artifacts = [{"type": "oci", "uri": transaction["images"][role]["uri"],
            "digest": transaction["images"][role]["digest"],
            "sbom": f"https://github.com/{REPOSITORY}/releases/download/{request['tag']}/marty-ui"
                    + ("" if role == "ui" else "-" + role.replace("_", "-")) + "-sbom.cdx.json",
            "provenance": f"https://github.com/{REPOSITORY}/attestations"} for role in REQUIRED_IMAGE_ROLES]
        _require(product == {"name": "marty-ui", "repository": REPOSITORY,
                 "version": request["tag"][1:], "commit": request["source_sha"], "artifacts": expected_artifacts},
                 "Checkpoint product images or source differ from the promoted transaction")
        inventory = _decode(captured["installer-inventory.json"])
        _require(set(inventory) == {"schema", "repository", "source_sha", "release_tag", "platform",
                 "build_run_id", "build_run_attempt", "artifacts", "images"}
                 and inventory["schema"] == "elevenid.installer-inventory/v1"
                 and inventory["repository"] == REPOSITORY and inventory["platform"] == "linux/amd64"
                 and inventory["source_sha"] == request["source_sha"]
                 and inventory["release_tag"] == request["tag"]
                 and _positive(inventory["build_run_id"]) and inventory["build_run_id"] == request["run_id"]
                 and type(inventory["build_run_attempt"]) is int and inventory["build_run_attempt"] == 1,
                 "Checkpoint installer inventory is not the original producer attempt")
        names = {"install.sh", "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json"}
        entries = inventory["artifacts"]
        _require(type(entries) is list and len(entries) == len(names)
                 and all(type(row) is dict and set(row) == {"name", "size", "sha256"}
                         and isinstance(row["name"], str) for row in entries)
                 and {row["name"] for row in entries} == names, "Checkpoint installer inventory assets differ")
        for row in entries:
            actual = request["assets"][row["name"]]
            _require(type(row["size"]) is int and row["size"] == actual["size"]
                     and _matches(RAW_DIGEST, row["sha256"])
                     and "sha256:" + row["sha256"] == actual["sha256"], "Checkpoint installer bytes differ from inventory")
        lock = _decode(captured["prepared-selfhost-images.json"])
        _require(set(lock) == {"schema", "release", "services", "openbao_didcomm_image"}
                 and lock["schema"] == "marty.selfhost-image-lock/v1"
                 and lock["release"] == "marty-ui@" + request["tag"][1:]
                 and type(lock["services"]) is dict and bool(lock["services"])
                 and "openbao_didcomm_image" not in lock["services"], "Checkpoint installer image lock differs")
        images = dict(lock["services"], openbao_didcomm_image=lock["openbao_didcomm_image"])
        _require(type(inventory["images"]) is dict and inventory["images"] == images
                 and all(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", key) is not None
                         and isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", value)
                         for key, value in images.items()), "Checkpoint installer images are not exact digest-pinned inputs")
        checksums: dict[str, str] = {}
        for line in captured["SHA256SUMS"].decode("ascii").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^ /\\]+)", line)
            _require(match is not None and match[2] not in checksums, "Checkpoint checksums are malformed or duplicated")
            checksums[match[2]] = "sha256:" + match[1]
        _require(set(checksums) == CHECKSUM_NAMES and all(request["assets"][name]["sha256"] == digest
                 for name, digest in checksums.items()), "Checkpoint checksum closure differs")
    except (ValueError, KeyError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise CheckpointError("Checkpoint payload evidence is invalid or inconsistent") from None


def check_files(directory: Path, request: dict | None = None, *, now: datetime | None = None) -> dict:
    """Read exactly 34 ordinary files and return their closed, bound request.

    Consumers must retain exclusive custody after this read and recheck at the
    operation boundary; this function cannot lock out another same-UID writer.
    The optional clock is for deterministic local tests, never a CLI option.
    """
    try:
        with _Directory(directory) as root:
            _require(set(os.listdir(root.fd)) == {"request.json", "official-interoperability.json", "assets"},
                     "Checkpoint root entries differ")
            request_meta, request_bytes = root.read("request.json", MAX_FILE_BYTES["request.json"])
            actual = validate_request(_decode(request_bytes), now=now)
            if request is not None:
                validate_request(request, now=now)
                _require(actual == request, "Checkpoint supplied request differs from its exact file")
            gate_meta, gate = root.read("official-interoperability.json", MAX_FILE_BYTES["official-interoperability.json"],
                                        request=actual, now=now)
            captured: dict[str, bytes] = {}
            total = request_meta["size"] + gate_meta["size"]
            with _Directory(root.path / "assets") as assets:
                _require(set(os.listdir(assets.fd)) == ASSET_NAMES, "Checkpoint asset entries differ")
                for name in sorted(ASSET_NAMES):
                    metadata, data = assets.read(name, MAX_FILE_BYTES["assets/" + name],
                        capture=name in CAPTURE_NAMES, request=actual, now=now)
                    _require(metadata == actual["assets"][name], "Checkpoint asset bytes differ from the sealed request")
                    total += metadata["size"]
                    _require(total <= MAX_TOTAL_BYTES, "Checkpoint exceeds its complete expanded size limit")
                    if name in CAPTURE_NAMES:
                        captured[name] = data
                _validate_payloads(actual, captured, gate)
                assets.unchanged()
                _require(set(os.listdir(assets.fd)) == ASSET_NAMES, "Checkpoint asset entries changed")
            root.unchanged()
            _require(set(os.listdir(root.fd)) == {"request.json", "official-interoperability.json", "assets"},
                     "Checkpoint root entries changed")
            _active(actual, now)
            return actual
    except OSError:
        raise CheckpointError("Checkpoint files are unavailable or unsafe") from None


def load_checkpoint(directory: Path, *, now: datetime | None = None) -> dict:
    return check_files(directory, now=now)


def request_digest(directory: Path) -> str:
    """Hash exact request bytes; admission still requires load_checkpoint."""
    try:
        with _Directory(directory) as root:
            metadata, _ = root.read("request.json", MAX_FILE_BYTES["request.json"], capture=False)
            root.unchanged()
            return metadata["sha256"]
    except OSError:
        raise CheckpointError("Checkpoint request is unavailable or unsafe") from None


def _producer_context(source_sha: str, environment: Mapping[str, str]) -> int:
    _require(_matches(SHA, source_sha) and environment.get("GITHUB_REPOSITORY") == REPOSITORY
             and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and environment.get("GITHUB_REF") == "refs/heads/main"
             and environment.get("GITHUB_SHA") == source_sha
             and environment.get("GITHUB_WORKFLOW_REF") == REPOSITORY + "/" + WORKFLOW + "@refs/heads/main"
             and environment.get("GITHUB_RUN_ATTEMPT") == "1"
             and _matches(RUN, environment.get("GITHUB_RUN_ID"))
             and int(environment["GITHUB_RUN_ID"]) < 2**53,
             "Checkpoint requires the original first-attempt CD context")
    _require(not environment.get("RESUME_RUN_ID") and not environment.get("RESUME_ARTIFACT"),
             "Checkpoint cannot resume a previous release attempt")
    return int(environment["GITHUB_RUN_ID"])


def prepare_checkpoint(assets: Path, transaction: Path, official_gate: Path, *, source_sha: str,
                       tag: str, claim_run_id: str, output: Path,
                       environment: Mapping[str, str] | None = None, now: datetime | None = None) -> dict:
    """Exclusively create the original request and copy unchanged signed bytes.

    A failed/partial output is preserved and never reopened or repaired. Caller
    must not retry the failed original attempt under another output name.
    """
    run_id = _producer_context(source_sha, os.environ if environment is None else environment)
    _require(_matches(TAG, tag) and _matches(RUN, claim_run_id) and int(claim_run_id) < 2**53,
             "Checkpoint stable tag or claim identity is invalid")
    created = _clock(now).replace(microsecond=0)
    request = {"created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "not_after": (created + timedelta(seconds=LIFETIME_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    output = Path(os.path.abspath(output))
    try:
        with _Directory(Path(transaction).parent) as transaction_parent, _Directory(Path(official_gate).parent) as gate_parent:
            _, transaction_bytes = transaction_parent.read(Path(transaction).name, MAX_FILE_BYTES["assets/release-transaction.json"],
                                                           request=request, now=now)
            _, gate_bytes = gate_parent.read(Path(official_gate).name, MAX_FILE_BYTES["official-interoperability.json"],
                                             request=request, now=now)
            claim = _transaction(transaction_bytes, source_sha=source_sha, tag=tag, claim_run_id=claim_run_id, run_id=run_id)
            try:
                authority = gate_authority(gate_bytes, claim, run_id=run_id, current_attempt=1)
            except (ValueError, KeyError, TypeError, RecursionError):
                raise CheckpointError("Checkpoint official gate is not the original candidate's") from None
            with _Directory(output.parent) as parent:
                os.mkdir(output.name, 0o700, dir_fd=parent.fd)
                os.fsync(parent.fd)
                with _Directory(output) as target, _Directory(assets) as source:
                    os.mkdir("assets", 0o700, dir_fd=target.fd)
                    captured: dict[str, bytes] = {}
                    inventory: dict[str, dict] = {}
                    with _Directory(output / "assets") as copied:
                        for name in sorted(ASSET_NAMES):
                            metadata, raw = source.read(name, MAX_FILE_BYTES["assets/" + name],
                                capture=name in CAPTURE_NAMES, destination=copied, request=request, now=now)
                            inventory[name] = metadata
                            if name in CAPTURE_NAMES:
                                captured[name] = raw
                        _require(captured["release-transaction.json"] == transaction_bytes,
                                 "Signed transaction differs from the actual promoted transaction")
                        request.update(schema=SCHEMA, repository=REPOSITORY, source_sha=source_sha,
                            claim_run_id=claim_run_id, tag=tag, transaction_id=claim["transaction_id"], run_id=run_id,
                            run_attempt=1, origin_attempt=1, protected_main_commit=authority["protected_main_commit"],
                            official_gate_sha256=_digest(gate_bytes), manifest_sha256=inventory["stack-manifest.json"]["sha256"],
                            transaction_sha256=_digest(transaction_bytes), assets=inventory, authority=authority)
                        validate_request(request, now=now)
                        _validate_payloads(request, captured, gate_bytes)
                        source.unchanged()
                        transaction_parent.unchanged()
                        gate_parent.unchanged()
                        copied.unchanged()
                        os.fsync(copied.fd)
                    target.write("official-interoperability.json", gate_bytes)
                    encoded = _encode(request)
                    _require(len(encoded) <= MAX_FILE_BYTES["request.json"], "Checkpoint request exceeds its bound")
                    _active(request, now)
                    target.write("request.json", encoded)
                    target.unchanged()
                    os.fsync(target.fd)
                parent.unchanged()
        return load_checkpoint(output, now=now)
    except OSError:
        raise CheckpointError("Checkpoint output exists, is partial, or cannot be safely created") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    for name in ("assets", "transaction", "official-gate", "output"):
        prepare.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha", "tag", "claim-run-id"):
        prepare.add_argument("--" + name, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--checkpoint", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            load_checkpoint(args.checkpoint)
        else:
            prepare_checkpoint(args.assets, args.transaction, args.official_gate, source_sha=args.source_sha,
                               tag=args.tag, claim_run_id=args.claim_run_id, output=args.output)
    except (CheckpointError, ValueError, TypeError, KeyError, OSError):
        print("Stable publication checkpoint refused; original evidence was preserved.", file=sys.stderr)
        return 1
    if args.command == "verify":
        print("Stable publication checkpoint verified; original deadline preserved.")
    else:
        print("Stable publication checkpoint sealed: 32 assets; original 900-second deadline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
