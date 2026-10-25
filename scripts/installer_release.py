"""Produce unsigned installer records from actual artifacts and verified evidence.

No publication or signing occurs here. Callers authenticate inventory/prior-channel
bytes and authoritative API run records before using them; serialize promotion
and compare-and-swap the prior channel when publishing. This module cannot grant
candidate replay authorization or bypass stable release qualification.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import installer_acceptance as acceptance
import verify_installer_provenance as provenance
from stack_tag_gate import classify_release_tag

REPOSITORY = acceptance.REPOSITORY
# Keep distribution limits compatible with the actual consumers: install.sh's
# operator download, installer_artifacts::MAX_ARCHIVE, and decode's JSON bound.
# The bootstrap itself has a separate small distribution ceiling; the initial
# convenience curl pipeline does not impose a transport size limit.
ARTIFACT_MAX_BYTES = {
    "install.sh": 64 * 1024,
    "marty-deploy-linux-amd64": 512 * 1024 * 1024,
    "prepared-selfhost-bundle.zip": 256 * 1024 * 1024,
    "prepared-selfhost-images.json": 64 * 1024,
}
ARTIFACTS = frozenset(ARTIFACT_MAX_BYTES)
PROMOTION_WORKFLOW = ".github/workflows/installer-promote.yml"
require = acceptance.require
exact = acceptance.exact


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(record: dict) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def decode(data: bytes) -> dict:
    require(isinstance(data, bytes) and len(data) <= 65536, "record exceeds size limit")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate record field")
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=pairs)
    require(isinstance(result, dict), "record must be object")
    return result


def sha(value: object, length: int = 40) -> None:
    require(acceptance.matches(value, rf"[0-9a-f]{{{length}}}"), "invalid digest")


def positive(value: object) -> None:
    require(type(value) is int and 0 < value < 2**53, "invalid exact integer")


def identity(source: str, tag: str, run_id: int, attempt: int) -> None:
    sha(source)
    classify_release_tag(tag)
    positive(run_id)
    positive(attempt)


def images(lock: dict, tag: str, expected_services: set[str]) -> dict:
    exact(lock, {"schema", "release", "services", "openbao_didcomm_image"}, "image lock")
    require(lock["schema"] == "marty.selfhost-image-lock/v1"
            and lock["release"] == "marty-ui@" + tag[1:], "image lock release differs")
    require(bool(expected_services) and isinstance(lock["services"], dict)
            and set(lock["services"]) == expected_services, "image service inventory differs")
    result = dict(lock["services"])
    require("openbao_didcomm_image" not in result, "reserved image role")
    result["openbao_didcomm_image"] = lock["openbao_didcomm_image"]
    for service, image in result.items():
        require(acceptance.matches(service, r"[a-z0-9][a-z0-9_-]*")
                and acceptance.matches(image, r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}"),
                "image must be digest pinned")
    return result


def inventory(directory: Path, *, source_sha: str, release_tag: str,
              build_run_id: int, build_run_attempt: int, expected_services: set[str]) -> dict:
    """Exact install-input inventory; separate from the full release asset policy."""
    identity(source_sha, release_tag, build_run_id, build_run_attempt)
    require(not directory.is_symlink() and directory.is_dir(), "invalid artifact directory")
    require({p.name for p in directory.iterdir()} == ARTIFACTS, "artifact allowlist differs")
    entries = []
    for name in sorted(ARTIFACTS):
        path = directory / name
        require(not path.is_symlink() and path.is_file(), "artifact must be ordinary file")
        size = path.stat().st_size
        require(0 < size <= ARTIFACT_MAX_BYTES[name], "invalid artifact size")
        with path.open("rb") as stream:
            hashed = hashlib.file_digest(stream, "sha256").hexdigest()
        require(path.stat().st_size == size, "artifact changed during inventory")
        entries.append(dict(name=name, sha256=hashed, size=size))
    lock_bytes = (directory / "prepared-selfhost-images.json").read_bytes()
    require(digest(lock_bytes) == next(e["sha256"] for e in entries if e["name"] == "prepared-selfhost-images.json"),
            "image lock changed")
    return dict(schema="elevenid.installer-inventory/v1", repository=REPOSITORY,
                source_sha=source_sha, release_tag=release_tag, platform="linux/amd64",
                build_run_id=build_run_id, build_run_attempt=build_run_attempt,
                artifacts=entries, images=images(decode(lock_bytes), release_tag, expected_services))


def validate_inventory(record: dict) -> None:
    exact(record, {"schema", "repository", "source_sha", "release_tag", "platform",
                   "build_run_id", "build_run_attempt", "artifacts", "images"}, "inventory")
    require(record["schema"] == "elevenid.installer-inventory/v1" and record["repository"] == REPOSITORY
            and record["platform"] == "linux/amd64", "inventory identity differs")
    identity(record["source_sha"], record["release_tag"], record["build_run_id"], record["build_run_attempt"])
    require(isinstance(record["artifacts"], list) and len(record["artifacts"]) == len(ARTIFACTS), "artifact count differs")
    names = []
    for entry in record["artifacts"]:
        exact(entry, {"name", "sha256", "size"}, "artifact")
        require(isinstance(entry["name"], str), "invalid artifact name")
        require(entry["name"] in ARTIFACTS, "artifact allowlist differs")
        names.append(entry["name"])
        sha(entry["sha256"], 64)
        positive(entry["size"])
        require(entry["size"] <= ARTIFACT_MAX_BYTES[entry["name"]], "artifact exceeds limit")
    require(len(set(names)) == len(names) and set(names) == ARTIFACTS, "artifact allowlist differs")
    require(isinstance(record["images"], dict) and len(record["images"]) > 1
            and "openbao_didcomm_image" in record["images"], "missing image inventory")
    for name, image in record["images"].items():
        require(acceptance.matches(name, r"[a-z0-9][a-z0-9_-]*")
                and acceptance.matches(image, r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}"), "unpinned image")


def admission(inventory_bytes: bytes, *, reports: dict, gh: Path,
              promotion_source_sha: str, promotion_run_id: int, promotion_run_attempt: int,
              runner=provenance.command) -> dict:
    """reports maps staged/published to (private report path, SLSA bundle, API run).

    Inventory bytes and API records must already be authenticated by the caller.
    Reports are cryptographically verified here before structural acceptance.
    """
    inv = decode(inventory_bytes)
    validate_inventory(inv)
    sha(promotion_source_sha)
    positive(promotion_run_id)
    positive(promotion_run_attempt)
    exact(reports, {"staged", "published"}, "acceptance phases")
    evidence = {}
    for phase in ("staged", "published"):
        path, bundle, run = reports[phase]
        report = acceptance.read_report(path)
        acceptance.validate(report, inventory_bytes=inventory_bytes, source_sha=inv["source_sha"],
                            release_tag=inv["release_tag"], phase=phase, run=run)
        provenance.verify_subject(path, bundle, gh=gh, workflow=acceptance.WORKFLOW,
                                  source_sha=report["harness_source_sha"], run_id=report["run_id"],
                                  run_attempt=report["run_attempt"], runner=runner)
        # Private staging with no concurrent writers is the provenance API contract.
        evidence[phase] = dict(sha256=digest(path.read_bytes()), run_id=report["run_id"],
                               run_attempt=report["run_attempt"])
    return dict(schema="elevenid.installer-admission/v1", repository=REPOSITORY,
                source_sha=inv["source_sha"], release_tag=inv["release_tag"], platform="linux/amd64",
                status="accepted", inventory_sha256=digest(inventory_bytes),
                operator_sha256=next(e["sha256"] for e in inv["artifacts"] if e["name"] == "marty-deploy-linux-amd64"),
                build_run_id=inv["build_run_id"], build_run_attempt=inv["build_run_attempt"],
                promotion_source_sha=promotion_source_sha, promotion_run_id=promotion_run_id,
                promotion_run_attempt=promotion_run_attempt, acceptance=evidence)


def validate_admission(record: dict) -> None:
    exact(record, {"schema", "repository", "source_sha", "release_tag", "platform", "status",
                   "inventory_sha256", "operator_sha256", "build_run_id", "build_run_attempt",
                   "promotion_source_sha", "promotion_run_id", "promotion_run_attempt", "acceptance"}, "admission")
    require(record["schema"] == "elevenid.installer-admission/v1" and record["repository"] == REPOSITORY
            and record["platform"] == "linux/amd64" and record["status"] == "accepted", "admission identity differs")
    identity(record["source_sha"], record["release_tag"], record["build_run_id"], record["build_run_attempt"])
    sha(record["promotion_source_sha"])
    positive(record["promotion_run_id"])
    positive(record["promotion_run_attempt"])
    sha(record["inventory_sha256"], 64)
    sha(record["operator_sha256"], 64)
    exact(record["acceptance"], {"staged", "published"}, "acceptance phases")
    for evidence in record["acceptance"].values():
        exact(evidence, {"sha256", "run_id", "run_attempt"}, "acceptance reference")
        sha(evidence["sha256"], 64)
        positive(evidence["run_id"])
        positive(evidence["run_attempt"])


def sequence(tag: str) -> tuple:
    classify_release_tag(tag)
    return tuple(int(n) for n in re.findall(r"\d+", tag))


def validate_channel(record: dict, *, now: int, allow_expired: bool = False) -> None:
    exact(record, {"schema", "repository", "channel", "generation", "previous_sha256", "source_sha",
                   "release_tag", "admission_sha256", "promotion_source_sha", "promotion_run_id",
                   "promotion_run_attempt", "issued_at", "expires_at"}, "channel")
    require(record["schema"] == "elevenid.installer-channel/v1" and record["repository"] == REPOSITORY,
            "channel identity differs")
    require(classify_release_tag(record["release_tag"])[0] == record["channel"], "channel tier differs")
    for name in ("source_sha", "promotion_source_sha"):
        sha(record[name])
    for name in ("generation", "promotion_run_id", "promotion_run_attempt"):
        positive(record[name])
    sha(record["admission_sha256"], 64)
    if record["generation"] == 1:
        require(record["previous_sha256"] is None, "initial channel has predecessor")
    else:
        sha(record["previous_sha256"], 64)
    require(type(now) is int and type(record["issued_at"]) is int and type(record["expires_at"]) is int,
            "invalid channel timestamps")
    require(0 <= record["issued_at"] <= now and 0 < record["expires_at"] - record["issued_at"] <= 604800,
            "invalid channel lifetime")
    require(allow_expired or record["expires_at"] > now, "channel expired")


def channel(admission_bytes: bytes, *, channel_name: str, previous_bytes: bytes | None,
            promotion_source_sha: str, promotion_run_id: int, promotion_run_attempt: int,
            now: int, lifetime: int = 604800) -> dict:
    """Caller authenticates admission and previous channel; atomically CAS at publish.

    An expired previous record still constrains sequence/generation. No rollback
    or same-version refresh is admitted by this monotonic publication primitive.
    """
    accepted = decode(admission_bytes)
    validate_admission(accepted)
    generation = 1
    previous_hash = None
    if previous_bytes is not None:
        previous = decode(previous_bytes)
        validate_channel(previous, now=now, allow_expired=True)
        require(previous["channel"] == channel_name, "previous channel differs")
        require(sequence(accepted["release_tag"]) > sequence(previous["release_tag"]), "stale promotion")
        generation = previous["generation"] + 1
        previous_hash = digest(previous_bytes)
    record = dict(schema="elevenid.installer-channel/v1", repository=REPOSITORY,
                  channel=channel_name, generation=generation, previous_sha256=previous_hash,
                  source_sha=accepted["source_sha"], release_tag=accepted["release_tag"],
                  admission_sha256=digest(admission_bytes), promotion_source_sha=promotion_source_sha,
                  promotion_run_id=promotion_run_id, promotion_run_attempt=promotion_run_attempt,
                  issued_at=now, expires_at=now + lifetime)
    validate_channel(record, now=now)
    return record
