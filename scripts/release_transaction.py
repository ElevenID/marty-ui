#!/usr/bin/env python3
"""Fail-closed state machine for digest-first stack releases.

The workflow persists every returned document as an immutable artifact.  A retry
may advance only the same repository/tag/source/lock claim and, once recorded,
the same image digests.  This module deliberately performs no network writes;
the workflow owns preflight, registry promotion, tag creation and publication.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import NoReturn

SCHEMA = "elevenid.stack-release-transaction/v1"
STACK_LOCK_SCHEMA = "marty.stack-lock/v1"
RELEASE_ELIGIBLE_STATE = "eligible"
REQUIRED_IMAGE_ROLES = ("ui", "services", "migrations")
REQUIRED_GATE_ROLES = ("public_stack", "verifier_differential")
IMAGE_URIS = {
    "ui": "ghcr.io/elevenid/marty-ui-oss/ui",
    "services": "ghcr.io/elevenid/marty-ui-oss/services",
    "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations",
}
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$")
RUN_ID = re.compile(r"^[1-9][0-9]*$")


class ReleaseTransactionError(ValueError):
    """A release claim or transition violates the frozen transaction."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseTransactionError(message)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _transaction_id(
    repository: str, tag: str, source_sha: str, stack_lock_sha256: str
) -> str:
    identity = {
        "repository": repository,
        "source_sha": source_sha,
        "stack_lock_sha256": stack_lock_sha256,
        "tag": tag,
    }
    return hashlib.sha256(
        b"elevenid.stack-release-transaction/v1\0" + _canonical(identity)
    ).hexdigest()


def _version(tag: str) -> str:
    match = TAG.fullmatch(tag)
    _require(match is not None, "release tag is not a stable vMAJOR.MINOR.PATCH tag")
    return match.group("version")


def _read_lock(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseTransactionError("stack lock is unreadable or invalid") from error
    _require(isinstance(value, dict), "stack lock must be a JSON object")
    return value


def _validate_image_uris(image_uris: dict[str, str]) -> None:
    _require(image_uris == IMAGE_URIS, "image URI roles or coordinates changed")
    for role, uri in image_uris.items():
        _require(
            isinstance(uri, str)
            and uri == uri.strip()
            and uri.startswith("ghcr.io/")
            and "@" not in uri
            and not uri.rsplit("/", 1)[-1].count(":"),
            f"{role} image URI is invalid or already qualified",
        )


def create_claim(
    *,
    repository: str,
    tag: str,
    source_sha: str,
    stack_lock: Path,
    claim_run_id: str,
    image_uris: dict[str, str],
    tag_absent: bool,
    release_absent: bool,
    version_tags_absent: dict[str, bool],
) -> dict[str, object]:
    """Create the only state allowed before any image write."""

    version = _version(tag)
    _require(repository == "ElevenID/marty-ui", "release repository changed")
    _require(SHA.fullmatch(source_sha) is not None, "source SHA is invalid")
    _require(RUN_ID.fullmatch(str(claim_run_id)) is not None, "claim run ID is invalid")
    _validate_image_uris(image_uris)
    _require(tag_absent is True, "release tag already exists or was not checked")
    _require(release_absent is True, "GitHub release already exists or was not checked")
    _require(
        version_tags_absent == {role: True for role in REQUIRED_IMAGE_ROLES},
        "every no-v registry version tag must be confirmed absent",
    )

    lock = _read_lock(stack_lock)
    _require(lock.get("schema") == STACK_LOCK_SCHEMA, "stack lock schema is invalid")
    _require(
        lock.get("release_state") == RELEASE_ELIGIBLE_STATE,
        "stack lock release_state must be exactly 'eligible'",
    )
    _require(
        lock.get("release") == f"marty-ui@{version}",
        "stack lock release does not match the requested tag",
    )
    lock_digest = file_digest(stack_lock)
    transaction_id = _transaction_id(repository, tag, source_sha, lock_digest)
    return {
        "schema": SCHEMA,
        "transaction_id": transaction_id,
        "state": "claimed",
        "repository": repository,
        "tag": tag,
        "version": version,
        "source_sha": source_sha,
        "stack_lock_sha256": lock_digest,
        "claim_run_id": str(claim_run_id),
        "preflight": {
            "git_tag_absent": True,
            "github_release_absent": True,
            "registry_version_tags_absent": {
                role: True for role in REQUIRED_IMAGE_ROLES
            },
        },
        "image_uris": dict(sorted(image_uris.items())),
        "images": {},
        "gates": {},
        "promoted_roles": [],
        "publication": None,
        "tombstone": None,
    }


def validate_claim(value: object) -> dict[str, object]:
    _require(isinstance(value, dict), "release transaction must be a JSON object")
    claim = value
    required = {
        "schema",
        "transaction_id",
        "state",
        "repository",
        "tag",
        "version",
        "source_sha",
        "stack_lock_sha256",
        "claim_run_id",
        "preflight",
        "image_uris",
        "images",
        "gates",
        "promoted_roles",
        "publication",
        "tombstone",
    }
    _require(set(claim) == required, "release transaction fields changed")
    _require(claim["schema"] == SCHEMA, "release transaction schema changed")
    _require(claim["repository"] == "ElevenID/marty-ui", "release repository changed")
    _require(isinstance(claim["tag"], str), "release tag is invalid")
    version = _version(claim["tag"])
    _require(claim["version"] == version, "release version does not match its tag")
    _require(
        isinstance(claim["source_sha"], str)
        and SHA.fullmatch(claim["source_sha"]) is not None,
        "source SHA is invalid",
    )
    _require(
        isinstance(claim["stack_lock_sha256"], str)
        and SHA256.fullmatch(claim["stack_lock_sha256"]) is not None,
        "stack lock digest is invalid",
    )
    expected_id = _transaction_id(
        claim["repository"],
        claim["tag"],
        claim["source_sha"],
        claim["stack_lock_sha256"],
    )
    _require(claim["transaction_id"] == expected_id, "transaction identity changed")
    _require(
        isinstance(claim["claim_run_id"], str)
        and RUN_ID.fullmatch(claim["claim_run_id"]) is not None,
        "claim run ID is invalid",
    )
    _require(
        claim["preflight"]
        == {
            "git_tag_absent": True,
            "github_release_absent": True,
            "registry_version_tags_absent": {
                role: True for role in REQUIRED_IMAGE_ROLES
            },
        },
        "release preflight is incomplete",
    )
    _require(isinstance(claim["image_uris"], dict), "image URIs are invalid")
    _validate_image_uris(claim["image_uris"])
    _require(isinstance(claim["images"], dict), "image evidence is invalid")
    _require(isinstance(claim["gates"], dict), "gate evidence is invalid")
    _require(isinstance(claim["promoted_roles"], list), "promotion evidence is invalid")
    _require(
        claim["state"]
        in {
            "claimed",
            "digests_recorded",
            "qualified",
            "promoting",
            "promoted",
            "published",
            "tombstoned",
        },
        "release transaction state is invalid",
    )
    images = claim["images"]
    if images:
        _require(
            tuple(sorted(images)) == tuple(sorted(REQUIRED_IMAGE_ROLES)),
            "recorded image roles changed",
        )
        for role in REQUIRED_IMAGE_ROLES:
            image = images[role]
            _require(
                isinstance(image, dict)
                and set(image) == {"uri", "digest", "build_run_id"},
                f"{role} image evidence changed",
            )
            _require(
                image["uri"] == claim["image_uris"][role], f"{role} image URI changed"
            )
            _require(
                isinstance(image["digest"], str)
                and SHA256.fullmatch(image["digest"]) is not None,
                f"{role} image digest is invalid",
            )
            _require(
                isinstance(image["build_run_id"], str)
                and RUN_ID.fullmatch(image["build_run_id"]) is not None,
                f"{role} build run ID is invalid",
            )
    gates = claim["gates"]
    if gates:
        _require(
            tuple(sorted(gates)) == tuple(sorted(REQUIRED_GATE_ROLES)),
            "qualification gate roles changed",
        )
        for role in REQUIRED_GATE_ROLES:
            gate = gates[role]
            _require(
                isinstance(gate, dict) and set(gate) == {"run_id", "evidence_sha256"},
                f"{role} gate evidence changed",
            )
            _require(
                isinstance(gate["run_id"], str)
                and RUN_ID.fullmatch(gate["run_id"]) is not None,
                f"{role} gate run ID is invalid",
            )
            _require(
                isinstance(gate["evidence_sha256"], str)
                and SHA256.fullmatch(gate["evidence_sha256"]) is not None,
                f"{role} gate evidence digest is invalid",
            )
    promoted = claim["promoted_roles"]
    _require(
        promoted == [role for role in REQUIRED_IMAGE_ROLES if role in promoted]
        and len(promoted) == len(set(promoted)),
        "promoted image roles changed",
    )
    state = claim["state"]
    _require(
        (state == "tombstoned") == (claim["tombstone"] is not None),
        "tombstone state and evidence disagree",
    )
    _require(
        (state == "published") == (claim["publication"] is not None),
        "publication state and evidence disagree",
    )
    if state == "claimed":
        _require(
            not images and not gates and not promoted,
            "claimed transaction has later evidence",
        )
    elif state == "digests_recorded":
        _require(
            images and not gates and not promoted,
            "digest state evidence is inconsistent",
        )
    elif state == "qualified":
        _require(
            images and gates and not promoted,
            "qualified state evidence is inconsistent",
        )
    elif state == "promoting":
        _require(
            images and gates and 0 < len(promoted) < len(REQUIRED_IMAGE_ROLES),
            "promoting state evidence is inconsistent",
        )
    elif state in {"promoted", "published"}:
        _require(
            images and gates and promoted == list(REQUIRED_IMAGE_ROLES),
            "promoted state evidence is inconsistent",
        )
    if claim["publication"] is not None:
        publication = claim["publication"]
        _require(
            isinstance(publication, dict)
            and set(publication)
            == {"manifest_sha256", "publication_run_id", "release_id"},
            "publication evidence changed",
        )
        _require(
            SHA256.fullmatch(publication["manifest_sha256"]) is not None,
            "publication manifest digest is invalid",
        )
        _require(
            RUN_ID.fullmatch(publication["publication_run_id"]) is not None,
            "publication run ID is invalid",
        )
    if claim["tombstone"] is not None:
        dead = claim["tombstone"]
        _require(
            isinstance(dead, dict) and set(dead) == {"evidence_sha256", "reason"},
            "tombstone evidence changed",
        )
        _require(
            isinstance(dead["evidence_sha256"], str)
            and SHA256.fullmatch(dead["evidence_sha256"]) is not None,
            "tombstone evidence digest is invalid",
        )
        _require(
            isinstance(dead["reason"], str)
            and dead["reason"].strip() == dead["reason"]
            and 1 <= len(dead["reason"]) <= 200,
            "tombstone reason is invalid",
        )
    return claim


def validate_resume(
    value: object,
    *,
    repository: str,
    source_sha: str,
    stack_lock: Path,
    claim_run_id: str,
    required_state: str | None = None,
) -> dict[str, object]:
    claim = validate_claim(value)
    _require(claim["repository"] == repository, "resume repository changed")
    _require(claim["source_sha"] == source_sha, "resume source SHA changed")
    _require(claim["claim_run_id"] == str(claim_run_id), "resume claim run changed")
    _require(
        claim["stack_lock_sha256"] == file_digest(stack_lock),
        "resume stack lock digest changed",
    )
    if required_state is not None:
        _require(claim["state"] == required_state, "resume transaction state changed")
    return claim


def _validated_digest_map(digests: dict[str, str]) -> dict[str, dict[str, str]]:
    _require(
        tuple(sorted(digests)) == tuple(sorted(REQUIRED_IMAGE_ROLES)),
        "image digest roles must be exactly ui, services and migrations",
    )
    evidence: dict[str, dict[str, str]] = {}
    for role in REQUIRED_IMAGE_ROLES:
        digest = digests[role]
        _require(SHA256.fullmatch(digest) is not None, f"{role} digest is invalid")
        evidence[role] = {"digest": digest}
    return evidence


def record_digests(
    value: object, digests: dict[str, str], *, build_run_id: str
) -> dict[str, object]:
    claim = deepcopy(validate_claim(value))
    _require(claim["state"] != "tombstoned", "tombstoned transaction cannot be reused")
    _require(RUN_ID.fullmatch(str(build_run_id)) is not None, "build run ID is invalid")
    if claim["images"]:
        recorded = {
            role: claim["images"][role]["digest"] for role in REQUIRED_IMAGE_ROLES
        }
        _require(recorded == digests, "recorded image digests conflict")
        return claim
    _require(claim["state"] == "claimed", "image digests cannot be recorded now")
    evidence = _validated_digest_map(digests)
    for role in REQUIRED_IMAGE_ROLES:
        evidence[role]["uri"] = claim["image_uris"][role]
        evidence[role]["build_run_id"] = str(build_run_id)
    claim["images"] = evidence
    claim["state"] = "digests_recorded"
    return claim


def qualify(value: object, gates: dict[str, dict[str, str]]) -> dict[str, object]:
    claim = deepcopy(validate_claim(value))
    _require(claim["state"] != "tombstoned", "tombstoned transaction cannot be reused")
    _require(
        tuple(sorted(gates)) == tuple(sorted(REQUIRED_GATE_ROLES)),
        "qualification gates must be exactly public_stack and verifier_differential",
    )
    normalized: dict[str, dict[str, str]] = {}
    for role in REQUIRED_GATE_ROLES:
        gate = gates[role]
        _require(set(gate) == {"run_id", "evidence_sha256"}, f"{role} gate changed")
        _require(
            RUN_ID.fullmatch(gate["run_id"]) is not None, f"{role} run ID is invalid"
        )
        _require(
            SHA256.fullmatch(gate["evidence_sha256"]) is not None,
            f"{role} evidence digest is invalid",
        )
        normalized[role] = dict(sorted(gate.items()))
    if claim["gates"]:
        _require(claim["gates"] == normalized, "qualification evidence conflicts")
        return claim
    _require(claim["state"] == "digests_recorded", "release cannot be qualified now")
    claim["gates"] = normalized
    claim["state"] = "qualified"
    return claim


def record_promotion(value: object, *, role: str, digest: str) -> dict[str, object]:
    claim = deepcopy(validate_claim(value))
    _require(claim["state"] != "tombstoned", "tombstoned transaction cannot be reused")
    _require(role in REQUIRED_IMAGE_ROLES, "promotion role is invalid")
    _require(SHA256.fullmatch(digest) is not None, "promotion digest is invalid")
    _require(claim["images"], "image digests have not been recorded")
    _require(
        claim["images"][role]["digest"] == digest,
        "promotion digest conflicts with the recorded image",
    )
    promoted = claim["promoted_roles"]
    if role in promoted:
        return claim
    _require(
        claim["state"] in {"qualified", "promoting"},
        "version tags cannot be promoted now",
    )
    promoted.append(role)
    claim["promoted_roles"] = [
        item for item in REQUIRED_IMAGE_ROLES if item in promoted
    ]
    claim["state"] = (
        "promoted"
        if claim["promoted_roles"] == list(REQUIRED_IMAGE_ROLES)
        else "promoting"
    )
    return claim


def publish(
    value: object,
    *,
    release_id: str,
    manifest_sha256: str,
    publication_run_id: str,
) -> dict[str, object]:
    claim = deepcopy(validate_claim(value))
    _require(claim["state"] != "tombstoned", "tombstoned transaction cannot be reused")
    _require(release_id.strip() == release_id and release_id, "release ID is invalid")
    _require(
        SHA256.fullmatch(manifest_sha256) is not None, "manifest digest is invalid"
    )
    _require(
        RUN_ID.fullmatch(str(publication_run_id)) is not None,
        "publication run ID is invalid",
    )
    publication = {
        "manifest_sha256": manifest_sha256,
        "publication_run_id": str(publication_run_id),
        "release_id": release_id,
    }
    if claim["publication"] is not None:
        _require(claim["publication"] == publication, "publication evidence conflicts")
        return claim
    _require(
        claim["state"] == "promoted",
        "all image version tags must be promoted before release publication",
    )
    claim["publication"] = publication
    claim["state"] = "published"
    return claim


def tombstone(value: object, *, reason: str, evidence_sha256: str) -> dict[str, object]:
    claim = deepcopy(validate_claim(value))
    _require(
        reason.strip() == reason and 1 <= len(reason) <= 200,
        "tombstone reason is invalid",
    )
    _require(
        SHA256.fullmatch(evidence_sha256) is not None, "tombstone evidence is invalid"
    )
    tombstone_value = {"evidence_sha256": evidence_sha256, "reason": reason}
    if claim["state"] == "tombstoned":
        _require(claim["tombstone"] == tombstone_value, "tombstone evidence conflicts")
        return claim
    _require(claim["state"] != "published", "a published release cannot be tombstoned")
    claim["tombstone"] = tombstone_value
    claim["state"] = "tombstoned"
    return claim


def _load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseTransactionError(
            "release transaction is unreadable or invalid"
        ) from error
    return validate_claim(value)


def _write(path: Path, value: dict[str, object]) -> None:
    validate_claim(value)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _assignments(values: list[str], *, expected: tuple[str, ...]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        _require(separator == "=" and key and item, "assignment must be NAME=VALUE")
        _require(key not in output, f"duplicate assignment for {key}")
        output[key] = item
    _require(
        tuple(sorted(output)) == tuple(sorted(expected)), "assignment roles changed"
    )
    return output


def _gate_assignments(values: list[str]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for value in values:
        role, separator, payload = value.partition("=")
        parts = payload.split(":", 2)
        _require(
            separator == "=" and len(parts) == 3 and parts[1] == "sha256",
            "gate must be ROLE=RUN_ID:sha256:DIGEST",
        )
        run_id, _, digest = parts
        _require(role not in output, f"duplicate gate for {role}")
        output[role] = {"run_id": run_id, "evidence_sha256": f"sha256:{digest}"}
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    claim = subparsers.add_parser("claim")
    claim.add_argument("--repository", required=True)
    claim.add_argument("--tag", required=True)
    claim.add_argument("--source-sha", required=True)
    claim.add_argument("--stack-lock", type=Path, required=True)
    claim.add_argument("--claim-run-id", required=True)
    claim.add_argument("--image", action="append", default=[], required=True)
    claim.add_argument("--tag-absent", action="store_true")
    claim.add_argument("--release-absent", action="store_true")
    claim.add_argument("--version-tag-absent", action="append", default=[])
    claim.add_argument("--output", type=Path, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--input", type=Path, required=True)
    validate.add_argument("--repository", required=True)
    validate.add_argument("--source-sha", required=True)
    validate.add_argument("--stack-lock", type=Path, required=True)
    validate.add_argument("--claim-run-id", required=True)
    validate.add_argument("--required-state")
    validate.add_argument("--output", type=Path, required=True)

    digests = subparsers.add_parser("record-digests")
    digests.add_argument("--input", type=Path, required=True)
    digests.add_argument("--digest", action="append", default=[], required=True)
    digests.add_argument("--build-run-id", required=True)
    digests.add_argument("--output", type=Path, required=True)

    qualification = subparsers.add_parser("qualify")
    qualification.add_argument("--input", type=Path, required=True)
    qualification.add_argument("--gate", action="append", default=[], required=True)
    qualification.add_argument("--output", type=Path, required=True)

    promotion = subparsers.add_parser("record-promotion")
    promotion.add_argument("--input", type=Path, required=True)
    promotion.add_argument("--role", required=True)
    promotion.add_argument("--digest", required=True)
    promotion.add_argument("--output", type=Path, required=True)

    publication = subparsers.add_parser("publish")
    publication.add_argument("--input", type=Path, required=True)
    publication.add_argument("--release-id", required=True)
    publication.add_argument("--manifest-sha256", required=True)
    publication.add_argument("--publication-run-id", required=True)
    publication.add_argument("--output", type=Path, required=True)

    dead = subparsers.add_parser("tombstone")
    dead.add_argument("--input", type=Path, required=True)
    dead.add_argument("--reason", required=True)
    dead.add_argument("--evidence-sha256", required=True)
    dead.add_argument("--output", type=Path, required=True)
    return parser


def main(args: argparse.Namespace) -> None:
    if args.command == "claim":
        image_uris = _assignments(args.image, expected=REQUIRED_IMAGE_ROLES)
        version_absence = {
            role: True
            for role, value in _assignments(
                args.version_tag_absent, expected=REQUIRED_IMAGE_ROLES
            ).items()
            if value == "true"
        }
        value = create_claim(
            repository=args.repository,
            tag=args.tag,
            source_sha=args.source_sha,
            stack_lock=args.stack_lock,
            claim_run_id=args.claim_run_id,
            image_uris=image_uris,
            tag_absent=args.tag_absent,
            release_absent=args.release_absent,
            version_tags_absent=version_absence,
        )
    elif args.command == "validate":
        value = validate_resume(
            _load(args.input),
            repository=args.repository,
            source_sha=args.source_sha,
            stack_lock=args.stack_lock,
            claim_run_id=args.claim_run_id,
            required_state=args.required_state,
        )
    elif args.command == "record-digests":
        value = record_digests(
            _load(args.input),
            _assignments(args.digest, expected=REQUIRED_IMAGE_ROLES),
            build_run_id=args.build_run_id,
        )
    elif args.command == "qualify":
        value = qualify(_load(args.input), _gate_assignments(args.gate))
    elif args.command == "record-promotion":
        value = record_promotion(_load(args.input), role=args.role, digest=args.digest)
    elif args.command == "publish":
        value = publish(
            _load(args.input),
            release_id=args.release_id,
            manifest_sha256=args.manifest_sha256,
            publication_run_id=args.publication_run_id,
        )
    else:
        value = tombstone(
            _load(args.input),
            reason=args.reason,
            evidence_sha256=args.evidence_sha256,
        )
    _write(args.output, value)


def _fatal(message: str) -> NoReturn:
    raise SystemExit(f"release transaction failed: {message}")


if __name__ == "__main__":
    try:
        main(_parser().parse_args())
    except ReleaseTransactionError as error:
        _fatal(str(error))
