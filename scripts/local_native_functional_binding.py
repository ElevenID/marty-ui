"""Validate a closed, cached native binary overlay for local OIDF feedback.

This is developer feedback only. It never changes release or conformance status.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROLES = {
    "auth": "marty-auth",
    "gateway": "marty-gateway",
    "signing-keys": "marty-signing-keys",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _private_reference(value: Any, label: str) -> tuple[Path, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError(f"{label} must have only path and sha256")
    raw_path, expected = value["path"], value["sha256"]
    if not isinstance(raw_path, str) or not raw_path or any(ord(ch) < 32 for ch in raw_path):
        raise ValueError(f"{label} path is invalid")
    path = Path(raw_path)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be an existing absolute regular file")
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise ValueError(f"{label} sha256 is invalid")
    if _file_hash(path) != expected:
        raise ValueError(f"{label} sha256 mismatch")
    return path, expected


def _source_proof_matches(role: str, binary: str, source_revision: str,
                          binary_path: Path, binary_sha: str, proof_path: Path) -> None:
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    if not isinstance(proof, dict):
        raise ValueError(f"{role} source proof is invalid")
    if role == "auth":
        actual_binary = proof.get("binary")
        valid = (
            proof.get("schema") == "marty.d05-auth-native-overlay-source-proof/v1"
            and proof.get("sourceCommit") == source_revision
            and isinstance(proof.get("acceptedCommit"), str)
            and HEX40.fullmatch(proof["acceptedCommit"])
            and proof.get("executionHeld") is True
            and proof.get("mutation") is False
            and isinstance(actual_binary, dict)
            and actual_binary.get("sha256") == binary_sha
            and actual_binary.get("target") == "/usr/local/bin/marty-auth"
            and Path(str(actual_binary.get("path", ""))).resolve() == binary_path.resolve()
        )
    else:
        actual_binary = proof.get("binaries", {}).get(binary) if isinstance(proof.get("binaries"), dict) else None
        valid = (
            proof.get("state") == "BUILD_SUCCEEDED"
            and proof.get("uiRevision") == source_revision
            and type(proof.get("exitCode")) is int and proof["exitCode"] == 0
            and proof.get("oomKilled") is False
            and proof.get("releaseQualified") is False
            and isinstance(proof.get("roleBinaries"), dict)
            and proof["roleBinaries"].get(role) == binary
            and isinstance(actual_binary, dict)
            and actual_binary.get("sha256") == binary_sha
            and Path(str(actual_binary.get("path", ""))).resolve() == binary_path.resolve()
        )
    if not valid:
        raise ValueError(f"{role} source proof does not bind the selected binary and revision")


def load_binding(path: Path, *, services_image_id: str | None = None) -> tuple[dict[str, Path], str]:
    """Bind three exact binaries to same-image UID and loader receipts."""
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError("binding must be an existing absolute regular file")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"schema", "state", "roles"}:
        raise ValueError("binding fields are not closed")
    if data["schema"] != "elevenid.local-native-functional-binding/v1" or data["state"] != "FUNCTIONAL_ONLY":
        raise ValueError("binding scope is not local functional only")
    roles = data["roles"]
    if not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise ValueError("binding must include exactly auth, gateway and signing-keys")
    result: dict[str, Path] = {}
    attested_image_ids: set[str] = set()
    for role, binary in ROLES.items():
        row = roles[role]
        if not isinstance(row, dict) or set(row) != {"binary", "sourceRevision", "sourceProof", "abiResult"}:
            raise ValueError(f"{role} binding fields are not closed")
        source_revision = row["sourceRevision"]
        if not isinstance(source_revision, str) or not HEX40.fullmatch(source_revision):
            raise ValueError(f"{role} source revision is invalid")
        source_proof, _ = _private_reference(row["sourceProof"], f"{role} source proof")
        binary_path, binary_sha = _private_reference(row["binary"], f"{role} binary")
        _source_proof_matches(role, binary, source_revision, binary_path, binary_sha, source_proof)
        abi_path, _ = _private_reference(row["abiResult"], f"{role} ABI result")
        abi = json.loads(abi_path.read_text(encoding="utf-8"))
        if abi.get("schema") != 1 or abi.get("state") != "ELF_LOADER_UID_COMPATIBILITY_PASS":
            raise ValueError(f"{role} ABI result did not pass")
        if (abi.get("candidateServiceEntrypointExecuted") is not False
                or abi.get("signingOrApi") is not False
                or abi.get("runtimeDeployed") is not False):
            raise ValueError(f"{role} ABI receipt is not a loader-only proof")
        matches = [item for item in abi.get("rows", []) if isinstance(item, dict) and item.get("binary") == binary]
        if len(matches) != 1:
            raise ValueError(f"{role} ABI row must be unique")
        proof = matches[0]
        image_id = proof.get("imageId")
        if proof.get("sha256") != binary_sha or not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError(f"{role} binary or image differs from ABI proof")
        attested_image_ids.add(image_id)
        if (any(type(proof.get(key)) is not int or proof[key] != expected
                for key, expected in {"uid": 10001, "gid": 10001, "exitCode": 0}.items())
                or any(proof.get(key) is not True for key in (
                    "candidateReadableExecutable", "loaderListSucceeded", "ownedContainerRemoved"
                ))):
            raise ValueError(f"{role} UID or loader proof failed")
        result[role] = binary_path
    if len(attested_image_ids) != 1:
        raise ValueError("native binaries lack one common attested services image")
    attested_image_id = attested_image_ids.pop()
    if services_image_id is not None and services_image_id != attested_image_id:
        raise ValueError("cached services image differs from ABI proof")
    return result, attested_image_id
