#!/usr/bin/env python3
"""Check optional Agent Trust source integrity and fixture shapes offline.

The independently reviewed consumer lock is trusted input. The Protocol checkout
is data: no upstream module, test, generator, hook or manifest path is executed.
The only child process is a fixed, local Git revision query. This is not an
authentication verifier, semantic reference runner or runtime qualification gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from typing import Any
from urllib.parse import urljoin, urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "contracts/agent-trust-protocol-consumer.json"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
MANIFEST_PATH = "conformance/agent-trust/v1/manifest.json"
REGISTER_PATH = "protocol/agent-trust/capability-register.json"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PACK_BYTES = 64 * 1024 * 1024
MAX_FILES = 4096

# Reviewed consumer policy, not imported from the source checkout or controlled
# by a submitted manifest. Keep in step with the selected, versioned source pack.
SOURCE_DIRECTORIES = (
    "docs/decisions", "protocol", "schemas", "enums",
    "reference/agent_trust", "reference/delegated_authority",
    "reference/principal_runtime_binding", "conformance/agent-trust/v1",
    "conformance/delegated-authority/v1", "conformance/principal-runtime-binding/v1",
    "tests/delegated_authority", "tests/principal_runtime_binding",
)
SOURCE_FILES = (
    ".github/workflows/delegated-authority.yml", "SPECIFICATION.md", "VERSIONING.md",
    "docs/format-mapping.md", "docs/migration-guide.md",
    "conformance/valid/mip-configuration.json", "pyproject.toml", "uv.lock",
    "scripts/agent-trust-manifest.py", "tests/__init__.py", "tests/helpers.py",
    "tests/test_agent_trust_catalog.py", "tests/test_agent_trust_manifest.py",
    "tests/test_agent_trust_profiles.py",
)
SELECTED_SCHEMAS = {
    "principal-runtime-binding.v1": [
        "schemas/principal-runtime-binding/v1/binding-record.json",
        "schemas/principal-runtime-binding/v1/profile-configuration.json",
    ],
    "delegated-commands.v1": [
        "schemas/delegated-authority/v1/command-request.json",
        "schemas/delegated-authority/v1/command-response.json",
    ],
    "oauth-account-linking.v1": [
        "schemas/agent-trust/v1/oauth-context.json", "schemas/agent-trust/v1/account-link.json",
    ],
    "authzen-mapping.v1": ["schemas/agent-trust/v1/authzen-decision.json"],
    "lifecycle-signals.v1": ["schemas/agent-trust/v1/security-event-impact.json"],
    "credential-evidence.v1": [
        "schemas/agent-trust/v1/domain-evidence-binding.json",
        "schemas/agent-trust/v1/portable-trust-manifest.json",
    ],
}
LOCK_CONSTANTS = {
    "schema_version": 1, "consumer": "marty-ui-agent-trust-source", "status": "SOURCE_ONLY",
    "runtime_qualification": "NOT_ASSESSED", "public_discovery": False,
    "public_mip_version": "0.5.0",
    "public_protocol_revision": "76c37dc229b328afe002b911a26624543f814a64",
    "coverage_policy": "marty-agent-trust-source-pack-v1", "fixture_policy": "schema-shapes-v1",
}
MANIFEST_CONSTANTS = {
    "manifest_version": 1, "pack_id": "urn:marty:agent-trust-conformance-pack:v1",
    "status": "DRAFT_REFERENCE", "runtime_qualification": "NOT_ASSESSED",
    "public_discovery": False, "digest_algorithm": "sha256",
}
PRINCIPAL_SEMANTIC_ERRORS = frozenset({
    "TENANT_MISMATCH", "PRINCIPAL_MISMATCH", "SOURCE_IDENTITY_MISMATCH",
    "AUDIENCE_MISMATCH", "RUNTIME_MISMATCH", "KEY_BINDING_MISMATCH",
    "NON_CANONICAL_ENCODING", "MISSING_SUBJECT_SESSION", "SESSION_BINDING_MISMATCH",
    "MISSING_MACHINE_STATE", "INACTIVE_MACHINE", "MACHINE_IDENTITY_MISMATCH",
    "ACTIVE_KEY_MISMATCH", "REGISTERED_KEY_MISMATCH", "EXTERNAL_MACHINE_ENROLLMENT",
    "SELECTED_ALGORITHM_MISMATCH", "ACTIVE_KEY_ALGORITHM_MISMATCH",
    "DEPLOYMENT_ASSIGNMENT_MISMATCH", "PRIVATE_KEY_MATERIAL", "SESSION_RUNTIME_MISMATCH",
})


class ConsumerCheckError(ValueError):
    """A source, contract or structural conformance check failed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConsumerCheckError(message)


def _constants(document: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    for key, value in expected.items():
        _require(type(document.get(key)) is type(value) and document[key] == value,
                 f"{label}: invalid {key}")


def decode_json(raw: bytes, label: str) -> dict[str, Any]:
    """Bounded strict JSON; duplicate members and nonfinite numbers are errors."""
    _require(len(raw) <= MAX_JSON_BYTES, f"{label}: JSON exceeds limit")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            _require(key not in result, f"{label}: duplicate JSON member")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ConsumerCheckError(f"{label}: nonfinite JSON number")

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ConsumerCheckError(f"{label}: invalid strict JSON") from exc
    _require(isinstance(document, dict), f"{label}: expected an object")
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        _require(depth <= 64, f"{label}: excessive JSON nesting")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, float):
            _require(math.isfinite(value), f"{label}: nonfinite JSON number")
    return document


def local_path(root: Path, relative: str, *, directory: bool = False) -> Path:
    _require(isinstance(relative, str), "source path must be a string")
    path = PurePosixPath(relative)
    _require(bool(path.parts) and not path.is_absolute() and str(path) == relative
             and all(part not in (".", "..") for part in path.parts)
             and re.fullmatch(r"[A-Za-z0-9_./-]{1,512}", relative) is not None,
             "source path must be canonical and repository-relative")
    current = root
    try:
        for part in path.parts:
            current = current / part
            _require(not stat.S_ISLNK(current.lstat().st_mode), "symlinked source path")
        mode = current.stat().st_mode
        _require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode),
                 "source path has the wrong file type")
        _require(current.resolve().is_relative_to(root.resolve()), "source path escapes root")
    except OSError as exc:
        raise ConsumerCheckError(f"missing or unreadable source path: {relative}") from exc
    return current


def _read(root: Path, relative: str) -> bytes:
    path = local_path(root, relative)
    try:
        _require(path.stat().st_size <= MAX_FILE_BYTES, "source file exceeds size limit")
        with path.open("rb") as handle:
            content = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ConsumerCheckError(f"unreadable source file: {relative}") from exc
    _require(len(content) <= MAX_FILE_BYTES, "source file exceeds size limit")
    return content


def validate_lock(document: dict[str, Any]) -> None:
    _require(isinstance(document, dict)
             and set(document) == {*LOCK_CONSTANTS, "protocol", "selected_profiles"},
             "consumer lock has unknown or missing fields")
    _constants(document, LOCK_CONSTANTS, "consumer lock")
    protocol = document["protocol"]
    _require(isinstance(protocol, dict) and set(protocol) == {
        "repository", "revision", "version", "manifest_path", "manifest_sha256",
        "capability_register_path",
    }, "consumer protocol pin has unknown or missing fields")
    _constants(protocol, {
        "repository": "https://github.com/Marty-Protocol/Marty-Protocol", "version": "0.6.0",
        "manifest_path": MANIFEST_PATH, "capability_register_path": REGISTER_PATH,
    }, "consumer protocol pin")
    for key, size in (("revision", 40), ("manifest_sha256", 64)):
        _require(isinstance(protocol[key], str)
                 and re.fullmatch(rf"[0-9a-f]{{{size}}}", protocol[key]) is not None,
                 f"consumer protocol pin requires immutable {key}")
    profiles = document["selected_profiles"]
    _require(isinstance(profiles, list) and len(profiles) == len(SELECTED_SCHEMAS),
             "consumer profile selection differs from reviewed policy")
    selected = {}
    for profile in profiles:
        _require(isinstance(profile, dict) and set(profile) == {"id", "schemas"},
                 "consumer profile has unknown or missing fields")
        identifier = profile["id"]
        _require(isinstance(identifier, str) and identifier not in selected,
                 "consumer profile selection is duplicated or invalid")
        selected[identifier] = profile["schemas"]
    _require(selected == SELECTED_SCHEMAS, "consumer profile selection differs from reviewed policy")


def verify_revision(root: Path, expected: str) -> None:
    """Use only Git's local revision parser; never run checkout-provided code."""
    executable = shutil.which("git")
    _require(executable is not None, "Git is required to verify the pinned source revision")
    # Remove inherited Git overrides, alternate object directories and config
    # injection. rev-parse neither runs hooks nor contacts a remote.
    environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT") if key in os.environ}
    environment.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    try:
        result = subprocess.run(
            [executable, "--no-replace-objects", "-c", f"core.hooksPath={os.devnull}",
             "-c", "core.fsmonitor=false", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False, env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConsumerCheckError("cannot read the local Protocol revision") from exc
    _require(result.returncode == 0 and result.stdout.strip() == expected,
             "Protocol checkout is not at the independently pinned revision")


def source_inventory(root: Path) -> list[str]:
    def unreadable(_: OSError) -> None:
        raise ConsumerCheckError("unreadable source directory")

    selected = set(SOURCE_FILES)
    for relative in SOURCE_DIRECTORIES:
        base = local_path(root, relative, directory=True)
        for current, directories, filenames in os.walk(base, followlinks=False, onerror=unreadable):
            for name in directories:
                _require(not (Path(current) / name).is_symlink(), "symlinked source directory")
            directories[:] = [name for name in directories if name != "__pycache__"]
            for name in filenames:
                path = (Path(current) / name).relative_to(root).as_posix()
                if path != MANIFEST_PATH:
                    selected.add(path)
                    _require(len(selected) <= MAX_FILES, "source inventory exceeds limit")
    for path in selected:
        local_path(root, path)
    return sorted(selected)


def verify_source_pack(root: Path, protocol: dict[str, Any]) -> dict[str, bytes]:
    """Read verified bytes once; schema work uses this snapshot, not a reread."""
    raw = _read(root, MANIFEST_PATH)
    _require(hashlib.sha256(raw).hexdigest() == protocol["manifest_sha256"],
             "source manifest differs from the independent consumer pin")
    manifest = decode_json(raw, "source manifest")
    _require(set(manifest) == {*MANIFEST_CONSTANTS, "files"}, "source manifest has unknown fields")
    _constants(manifest, MANIFEST_CONSTANTS, "source manifest")
    entries = manifest["files"]
    _require(isinstance(entries, list) and 0 < len(entries) <= MAX_FILES, "invalid source inventory")
    paths = []
    for entry in entries:
        _require(isinstance(entry, dict) and set(entry) == {"path", "sha256"}, "invalid source entry")
        local_path(root, entry["path"])
        _require(isinstance(entry["sha256"], str)
                 and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
                 "invalid source entry digest")
        paths.append(entry["path"])
    _require(paths == source_inventory(root), "source pack coverage differs from fixed consumer policy")
    snapshot: dict[str, bytes] = {}
    total = 0
    for entry in entries:
        content = _read(root, entry["path"])
        total += len(content)
        _require(total <= MAX_PACK_BYTES, "source pack exceeds size limit")
        _require(hashlib.sha256(content).hexdigest() == entry["sha256"],
                 f"source digest mismatch: {entry['path']}")
        snapshot[entry["path"]] = content
    _require(paths == source_inventory(root), "source inventory changed during verification")
    _require(_read(root, MANIFEST_PATH) == raw, "source manifest changed during verification")
    return snapshot


def _deny_retrieval(uri: str) -> Resource:
    raise NoSuchResource(ref=uri)


def schema_registry(snapshot: dict[str, bytes], *, selected_paths: tuple[str, ...] | None = None
                    ) -> tuple[dict[str, dict[str, Any]], Registry]:
    """Validate the selected schemas and their full local reference closure.

    All source bytes are integrity checked first. Unrelated core schema/enum
    documents are not advertised as structurally checked by this optional gate.
    """
    schemas: dict[str, dict[str, Any]] = {}
    registry = Registry(retrieve=_deny_retrieval)
    ids: dict[str, str] = {}
    try:
        for path, raw in sorted(snapshot.items()):
            if not path.startswith(("schemas/", "enums/")) or not path.endswith(".json"):
                continue
            schema = decode_json(raw, path)
            _require(schema.get("$schema") == DRAFT, "unsupported schema dialect")
            identifier = schema.get("$id")
            _require(isinstance(identifier, str) and identifier not in ids
                     and identifier.startswith("https://protocol.elevenid.io/")
                     and not urlsplit(identifier).fragment, "invalid or duplicate bundled schema ID")
            ids[identifier] = path
            schemas[path] = schema
        _require(bool(schemas), "verified pack contains no schemas")
        if selected_paths is None:
            selected_paths = tuple(path for paths in SELECTED_SCHEMAS.values() for path in paths) + (
                "schemas/agent-trust/v1/capability-register.json", "schemas/machine-identity.json",
            )
        remaining = list(selected_paths)
        checked: dict[str, dict[str, Any]] = {}
        references: list[tuple[str, str]] = []
        # Check even unexercised branches. A resolver failure must never be
        # counted as the intended rejection of a negative fixture.
        while remaining:
            path = remaining.pop()
            if path in checked:
                continue
            _require(path in schemas, "selected schema is outside the verified pack")
            schema = schemas[path]
            Draft202012Validator.check_schema(schema)
            checked[path] = schema
            pending = [(schema, schema["$id"])]
            while pending:
                value, base = pending.pop()
                if isinstance(value, dict):
                    if "$id" in value:
                        base = urljoin(base, value["$id"])
                    for keyword in ("$ref", "$dynamicRef"):
                        if keyword in value:
                            target = urlsplit(urljoin(base, value[keyword]))._replace(fragment="").geturl()
                            _require(target in ids, "reference has no bundled root schema")
                            references.append((base, value[keyword]))
                            if ids[target] not in checked:
                                remaining.append(ids[target])
                    pending.extend((child, base) for child in value.values())
                elif isinstance(value, list):
                    pending.extend((child, base) for child in value)
        # Register only the checked closure. Unrelated metadata must not be
        # crawled as a schema, and never supplies a fallback for an unknown ref.
        for schema in checked.values():
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
        for base, reference in references:
            registry.resolver(base).lookup(reference)
    except (SchemaError, Unresolvable, NoSuchResource, TypeError, ValueError) as exc:
        raise ConsumerCheckError("bundled schema or reference is invalid; no network retrieval is allowed") from exc
    return checked, registry


def _errors(schema: dict[str, Any], document: Any, registry: Registry) -> list[Any]:
    try:
        return list(Draft202012Validator(schema, registry=registry,
                                        format_checker=FormatChecker()).iter_errors(document))
    except (Unresolvable, NoSuchResource, ValueError) as exc:
        raise ConsumerCheckError("schema resolution failed, not an expected fixture rejection") from exc


def _json(snapshot: dict[str, bytes], path: str) -> dict[str, Any]:
    _require(path in snapshot, f"required source is not covered: {path}")
    return decode_json(snapshot[path], path)


def _sidecar(snapshot: dict[str, bytes], path: str) -> dict[str, Any]:
    sidecar = _json(snapshot, path.removesuffix(".json") + ".expected.json")
    _require(set(sidecar) == {"error_type", "field_path", "spec_reference"}
             and all(isinstance(value, str) and 0 < len(value) <= 2048 for value in sidecar.values()),
             "invalid expected-rejection sidecar")
    reference = urlsplit(sidecar["spec_reference"])
    _require(not reference.scheme and not reference.netloc and not reference.query
             and bool(reference.fragment) and reference.path.startswith("protocol/")
             and reference.path in snapshot, "sidecar specification is outside the verified pack")
    return sidecar


def _cases(snapshot: dict[str, bytes], directory: str) -> list[str]:
    prefix = directory + "/"
    cases = sorted(path for path in snapshot if path.startswith(prefix)
                   and "/" not in path[len(prefix):] and path.endswith(".json")
                   and not path.endswith(".expected.json"))
    _require(bool(cases), f"no fixtures in {directory}")
    if directory.endswith("/invalid"):
        expected = {path.removesuffix(".json") + ".expected.json" for path in cases}
        actual = {path for path in snapshot if path.startswith(prefix) and path.endswith(".expected.json")}
        _require(actual == expected, "negative fixture/sidecar coverage differs")
    return cases


def check_fixture_shapes(snapshot: dict[str, bytes], schemas: dict[str, dict[str, Any]],
                         registry: Registry) -> dict[str, Any]:
    accepted = rejected = 0
    semantic_not_executed = []
    agent_prefix = "schemas/agent-trust/v1/"
    agent_names = tuple(Path(path).stem for paths in SELECTED_SCHEMAS.values()
                        for path in paths if path.startswith(agent_prefix))
    for kind in ("valid", "invalid"):
        for path in _cases(snapshot, f"conformance/agent-trust/v1/{kind}"):
            matches = [name for name in agent_names if Path(path).stem.startswith(name + "-")]
            _require(len(matches) == 1, "fixture has no selected agent-trust schema")
            errors = _errors(schemas[f"{agent_prefix}{matches[0]}.json"], _json(snapshot, path), registry)
            if kind == "invalid":
                _require(_sidecar(snapshot, path)["error_type"] == "schema", "unexpected fixture error kind")
                _require(bool(errors), f"negative schema fixture was accepted: {path}")
                rejected += 1
            else:
                _require(not errors, f"positive schema fixture was rejected: {path}")
                accepted += 1

    commands = "conformance/delegated-authority/v1/commands"
    for kind in ("valid", "responses", "invalid"):
        name = "command-response" if kind == "responses" else "command-request"
        schema = schemas[f"schemas/delegated-authority/v1/{name}.json"]
        for path in _cases(snapshot, f"{commands}/{kind}"):
            errors = _errors(schema, _json(snapshot, path), registry)
            if kind == "invalid":
                _require(_sidecar(snapshot, path)["error_type"] == "schema_violation", "unexpected command error kind")
                _require(bool(errors), f"negative command fixture was accepted: {path}")
                rejected += 1
            else:
                _require(not errors, f"positive command fixture was rejected: {path}")
                accepted += 1

    principals = "conformance/principal-runtime-binding/v1"
    manifest = _json(snapshot, f"{principals}/manifest.json")
    _require(set(manifest) == {"profile", "status", "valid", "invalid", "vectors"},
             "unexpected principal fixture inventory")
    _constants(manifest, {"profile": "urn:marty:principal-runtime-binding:v1",
                         "status": "REFERENCE_ONLY_NOT_RUNTIME_QUALIFIED"}, "principal fixtures")
    for vector in manifest["vectors"]:
        _require(isinstance(vector, str) and f"{principals}/{vector}" in snapshot,
                 "principal vector is outside the verified pack")
    for kind in ("valid", "invalid"):
        cases = _cases(snapshot, f"{principals}/{kind}")
        _require(isinstance(manifest[kind], list)
                 and sorted(f"{principals}/{name}" for name in manifest[kind]) == cases,
                 "principal fixture coverage differs from its pinned inventory")
        for path in cases:
            fixture = _json(snapshot, path)
            _require({"record", "configuration"} <= set(fixture)
                     <= {"record", "configuration", "machine_identity", "expected_session"},
                     "unexpected principal fixture envelope")
            errors = []
            for field, name in (("record", "binding-record"), ("configuration", "profile-configuration")):
                errors.extend(_errors(schemas[f"schemas/principal-runtime-binding/v1/{name}.json"],
                                      fixture[field], registry))
            if "machine_identity" in fixture:
                errors.extend(_errors(schemas["schemas/machine-identity.json"], fixture["machine_identity"], registry))
            if "expected_session" in fixture:
                errors.extend(_errors({"$ref": schemas["schemas/principal-runtime-binding/v1/binding-record.json"]["$id"]
                                       + "#/$defs/session"}, fixture["expected_session"], registry))
            if kind == "valid":
                _require(not errors, f"positive principal shape was rejected: {path}")
                accepted += 1
            else:
                expected = _sidecar(snapshot, path)["error_type"]
                if expected == "SCHEMA_INVALID":
                    _require(bool(errors), f"negative principal shape was accepted: {path}")
                    rejected += 1
                else:
                    _require(expected in PRINCIPAL_SEMANTIC_ERRORS and not errors,
                             "principal semantic fixture has unexpected schema/error semantics")
                    semantic_not_executed.append(path)
    return {"positive_schema_fixtures": accepted, "negative_schema_fixtures": rejected,
            "semantic_fixture_shapes_only": len(semantic_not_executed),
            "semantic_conformance": "NOT_EXECUTED"}


def check_consumer(protocol_root: Path, *, lock_path: Path = LOCK_PATH) -> dict[str, Any]:
    """Read the consumer-owned lock; never accept trust pins from the Protocol tree."""
    lock = decode_json(lock_path.read_bytes(), "consumer lock")
    validate_lock(lock)
    _require(not protocol_root.is_symlink(), "Protocol root cannot be a symlink")
    root = protocol_root.resolve(strict=True)
    protocol = lock["protocol"]
    verify_revision(root, protocol["revision"])
    snapshot = verify_source_pack(root, protocol)
    try:
        metadata = tomllib.loads(snapshot["pyproject.toml"].decode("utf-8"))
        _require(metadata.get("project", {}).get("version") == protocol["version"],
                 "Protocol package version differs from the optional consumer pin")
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConsumerCheckError("invalid Protocol package metadata") from exc
    schemas, registry = schema_registry(snapshot)
    register = _json(snapshot, REGISTER_PATH)
    _require(not _errors(schemas["schemas/agent-trust/v1/capability-register.json"], register, registry),
             "invalid source capability register")
    profiles = {profile["id"]: profile for profile in register["profiles"]}
    _require(len(profiles) == len(register["profiles"]), "duplicate source profile ID")
    for identifier, selected in SELECTED_SCHEMAS.items():
        _require(identifier in profiles, "selected source profile is absent")
        profile = profiles[identifier]
        _require(profile["implementation_status"] == "REFERENCE_MODEL"
                 and profile["schemas"] == selected
                 and set(profile["depends_on"]) <= SELECTED_SCHEMAS.keys(),
                 "selected source profile/dependency mapping differs")
        for field in ("specifications", "schemas", "reference_modules", "test_targets"):
            _require(set(profile[field]) <= snapshot.keys(), "selected profile source is outside the pack")
    counts = check_fixture_shapes(snapshot, schemas, registry)
    return {"protocol_revision": protocol["revision"], "protocol_version": protocol["version"],
            "verified_source_files": len(snapshot), "verified_schema_documents": len(schemas),
            "selected_profiles": len(SELECTED_SCHEMAS), **counts,
            "runtime_qualification": "NOT_ASSESSED", "public_discovery": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol-root", required=True, type=Path,
                        help="local checkout at the independently pinned optional Protocol revision")
    args = parser.parse_args()
    try:
        result = check_consumer(args.protocol_root)
    except (ConsumerCheckError, OSError) as exc:
        print(f"Agent Trust source-consumer check failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
