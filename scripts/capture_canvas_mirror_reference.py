"""Capture pinned Canvas mirror HTTP and distinct automation-loop behavior.

Controlled frozen memory repository and HTTP peers, not PG/deployed parity.
No application checkout imports, operator configuration, network or crypto.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import builtins
from contextlib import contextmanager
import copy
import dataclasses
import dis
from datetime import UTC, datetime
import hashlib
import importlib
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import CodeType, FunctionType, ModuleType, SimpleNamespace
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
REVISION = "aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26"
ROUTES = "issuance.infrastructure.api.routes"
ADAPTER = "issuance.infrastructure.adapters.canvas_credentials_adapter"
SOURCES = {
    ROUTES: (
        "services/issuance/infrastructure/api/routes.py",
        "f71dd82163fcb2296209f880fe78d55a130d356b",
    ),
    ADAPTER: (
        "services/issuance/infrastructure/adapters/canvas_credentials_adapter.py",
        "c86671e2b2ab5bb8a72de78a9bdadb0f340a5ec8",
    ),
    "issuance.domain.entities": (
        "services/issuance/domain/entities.py",
        "1b5e2eba90c1ec13c1a38135f4da92813f1d1073",
    ),
    "issuance.domain.ports": (
        "services/issuance/domain/ports.py",
        "3454e78deb21af39a1d842ebfed3d8899aa69325",
    ),
    "issuance.infrastructure.adapters.memory_repository": (
        "services/issuance/infrastructure/adapters/memory_repository.py",
        "b9c65f5b35eebe1de9392491b8e3595396ff6565",
    ),
    "issuance.infrastructure.adapters.delivery_records": (
        "services/issuance/infrastructure/adapters/delivery_records.py",
        "eda21f907f3abd1e4652e06400f5a6dcf424952f",
    ),
    "issuance.application.canvas_feature_flags": (
        "services/issuance/application/canvas_feature_flags.py",
        "0fd22c63f09641f886d6c7c4bad5d16393fabe92",
    ),
    "issuance.application.canvas_runtime": (
        "services/issuance/application/canvas_runtime.py",
        "ae2874fb057e19db7cfd6b28dc39a77eba02c3fb",
    ),
    "issuance.application.canvas_lti_services": (
        "services/issuance/application/canvas_lti_services.py",
        "6bde953e9be8c01b51e622668a2cf9fc016f581d",
    ),
    "issuance.application.credential_vct": (
        "services/issuance/application/credential_vct.py",
        "bff0c6bf046e7df15447350d0e4bcc645b8e28d2",
    ),
    "mirror_seed": (
        "tests/test_issuance_changes.py",
        "7ab0a410bd6a4b4507ddd535365fadf7f3dbac03",
    ),
    "startup_evidence": (
        "services/issuance/main.py",
        "d2c7135bffc8d3ea8184233626b7e573f1fb837d",
    ),
    "release_profile": (
        "services/Dockerfile",
        "13bcb60f46601303b0f524427d9d5aa6bce927d9",
    ),
}
RELEASE_IMAGE = "ghcr.io/elevenid/marty-credentials-issuance"
RELEASE_IMAGE_DIGEST = (
    "sha256:815cbba6efc7c91e770a8dd15fe5fa102d252a485073bf60f0e0d5e0a73b28e5"
)
RELEASE_DEPENDENCIES = {
    "fastapi": "0.109.0",
    "pydantic": "2.11.7",
    "httpx": "0.26.0",
}
OPERATIONS = (
    "publish_issued_credential_canvas_mirror",
    "process_pending_canvas_mirror_deliveries",
    "process_failed_canvas_mirror_status_syncs",
    "run_canvas_mirror_automation_cycle_endpoint",
    "get_canvas_mirror_health",
    "get_canvas_mirror_provenance",
)
REFERENCE = ROOT / "contracts/canvas-mirror-python-reference.json"
SCENARIOS = ROOT / "contracts/canvas-mirror-scenarios.json"
ADAPTER_SCENARIOS = ROOT / "contracts/canvas-mirror-adapter-scenarios.json"
ADAPTER_REFERENCE = ROOT / "contracts/canvas-mirror-adapter-reference.json"
PUBLICATION_BOUNDARY_SCENARIOS = (
    ROOT / "contracts/canvas-publication-boundary-scenarios.json"
)
PUBLICATION_BOUNDARY_REFERENCE = (
    ROOT / "contracts/canvas-publication-boundary-reference.json"
)
ENVIRONMENT = {
    "ISSUANCE_API_KEY": "synthetic-mirror-management",
    "ISSUER_BASE_URL": "https://issuer.example",
    "PUBLIC_BASE_URL": "https://issuer.example",
    "CANVAS_PORTABLE_INTEGRATION_ENABLED": "true",
    "CANVAS_PILOT_ORGANIZATION_IDS": "org-1",
    "CANVAS_CREDENTIALS_PUBLISH_URL": "https://bridge.example/publish",
    "CANVAS_CREDENTIALS_STATUS_SYNC_URL": "https://bridge.example/status",
    "CANVAS_CREDENTIALS_API_TOKEN": "synthetic-provider-token",
    "CANVAS_CREDENTIALS_ISSUER_ID": "issuer-elevenid",
    "CANVAS_CREDENTIALS_BADGECLASS_ID": "badge-1",
}
VIOLATIONS = []


def canonical_json_bytes(raw):
    """Checked-in JSON identity: strict UTF-8, CRLF to LF, no other changes.

    This is not used for pinned Git blobs, which retain exact byte identities.
    """
    return raw.decode("utf-8").replace("\r\n", "\n").encode("utf-8")


def read_sources(checkout):
    result = {}
    for name, (path, expected) in SOURCES.items():
        completed = subprocess.run(
            ["git", "-C", str(checkout), "show", f"{REVISION}:{path}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
        if completed.returncode:
            raise ValueError(f"Pinned source unavailable: {path}")
        raw = completed.stdout
        digest = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw
        ).hexdigest()
        if digest != expected:
            raise ValueError(f"Pinned source identity differs: {path}")
        result[name] = raw.decode("utf-8")
    return result


def verify_sources(sources):
    if set(sources) != set(SOURCES):
        raise ValueError("Incomplete pinned source envelope")
    for name, source in sources.items():
        raw = source.encode("utf-8")
        digest = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw
        ).hexdigest()
        if digest != SOURCES[name][1]:
            raise ValueError(f"Untrusted observation source: {name}")
    verify_release_profile_source(sources["release_profile"])


def verify_release_profile_source(dockerfile):
    """Require the pinned image recipe to carry the exact runtime pins."""

    for package, version in RELEASE_DEPENDENCIES.items():
        if dockerfile.count(f"{package}=={version}") != 1:
            raise ValueError(
                f"Pinned release dependency profile differs: {package}"
            )


def require_release_dependency_profile():
    """Refuse observations outside the exact immutable v0.1.76 image profile."""

    observed = {
        package: importlib.metadata.version(package)
        for package in RELEASE_DEPENDENCIES
    }
    if observed != RELEASE_DEPENDENCIES:
        raise RuntimeError(
            "Canvas mirror capture requires the immutable Credentials v0.1.76 "
            "dependency profile"
        )
    return observed


def require_reference_mode(
    *, audit=False, adapter_reference=False, publication_boundary=False
):
    if sum((audit, adapter_reference, publication_boundary)) > 1:
        raise ValueError("Reference and audit modes are mutually exclusive")


def require_release_image_controller(
    *, audit=False, check=False, write_reference=False, release_image=False
):
    """Prevent ambient runtimes from approving or replacing behavior artifacts."""

    if not audit and (check or write_reference) and not release_image:
        raise ValueError(
            "behavioral --check and --write-reference require --release-image"
        )


def run_bounded_process(
    arguments,
    source_input,
    *,
    deadline_seconds,
    label,
    env=None,
    creationflags=0,
):
    """Run one child with concurrent, capped drains and a hard deadline."""

    failure = threading.Event()
    outputs = [bytearray(), bytearray()]
    cap = 4 * 1024 * 1024

    def drain(stream, destination):
        try:
            while block := stream.read(4096):
                if len(destination) + len(block) > cap:
                    failure.set()
                elif not failure.is_set():
                    destination.extend(block)
        except Exception:
            failure.set()
        finally:
            try:
                stream.close()
            except Exception:
                failure.set()

    child = subprocess.Popen(
        arguments,
        stdin=source_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        creationflags=creationflags,
    )
    threads = []
    reason = None
    try:
        for stream, output in zip((child.stdout, child.stderr), outputs, strict=True):
            thread = threading.Thread(
                target=drain, args=(stream, output), daemon=True
            )
            threads.append(thread)
            thread.start()
        deadline = time.monotonic() + deadline_seconds
        while child.poll() is None:
            if failure.is_set():
                reason = f"{label} output collection failed (reader or size limit)"
                break
            if time.monotonic() >= deadline:
                reason = f"{label} exceeded {deadline_seconds}-second deadline"
                break
            time.sleep(0.02)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError(f"{label} pipe cleanup did not complete")
        for stream in (child.stdout, child.stderr):
            stream.close()
    if reason or failure.is_set():
        raise RuntimeError(
            reason or f"{label} output collection failed (reader or size limit)"
        )
    return child.returncode, bytes(outputs[0]), bytes(outputs[1])


def bounded_observation_child(
    sources, *, audit=False, adapter_reference=False, publication_boundary=False
):
    """One owned child, no subprocess descendants; capped pipe drains + deadline.

    Source Git reads precede this observation-phase bound. A child that swallows
    cancellation cannot hang the capture parent or yield a partial artifact.
    """
    require_reference_mode(
        audit=audit,
        adapter_reference=adapter_reference,
        publication_boundary=publication_boundary,
    )
    verify_sources(sources)
    child_env = {
        key: os.environ[key]
        for key in ("SystemRoot", "WINDIR", "SystemDrive")
        if key in os.environ
    }
    child_env.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    arguments = [sys.executable, str(Path(__file__).resolve()), "--worker"]
    if audit:
        arguments.append("--audit")
    if adapter_reference:
        arguments.append("--adapter-reference")
    if publication_boundary:
        arguments.append("--publication-boundary-reference")
    # A pre-populated owned regular file avoids an unbounded pipe write to a
    # child that never reads stdin. It is unlinked by this context on every path.
    with tempfile.TemporaryFile(dir=ROOT) as source_input:
        source_input.write(json.dumps(sources, ensure_ascii=True).encode("utf-8"))
        source_input.seek(0)
        returncode, stdout, stderr = run_bounded_process(
            arguments,
            source_input,
            deadline_seconds=30,
            label="Observation child",
            env=child_env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if returncode:
            raise RuntimeError("Observation child failed:\n" + stderr.decode("utf-8"))
        result = json.loads(stdout.decode("utf-8"))
        if not isinstance(result, dict) or result.get("source_commit") != REVISION:
            raise ValueError("Invalid terminal observation envelope")
        if result.get("schema") != (
            "marty.canvas-mirror-source-audit/v1"
            if audit
            else "marty.canvas-publication-boundary-reference/v1"
            if publication_boundary
            else "marty.canvas-mirror-adapter-reference/v1"
            if adapter_reference
            else "marty.canvas-mirror-python-reference/v1"
        ):
            raise ValueError("Unexpected observation schema")
        return stdout.decode("utf-8").replace("\r\n", "\n"), result


def release_image_observation(
    sources, *, audit=False, adapter_reference=False, publication_boundary=False
):
    """Run the owned observation worker in the exact immutable release image."""

    require_reference_mode(
        audit=audit,
        adapter_reference=adapter_reference,
        publication_boundary=publication_boundary,
    )
    verify_sources(sources)
    arguments = [
        "docker",
        "run",
        "--rm",
        "--interactive",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint",
        "python",
        "--volume",
        f"{ROOT}:/review:ro",
        f"{RELEASE_IMAGE}@{RELEASE_IMAGE_DIGEST}",
        "-I",
        "/review/scripts/capture_canvas_mirror_reference.py",
        "--worker",
    ]
    if audit:
        arguments.append("--audit")
    if adapter_reference:
        arguments.append("--adapter-reference")
    if publication_boundary:
        arguments.append("--publication-boundary-reference")
    source_input = json.dumps(sources, ensure_ascii=True).encode("utf-8")
    if len(source_input) > 4 * 1024 * 1024:
        raise RuntimeError("Immutable release-image source envelope exceeded limit")
    with tempfile.TemporaryFile(dir=ROOT) as input_file:
        input_file.write(source_input)
        input_file.seek(0)
        returncode, stdout, stderr = run_bounded_process(
            arguments,
            input_file,
            deadline_seconds=45,
            label="Immutable release-image observation",
        )
    if returncode or stderr:
        raise RuntimeError(
            "Immutable release-image observation failed:\n"
            + stderr.decode("utf-8", errors="replace")
        )
    result = json.loads(stdout)
    if not audit and (
        result.get("release_image")
        != {"uri": RELEASE_IMAGE, "digest": RELEASE_IMAGE_DIGEST}
        or result.get("dependencies") != RELEASE_DEPENDENCIES
    ):
        raise RuntimeError("Immutable release-image observation profile differs")
    return stdout.decode("utf-8").replace("\r\n", "\n"), result


def bound_names(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return [
            item.id
            for target in targets
            for item in ast.walk(target)
            if isinstance(item, ast.Name)
        ]
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [alias.asname or alias.name.split(".")[0] for alias in node.names]
    return []


def referenced_names(node):
    """Return loaded names without mistaking function locals for globals."""

    loaded = {
        item.id
        for item in ast.walk(node)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
    }
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        local = {
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
        }
        if node.args.vararg is not None:
            local.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            local.add(node.args.kwarg.arg)
        local.update(
            item.id
            for item in ast.walk(node)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store)
        )
        loaded.difference_update(local)
    return loaded


class PinnedDefinitions:
    """Closed pinned-source selection; no replacement domain implementations.

    Preserve source order, decorators and defaults. Only unneeded top-level
    definitions/imports/startup statements are excluded. Every selected local
    dependency must be available from SOURCES; external imports are allowlisted.
    """

    def __init__(self, sources):
        self.sources = sources
        self.selected = {}
        self.modules = {}
        self.previous = {}
        self.allowed = set(sys.stdlib_module_names) | {
            "fastapi",
            "pydantic",
            "httpx",
            "pytest",
        }

    def close(self):
        for name, previous in reversed(list(self.previous.items())):
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous

    def install(self, name):
        if name in self.modules:
            return self.modules[name]
        if "." in name:
            self.install(name.rsplit(".", 1)[0])
        module = ModuleType(name)
        module.__path__ = []
        self.previous[name] = sys.modules.get(name)
        sys.modules[name] = module
        self.modules[name] = module
        return module

    def load(self, name, roots):
        if name not in self.sources:
            raise ValueError(f"Unpinned executed source: {name}")
        module = self.install(name)
        nodes = ast.parse(self.sources[name]).body
        bindings = {key: node for node in nodes for key in bound_names(node)}
        selected = set(self.selected.get(name, ()))
        queue = list(roots)
        while queue:
            key = queue.pop()
            if key in selected or key not in bindings:
                if key not in bindings and key in roots and not hasattr(module, key):
                    raise ValueError(f"Missing pinned definition: {name}.{key}")
                continue
            selected.add(key)
            node = bindings[key]
            queue.extend(referenced_names(node))
        old = set(self.selected.get(name, ()))
        self.selected[name] = sorted(selected)
        chosen = [
            copy.deepcopy(node)
            for node in nodes
            if set(bound_names(node)) & (selected - old)
        ]
        for node in chosen:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                node.names = [
                    alias
                    for alias in node.names
                    if (alias.asname or alias.name.split(".")[0]) in selected
                ]
        # Resolve original imported symbols before executing intact definitions.
        for node in chosen:
            for imported in ast.walk(node):
                if isinstance(imported, ast.ImportFrom):
                    origin = imported.module or ""
                    if origin.startswith("issuance."):
                        self.load(origin, [alias.name for alias in imported.names])
                    elif (
                        origin.split(".")[0] not in self.allowed
                        and origin != "__future__"
                    ):
                        raise ValueError(f"Unapproved reference import: {origin}")
                elif isinstance(imported, ast.Import):
                    for alias in imported.names:
                        if alias.name.split(".")[0] not in self.allowed:
                            raise ValueError(
                                f"Unapproved reference import: {alias.name}"
                            )
        futures = [
            copy.deepcopy(node)
            for node in nodes
            if isinstance(node, ast.ImportFrom) and node.module == "__future__"
        ]
        tree = ast.fix_missing_locations(
            ast.Module(body=[*futures, *copy.deepcopy(chosen)], type_ignores=[])
        )
        exec(
            compile(tree, SOURCES[name][0], "exec", dont_inherit=True), module.__dict__
        )
        return module

    def validate_bindings(self):
        def check(code, namespace):
            for instruction in dis.get_instructions(code):
                if (
                    instruction.opname == "LOAD_GLOBAL"
                    and instruction.argval not in namespace
                    and not hasattr(builtins, instruction.argval)
                ):
                    raise ValueError(
                        f"Unresolved pinned global: {code.co_filename}:{code.co_name}:{instruction.argval}"
                    )
            for nested in code.co_consts:
                if isinstance(nested, CodeType):
                    check(nested, namespace)

        for module in self.modules.values():
            for value in vars(module).values():
                if getattr(value, "__module__", None) != module.__name__:
                    continue
                members = vars(value).values() if isinstance(value, type) else [value]
                for member in members:
                    if isinstance(member, (staticmethod, classmethod)):
                        member = member.__func__
                    if isinstance(member, FunctionType):
                        check(member.__code__, member.__globals__)


def denied_network(*_args, **_kwargs):
    VIOLATIONS.append("uncontrolled network")
    raise AssertionError("Reference attempted uncontrolled network access")


def require_clean_capture():
    if VIOLATIONS:
        raise AssertionError(
            "Capture infrastructure failure was caught by reference code"
        )


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 9, 1, 12, tzinfo=UTC)
        return value.astimezone(tz) if tz else value.replace(tzinfo=None)


def serial(value):
    if dataclasses.is_dataclass(value):
        return serial(dataclasses.asdict(value))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): serial(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serial(item) for item in value]
    if hasattr(value, "model_dump"):
        return serial(value.model_dump())
    return value


def snapshot(repo):
    return {
        name.removeprefix("_"): serial(getattr(repo, name))
        for name in (
            "_transactions",
            "_credentials",
            "_delivery_records",
            "_events",
            "_applications",
            "_canvas_platforms",
            "_canvas_program_bindings",
        )
    }


@contextmanager
def recorded_logs(logger, trace):
    class Recorder(logging.Handler):
        def emit(self, record):
            item = {
                "kind": "log",
                "level": record.levelname,
                "message": record.getMessage(),
            }
            for key in (
                "mip_event",
                "canvas_mirror_alert",
                "organization_id",
                "severity",
            ):
                if hasattr(record, key):
                    item[key] = serial(getattr(record, key))
            if record.exc_info:
                item["exception"] = record.exc_info[0].__name__
            trace.append(item)

    previous = logger.handlers, logger.level, logger.propagate
    logger.handlers, logger.propagate = [Recorder()], False
    logger.setLevel(logging.DEBUG)
    try:
        yield
    finally:
        logger.handlers, logger.level, logger.propagate = previous


def intern_snapshots(observed):
    """Losslessly deduplicate repeated complete objects, never discard fields."""
    snapshots = {}

    def intern(value):
        encoded = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        snapshots.setdefault(digest, value)
        return {"snapshot_sha256": digest}

    for case in [
        *observed["http"],
        *observed["provider_cancellation"],
        *observed.get("adapter", []),
    ]:
        case["before"] = intern(case["before"])
        case["after"] = intern(case["after"])
        for call in case["trace"]:
            if call["kind"] == "repository":
                call["args"] = [
                    intern(value) if isinstance(value, dict) else value
                    for value in call["args"]
                ]
    observed["snapshots"] = snapshots
    return observed


def instrument_repository(repo, trace, *, failure_method=None):
    for name in dir(type(repo)):
        original = getattr(repo, name)
        if not asyncio.iscoroutinefunction(original):
            continue

        async def observed(*args, _name=name, _original=original, **kwargs):
            call = {
                "kind": "repository",
                "method": _name,
                "args": serial(args),
                "kwargs": serial(kwargs),
            }
            trace.append(call)
            if _name == failure_method:
                call["failure"] = "RuntimeError"
                raise RuntimeError(f"synthetic repository failure: {_name}")
            return await _original(*args, **kwargs)

        setattr(repo, name, observed)


async def prepare(loader, case):
    seed = loader.modules["mirror_seed"]
    entities = loader.modules["issuance.domain.entities"]
    repo = loader.modules[
        "issuance.infrastructure.adapters.memory_repository"
    ].InMemoryIssuanceRepository()
    tx = seed._make_transaction(
        status=entities.IssuanceStatus.ISSUED,
        delivery_mode="wallet_plus_canvas_mirror",
        pre_auth_code="synthetic-precode",
    )
    if "provider" in case and not case.get("missing_recipient"):
        # Synthetic input required by the unchanged recipient precedence helper,
        # not a manufactured provider/domain response.
        tx.claims["email"] = "learner@example.edu"
    credential = seed._make_credential(
        status=entities.CredentialStatus(case.get("credential_status", "active")),
        issuer_did="did:web:issuer.example",
    )
    provider = (
        {"provider": case["provider"], "badgeclass_id": "badge-1"}
        if "provider" in case
        else {}
    )
    platform, binding = await seed._save_canvas_program_target(
        repo,
        platform_enabled=case.get("disabled") != "platform",
        binding_enabled=case.get("disabled") != "binding",
        canvas_credentials=provider,
    )
    metadata = seed._canvas_binding_metadata(
        publish_attempts=case.get("attempts", 0),
        private_fixture_marker="must-not-enter-public-provenance-metadata",
    )
    if "gate" in case:
        metadata["canvas_feature_flags"] = {
            "enable_canvas_mirror_publish": True,
            "enable_canvas_mirror_ops": True,
        }
        metadata["canvas_feature_flags"][case["gate"]] = False
    if case.get("sync_failure"):
        metadata.update(
            last_status_sync_error="synthetic previous failure",
            status_sync_attempts=2,
            last_status_sync_error_at="2026-08-31T12:00:00+00:00",
        )
    record = seed._make_delivery_record(
        delivery_target=entities.DeliveryTarget.CANVAS_CREDENTIALS,
        delivery_mode="wallet_plus_canvas_mirror",
        status=entities.CredentialDeliveryStatus(
            case.get("delivery_status", "pending")
        ),
        organization_id=case.get("record_organization", "org-1"),
        canvas_account_id=platform.canvas_account_id,
        external_credential_id="external-1"
        if case.get("delivery_status") == "delivered"
        else None,
        metadata=metadata,
    )
    if case.get("entrypoint") == "direct_adapter":
        # Explicit provider inputs normally supplied by the route's target
        # hydration. The original adapter is called unchanged, not the route.
        record.metadata["canvas_credentials"] = provider
        for name, owner, allowed in (
            (
                "transaction",
                tx,
                {
                    "id",
                    "organization_id",
                    "claims",
                    "issuer_did_override",
                    "credential_payload_format",
                    "applicant_id",
                    "subject_did",
                },
            ),
            (
                "credential",
                credential,
                {
                    "id",
                    "organization_id",
                    "transaction_id",
                    "issuer_did",
                    "issued_at",
                    "expires_at",
                    "status_list_entries",
                    "applicant_id",
                    "subject_did",
                },
            ),
            ("platform", platform, {"organization_id", "canvas_account_id"}),
            (
                "delivery",
                record,
                {"organization_id", "credential_id", "transaction_id", "metadata"},
            ),
        ):
            changes = case.get("inputs", {}).get(name, {})
            if set(changes) - allowed:
                raise ValueError(f"Unsupported adapter input field: {name}")
            for key, value in changes.items():
                if key in {"issued_at", "expires_at"} and value is not None:
                    value = datetime.fromisoformat(value)
                setattr(owner, key, copy.deepcopy(value))
    if case.get("omit") != "transaction":
        await repo.save_transaction(tx)
    if case.get("omit") != "credential":
        await repo.save_credential(credential)
    if case.get("omit") != "delivery":
        await repo.save_delivery_record(record)
    if case.get("omit") == "binding":
        repo._canvas_program_bindings.pop(binding.id)
    if case.get("omit") == "platform":
        repo._canvas_platforms.pop(platform.id)
    if case.get("extra_sync_record"):
        extra = copy.deepcopy(record)
        extra.id = "delivery-sync"
        extra.status = entities.CredentialDeliveryStatus.DELIVERED
        extra.external_credential_id = "external-sync"
        extra.metadata.update(
            last_status_sync_error="synthetic previous failure", status_sync_attempts=1
        )
        await repo.save_delivery_record(extra)
    if case.get("mixed_health"):
        for index, (state, attempts, failure) in enumerate(
            [
                ("failed", 3, False),
                ("failed", 5, False),
                ("delivered", 6, True),
                ("delivered", 1, False),
            ]
        ):
            extra = copy.deepcopy(record)
            extra.id = f"delivery-health-{index}"
            extra.status = entities.CredentialDeliveryStatus(state)
            extra.metadata.update(
                publish_attempts=attempts,
                status_sync_attempts=attempts,
                published_at="2026-08-30T12:00:00+00:00",
            )
            if failure:
                extra.metadata.update(
                    last_status_sync_error="synthetic previous failure",
                    last_status_sync_error_at="2026-08-31T12:00:00+00:00",
                )
            await repo.save_delivery_record(extra)
    return repo


REQUESTS = {
    "publish": (
        "POST",
        "/v1/issued-credentials/cred-001/deliveries/canvas-credentials/publish",
    ),
    "pending": (
        "POST",
        "/v1/issuance/delivery-records/canvas-credentials/process-pending",
    ),
    "resync": (
        "POST",
        "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
    ),
    "cycle": (
        "POST",
        "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
    ),
    "health": ("GET", "/v1/issuance/organizations/org-1/canvas-mirror-health"),
    "provenance": (
        "GET",
        "/v1/issuance/delivery-records/canvas-credentials/provenance",
    ),
}


def controlled_dns(host, port, *args, **kwargs):
    if host not in {
        "api.badgr.io",
        "bridge.example",
        "alerts.example",
        "canvas.example.test",
    }:
        VIOLATIONS.append("unowned DNS")
        raise AssertionError("Reference attempted unowned DNS resolution")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


async def observe_http(loader, routes, case):
    import httpx
    from fastapi import FastAPI

    repo = await prepare(loader, case)
    before = snapshot(repo)
    trace = []
    instrument_repository(
        repo,
        trace,
        failure_method=case.get("repository_failure"),
    )
    app = FastAPI()
    app.include_router(routes.issuance_router)
    app.include_router(routes.issued_credential_router)
    app.dependency_overrides[routes.IIssuanceRepository] = lambda: repo
    original_client = httpx.AsyncClient
    provider_entered, provider_release = asyncio.Event(), asyncio.Event()

    async def peer(request):
        if request.url.host not in {"api.badgr.io", "bridge.example", "alerts.example"}:
            VIOLATIONS.append("unowned HTTP origin")
            raise AssertionError("Reference attempted an unowned HTTP origin")
        trace.append(
            {
                "kind": "http",
                "method": request.method,
                "url": str(request.url),
                "headers": {
                    key: value
                    for key, value in request.headers.items()
                    if key in {"authorization", "content-type", "accept"}
                },
                "body": request.content.decode("utf-8"),
            }
        )
        if case.get("cancel_provider"):
            provider_entered.set()
            await provider_release.wait()
        if request.url.host == "alerts.example":
            return httpx.Response(case["webhook_status"], json={"accepted": True})
        if case.get("provider_failure") == "transport":
            raise httpx.ConnectError(
                "synthetic controlled connection failure", request=request
            )
        body = case.get("provider_body")
        if body is None:
            body = (
                json.dumps(
                    {
                        "result": [
                            {
                                "entityId": "external-1",
                                "issuer": "issuer-elevenid",
                                "openBadgeId": "https://badges.example/assertion/external-1",
                            }
                        ]
                    }
                )
                if "provider" in case
                else json.dumps({"id": "external-1", "issuer_id": "issuer-elevenid"})
            )
        return httpx.Response(
            case.get("provider_status", 201),
            content=body.encode(case["provider_encoding"])
            if "provider_encoding" in case
            else body,
            headers={
                "content-type": case.get("provider_content_type", "application/json"),
                "x-request-id": "synthetic-request-1",
            },
        )

    def client(*args, **kwargs):
        # Keep all original timeout/redirect/proxy options; replace only network
        # transport. DNS/TLS connection enforcement is explicitly outside proof.
        supplied = kwargs.pop("transport", None)
        trace.append(
            {
                "kind": "client",
                "timeout": kwargs.get("timeout"),
                "follow_redirects": kwargs.get("follow_redirects", False),
                "trust_env": kwargs.get("trust_env", True),
                "transport": type(supplied).__name__
                if supplied is not None
                else "default",
            }
        )
        return original_client(*args, **kwargs, transport=httpx.MockTransport(peer))

    headers = {}
    key = case.get("key", ENVIRONMENT["ISSUANCE_API_KEY"])
    if key is not None:
        headers["X-API-Key"] = key
    organization = case.get("organization_header", "org-1")
    if organization is not None:
        headers["X-Organization-ID"] = organization
    query = (
        {"organization_id": "org-1"}
        if case["operation"] in {"pending", "resync", "cycle", "provenance"}
        else {}
    )
    if case["operation"] == "provenance":
        query["delivery_record_id"] = "delivery-001"
    query.update(case.get("query", {}))
    query = {key: value for key, value in query.items() if value is not None}
    method, path = REQUESTS[case["operation"]]
    env = (
        {"CANVAS_MIRROR_ALERT_WEBHOOK_URL": "https://alerts.example/hook"}
        if "webhook_status" in case
        else {}
    )
    env.update(case.get("env", {}))
    if any(key.endswith("_FILE") for key in env):
        raise ValueError("Adapter vectors may not select filesystem secrets")
    responses = []
    with (
        recorded_logs(routes.logger, trace),
        patch.dict(os.environ, env),
        patch.object(httpx, "AsyncClient", client),
        patch.object(socket, "getaddrinfo", controlled_dns),
    ):
        async with original_client(
            transport=httpx.ASGITransport(
                app=app,
                raise_app_exceptions=not bool(case.get("repository_failure")),
            ),
            base_url="https://capture.example",
        ) as transport:
            if case.get("entrypoint") == "direct_adapter":
                adapter = loader.modules[
                    "issuance.infrastructure.adapters.canvas_credentials_adapter"
                ]

                async def secret(organization, identifier):
                    trace.append(
                        {
                            "kind": "secret",
                            "organization": organization,
                            "identifier": identifier,
                        }
                    )
                    if case.get("secret_failure"):
                        raise RuntimeError("synthetic secret lookup failure")
                    return case.get("secrets", {}).get(identifier)

                for _ in range(case.get("repeat", 1)):
                    try:
                        action = adapter.publish_canvas_credential_mirror(
                            credential=next(iter(repo._credentials.values())),
                            transaction=next(iter(repo._transactions.values())),
                            platform=next(iter(repo._canvas_platforms.values())),
                            delivery_record=next(iter(repo._delivery_records.values())),
                            secret_resolver=secret,
                        )
                        if case.get("cancel_provider"):
                            responses.append(
                                await cancel_provider_action(action, provider_entered)
                            )
                            continue
                        result = await asyncio.wait_for(action, timeout=2)
                    except Exception as error:
                        require_clean_capture()
                        expected = case.get("expected_exception")
                        # Infrastructure, source binding, timeout and arbitrary
                        # failures cannot silently become accepted observations.
                        if (
                            expected
                            not in {"RuntimeError", "UnicodeDecodeError", "LookupError"}
                            or type(error).__name__ != expected
                        ):
                            raise
                        responses.append(
                            {"exception": type(error).__name__, "detail": str(error)}
                        )
                    else:
                        if case.get("expected_exception"):
                            raise AssertionError(
                                "Expected adapter failure did not occur"
                            )
                        # The original model may retain non-finite Python JSON
                        # values and unpaired surrogates. Preserve its complete
                        # JSON text inside a strict outer JSON string, without
                        # converting those values or claiming ASGI rendering.
                        responses.append(
                            {
                                "result_encoding": "python-json-text",
                                "result_json": json.dumps(
                                    serial(result),
                                    ensure_ascii=True,
                                    separators=(",", ":"),
                                ),
                            }
                        )
            elif case.get("cancel_provider"):
                if case.get("entrypoint") == "automation_loop":
                    action = routes.run_canvas_mirror_automation_loop(
                        lambda: repo,
                        routes.CanvasMirrorAutomationConfig(
                            enabled=True, organization_id="org-1"
                        ),
                    )
                else:
                    action = transport.request(
                        method, path, headers=headers, params=query
                    )
                responses.append(await cancel_provider_action(action, provider_entered))
            else:
                for _ in range(case.get("repeat", 1)):
                    response = await asyncio.wait_for(
                        transport.request(method, path, headers=headers, params=query),
                        timeout=2,
                    )
                    require_clean_capture()
                    if response.status_code != case.get("expected_status", 200):
                        raise AssertionError(
                            f"Scenario {case['id']} did not reach its qualified HTTP outcome: {response.status_code}, {response.text}"
                        )
                    content_type = response.headers.get("content-type", "")
                    body = (
                        response.json()
                        if content_type.split(";", 1)[0].strip().endswith("json")
                        else response.text
                    )
                    responses.append({"status": response.status_code, "body": body})
    require_clean_capture()
    return {
        "id": case["id"],
        "entrypoint": case.get("entrypoint", "ASGI"),
        "request": None
        if case.get("entrypoint") in {"automation_loop", "direct_adapter"}
        else {"method": method, "path": path, "query": query, "headers": headers},
        "before": before,
        "responses": responses,
        "trace": trace,
        "after": snapshot(repo),
    }


async def cancel_provider_action(action, provider_entered):
    # Preserve the prior action/cancel/join sequence for original ASGI and loop
    # cases. The complete parent-owned child deadline bounds swallowed cancel.
    task = asyncio.create_task(action)
    try:
        await asyncio.wait_for(provider_entered.wait(), 2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            return {"outcome": "CancelledError"}
        raise AssertionError("Provider cancellation was swallowed")
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def observe_loop(routes, case):
    trace = []
    now = 0.0
    sleeps = 0
    entered = asyncio.Event()
    release = asyncio.Event()
    token = object()

    async def phase(name, repository, **kwargs):
        nonlocal now
        assert repository is token
        trace.append({"phase": name, "at": now, "arguments": kwargs})
        if case.get("cancel_at") == name:
            entered.set()
            await release.wait()
        now += case.get(f"{name}_duration", 0)
        if case.get(f"{name}_failure") == "runtime":
            raise RuntimeError("synthetic batch failure")
        return SimpleNamespace(processed_count=0)

    async def publish(repository, **kwargs):
        return await phase("publish", repository, **kwargs)

    async def synchronize(repository, **kwargs):
        return await phase("sync", repository, **kwargs)

    async def sleep(seconds):
        nonlocal now, sleeps
        trace.append({"phase": "sleep", "at": now, "seconds": seconds})
        sleeps += 1
        if case.get("cancel_at") == "sleep" or sleeps >= case.get("sleeps", 1):
            entered.set()
            await release.wait()
        now += seconds

    config = routes.CanvasMirrorAutomationConfig(
        enabled=case.get("enabled", True),
        organization_id="org-1",
        publish_interval_seconds=5,
        status_sync_interval_seconds=7,
        batch_limit=3,
        retry_failed_publish=True,
        run_on_startup=case.get("run_on_startup", True),
    )
    with (
        recorded_logs(routes.logger, trace),
        patch.object(routes, "time", SimpleNamespace(monotonic=lambda: now)),
        patch.object(
            routes,
            "asyncio",
            SimpleNamespace(sleep=sleep, CancelledError=asyncio.CancelledError),
        ),
        patch.object(routes, "run_canvas_mirror_publish_batch", publish),
        patch.object(routes, "run_canvas_mirror_status_sync_batch", synchronize),
    ):
        task = asyncio.create_task(
            routes.run_canvas_mirror_automation_loop(lambda: token, config)
        )
        try:
            if not config.enabled:
                await asyncio.wait_for(task, 2)
                outcome = "returned"
            else:
                await asyncio.wait_for(entered.wait(), 2)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    outcome = "CancelledError"
                else:
                    raise AssertionError("Frozen loop swallowed cancellation")
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    return {
        "id": case["id"],
        "configuration": serial(config),
        "trace": trace,
        "outcome": outcome,
    }


async def observe(loader, routes, scenarios):
    loader.validate_bindings()
    VIOLATIONS.clear()
    http_cases = list(scenarios["http"])
    for operation in scenarios["authentication"]["operations"]:
        for key in scenarios["authentication"]["keys"]:
            http_cases.append(
                {
                    "id": f"auth_{operation}_{'missing' if key is None else 'wrong'}",
                    "operation": operation,
                    "key": key,
                    "expected_status": 401,
                }
            )
    http_cases.extend(copy.deepcopy(scenarios["authentication"]["order_cases"]))
    observations = []
    with (
        patch.object(socket.socket, "connect", denied_network),
        patch.object(socket.socket, "connect_ex", denied_network),
        patch.object(socket, "create_connection", denied_network),
    ):
        for case in http_cases:
            counter = iter(range(1, 10000))
            with patch.object(uuid, "uuid4", lambda: uuid.UUID(int=next(counter))):
                observations.append(await observe_http(loader, routes, case))
        cancellation = [
            await observe_http(loader, routes, {**case, "cancel_provider": True})
            for case in scenarios["provider_cancellation"]
        ]
        loops = [await observe_loop(routes, case) for case in scenarios["loop"]]
    configurations = []
    for case in scenarios["configuration"]:
        logs = []
        with (
            recorded_logs(routes.logger, logs),
            patch.dict(os.environ, {**ENVIRONMENT, **case["env"]}, clear=True),
        ):
            configurations.append(
                {
                    "id": case["id"],
                    "value": serial(routes.CanvasMirrorAutomationConfig.from_env()),
                    "logs": logs,
                }
            )
    require_clean_capture()
    return intern_snapshots(
        {
            "http": observations,
            "provider_cancellation": cancellation,
            "loop": loops,
            "configuration": configurations,
        }
    )


async def verify_infrastructure_controls(loader, routes):
    """Actual selected graph must not freeze an infrastructure error as parity."""
    original = routes._next_canvas_publish_metadata
    del routes._next_canvas_publish_metadata
    try:
        try:
            loader.validate_bindings()
        except ValueError as error:
            assert "_next_canvas_publish_metadata" in str(error)
        else:
            raise AssertionError("Missing source dependency was accepted")
    finally:
        routes._next_canvas_publish_metadata = original
    VIOLATIONS.clear()
    try:
        with patch.dict(
            os.environ,
            {"CANVAS_CREDENTIALS_PUBLISH_URL": "https://unowned.example/publish"},
        ):
            try:
                await observe_http(
                    loader,
                    routes,
                    {
                        "id": "negative-unowned-origin",
                        "operation": "publish",
                        "expected_status": 502,
                    },
                )
            except AssertionError as error:
                assert "Capture infrastructure failure" in str(error)
            else:
                raise AssertionError(
                    "Caught unowned-origin failure was accepted as a 502 oracle"
                )
        assert VIOLATIONS == ["unowned HTTP origin"]
    finally:
        VIOLATIONS.clear()
    return ["missing-global-fatal", "caught-unowned-origin-fatal"]


def observe_sources(
    sources, *, audit=False, adapter_reference=False, publication_boundary=False
):
    require_reference_mode(
        audit=audit,
        adapter_reference=adapter_reference,
        publication_boundary=publication_boundary,
    )
    verify_sources(sources)
    # Source-only audit remains usable without application dependencies. Every
    # behavioral observation, including adapter-only modes, is release-bound.
    dependency_profile = None if audit else require_release_dependency_profile()
    with patch.dict(os.environ, ENVIRONMENT, clear=True):
        loader = PinnedDefinitions(sources)
        try:
            routes = loader.load(
                ROUTES, [*OPERATIONS, "run_canvas_mirror_automation_loop"]
            )
            loader.load(
                "issuance.infrastructure.adapters.memory_repository",
                ["InMemoryIssuanceRepository"],
            )
            loader.load(
                "mirror_seed",
                [
                    "_make_transaction",
                    "_make_credential",
                    "_make_delivery_record",
                    "_save_canvas_program_target",
                    "_canvas_binding_metadata",
                ],
            )
            if audit:
                loader.validate_bindings()
                return {
                    "schema": "marty.canvas-mirror-source-audit/v1",
                    "source_commit": REVISION,
                    "selected_definitions": loader.selected,
                }
            for module in loader.modules.values():
                if getattr(module, "datetime", None) is datetime:
                    module.datetime = FixedDatetime
            scenario_path = (
                PUBLICATION_BOUNDARY_SCENARIOS
                if publication_boundary
                else ADAPTER_SCENARIOS
                if adapter_reference
                else SCENARIOS
            )
            scenarios = json.loads(scenario_path.read_text(encoding="utf-8"))
            controls = asyncio.run(verify_infrastructure_controls(loader, routes))
            if adapter_reference or publication_boundary:

                async def adapter_observations():
                    loader.validate_bindings()
                    VIOLATIONS.clear()
                    results = []
                    with (
                        patch.object(socket.socket, "connect", denied_network),
                        patch.object(socket.socket, "connect_ex", denied_network),
                        patch.object(socket, "create_connection", denied_network),
                    ):
                        for case in scenarios["adapter"]:
                            counter = iter(range(1, 10000))
                            with patch.object(
                                uuid, "uuid4", lambda: uuid.UUID(int=next(counter))
                            ):
                                results.append(
                                    await observe_http(
                                        loader,
                                        routes,
                                        {
                                            **case,
                                            "operation": "publish",
                                            "entrypoint": "direct_adapter",
                                        },
                                    )
                                )
                    require_clean_capture()
                    return intern_snapshots(
                        {"http": [], "provider_cancellation": [], "adapter": results}
                    )

                observed = asyncio.run(adapter_observations())
            else:
                observed = asyncio.run(observe(loader, routes, scenarios))
            return {
                "schema": "marty.canvas-publication-boundary-reference/v1"
                if publication_boundary
                else "marty.canvas-mirror-adapter-reference/v1"
                if adapter_reference
                else "marty.canvas-mirror-python-reference/v1",
                "source_commit": REVISION,
                "sources": SOURCES,
                "selected_definitions": loader.selected,
                "scenarios_sha256": hashlib.sha256(
                    canonical_json_bytes(scenario_path.read_bytes())
                ).hexdigest(),
                "infrastructure_controls": controls,
                "release_image": {
                    "uri": RELEASE_IMAGE,
                    "digest": RELEASE_IMAGE_DIGEST,
                },
                "dependencies": dependency_profile,
                "boundary": "Pinned publication adapter and models; original seed helpers with explicit inputs; controlled HTTP/org-secret lookup and clock; no ASGI/PG/filesystem/TLS/deployed proof"
                if adapter_reference or publication_boundary
                else "Pinned ASGI routes/models; frozen memory repository; controlled HTTP transport and clock; loop batch ports controlled; no PG/gateway/TLS/deployed proof",
                **observed,
            }
        finally:
            loader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("credentials_checkout", type=Path, nargs="?")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--adapter-reference", action="store_true")
    parser.add_argument("--publication-boundary-reference", action="store_true")
    parser.add_argument(
        "--audit", action="store_true", help="Validate pinned AST closure only"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print status observations only (not a capture gate)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print losslessly compact JSON instead of indented output",
    )
    parser.add_argument(
        "--write-reference",
        action="store_true",
        help="Atomically replace only the selected checked-in reference artifact",
    )
    parser.add_argument(
        "--release-image",
        action="store_true",
        help="Execute the observation worker in the exact immutable release image",
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        # No Git or child process is launched in the observation child.
        result = observe_sources(
            json.load(sys.stdin),
            audit=args.audit,
            adapter_reference=args.adapter_reference,
            publication_boundary=args.publication_boundary_reference,
        )
        print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
        return
    if args.credentials_checkout is None:
        parser.error("credentials_checkout is required")
    if args.check and (
        args.audit or args.summary or args.compact or args.write_reference
    ):
        parser.error("--check cannot be combined with display/audit/write modes")
    if args.write_reference and (args.audit or args.summary or args.compact):
        parser.error("--write-reference cannot be combined with display/audit modes")
    if args.adapter_reference and (args.audit or args.summary):
        parser.error("--adapter-reference cannot be combined with audit/summary")
    if args.publication_boundary_reference and (
        args.audit or args.summary or args.adapter_reference
    ):
        parser.error(
            "--publication-boundary-reference cannot be combined with other reference/audit/summary modes"
        )
    try:
        require_release_image_controller(
            audit=args.audit,
            check=args.check,
            write_reference=args.write_reference,
            release_image=args.release_image,
        )
    except ValueError as exc:
        parser.error(str(exc))
    observe = release_image_observation if args.release_image else bounded_observation_child
    encoded, result = observe(
        read_sources(args.credentials_checkout),
        audit=args.audit,
        adapter_reference=args.adapter_reference,
        publication_boundary=args.publication_boundary_reference,
    )
    reference_path = (
        PUBLICATION_BOUNDARY_REFERENCE
        if args.publication_boundary_reference
        else ADAPTER_REFERENCE
        if args.adapter_reference
        else REFERENCE
    )
    if args.check:
        if canonical_json_bytes(reference_path.read_bytes()).decode("utf-8") != encoded:
            raise ValueError("Frozen Canvas mirror observations differ")
        if args.publication_boundary_reference:
            print(
                f"Canvas publication boundary reference PASS: {len(result['adapter'])} cases"
            )
        elif args.adapter_reference:
            print(
                f"Canvas mirror adapter reference PASS: {len(result['adapter'])} cases"
            )
        else:
            print(
                f"Canvas mirror reference PASS: {len(result['http'])} HTTP, {len(result['provider_cancellation'])} provider cancellations, {len(result['loop'])} loop, {len(result['configuration'])} configuration cases"
            )
    elif args.write_reference:
        reference_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                newline="\n",
                dir=reference_path.parent,
                prefix=f".{reference_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(encoded)
                temporary = Path(handle.name)
            temporary.replace(reference_path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        print(f"Wrote {reference_path.relative_to(ROOT)}")
    elif args.summary and not args.audit:
        print(
            json.dumps(
                {
                    "http": [
                        {
                            "id": case["id"],
                            "status": [
                                response["status"] for response in case["responses"]
                            ],
                            "http_attempts": sum(
                                call["kind"] == "http" for call in case["trace"]
                            ),
                        }
                        for case in result["http"]
                    ],
                    "loop": result["loop"],
                },
                indent=2,
            )
        )
    else:
        print(
            json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            if args.compact
            else encoded,
            end="\n" if args.compact else "",
        )


if __name__ == "__main__":
    main()
