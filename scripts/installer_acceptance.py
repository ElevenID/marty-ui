"""Closed installed-release evidence contract shared by release publishers.

This module validates evidence structure and candidate binding, not signatures.
Callers must authenticate the inventory, report and GitHub run before admission.
It deliberately cannot publish, promote, or manufacture acceptance evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from stack_tag_gate import classify_release_tag

REPOSITORY = "ElevenID/marty-ui"
SCHEMA = "elevenid.installer-acceptance/v1"
WORKFLOW = ".github/workflows/installer-acceptance.yml"
MAX_REPORT_BYTES = 65536
CASES = (
    "anonymous-download", "artifact-verification", "isolated-install",
    "browser-tls-login", "issue", "present", "verify", "revoke", "deny",
    "kms-custody", "restart-recovery", "existing-stack-isolation",
    "uninstall-retains-recovery", "owned-cleanup",
    "tampered-artifact-rejected", "wrong-provenance-rejected",
    "interrupted-download-recovery", "uncertain-provisioning-refused",
    "concurrent-install-refused", "partial-cleanup-preserves-recovery",
    "failed-public-replay-blocks-channel", "stale-promotion-refused",
    "existing-stack-survives-cleanup",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact(value: object, fields: set[str], label: str) -> dict:
    require(isinstance(value, dict) and set(value) == fields, label + " fields differ")
    return value


def matches(value: object, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def read_report(path: Path) -> dict:
    """Reject duplicate keys and oversized evidence before interpreting JSON."""
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "duplicate evidence field")
            result[key] = value
        return result

    require(not path.is_symlink() and path.is_file(), "report must be a regular file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    require(len(raw) <= MAX_REPORT_BYTES, "report exceeds size limit")
    result = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(result, dict), "report must be an object")
    return result


def validate(report: dict, *, inventory_bytes: bytes, source_sha: str,
             release_tag: str, phase: str, run: dict) -> None:
    """Bind an authenticated report to exact inventory bytes and API run identity.

    The run is an independently fetched terminal GitHub Actions run, never a
    nested report assertion. Staged/public phases both exercise the real installer;
    runtime-happy-path evidence is intentionally not accepted here.
    The caller must verify the report attestation invocation binds this SAME run
    and attempt, not merely authenticate the report and run independently.

    Host observations precede any pulls or neighboring-stack fixture setup.
    Retained-state recovery is tested after default uninstall; final owned counts
    are measured after explicit purge of the test installation. Neighboring-stack
    resources are excluded from those counts and independently checked unchanged.
    """
    require(phase in {"staged", "published", "channel"}, "unknown acceptance phase")
    require(matches(source_sha, r"[0-9a-f]{40}"), "invalid expected source")
    tier, _ = classify_release_tag(release_tag)
    exact(report, {"schema", "repository", "source_sha", "harness_source_sha", "source_ref", "release_tag",
                   "phase", "platform", "inventory_sha256", "workflow", "run_id",
                   "run_attempt", "cases", "host", "cleanup"}, "report")
    require(report["schema"] == SCHEMA and report["repository"] == REPOSITORY,
            "wrong report identity")
    require(report["source_sha"] == source_sha and report["source_ref"] == "refs/heads/main"
            and report["release_tag"] == release_tag and report["phase"] == phase,
            "report candidate differs")
    require(report["platform"] == "linux/amd64" and tier in {"stable", "nightly"},
            "unsupported installation target")
    require(report["inventory_sha256"] == "sha256:" + hashlib.sha256(inventory_bytes).hexdigest(),
            "tested inventory differs")
    require(report["workflow"] == WORKFLOW, "wrong acceptance workflow")
    require(matches(report["harness_source_sha"], r"[0-9a-f]{40}"), "invalid acceptance harness source")
    for name in ("run_id", "run_attempt"):
        require(type(report[name]) is int and report[name] > 0, "invalid " + name)
    require(isinstance(run, dict) and isinstance(run.get("repository"), dict),
            "invalid authoritative run shape")
    require(run.get("id") == report["run_id"] and run.get("run_attempt") == report["run_attempt"]
            and run.get("path") == WORKFLOW and run.get("head_sha") == report["harness_source_sha"]
            and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and run.get("status") == "completed" and run.get("conclusion") == "success"
            and run.get("repository", {}).get("full_name") == REPOSITORY,
            "acceptance run is not successful exact-main execution")
    exact(report["cases"], set(CASES), "installed journey")
    require(all(result == "passed" for result in report["cases"].values()),
            "installed journey incomplete")
    host = exact(report["host"], {"docker_version", "compose_version", "memory_bytes",
                 "disk_free_bytes", "image_cache_empty", "source_available",
                 "development_tools_available", "credentials_available",
                 "tls_errors_ignored"}, "host")
    for name in ("docker_version", "compose_version"):
        require(matches(host[name], r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?"),
                "invalid " + name)
    for name in ("memory_bytes", "disk_free_bytes"):
        require(type(host[name]) is int and host[name] > 0, "missing host measurement")
    require(host["image_cache_empty"] is True, "host image cache was not empty")
    require(all(host[name] is False for name in (
        "source_available", "development_tools_available", "credentials_available",
        "tls_errors_ignored")), "host is not a clean anonymous TLS-verified installation")
    cleanup = exact(report["cleanup"], {"owned_containers_remaining", "owned_networks_remaining",
                    "owned_volumes_remaining", "recovery_retention_verified"}, "cleanup")
    require(all(type(cleanup[name]) is int and cleanup[name] == 0 for name in (
        "owned_containers_remaining", "owned_networks_remaining", "owned_volumes_remaining"))
        and cleanup["recovery_retention_verified"] is True,
        "owned cleanup or retained-state recovery incomplete")
