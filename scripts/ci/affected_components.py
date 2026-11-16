#!/usr/bin/env python3
"""Closed, source-bound CI plans and the required aggregate result contract."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys


FLAGS = (
    "all", "ui", "website", "website_only", "python", "rust", "rust_runtime",
    "openbao", "rollback_test_only", "didcomm_release_test_only", "k8s_policy_test_only",
    "release", "verification", "security",
)
FULL_MATRIX = ["canvas", "contracts", "selfhost"]
JOB_FLAGS = {
    "changes": None, "release-preflight": None, "lint": None,
    "test-website": "website", "fast-feedback": "ui", "test-ui": "ui",
    "test-ui-crawler-artifacts": "ui", "test-ui-crawler-nginx": "ui",
    "test-credential-lifecycle-browser": "ui", "test-services": "python",
    "test-rust-feature-probe": "rust_runtime", "test-rust-service-images": "rust_runtime",
    "test-rust-services": "rust", "test-native-operator": "rust",
    "rust-lint-policy": "rust", "rust-supply-chain": "rust",
    "test-openbao-didcomm-plugin": "openbao", "security": "security",
    "public-protocol-contract": ("ui", "python", "rust", "release"),
    "test-release-contracts": ("release", "verification", "rust"),
}
PLAN_KEYS = {"schema_version", "event", "source_sha", "base_sha", "head_sha", "flags",
             "rust_matrix", "selected_jobs", "unselected_jobs"}


def load_json(value: str):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=unique)


def identity(env):
    result = {"event": env.get("EVENT_NAME", ""), "source_sha": env.get("SOURCE_SHA", ""),
              "base_sha": env.get("BASE_SHA", ""), "head_sha": env.get("HEAD_SHA", "")}
    if result["event"] not in {"pull_request", "merge_group", "workflow_dispatch", "schedule", "push"}:
        raise ValueError("unsupported or missing event")
    for key in ("source_sha", "head_sha"):
        if not re.fullmatch(r"[0-9a-f]{40}", result[key]):
            raise ValueError(f"missing or malformed {key}")
    if result["event"] in {"pull_request", "merge_group"}:
        if not re.fullmatch(r"[0-9a-f]{40}", result["base_sha"]):
            raise ValueError("missing or malformed comparison base")
        if result["event"] == "merge_group" and result["head_sha"] != result["source_sha"]:
            raise ValueError("merge-group head differs from checked-out source")
    elif result["base_sha"]:
        raise ValueError("unexpected comparison base for a full run")
    return result


def regular_path(root: Path, value: str) -> bool:
    path = PurePosixPath(value)
    if (not value or str(path) != value or path.is_absolute() or ".." in path.parts or "\\" in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        return False
    current = root
    for part in path.parts:
        current /= part
        if current.is_symlink():
            return False
    return current.is_file()


def website_only(root: Path, changed: bytes) -> bool:
    """Narrow only explicit marketing modules proved absent from app outputs.

    The required website lane builds all three surfaces and runs the emitted
    module guards. Changes to this roster, those guards, shared UI, routing,
    assets, dependency locks or build configuration therefore remain broad.
    """
    try:
        if not changed or not changed.endswith(b"\0"):
            return False
        paths = [value.decode("utf-8", "strict") for value in changed[:-1].split(b"\0")]
        if len(set(paths)) != len(paths) or not all(regular_path(root, path) for path in paths):
            return False
        roster_path = "contracts/website-source-ownership.json"
        if not regular_path(root, roster_path):
            return False
        roster = load_json((root / roster_path).read_text())
        if set(roster) != {"schema_version", "modules"} or type(roster["schema_version"]) is not int or roster["schema_version"] != 1:
            return False
        modules = roster["modules"]
        if not isinstance(modules, list) or not modules or not all(isinstance(p, str) for p in modules):
            return False
        if len(set(modules)) != len(modules) or not all(p.startswith("ui/src/") and regular_path(root, p) for p in modules):
            return False
        return all(path in modules or path == "ui/src/website.jsx" or
                   path.startswith("ui/src/apps/website/") for path in paths)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        return False


def validate_flags(flags, matrix, event):
    if not isinstance(flags, dict) or set(flags) != set(FLAGS) or any(type(v) is not bool for v in flags.values()):
        raise ValueError("closed boolean flag roster required")
    broad = {"ui", "website", "python", "rust", "rust_runtime", "openbao", "release", "verification", "security"}
    if flags["all"] and (not all(flags[f] for f in broad) or flags["website_only"]):
        raise ValueError("incomplete full plan")
    if flags["ui"] and not flags["website"]:
        raise ValueError("shared UI must validate the website")
    if flags["website_only"] and (not flags["website"] or any(flags[f] for f in FLAGS if f not in {"website", "website_only"})):
        raise ValueError("mixed website-only plan")
    if flags["rust_runtime"] and not flags["rust"]:
        raise ValueError("runtime without Rust ownership")
    if not isinstance(matrix, list) or not all(isinstance(v, str) for v in matrix):
        raise ValueError("invalid Rust matrix")
    if flags["rust"] and not flags["rust_runtime"]:
        if event != "pull_request" or matrix not in [["contracts"], ["worker"], ["flow"], ["selfhost"], ["renewal-unit"]]:
            raise ValueError("invalid scoped Rust matrix")
    elif matrix != FULL_MATRIX:
        raise ValueError("full Rust matrix required")
    for leaf, required in (("rollback_test_only", {"release", "security"}),
                           ("didcomm_release_test_only", {"release"}),
                           ("k8s_policy_test_only", {"release"})):
        if flags[leaf] and (event != "pull_request" or {f for f in broad if flags[f]} != required):
            raise ValueError(f"invalid {leaf} plan")
    if event == "merge_group" and not flags["website_only"] and not flags["all"]:
        raise ValueError("non-website merge groups require full qualification")
    if event not in {"pull_request", "merge_group"} and not flags["all"]:
        raise ValueError("full qualification required for this event")


def job_selection(flags):
    selected = []
    for job, flag in JOB_FLAGS.items():
        if flag is None or (any(flags[f] for f in flag) if isinstance(flag, tuple) else flags[flag]):
            selected.append(job)
    return sorted(selected)


def make_plan(raw, env):
    expected = {*FLAGS, "rust_matrix"}
    if set(raw) != expected or any(raw[f] not in {"true", "false"} for f in FLAGS):
        raise ValueError("incomplete classifier output")
    binding = identity(env)
    flags = {f: raw[f] == "true" for f in FLAGS}
    matrix = load_json(raw["rust_matrix"])
    validate_flags(flags, matrix, binding["event"])
    selected = job_selection(flags)
    return {"schema_version": 1, **binding, "flags": flags, "rust_matrix": matrix,
            "selected_jobs": selected, "unselected_jobs": sorted(set(JOB_FLAGS) - set(selected))}


def validate_plan(plan, env):
    if not isinstance(plan, dict) or set(plan) != PLAN_KEYS or type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise ValueError("invalid closed CI plan schema")
    binding = identity(env)
    if any(plan[k] != v for k, v in binding.items()):
        raise ValueError("CI plan does not match this event/base/head/source")
    validate_flags(plan["flags"], plan["rust_matrix"], binding["event"])
    selected = job_selection(plan["flags"])
    if plan["selected_jobs"] != selected or plan["unselected_jobs"] != sorted(set(JOB_FLAGS) - set(selected)):
        raise ValueError("CI job roster or selection changed")
    return plan


def check_results(plan, needs, env):
    validate_plan(plan, env)
    if not isinstance(needs, dict) or set(needs) != set(JOB_FLAGS):
        raise ValueError("required job results roster changed")
    for job in JOB_FLAGS:
        expected = "success" if job in plan["selected_jobs"] else "skipped"
        if not isinstance(needs[job], dict) or needs[job].get("result") != expected:
            raise ValueError(f"{job} must report {expected}")
    outputs = needs["changes"].get("outputs", {})
    for flag in FLAGS:
        if outputs.get(flag) != str(plan["flags"][flag]).lower():
            raise ValueError(f"selection output differs from plan: {flag}")
    if load_json(outputs.get("rust_matrix", "null")) != plan["rust_matrix"]:
        raise ValueError("matrix output differs from plan")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["identity", "website-only", "emit", "gate"])
    parser.add_argument("--paths-file", type=Path)
    args = parser.parse_args()
    if args.command == "identity":
        identity(os.environ)
    elif args.command == "website-only":
        print(str(website_only(Path.cwd(), args.paths_file.read_bytes())).lower())
    elif args.command == "emit":
        output = Path(os.environ["GITHUB_OUTPUT"])
        pairs = [line.split("=", 1) for line in output.read_text().splitlines()]
        if any(len(pair) != 2 for pair in pairs) or len({pair[0] for pair in pairs}) != len(pairs):
            raise ValueError("invalid or duplicate classifier outputs")
        plan = make_plan(dict(pairs), os.environ)
        with output.open("a") as stream:
            stream.write("plan=" + json.dumps(plan, separators=(",", ":"), sort_keys=True) + "\n")
    else:
        check_results(load_json(os.environ["CI_PLAN"]), load_json(os.environ["CI_NEEDS_JSON"]), os.environ)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as exc:
        print(f"CI plan rejected: {exc}", file=sys.stderr)
        sys.exit(1)
