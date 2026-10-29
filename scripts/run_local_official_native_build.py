#!/usr/bin/env python3
"""Bind a frozen native source export to the shared bounded build/journal path."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import scoped_native_build as build
import scoped_native_profiles as profiles
import seed_local_official_native_target as seed
from scoped_native_runtime import ref, require, sha

HELPER = Path("C:/Users/maree/OneDrive/Glthub/marty-workspace/audits/beta-release-20261018/core440-issuer-build.py")
PROFILE = "oid4vc-all-services"
IMAGE = "sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1"


def read_exact(path: Path, digest: str) -> dict:
    require(path.is_file() and not path.is_symlink() and re.fullmatch(r"[a-f0-9]{64}", digest)
            and sha(path) == digest, "EXACT_INPUT_CHANGED")
    return json.loads(path.read_text(encoding="utf-8"))


def source_export(path: Path, digest: str) -> dict:
    packet = read_exact(path, digest)
    require(packet["state"] == "SOURCE_EXPORTED_NO_COMPILER"
            and packet["buildProfile"] == PROFILE
            and packet["freeze"]["sha256"] == build.OFFICIAL_FREEZE_SHA256,
            "SOURCE_EXPORT_CHANGED")
    root = path.parent.resolve()
    for name, bound in packet["operatorFiles"].items():
        file = Path(bound["path"]).resolve()
        require(file == root / "operator" / name and file.is_file()
                and file.stat().st_size == bound["bytes"] and sha(file) == bound["sha256"],
                "OPERATOR_CLOSURE_CHANGED")
    require(Path(__file__).resolve() == root / "operator" / Path(__file__).name,
            "OPERATOR_OUTSIDE_FROZEN_CLOSURE")
    require(sha(Path(build.__file__)) == packet["operatorFiles"]["scoped_native_build.py"]["sha256"]
            and sha(Path(profiles.__file__)) == packet["operatorFiles"]["scoped_native_profiles.py"]["sha256"],
            "LOADED_BUILD_SOURCE_CHANGED")
    product_repo = Path(packet["sources"]["ui"]["repository"])
    producer = packet["producerRevision"]
    tool = Path(packet["buildTool"]["path"])
    require(re.fullmatch(r"[a-f0-9]{40}", producer)
            and subprocess.check_output(["git", "-C", str(product_repo), "rev-parse",
                                         producer + "^{tree}"], text=True).strip() == packet["producerTree"]
            and subprocess.check_output(["git", "-C", str(product_repo), "show",
                                         producer + ":scripts/build-rust-service-binaries.sh"]) == tool.read_bytes(),
            "REVIEWED_BUILD_TOOL_GIT_OBJECT_CHANGED")
    for name, bound in packet["operatorFiles"].items():
        require(subprocess.check_output(["git", "-C", str(product_repo), "show",
                                         producer + ":scripts/" + name])
                == Path(bound["path"]).read_bytes(), "OPERATOR_GIT_OBJECT_CHANGED")
    return packet


def helper_module():
    require(sha(HELPER) == build.REVIEWED_BUILD_HELPER_SHA256, "REVIEWED_RESOURCE_HELPER_CHANGED")
    spec = importlib.util.spec_from_file_location("reviewed_official_build_resource_helper", HELPER)
    require(spec is not None and spec.loader is not None, "REVIEWED_RESOURCE_HELPER_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_build_identifiers(run_id: str, engine_id: str) -> None:
    require(re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", run_id)
            and engine_id == seed.ENGINE, "OWNED_BUILD_IDENTIFIERS_REQUIRED")


def require_official_journal(journal: dict) -> None:
    require(journal.get("backend") == "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1"
            and journal.get("desktop", {}).get("engineId") == seed.ENGINE
            and journal.get("desktop", {}).get("volumeProof") is not None,
            "DURABLE_DESKTOP_JOURNAL_REQUIRED")


def prepare(packet_path: Path, packet_sha: str, seed_path: Path, seed_sha: str,
            journal_path: Path, run_id: str, engine_id: str) -> None:
    packet = source_export(packet_path, packet_sha)
    seed = read_exact(seed_path, seed_sha)
    scope = build.build_scope(PROFILE)
    freeze = read_exact(Path(packet["freeze"]["path"]), packet["freeze"]["sha256"])
    source_script = Path(packet["sources"]["ui"]["directory"]) / "scripts/build-rust-service-binaries.sh"
    build.verify_official_inputs(freeze, seed, source_script.read_text(), scope,
                                 Path(packet["buildTool"]["path"]).read_text())
    require_build_identifiers(run_id, engine_id)
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    require_official_journal(journal)
    root = packet_path.parent.resolve()
    plan = {"privateDirectory": str(root), "buildProfile": PROFILE,
            "profileSourceSha256": packet["operatorFiles"]["scoped_native_profiles.py"]["sha256"],
            "executionOperatorSha256": packet["operatorFiles"]["scoped_native_build.py"]["sha256"],
            "uiRevision": scope["uiRevision"], "coreRevision": build.CORE_REVISION,
            "roleBinaries": scope["roles"], "sources": packet["sources"],
            "sourceFreezeReceipt": packet["freeze"], "targetSeedReceipt": ref(seed_path),
            "recipe": packet["recipe"], "buildTool": packet["buildTool"],
            "buildToolProducerRevision": packet["producerRevision"],
            "builderImage": IMAGE, "engineId": engine_id,
            "runId": run_id, "containerName": scope["prefix"] + run_id,
            "outputDirectory": str(root / "output"), "journalBackend": journal,
            "releaseQualified": False, "recordingQualified": False}
    require(plan["targetSeedReceipt"]["sha256"] == seed_sha, "TARGET_SEED_CHANGED")
    build.verify(plan, lambda args: subprocess.check_output(["git", *args]), PROFILE)
    destination = root / "prepared-build.json"
    with destination.open("x", encoding="utf-8") as target:
        json.dump(plan, target, indent=2)
        target.write("\n")
    print(json.dumps({"state": "PREPARED_NO_COMPILER", "preparedSha256": sha(destination)}))


def execute(mode: str, packet_path: Path, packet_sha: str, prepared_sha: str) -> None:
    packet = source_export(packet_path, packet_sha)
    prepared = packet_path.parent / "prepared-build.json"
    plan = read_exact(prepared, prepared_sha)
    require(plan["buildProfile"] == PROFILE and plan["builderImage"] == IMAGE
            and plan["profileSourceSha256"] == packet["operatorFiles"]["scoped_native_profiles.py"]["sha256"]
            and plan["buildTool"] == packet["buildTool"]
            and plan["buildToolProducerRevision"] == packet["producerRevision"],
            "PREPARED_PROFILE_CHANGED")
    reference = {"path": str(prepared), "sha256": prepared_sha}
    git = lambda args: subprocess.check_output(["git", *args])
    if mode == "check":
        build.verify(plan, git, PROFILE)
        print(json.dumps({"state": "SOURCE_INPUTS_VERIFIED_NO_COMPILER", "source": plan["uiRevision"]}))
        return
    require(os.environ.get("DOCKER_CONTEXT") == "desktop-linux", "EXPLICIT_DESKTOP_CONTEXT_REQUIRED")
    helper = helper_module()
    result = (build.start(reference, helper, git, PROFILE) if mode == "start"
              else build.finish(reference, helper, git, PROFILE))
    print(json.dumps({"state": result["state"], "source": plan["uiRevision"],
                      "exitCode": result.get("exitCode"), "releaseQualified": False}))


def main() -> None:
    require(sys.version_info >= (3, 12), "PYTHON312_REQUIRED_FOR_REVIEWED_TRANSPORT")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "check", "start", "finish"))
    parser.add_argument("--source-export", type=Path, required=True)
    parser.add_argument("--source-export-sha256", required=True)
    parser.add_argument("--seed-receipt", type=Path)
    parser.add_argument("--seed-sha256")
    parser.add_argument("--journal-backend", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--engine-id")
    parser.add_argument("--prepared-sha256")
    args = parser.parse_args()
    if args.mode == "prepare":
        require(all((args.seed_receipt, args.seed_sha256, args.journal_backend,
                     args.run_id, args.engine_id)) and args.prepared_sha256 is None,
                "PREPARE_INPUTS_REQUIRED")
        prepare(args.source_export, args.source_export_sha256,
                args.seed_receipt, args.seed_sha256, args.journal_backend,
                args.run_id, args.engine_id)
    else:
        require(args.prepared_sha256 and not any((args.seed_receipt, args.seed_sha256,
                                                   args.journal_backend, args.run_id, args.engine_id)),
                "EXACT_PREPARED_INPUT_REQUIRED")
        execute(args.mode, args.source_export, args.source_export_sha256,
                args.prepared_sha256)


if __name__ == "__main__":
    main()
