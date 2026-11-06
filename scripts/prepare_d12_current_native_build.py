#!/usr/bin/env python3
"""Bind the accepted D12 source to the existing three-ELF native builder.

Export and prepare are file-only. Start and finish require separately supplied,
hash-bound Desktop journal and fresh owned target receipts. This never deploys.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import prepare_local_official_native_build as source_exporter
import scoped_native_build as build
import scoped_native_cargo_cache as cargo_cache
import run_local_official_native_build as native_runner
from scoped_native_profiles import D12_PASSPORT_CURRENT
from scoped_native_runtime import read_ref, ref, require, sha

PROFILE = D12_PASSPORT_CURRENT.name
SOURCE = D12_PASSPORT_CURRENT.ui_revision
CORE = D12_PASSPORT_CURRENT.core_revision
ORIGIN = source_exporter.ORIGINS
OPERATORS = ("prepare_d12_current_native_build.py", "prepare_local_official_native_build.py",
             "scoped_native_build.py", "scoped_native_profiles.py", "scoped_native_runtime.py",
             "scoped_native_cargo_cache.py",
             "scoped_linux_journal.py", "desktop_journal_transport.py",
             "run_local_official_native_build.py", "seed_local_official_native_target.py")
PRIVATE = (Path.home() / ".codex/private").resolve()
RUN = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z")


def exact_file(path: Path, digest: str) -> dict:
    require(path.is_file() and not path.is_symlink() and re.fullmatch(r"[a-f0-9]{64}", digest)
            and sha(path) == digest, "D12_INPUT_BYTES_CHANGED")
    return json.loads(path.read_text(encoding="utf-8"))


def git(repo: Path, *args: str) -> bytes:
    return source_exporter.git(repo, *args)


def verified_git(args: list[str]) -> bytes:
    require(len(args) >= 4 and args[0] == "-C", "D12_GIT_SOURCE_COMMAND_CHANGED")
    return git(Path(args[1]), *args[2:])


def write_operator_blob(destination: Path, raw: bytes) -> dict:
    """Stage Git object bytes; Windows checkout CRLF is never source authority."""
    with destination.open("xb") as stream:
        stream.write(raw)
    require(destination.read_bytes() == raw, "D12_OPERATOR_EXPORT_CHANGED")
    return ref(destination)


def producer_closure(repo: Path, revision: str, directory: Path | None = None) -> dict:
    require(re.fullmatch(r"[a-f0-9]{40}", revision)
            and git(repo, "remote", "get-url", "origin").decode().strip() == ORIGIN["ui"]
            and git(repo, "cat-file", "-t", revision).decode().strip() == "commit",
            "D12_REVIEWED_PRODUCER_REQUIRED")
    result = {}
    for name in OPERATORS:
        raw = git(repo, "show", revision + ":scripts/" + name)
        if directory is not None:
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            result[name] = write_operator_blob(path, raw)
        else:
            path = Path(__file__).with_name(name)
            require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw,
                    "D12_LOADED_OPERATOR_CHANGED")
            result[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return result


def bootstrap(ui_repo: Path, core_repo: Path, producer_revision: str, destination: Path) -> dict:
    """Stage exact committed operators, then run their strict export entrypoint."""
    destination = destination.resolve()
    require(destination.parent.is_relative_to(PRIVATE) and not destination.exists(),
            "D12_NEW_PRIVATE_BOOTSTRAP_REQUIRED")
    destination.mkdir()
    operators = destination / "operator"
    operators.mkdir()
    producer_closure(ui_repo.resolve(strict=True), producer_revision, operators)
    exact_entry = operators / Path(__file__).name
    child = destination / "source-export"
    command = [sys.executable, str(exact_entry), "export", "--ui-repo", str(ui_repo),
               "--core-repo", str(core_repo), "--producer-revision", producer_revision,
               "--output", str(child)]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=1200)
    require(result.returncode == 0 and len(result.stdout) < 4096 and len(result.stderr) < 4096,
            "D12_EXACT_OPERATOR_EXPORT_REFUSED")
    receipt = child / "source-export-receipt.json"
    require(receipt.is_file() and not receipt.is_symlink(), "D12_SOURCE_EXPORT_MISSING")
    return {"state": "EXACT_OPERATOR_SOURCE_EXPORTED_NO_COMPILER", "sourceExport": ref(receipt),
            "operatorRevision": producer_revision}


def export_source(ui_repo: Path, core_repo: Path, producer_revision: str, destination: Path) -> dict:
    require(destination.parent.resolve() == PRIVATE or destination.parent.resolve().is_relative_to(PRIVATE),
            "D12_PRIVATE_OUTPUT_REQUIRED")
    require(not destination.exists() and destination.parent.is_dir(), "D12_NEW_OUTPUT_REQUIRED")
    repositories = {"ui": ui_repo.resolve(strict=True), "core": core_repo.resolve(strict=True)}
    for name, revision in (("ui", SOURCE), ("core", CORE)):
        repo = repositories[name]
        require(git(repo, "remote", "get-url", "origin").decode().strip() == ORIGIN[name]
                and git(repo, "cat-file", "-t", revision).decode().strip() == "commit",
                "D12_ACCEPTED_SOURCE_MISSING")
    producer_closure(repositories["ui"], producer_revision)
    destination.mkdir()
    sources = {name: source_exporter.export(repositories[name], SOURCE if name == "ui" else CORE,
                       destination / (name + "-source")) for name in ("ui", "core")}
    recipe = destination / "build.sh"
    with recipe.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(build.render_recipe(PROFILE))
    operator_directory = destination / "operator"
    operator_directory.mkdir()
    operators = producer_closure(repositories["ui"], producer_revision, operator_directory)
    (destination / "output").mkdir()
    result = {"schema": "marty.d12-current-native-source-export/v1", "state": "SOURCE_EXPORTED_NO_COMPILER",
              "buildProfile": PROFILE, "sources": sources, "recipe": ref(recipe),
              "producerRevision": producer_revision,
              "producerTree": git(repositories["ui"], "rev-parse", producer_revision + "^{tree}").decode().strip(),
              "operators": operators, "imagesBuilt": False, "releaseQualified": False,
              "recordingQualified": False}
    with (destination / "source-export-receipt.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return result


def source_packet(path: Path, digest: str) -> dict:
    packet = exact_file(path, digest)
    require(packet.get("schema") == "marty.d12-current-native-source-export/v1"
            and packet.get("state") == "SOURCE_EXPORTED_NO_COMPILER"
            and packet.get("buildProfile") == PROFILE
            and packet.get("imagesBuilt") is False
            and packet.get("releaseQualified") is False
            and packet.get("recordingQualified") is False,
            "D12_SOURCE_EXPORT_CHANGED")
    root = path.parent.resolve()
    require(root.is_relative_to(PRIVATE) and set(packet["operators"]) == set(OPERATORS),
            "D12_SOURCE_EXPORT_CUSTODY_CHANGED")
    for name, bound in packet["operators"].items():
        file = Path(bound["path"]).resolve()
        require(file == root / "operator" / name and file.stat().st_size == bound["bytes"]
                and sha(file) == bound["sha256"], "D12_OPERATOR_CLOSURE_CHANGED")
    require(Path(__file__).resolve() == root / "operator" / Path(__file__).name,
            "D12_OPERATOR_OUTSIDE_CLOSURE")
    require(Path(build.__file__).resolve() == root / "operator/scoped_native_build.py"
            and Path(source_exporter.__file__).resolve()
                == root / "operator/prepare_local_official_native_build.py"
            and Path(native_runner.__file__).resolve()
                == root / "operator/run_local_official_native_build.py",
            "D12_LOADED_OPERATOR_CHANGED")
    ui = Path(packet["sources"]["ui"]["repository"])
    core = Path(packet["sources"]["core"]["repository"])
    revision = packet["producerRevision"]
    require(git(ui, "remote", "get-url", "origin").decode().strip() == ORIGIN["ui"]
            and git(core, "remote", "get-url", "origin").decode().strip() == ORIGIN["core"]
            and packet["sources"]["ui"]["revision"] == SOURCE
            and packet["sources"]["core"]["revision"] == CORE,
            "D12_ACCEPTED_SOURCE_CHANGED")
    require(git(ui, "rev-parse", revision + "^{tree}").decode().strip() == packet["producerTree"],
            "D12_PRODUCER_TREE_CHANGED")
    for name, bound in packet["operators"].items():
        require(git(ui, "show", revision + ":scripts/" + name) == Path(bound["path"]).read_bytes(),
                "D12_PRODUCER_OBJECT_CHANGED")
    return packet


def target_input(value: dict, *, run_id: str, engine_id: str) -> None:
    volume = build.build_scope(PROFILE)["volumes"][1]
    require(value.get("state") == "CREATED_EMPTY_OWNED_TARGET"
            and value.get("volume") == volume
            and value.get("runId") == run_id and value.get("engineId") == engine_id
            and value.get("owner") == D12_PASSPORT_CURRENT.owner
            and value.get("emptyReadback") is True
            and value.get("sourceIndependent") is True
            and value.get("consumers") == []
            and isinstance(value.get("createdAt"), str) and bool(value["createdAt"]),
            "D12_FRESH_OWNED_TARGET_REQUIRED")


def journal_input(value: dict, *, run_id: str, engine_id: str) -> None:
    desktop = value.get("desktop", {})
    require(value.get("backend") == "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1"
            and value.get("schema") == 1
            and desktop.get("engineId") == engine_id
            and desktop.get("volumeProof") is not None
            and value.get("bootstrapParent", {}).get("supported") is True
            and value.get("bootstrapParent", {}).get("synced") is True
            and desktop.get("volumeProof", {}).get("Labels", {}).get("elevenid.run") == run_id,
            "D12_DESKTOP_JOURNAL_REQUIRED")


def prepare_cache(packet_path: Path, packet_sha: str, journal_path: Path,
                  journal_sha: str, run_id: str, engine_id: str,
                  builder_image: str) -> dict:
    packet = source_packet(packet_path, packet_sha)
    require(RUN.fullmatch(run_id) and builder_image == native_runner.IMAGE
            and isinstance(engine_id, str) and bool(engine_id),
            "D12_CACHE_IDENTIFIERS_REQUIRED")
    journal = exact_file(journal_path, journal_sha)
    journal_input(journal, run_id=run_id, engine_id=engine_id)
    root = packet_path.parent.resolve()
    output = root / ("cargo-cache-output-" + run_id)
    output.mkdir()
    lock = Path(packet["sources"]["ui"]["directory"]) / "rust/Cargo.lock"
    lock_bytes = lock.read_bytes()
    sources = cargo_cache.git_sources(lock_bytes)
    require("marty-core@" + CORE in sources, "D12_CACHE_FROZEN_CORE_LOCK_CHANGED")
    script = root / ("cargo-cache-fetch-" + run_id + ".sh")
    with script.open("xb") as stream:
        stream.write(cargo_cache.render_fetch_script(hashlib.sha256(lock_bytes).hexdigest(), sources))
    plan = {"sourceExportReceipt": ref(packet_path), "buildProfile": PROFILE,
            "sources": packet["sources"], "cacheRunId": run_id,
            "cacheOutputDirectory": str(output), "cacheScript": ref(script),
            "cacheGuard": packet["operators"]["scoped_native_cargo_cache.py"],
            "originalLockSha256": hashlib.sha256(lock_bytes).hexdigest(),
            "gitSources": sources, "builderImage": builder_image,
            "engineId": engine_id, "journalBackend": journal,
            "imagesBuilt": False, "releaseQualified": False, "recordingQualified": False}
    path = root / ("prepared-cache-" + run_id + ".json")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(plan, stream, indent=2)
        stream.write("\n")
    return {"state": "CACHE_PREPARED_NO_FETCH", "preparedCache": ref(path)}


def hydrate_cache(packet_path: Path, packet_sha: str,
                  cache_plan_path: Path, cache_plan_sha: str) -> dict:
    packet = source_packet(packet_path, packet_sha)
    plan = exact_file(cache_plan_path, cache_plan_sha)
    run_id = plan["cacheRunId"]
    require(plan["sourceExportReceipt"]["sha256"] == packet_sha
            and plan["sources"] == packet["sources"]
            and plan["buildProfile"] == PROFILE
            and cache_plan_path.resolve() == packet_path.parent.resolve() / ("prepared-cache-" + run_id + ".json")
            and plan["originalLockSha256"] == sha(Path(plan["sources"]["ui"]["directory"]) / "rust/Cargo.lock")
            and plan["gitSources"] == cargo_cache.git_sources(
                (Path(plan["sources"]["ui"]["directory"]) / "rust/Cargo.lock").read_bytes()),
            "D12_CACHE_PREPARED_SOURCE_CHANGED")
    for name in ("ui", "core"):
        source = plan["sources"][name]
        build.verify_export(source["repository"], source["revision"],
                            source["directory"], source["inventory"], verified_git)
    journal_input(plan["journalBackend"], run_id=run_id, engine_id=plan["engineId"])
    require(os.environ.get("DOCKER_CONTEXT") == "desktop-linux"
            and os.environ.get("DOCKER_CONFIG") == plan["journalBackend"]["desktop"]["configDirectory"],
            "EXPLICIT_DESKTOP_CONTEXT_REQUIRED")
    from scoped_linux_journal import LinuxBuildJournal
    store = LinuxBuildJournal(packet_path.parent, run_id, plan["journalBackend"])
    value = cargo_cache.hydrate(plan, native_runner.helper_module(), store)
    require(store.read("build-receipt.json") == value, "D12_CACHE_AUTHORITATIVE_RECEIPT_CHANGED")
    path = packet_path.parent / ("cargo-cache-receipt-" + run_id + ".json")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    return {"state": value["state"], "cacheReceipt": ref(path), "releaseQualified": False}


def prepare(packet_path: Path, packet_sha: str, target_path: Path, target_sha: str,
            journal_path: Path, journal_sha: str, run_id: str, engine_id: str,
            builder_image: str, cache_path: Path, cache_sha: str) -> dict:
    packet = source_packet(packet_path, packet_sha)
    require(RUN.fullmatch(run_id) and builder_image == native_runner.IMAGE
            and isinstance(engine_id, str) and bool(engine_id), "D12_EXACT_BUILD_IDENTIFIERS_REQUIRED")
    target = exact_file(target_path, target_sha)
    journal = exact_file(journal_path, journal_sha)
    require(target_path.resolve().is_relative_to(PRIVATE)
            and journal_path.resolve().is_relative_to(PRIVATE), "D12_PRIVATE_INPUT_REQUIRED")
    target_input(target, run_id=run_id, engine_id=engine_id)
    journal_input(journal, run_id=run_id, engine_id=engine_id)
    from scoped_native_cargo_cache import validate_bound_receipt
    cache_path = cache_path.resolve()
    require(cache_path.is_relative_to(PRIVATE), "D12_PRIVATE_CACHE_RECEIPT_REQUIRED")
    root = packet_path.parent.resolve()
    plan = {"privateDirectory": str(root), "buildProfile": PROFILE,
            "profileSourceSha256": packet["operators"]["scoped_native_profiles.py"]["sha256"],
            "executionOperatorSha256": packet["operators"]["scoped_native_build.py"]["sha256"],
            "uiRevision": SOURCE, "coreRevision": CORE,
            "roleBinaries": dict(D12_PASSPORT_CURRENT.roles), "sources": packet["sources"],
            "recipe": packet["recipe"], "builderImage": builder_image, "engineId": engine_id,
            "runId": run_id, "containerName": D12_PASSPORT_CURRENT.container_prefix + run_id,
            "outputDirectory": str(root / "output"), "journalBackend": journal,
            "targetVolumeReceipt": ref(target_path), "releaseQualified": False,
            "recordingQualified": False}
    validate_bound_receipt(plan, cache_path, cache_sha)
    cache = exact_file(cache_path, cache_sha)
    journal_input(cache["journalBackend"], run_id=cache["runId"], engine_id=engine_id)
    plan["cargoCacheRunId"] = cache["runId"]
    plan["cargoCacheJournalBackend"] = cache["journalBackend"]
    plan["cargoCacheReceipt"] = ref(cache_path)
    require(plan["targetVolumeReceipt"]["sha256"] == target_sha, "D12_TARGET_RECEIPT_CHANGED")
    build.verify(plan, verified_git, PROFILE)
    path = root / "prepared-build.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(plan, stream, indent=2)
        stream.write("\n")
    return {"state": "PREPARED_NO_COMPILER", "preparedSha256": sha(path)}


def execute(mode: str, packet_path: Path, packet_sha: str, prepared_sha: str) -> dict:
    packet = source_packet(packet_path, packet_sha)
    prepared = packet_path.parent / "prepared-build.json"
    plan = exact_file(prepared, prepared_sha)
    require(plan.get("buildProfile") == PROFILE
            and plan.get("executionOperatorSha256") == packet["operators"]["scoped_native_build.py"]["sha256"]
            and plan.get("profileSourceSha256") == packet["operators"]["scoped_native_profiles.py"]["sha256"],
            "D12_PREPARED_SOURCE_CHANGED")
    build.verify(plan, verified_git, PROFILE)
    if mode == "check":
        return {"state": "SOURCE_INPUTS_VERIFIED_NO_COMPILER", "source": SOURCE}
    require(os.environ.get("DOCKER_CONTEXT") == "desktop-linux", "EXPLICIT_DESKTOP_CONTEXT_REQUIRED")
    helper = native_runner.helper_module()
    result = (build.start(ref(prepared), helper, verified_git, PROFILE) if mode == "start"
              else build.finish(ref(prepared), helper, verified_git, PROFILE))
    return {"state": result["state"], "source": SOURCE, "releaseQualified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("bootstrap", "export", "prepare-cache", "hydrate-cache",
                                         "prepare", "check", "start", "finish"))
    parser.add_argument("--ui-repo", type=Path)
    parser.add_argument("--core-repo", type=Path)
    parser.add_argument("--producer-revision")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-export", type=Path)
    parser.add_argument("--source-export-sha256")
    parser.add_argument("--target-receipt", type=Path)
    parser.add_argument("--target-sha256")
    parser.add_argument("--journal-backend", type=Path)
    parser.add_argument("--journal-sha256")
    parser.add_argument("--cargo-cache-receipt", type=Path)
    parser.add_argument("--cargo-cache-sha256")
    parser.add_argument("--cache-plan", type=Path)
    parser.add_argument("--cache-plan-sha256")
    parser.add_argument("--run-id")
    parser.add_argument("--engine-id")
    parser.add_argument("--builder-image")
    parser.add_argument("--prepared-sha256")
    args = parser.parse_args()
    if args.mode == "bootstrap":
        require(all((args.ui_repo, args.core_repo, args.producer_revision, args.output)),
                "D12_BOOTSTRAP_INPUTS_REQUIRED")
        print(json.dumps(bootstrap(args.ui_repo, args.core_repo, args.producer_revision, args.output)))
    elif args.mode == "export":
        require(all((args.ui_repo, args.core_repo, args.producer_revision, args.output)),
                "D12_EXPORT_INPUTS_REQUIRED")
        value = export_source(args.ui_repo, args.core_repo, args.producer_revision, args.output)
        print(json.dumps({"state": value["state"], "source": SOURCE, "core": CORE}))
    elif args.mode == "prepare-cache":
        require(all((args.source_export, args.source_export_sha256,
                     args.journal_backend, args.journal_sha256,
                     args.run_id, args.engine_id, args.builder_image)),
                "D12_CACHE_PREPARE_INPUTS_REQUIRED")
        print(json.dumps(prepare_cache(args.source_export, args.source_export_sha256,
              args.journal_backend, args.journal_sha256, args.run_id, args.engine_id,
              args.builder_image)))
    elif args.mode == "hydrate-cache":
        require(all((args.source_export, args.source_export_sha256,
                     args.cache_plan, args.cache_plan_sha256)),
                "D12_CACHE_EXECUTE_INPUTS_REQUIRED")
        print(json.dumps(hydrate_cache(args.source_export, args.source_export_sha256,
              args.cache_plan, args.cache_plan_sha256)))
    elif args.mode == "prepare":
        require(all((args.source_export, args.source_export_sha256, args.target_receipt,
                     args.target_sha256, args.journal_backend, args.journal_sha256,
                     args.run_id, args.engine_id, args.builder_image,
                     args.cargo_cache_receipt, args.cargo_cache_sha256)), "D12_PREPARE_INPUTS_REQUIRED")
        print(json.dumps(prepare(args.source_export, args.source_export_sha256,
             args.target_receipt, args.target_sha256, args.journal_backend, args.journal_sha256,
             args.run_id, args.engine_id, args.builder_image,
             args.cargo_cache_receipt, args.cargo_cache_sha256)))
    else:
        require(args.source_export and args.source_export_sha256 and args.prepared_sha256,
                "D12_PREPARED_INPUTS_REQUIRED")
        print(json.dumps(execute(args.mode, args.source_export,
                                  args.source_export_sha256, args.prepared_sha256)))


if __name__ == "__main__":
    main()
