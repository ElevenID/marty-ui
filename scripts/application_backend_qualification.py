#!/usr/bin/env python3
"""Prepare or reauthenticate an unqualified application/backend evidence directory.

This Linux-only tool retains original publications and a fixed observation
profile. It does not run their payloads, generate a deployment override, test
compatibility, sign anything, or admit either image into a composition. Callers
must exclude concurrent writers to input and output parent directories.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile

import application_provenance as application_proof
import application_release as application
import application_release_intake as intake
import installer_release as installer
import stable_installer_assets as stable
import ui_release as ui
import verify_installer_provenance as verifier
import website_release as web

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "contracts/application-backend-qualification.json"
PROFILE_SHA256 = "sha256:141cabb10a8de5311bde6e8e6808a73b78c22f37c15307b3b51816df71b91577"
PROFILE_ID = "public-application-session/v1"
PROFILE_NAME = "qualification-profile.json"
PLAN_NAME = "qualification-plan.json"
SCHEMA = "marty.application-backend-qualification-plan/v1"
JSON_LIMIT = 128 * 1024
CHUNK_BYTES = 1024 * 1024
BACKEND_FILES = (*stable.SUBJECTS, *(name + ".provenance.jsonl" for name in stable.SUBJECTS))
BACKEND_LIMITS = {**installer.ARTIFACT_MAX_BYTES, "installer-inventory.json": 65536,
                  **{name + ".provenance.jsonl": stable.PROVENANCE_LIMIT for name in stable.SUBJECTS}}
ORIGINAL_LIMITS = {**{"application/" + name: limit for name, limit in intake.FILE_LIMITS.items()},
                   **{"backend/" + name: limit for name, limit in BACKEND_LIMITS.items()}}
QUALIFICATION = dict.fromkeys(("runtime_compatible", "backend_api_tested", "oidc_journey_tested",
                              "host_deployment_tested", "website_routes_matched", "rollback_tested",
                              "composition_admitted", "deployment_admitted", "activated"), False)
PLAN_FIELDS = {"schema", "status", "platform", "application", "backend", "profile", "files",
               "required_observations", "separate_gates", "qualification", "plan_id"}


def _path(path: Path) -> None:
    ui.require(path.is_absolute() and ".." not in path.parts and "\0" not in str(path)
               and not any(part.is_symlink() for part in (path, *path.parents)),
               "qualification paths must be absolute and non-symlink")


def _directory(path: Path, names: set[str], *, private: bool = False) -> None:
    _path(path)
    info = path.stat()
    ui.require(stat.S_ISDIR(info.st_mode), "qualification input is not a directory")
    if private:
        ui.require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                   "qualification directory must be private")
    ui.require({item.name for item in path.iterdir()} == names, "qualification file closure differs")


def _identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _file(path: Path, maximum: int, *, target: Path | None = None, private: bool = False) -> dict:
    """Hash/copy bounded regular files without loading large backend artifacts."""
    _path(path)
    before = path.stat()
    ui.require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
               "qualification input must be a bounded regular file")
    if private:
        ui.require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
                   "qualification evidence mode differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    output = None
    try:
        with os.fdopen(descriptor, "rb") as source:
            ui.require(_identity(os.fstat(source.fileno())) == _identity(before),
                       "qualification input changed before reading")
            if target is not None:
                output = target.open("xb")
                target.chmod(0o600)
            digest = hashlib.sha256()
            count = 0
            while chunk := source.read(min(CHUNK_BYTES, maximum + 1 - count)):
                count += len(chunk)
                ui.require(count <= maximum, "qualification input exceeds its bound")
                digest.update(chunk)
                if output is not None:
                    output.write(chunk)
            ui.require(count == before.st_size
                       and _identity(os.fstat(source.fileno())) == _identity(before)
                       and _identity(path.stat()) == _identity(before),
                       "qualification input changed while reading")
    finally:
        if output is not None:
            output.close()
    return {"bytes": count, "sha256": "sha256:" + digest.hexdigest()}


def _originals(directory: Path, limits: dict[str, int], *, private: bool = False) -> dict:
    _directory(directory, set(limits), private=private)
    result = {name: _file(directory / name, maximum, private=private) for name, maximum in limits.items()}
    _directory(directory, set(limits), private=private)
    return result


def _closure(directory: Path) -> dict:
    _directory(directory, {"application", "backend", PLAN_NAME, PROFILE_NAME}, private=True)
    result = {**{"application/" + name: pin for name, pin in _originals(directory / "application", intake.FILE_LIMITS,
                                                                      private=True).items()},
            **{"backend/" + name: pin for name, pin in _originals(directory / "backend", BACKEND_LIMITS,
                                                                  private=True).items()},
            **{name: _file(directory / name, JSON_LIMIT, private=True) for name in (PLAN_NAME, PROFILE_NAME)}}
    _directory(directory, {"application", "backend", PLAN_NAME, PROFILE_NAME}, private=True)
    return result


def _profile() -> tuple[bytes, dict]:
    raw = application.read_bytes(PROFILE_PATH, JSON_LIMIT)
    ui.require(ui.digest(raw) == PROFILE_SHA256, "trusted qualification profile differs from the reviewed tool")
    value = application.parse(raw)
    ui.require(value.get("schema") == "marty.application-backend-qualification-profile/v1"
               and value.get("id") == PROFILE_ID and value.get("platform") == "linux/amd64",
               "qualification profile identity differs")
    return raw, value


def _selection(application_source_sha: str, backend_source_sha: str, backend_tag: str) -> None:
    ui.require(sys.platform == "linux", "application/backend qualification is supported only on Linux")
    web.full_sha(application_source_sha)
    web.full_sha(backend_source_sha)
    ui.require(isinstance(backend_tag, str) and installer.classify_release_tag(backend_tag)[0] == "stable",
               "an explicit stable backend tag is required")


def plan_id(value: dict) -> str:
    return ui.digest(ui.canonical({key: item for key, item in value.items() if key != "plan_id"}))


def _describe(release: dict, inventory: dict, image_lock: dict, files: dict, profile: dict, profile_pin: dict) -> dict:
    build = release["build_plan"]
    value = {"schema": SCHEMA, "status": "unqualified", "platform": "linux/amd64",
             "application": {"source_sha": release["source_sha"], "producer": release["producer"],
                             "repository_id": verifier.REPOSITORY_ID, "image": release["image"],
                             "receipt": files["application/" + application.RECEIPT],
                             "build_plan_sha256": release["build_plan_sha256"],
                             "route_contract": build["route_contract"], "runtime_context": build["runtime_context"],
                             "output": build["output"]},
             "backend": {"source_sha": inventory["source_sha"], "tag": inventory["release_tag"],
                         "producer": {"repository": inventory["repository"], "repository_id": verifier.REPOSITORY_ID,
                                      "workflow": stable.WORKFLOW, "ref": verifier.REF,
                                      "source_sha": inventory["source_sha"], "run_id": inventory["build_run_id"],
                                      "run_attempt": inventory["build_run_attempt"]},
                         "inventory": files["backend/installer-inventory.json"], "image_lock": image_lock},
             "profile": {"id": profile["id"], **profile_pin}, "files": files,
             "required_observations": [{"id": row["id"], "status": "pending"} for row in profile["required_observations"]],
             "separate_gates": [{"id": name, "status": "pending"} for name in profile["separate_gates"]],
             "qualification": dict(QUALIFICATION)}
    value["plan_id"] = plan_id(value)
    return value


def _pending(value: dict, *, expected_plan_id: str, application_source_sha: str,
             backend_source_sha: str, backend_tag: str, profile: dict, profile_pin: dict) -> None:
    """Reject authority claims and retargeting before making proof calls."""
    web.object_keys(value, PLAN_FIELDS, "qualification plan")
    web.image_digest(expected_plan_id)
    ui.require(value["schema"] == SCHEMA and value["status"] == "unqualified" and value["platform"] == "linux/amd64",
               "qualification plan identity differs")
    ui.require(value["plan_id"] == expected_plan_id == plan_id(value), "qualification plan ID differs")
    ui.require(isinstance(value["application"], dict) and value["application"].get("source_sha") == application_source_sha
               and isinstance(value["backend"], dict) and value["backend"].get("source_sha") == backend_source_sha
               and value["backend"].get("tag") == backend_tag, "qualification selection differs")
    web.object_keys(value["qualification"], set(QUALIFICATION), "qualification claims")
    ui.require(all(item is False for item in value["qualification"].values()), "qualification cannot claim success or admission")
    web.object_keys(value["files"], set(ORIGINAL_LIMITS), "qualification originals")
    for name, pin in value["files"].items():
        application._pin(pin, name, ORIGINAL_LIMITS[name])
    ui.require(value["profile"] == {"id": profile["id"], **profile_pin}
               and value["required_observations"] == [{"id": row["id"], "status": "pending"} for row in profile["required_observations"]]
               and value["separate_gates"] == [{"id": name, "status": "pending"} for name in profile["separate_gates"]],
               "qualification profile or pending gates differ")


def _authenticate(directory: Path, *, application_source_sha: str, backend_source_sha: str,
                  backend_tag: str, gh: Path, cosign: Path, runner: verifier.Run) -> tuple[dict, dict, dict]:
    app_assets, backend_assets = directory / "application", directory / "backend"
    release = application_proof.verify_package_application(app_assets, gh=gh, cosign=cosign,
                                                           source_sha=application_source_sha, runner=runner)
    intake._validate_retained(app_assets, release)
    stable.verify_published(backend_assets, source_sha=backend_source_sha, tag=backend_tag, gh=gh)
    inventory = stable.read_inventory(backend_assets)
    image_lock = application.parse(application.read_bytes(backend_assets / "prepared-selfhost-images.json", 65536))
    # Retain all original roles, including the original backend UI. The new
    # package application is an independent candidate, never an active override.
    ui.require(installer.images(image_lock, backend_tag, set(image_lock["services"])) == inventory["images"],
               "backend image lock differs from its authenticated inventory")
    return release, inventory, image_lock


def _write(path: Path, raw: bytes) -> None:
    with path.open("xb") as output:
        path.chmod(0o600)
        output.write(raw)


def prepare(*, application_assets: Path, application_source_sha: str, backend_assets: Path,
            backend_source_sha: str, backend_tag: str, output: Path, gh: Path, cosign: Path,
            runner: verifier.Run = verifier.command) -> dict:
    _selection(application_source_sha, backend_source_sha, backend_tag)
    for path in (application_assets, backend_assets, output, gh, cosign):
        _path(path)
    ui.require(not os.path.lexists(output), "qualification destination already exists")
    for tool in (gh, cosign):
        verifier.local_file(tool)
    profile_raw, profile = _profile()
    profile_pin = application.file_record(profile_raw)
    sources = (("application", application_assets, intake.FILE_LIMITS), ("backend", backend_assets, BACKEND_LIMITS))
    with tempfile.TemporaryDirectory(prefix=".application-backend-qualification-", dir=output.parent) as temporary:
        held = Path(temporary) / "assets"
        held.mkdir(mode=0o700)
        originals = {}
        for prefix, source, limits in sources:
            _directory(source, set(limits))
            (held / prefix).mkdir(mode=0o700)
            for name, maximum in limits.items():
                originals[prefix + "/" + name] = _file(source / name, maximum, target=held / prefix / name)
            _directory(source, set(limits))
        _write(held / PROFILE_NAME, profile_raw)
        release, inventory, image_lock = _authenticate(held, application_source_sha=application_source_sha,
                                                       backend_source_sha=backend_source_sha, backend_tag=backend_tag,
                                                       gh=gh, cosign=cosign, runner=runner)
        value = _describe(release, inventory, image_lock, originals, profile, profile_pin)
        _pending(value, expected_plan_id=value["plan_id"], application_source_sha=application_source_sha,
                 backend_source_sha=backend_source_sha, backend_tag=backend_tag, profile=profile, profile_pin=profile_pin)
        raw = ui.canonical(value)
        ui.require(len(raw) <= JSON_LIMIT, "qualification plan exceeds its bound")
        _write(held / PLAN_NAME, raw)
        ui.require(_closure(held) == {**originals, PROFILE_NAME: profile_pin, PLAN_NAME: application.file_record(raw)},
                   "qualification originals changed during authentication")
        for prefix, source, limits in sources:
            ui.require(_originals(source, limits) == {name: originals[prefix + "/" + name] for name in limits},
                       "source publication changed during qualification preparation")
        ui.require(_profile()[0] == profile_raw, "trusted qualification profile changed during preparation")
        intake._publish_directory(held, output)
    return value


def validate(*, assets: Path, application_source_sha: str, backend_source_sha: str, backend_tag: str,
             expected_plan_id: str, gh: Path, cosign: Path, runner: verifier.Run = verifier.command) -> dict:
    _selection(application_source_sha, backend_source_sha, backend_tag)
    for path in (assets, gh, cosign):
        _path(path)
    for tool in (gh, cosign):
        verifier.local_file(tool)
    profile_raw, profile = _profile()
    profile_pin = application.file_record(profile_raw)
    before = _closure(assets)
    ui.require(before[PROFILE_NAME] == profile_pin, "retained qualification profile differs from trusted profile")
    value = application.parse(application.read_bytes(assets / PLAN_NAME, JSON_LIMIT))
    _pending(value, expected_plan_id=expected_plan_id, application_source_sha=application_source_sha,
             backend_source_sha=backend_source_sha, backend_tag=backend_tag, profile=profile, profile_pin=profile_pin)
    originals = {name: before[name] for name in ORIGINAL_LIMITS}
    ui.require(value["files"] == originals, "qualification originals differ from reviewed plan")
    release, inventory, image_lock = _authenticate(assets, application_source_sha=application_source_sha,
                                                   backend_source_sha=backend_source_sha, backend_tag=backend_tag,
                                                   gh=gh, cosign=cosign, runner=runner)
    ui.require(value == _describe(release, inventory, image_lock, originals, profile, profile_pin),
               "qualification plan differs from original authenticated evidence")
    ui.require(_closure(assets) == before and _profile()[0] == profile_raw,
               "qualification evidence changed during authentication")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "validate"):
        child = commands.add_parser(command)
        child.add_argument("--application-source-sha", required=True)
        child.add_argument("--backend-source-sha", required=True)
        child.add_argument("--backend-tag", required=True)
        child.add_argument("--gh", required=True, type=Path)
        child.add_argument("--cosign", required=True, type=Path)
        if command == "prepare":
            child.add_argument("--application-assets", required=True, type=Path)
            child.add_argument("--backend-assets", required=True, type=Path)
            child.add_argument("--output", required=True, type=Path)
        else:
            child.add_argument("--assets", required=True, type=Path)
            child.add_argument("--plan-id", dest="expected_plan_id", required=True)
    options = vars(parser.parse_args())
    command = options.pop("command")
    try:
        value = (prepare if command == "prepare" else validate)(**options)
    except (OSError, ValueError) as error:
        parser.exit(1, f"application/backend qualification failed: {error}\n")
    print(value["plan_id"])


if __name__ == "__main__":
    main()
