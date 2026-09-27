#!/usr/bin/env python3
"""Bind a disposable Compose plan to protected release and workflow identity.

Plans contain no credentials and authorize no Docker mutation. A later record
must be separately attested by a protected producer before live ownership can
be considered; even a verified record cannot qualify passport retirement.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from typing import Callable

if __package__:
    from .check_passport_supported_compose_ownership import verify as verify_ownership
    from .collect_passport_beta_acceptance import verify_attestations
    from .passport_supported_infra_images import qualified_images
else:
    from check_passport_supported_compose_ownership import verify as verify_ownership
    from collect_passport_beta_acceptance import verify_attestations
    from passport_supported_infra_images import qualified_images


COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
UI_SERVICES = "ghcr.io/elevenid/marty-ui-oss/services"
UI_MIGRATIONS = "ghcr.io/elevenid/marty-ui-oss/migrations"
LEGACY = "ghcr.io/elevenid/marty-credentials-issuance"
# The v0.1.78 release source matches all three SHA256 values in
# marty-credentials/contracts/physical-passport-python-route-reference.json:
# physical_document_routes.py 2206f15dfd8a8040e997cba0e4a7f27cc8e3f4e84d6094c62ae71beae5d90e37,
# emrtd_signer_client.py 8064185f747bae091c5164a32915f83b435ccd6526434f5ddca5114cc6661472,
# personalization_bureau_client.py 31d70c676c2b4e5e09d0e0ea6aa7bea37432b98984a5adffd5fea7e18ede9afb.
# Its release digest asset, checksum manifest,
# and hosted release-images.yml OCI attestation were verified together.
# A signed older image with the nine routes is insufficient for rollback when
# its route or bureau behavior differs from that frozen reference.
FROZEN_LEGACY_RELEASE = (
    "0.1.78",
    "efd5da1e2d41419ce93721f98d314c7b911e6b5e",
    "sha256:e7bb482120837c68af6cec2f6d1d5276488de440b93fc811987860b7b99b4657",
)
PLAN_WORKFLOW = "ElevenID/marty-ui/.github/workflows/passport-supported-provisioning-plan.yml"
# This hosted attestor does not exist yet. The current acceptance workflow runs
# on a self-hosted runner and cannot satisfy --deny-self-hosted-runners.
RECORD_WORKFLOW = "ElevenID/marty-ui/.github/workflows/passport-supported-provisioning-record.yml"


class PlanError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise PlanError(message)


def _attest(target: str, repository: str, signer: str, commit: str,
            source_ref: str) -> bool:
    try:
        subprocess.run([
            "gh", "attestation", "verify", target, "--repo", repository,
            "--signer-workflow", signer, "--source-digest", commit,
            "--source-ref", source_ref, "--deny-self-hosted-runners",
        ], check=True, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PlanError("Protected provenance attestation failed") from exc
    return True


def _component(manifest: dict, name: str, repository: str,
               image: str) -> tuple[str, str, str]:
    components = manifest.get("components")
    require(isinstance(components, list), "Official stack components are missing")
    matches = [item for item in components if isinstance(item, dict)
               and item.get("name") == name]
    require(len(matches) == 1, "Official stack component is missing or ambiguous")
    item = matches[0]
    commit = item.get("commit")
    version = item.get("version")
    require(item.get("repository") == repository
            and isinstance(commit, str) and COMMIT.fullmatch(commit) is not None
            and isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version),
            "Official stack component source is invalid")
    artifacts = item.get("artifacts")
    require(isinstance(artifacts, list), "Official stack artifacts are missing")
    images = [value for value in artifacts if isinstance(value, dict)
              and value.get("type") == "oci" and value.get("uri") == image]
    require(len(images) == 1 and isinstance(images[0].get("digest"), str)
            and DIGEST.fullmatch(images[0]["digest"]) is not None,
            "Official stack image is missing or ambiguous")
    return commit, version, images[0]["digest"]


def release_inputs(manifest_path: Path, source_commit: str, *,
                   verify_ui: Callable[[Path, dict[str, str], str], bool] = verify_attestations,
                   attest: Callable[[str, str, str, str, str], bool] = _attest,
                   infra: Callable[[], dict[str, str]] = qualified_images) -> dict:
    require(COMMIT.fullmatch(source_commit) is not None,
            "Protected UI source commit is invalid")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PlanError("Official stack manifest is missing or invalid") from exc
    require(isinstance(manifest, dict) and manifest.get("schema") == "marty.stack/v1",
            "Official stack manifest schema is invalid")
    ui_commit, _, services_digest = _component(
        manifest, "marty-ui", "ElevenID/marty-ui", UI_SERVICES)
    require(ui_commit == source_commit,
            "Official stack UI source differs from protected main")
    _, _, migrations_digest = _component(
        manifest, "marty-ui", "ElevenID/marty-ui", UI_MIGRATIONS)
    legacy_commit, legacy_version, legacy_digest = _component(
        manifest, "marty-credentials-issuance", "ElevenID/marty-credentials",
        LEGACY)
    require((legacy_version, legacy_commit, legacy_digest) == FROZEN_LEGACY_RELEASE,
            "Legacy issuance release differs from frozen Python route reference")
    ui_images = {artifact.get("uri"): artifact.get("digest")
                 for component in manifest["components"] if isinstance(component, dict)
                 and component.get("name") == "marty-ui"
                 for artifact in component.get("artifacts", [])
                 if isinstance(artifact, dict) and artifact.get("type") == "oci"}
    require(set(ui_images) == {UI_SERVICES, UI_MIGRATIONS,
                              "ghcr.io/elevenid/marty-ui-oss/ui"}
            and all(isinstance(value, str) and DIGEST.fullmatch(value)
                    for value in ui_images.values()),
            "Official stack UI image roles are incomplete")
    require(verify_ui(manifest_path, ui_images, source_commit) is True,
            "Official stack UI attestations are unverified")
    require(attest(f"oci://{LEGACY}@{legacy_digest}",
                   "ElevenID/marty-credentials",
                   "ElevenID/marty-credentials/.github/workflows/release-images.yml",
                   legacy_commit, f"refs/tags/v{legacy_version}") is True,
            "Legacy issuance image attestation is unverified")
    infra_images = infra()
    return {
        "source_commit": source_commit,
        "stack_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "services_reference": f"{UI_SERVICES}@{services_digest}",
        "migrations_reference": f"{UI_MIGRATIONS}@{migrations_digest}",
        "legacy_reference": f"{LEGACY}@{legacy_digest}",
        "legacy_commit": legacy_commit,
        "legacy_version": legacy_version,
        "infra_images": infra_images,
    }


def protected_context(environment: dict[str, str]) -> tuple[str, str]:
    require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("GITHUB_REPOSITORY") == "ElevenID/marty-ui"
            and environment.get("GITHUB_REF") == "refs/heads/main"
            and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environment.get("GITHUB_WORKFLOW_REF") == (
                "ElevenID/marty-ui/.github/workflows/"
                "passport-supported-provisioning-plan.yml@refs/heads/main"),
            "Protected plan workflow identity is invalid")
    commit, run_id = environment.get("GITHUB_SHA"), environment.get("GITHUB_RUN_ID")
    require(isinstance(commit, str) and COMMIT.fullmatch(commit) is not None
            and isinstance(run_id, str) and RUN_ID.fullmatch(run_id) is not None,
            "Protected plan workflow source/run is invalid")
    return commit, run_id


def build_plan(surface: str, run_id: str, inputs: dict,
               now: datetime, nonce: str) -> dict:
    require(surface in {"base", "selfhost"}, "Disposable surface is invalid")
    require(RUN_ID.fullmatch(run_id) is not None,
            "Protected plan run ID is invalid")
    require(re.fullmatch(r"[0-9a-f]{16}", nonce) is not None,
            "Protected plan nonce is invalid")
    require(now.tzinfo is not None, "Protected plan clock is invalid")
    project = f"marty-passport-acceptance-{surface}-{run_id}{nonce[:6]}"
    require(len(project.split("-")[-1]) <= 32,
            "Disposable project suffix is too long")
    return {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": surface, "project": project,
        "run_id": run_id, "nonce": nonce,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        **inputs,
        "owner_labels": {
            "com.marty.passport.acceptance.owner": "supported-consumer",
            "com.marty.passport.acceptance.run-id": run_id,
            "com.marty.passport.acceptance.source-commit": inputs["source_commit"],
            "com.marty.passport.acceptance.services-image": inputs["services_reference"],
        },
        "blocker": "no protected disposable provisioning or live rollback record",
    }


def verify_record(plan_path: Path, record_path: Path, now: datetime, *,
                  attest: Callable[[str, str, str, str, str], bool] = _attest,
                  ownership: Callable[..., dict] = verify_ownership) -> dict:
    """Require two protected attestations before inspecting any live Docker ID."""
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PlanError("Protected plan or resource record is invalid") from exc
    require(isinstance(plan, dict) and isinstance(record, dict)
            and plan.get("schema") == "marty.passport-supported-provisioning-plan/v1"
            and record.get("schema") == "marty.passport-supported-compose-ownership/v1",
            "Protected plan/resource schema mismatch")
    source = plan.get("source_commit")
    require(isinstance(source, str) and COMMIT.fullmatch(source) is not None,
            "Protected plan source is invalid")
    require(attest(str(plan_path), "ElevenID/marty-ui", PLAN_WORKFLOW,
                   source, "refs/heads/main") is True,
            "Protected plan attestation is missing")
    require(attest(str(record_path), "ElevenID/marty-ui", RECORD_WORKFLOW,
                   source, "refs/heads/main") is True,
            "Protected resource record attestation is missing")
    _require_record_binding(plan_path, plan, record)
    result = ownership(record, plan["surface"], now)
    require(result.get("live_ownership_verified") is True
            and result.get("rollback_accepted") is False,
            "Disposable resource ownership was not verified")
    return {"schema": "marty.passport-supported-provisioning-record-check/v1",
            "status": "blocked", "project": plan["project"],
            "live_ownership_verified": True, "rollback_accepted": False,
            "blocker": "live Rust-to-Python-to-Rust route proof is absent"}


def _require_record_binding(plan_path: Path, plan: dict, record: dict) -> None:
    require(plan.get("status") == "blocked"
            and record.get("plan_sha256") == hashlib.sha256(plan_path.read_bytes()).hexdigest()
            and record.get("run_id") == plan.get("run_id")
            and record.get("project") == plan.get("project")
            and record.get("source_commit") == plan.get("source_commit")
            and record.get("services_reference") == plan.get("services_reference")
            and record.get("migrations_reference") == plan.get("migrations_reference")
            and record.get("legacy_reference") == plan.get("legacy_reference")
            and record.get("infra_images") == plan.get("infra_images")
            and record.get("created_at") == plan.get("created_at")
            and record.get("expires_at") == plan.get("expires_at")
            and record.get("owner_labels") == plan.get("owner_labels"),
            "Protected resource record differs from attested plan")
    producer_run_id = record.get("producer_run_id")
    require(isinstance(producer_run_id, str)
            and RUN_ID.fullmatch(producer_run_id) is not None,
            "Protected producer run ID is invalid")
    require(plan.get("surface") in {"base", "selfhost"},
            "Protected surface is invalid")


def verify_handoff(plan_path: Path, record_path: Path, source_commit: str,
                   producer_run_id: str, *,
                   attest: Callable[[str, str, str, str, str], bool] = _attest) -> dict:
    """Check exact protected producer handoff before a hosted job signs it."""
    require(COMMIT.fullmatch(source_commit) is not None
            and RUN_ID.fullmatch(producer_run_id) is not None,
            "Protected handoff source/run is invalid")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PlanError("Protected handoff artifacts are invalid") from exc
    require(isinstance(plan, dict) and isinstance(record, dict)
            and plan.get("schema") == "marty.passport-supported-provisioning-plan/v1"
            and record.get("schema") == "marty.passport-supported-compose-ownership/v1"
            and plan.get("source_commit") == source_commit
            and record.get("producer_run_id") == producer_run_id,
            "Protected handoff source/run mismatch")
    require(attest(str(plan_path), "ElevenID/marty-ui", PLAN_WORKFLOW,
                   source_commit, "refs/heads/main") is True,
            "Protected plan attestation is missing")
    _require_record_binding(plan_path, plan, record)
    return {"schema": "marty.passport-supported-record-handoff/v1",
            "status": "blocked", "project": plan["project"],
            "producer_run_id": producer_run_id,
            "blocker": "live ownership and rollback have not been verified"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", choices=("base", "selfhost"), required=True)
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        source, run_id = protected_context(os.environ)
        inputs = release_inputs(args.stack_manifest, source)
        plan = build_plan(args.surface, run_id, inputs,
                          datetime.now(timezone.utc), secrets.token_hex(8))
    except (PlanError, OSError, ValueError) as exc:
        parser.exit(1, f"Protected provisioning plan blocked: {exc}\n")
    args.output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("Wrote blocked, source-bound disposable provisioning plan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
