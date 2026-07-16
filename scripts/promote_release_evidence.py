#!/usr/bin/env python3
"""Validate protected wallet evidence and produce a release-ready manifest."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED_REPOSITORIES = {
    "marty_ui",
    "marty_protocol",
    "marty_credentials",
    "marty_core",
    "marty_cli",
    "marty_blog",
    "marty_subscriptions",
}
REQUIRED_IMAGES = {
    "services",
    "ui",
    "ui_selfhost",
    "migrations",
    "waltid_wallet_api",
    "waltid_web_wallet",
}
REQUIRED_IMAGE_DIGESTS = {"services", "ui", "ui_selfhost", "migrations"}
FRESH_ORG_RESOURCE_TYPES = {
    "signing_service",
    "issuer_identity",
    "trust_profile",
    "revocation_profile",
    "credential_template",
    "application_template",
    "presentation_policy",
    "deployment_profile",
    "issuance_flow",
    "verification_flow",
    "api_key",
}


class EvidenceError(ValueError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"Could not read JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain a JSON object")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _is_https_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _latest_report(root: Path, directory_prefix: str) -> tuple[Path, dict[str, Any]]:
    candidates = list(root.glob(f"**/{directory_prefix}*/report.json"))
    _require(bool(candidates), f"Missing {directory_prefix} report in beta lifecycle artifact")
    reports = [(path, _load_json(path)) for path in candidates]
    return max(
        reports,
        key=lambda item: str(
            item[1].get("finishedAt")
            or item[1].get("createdAt")
            or item[1].get("startedAt")
            or item[1].get("created_at")
            or ""
        ),
    )


def validate_build_manifest(
    manifest: dict[str, Any],
    *,
    release_version: str,
    marty_ui_sha: str,
    mip_version: str,
    beta_origin: str,
) -> None:
    _require(manifest.get("release_version") == release_version, "Build manifest release version mismatch")
    _require(manifest.get("mip_version") == mip_version, "Build manifest MIP version mismatch")
    _require(manifest.get("build_ready") is True, "Build manifest is not build-ready")
    _require(manifest.get("release_ready") is False, "Input manifest must not already be release-ready")
    _require(manifest.get("mixed_versions_supported") is False, "Mixed-version manifests cannot be promoted")
    repositories = manifest.get("repositories") or {}
    _require(set(repositories) == REQUIRED_REPOSITORIES, "Build manifest coordinated repository set mismatch")
    _require(repositories.get("marty_ui") == marty_ui_sha, "Build manifest Marty UI SHA mismatch")
    _require(all(GIT_SHA_RE.fullmatch(str(value or "")) for value in repositories.values()), "Repository revisions must be full commit SHAs")
    images = manifest.get("images") or {}
    _require(set(images) == REQUIRED_IMAGES, "Build manifest image set mismatch")
    for name in ("services", "ui", "ui_selfhost", "migrations"):
        _require(
            str(images.get(name) or "").endswith(f":{release_version}"),
            f"Build manifest {name} image is not bound to the release version",
        )
    for name in ("waltid_wallet_api", "waltid_web_wallet"):
        _require(
            re.search(r"@sha256:[0-9a-f]{64}$", str(images.get(name) or "")) is not None,
            f"Build manifest {name} image is not digest-pinned",
        )
    image_digests = manifest.get("image_digests") or {}
    _require(set(image_digests) == REQUIRED_IMAGE_DIGESTS, "Build manifest image digest set mismatch")
    _require(
        all(IMAGE_DIGEST_RE.fullmatch(str(value or "")) for value in image_digests.values()),
        "Every built image must have a full lowercase sha256 digest",
    )
    rehearsal = manifest.get("migration_rehearsal") or {}
    _require(rehearsal.get("status") == "passed", "Migration rehearsal did not pass")
    _require(rehearsal.get("mode") == "beta-copy", "Migration rehearsal must use a beta database copy")
    _require(bool(rehearsal.get("snapshot_id")), "Migration rehearsal snapshot ID is missing")
    _require(rehearsal.get("public_origin") == beta_origin, "Migration rehearsal public origin mismatch")


def validate_beta_lifecycle(
    artifact_root: Path,
    *,
    cd_run_id: str,
    beta_run_id: str,
    release_version: str,
    marty_ui_sha: str,
    marty_core_sha: str,
    beta_origin: str,
    mip_version: str,
    browser_wallet_ids: list[str],
    spruce_requirements: dict[str, Any],
) -> dict[str, str]:
    contexts = list(artifact_root.glob("**/release-context.json"))
    _require(len(contexts) == 1, "Beta lifecycle artifact must contain exactly one release-context.json")
    context = _load_json(contexts[0])
    _require(str(context.get("run_id")) == str(beta_run_id), "Beta lifecycle run ID mismatch")
    _require(str(context.get("cd_run_id")) == str(cd_run_id), "Beta lifecycle CD run ID mismatch")
    _require(context.get("release_version") == release_version, "Beta lifecycle release version mismatch")
    _require(context.get("marty_ui_sha") == marty_ui_sha, "Beta lifecycle Marty UI SHA mismatch")
    _require(context.get("marty_core_sha") == marty_core_sha, "Beta lifecycle Marty Core SHA mismatch")
    _require(context.get("beta_origin") == beta_origin, "Beta lifecycle origin mismatch")
    _require(context.get("mip_version") == mip_version, "Beta lifecycle MIP version mismatch")

    for component in ("services", "ui"):
        paths = list(artifact_root.glob(f"**/{component}-release.json"))
        _require(len(paths) == 1, f"Beta lifecycle artifact must contain exactly one {component} release report")
        deployed = _load_json(paths[0])
        _require(deployed.get("component") == component, f"Deployed {component} component marker mismatch")
        _require(deployed.get("release_version") == release_version, f"Deployed {component} release version mismatch")
        _require(deployed.get("marty_ui_sha") == marty_ui_sha, f"Deployed {component} Marty UI SHA mismatch")

    metadata_paths = list(artifact_root.glob("**/spruce-metadata.json"))
    _require(len(metadata_paths) == 1, "Beta lifecycle artifact must contain exactly one Spruce metadata report")
    metadata = _load_json(metadata_paths[0])
    _require(metadata.get("base") == beta_origin, "Spruce metadata report origin mismatch")
    organization_id = str(metadata.get("organization_id") or "")
    _require(bool(organization_id), "Spruce metadata report organization is missing")
    _require(
        metadata.get("credential_issuer") == f"{beta_origin}/org/{organization_id}/spruce",
        "Spruce credential issuer mismatch",
    )
    _require(
        metadata.get("issuer_display_name") == spruce_requirements["expected_issuer_display_name"],
        "Spruce issuer display name mismatch",
    )
    _require(int(metadata.get("configuration_count") or 0) > 0, "Spruce credential configuration set is empty")
    _require(
        metadata.get("member_configuration") == spruce_requirements["expected_configuration_id"],
        "Spruce member configuration mismatch",
    )
    _require(
        metadata.get("member_vct") == f"{beta_origin}{spruce_requirements['expected_vct_path']}",
        "Spruce member VCT mismatch",
    )
    _require(
        metadata.get("member_badge_name") == spruce_requirements["expected_badge_name"],
        "Spruce member badge display name mismatch",
    )

    report_specs = {
        "membership": "beta-membership-probe-",
        "credential_login": "beta-credential-login-",
        "organization": "beta-org-credential-paths-",
        "credential_lifecycle": "beta-credential-lifecycle-",
    }
    report_paths: dict[str, str] = {}
    report_paths["spruce_metadata"] = metadata_paths[0].relative_to(artifact_root).as_posix()
    loaded: dict[str, dict[str, Any]] = {}
    for name, prefix in report_specs.items():
        path, report = _latest_report(artifact_root, prefix)
        _require(report.get("releaseReady") is True, f"Latest {name} beta report is not release-ready")
        report_paths[name] = path.relative_to(artifact_root).as_posix()
        loaded[name] = report

    fresh_org_path, fresh_org = _latest_report(artifact_root, "beta-org-console-audit-")
    _require(
        fresh_org.get("release_checks", {}).get("status") == "pass",
        "Fresh-organization beta report did not pass release checks",
    )
    _require(not fresh_org.get("page_errors"), "Fresh-organization beta report contains page errors")
    _require(not fresh_org.get("failed_requests"), "Fresh-organization beta report contains failed requests")
    inventory_steps = [
        step
        for step in (fresh_org.get("steps") or [])
        if step.get("label") == "resource-inventory-verified"
    ]
    _require(len(inventory_steps) == 1, "Fresh-organization beta report must contain one verified inventory")
    resource_types = {
        item.get("resource_type")
        for item in (inventory_steps[0].get("inventory") or [])
        if isinstance(item, dict)
    }
    _require(
        resource_types == FRESH_ORG_RESOURCE_TYPES,
        "Fresh-organization beta inventory is incomplete or unexpected",
    )
    report_paths["fresh_organization"] = fresh_org_path.relative_to(artifact_root).as_posix()

    login = loaded["credential_login"]
    _require(login.get("completion", {}).get("authenticated") is True, "Credential login did not restore an authenticated session")
    organization = loaded["organization"]
    _require(
        organization.get("membershipBadge", {}).get("walletId") in browser_wallet_ids,
        "Organization journey did not use the required generic browser handoff",
    )
    _require(organization.get("membershipBadge", {}).get("accepted") is True, "Generic browser handoff was not accepted")
    _require(organization.get("credentialLogin", {}).get("authenticated") is True, "Organization journey did not complete badge login")
    _require(organization.get("verification", {}).get("poll", {}).get("decision") == "allow", "Organization verification did not allow")
    lifecycle = loaded["credential_lifecycle"]
    _require(lifecycle.get("renewal", {}).get("ok") is True, "Credential renewal did not pass")
    _require(lifecycle.get("statusListOwnership", {}).get("ok") is True, "Credential status list is not organization-owned")
    _require(lifecycle.get("crossOrg", {}).get("denied") is True, "Cross-organization lifecycle request was not denied")
    expected_decisions = {"suspend": "deny", "reinstate": "allow", "revoke": "deny"}
    for action, decision in expected_decisions.items():
        actual = lifecycle.get(action, {}).get("verification", {}).get("result", {}).get("decision")
        _require(actual == decision, f"Credential {action} verification decision must be {decision}")
    return report_paths


def validate_wallet_evidence(
    evidence: dict[str, Any],
    requirements: dict[str, Any],
    *,
    release_version: str,
    beta_run_id: str,
    marty_ui_sha: str,
    beta_origin: str,
    mip_version: str,
) -> dict[str, Any]:
    _require(evidence.get("schema_version") == requirements.get("schema_version"), "Wallet evidence schema version mismatch")
    _require(evidence.get("release_version") == release_version, "Wallet evidence release version mismatch")
    _require(evidence.get("mip_version") == mip_version, "Wallet evidence MIP version mismatch")
    _require(evidence.get("beta_origin") == beta_origin, "Wallet evidence beta origin mismatch")
    _require(evidence.get("marty_ui_sha") == marty_ui_sha, "Wallet evidence Marty UI SHA mismatch")
    _require(str(evidence.get("beta_lifecycle_run_id")) == str(beta_run_id), "Wallet evidence beta lifecycle run mismatch")
    _require(bool(evidence.get("tested_at")), "Wallet evidence must record tested_at")
    _require(bool(evidence.get("device_lab")), "Wallet evidence must identify the device lab")
    _require(bool(evidence.get("approver")), "Wallet evidence must identify its approver")

    spruce_requirements = requirements["sprucekit_login"]
    spruce = evidence.get("sprucekit_login") or {}
    _require(spruce.get("wallet_id") == spruce_requirements["wallet_id"], "SpruceKit wallet ID mismatch")
    _require(bool(spruce.get("wallet_build_revision")), "SpruceKit wallet build revision is required")
    _require(spruce.get("platform") in {"ios", "android"}, "SpruceKit platform must be ios or android")
    _require(bool(spruce.get("device_model")) and bool(spruce.get("os_version")), "SpruceKit device and OS are required")
    checks = spruce.get("checks") or {}
    for check in spruce_requirements["required_checks"]:
        _require(checks.get(check) is True, f"SpruceKit check did not pass: {check}")
    request_sha = str(spruce.get("signed_request_sha256") or "")
    resolved_sha = str(spruce.get("resolved_request_sha256") or "")
    _require(SHA256_RE.fullmatch(request_sha) is not None, "SpruceKit signed request SHA-256 is invalid")
    _require(request_sha == resolved_sha, "SpruceKit resolved request differs from the signed Marty request")
    credential = spruce.get("credential") or {}
    _require(
        credential.get("badge_name") == spruce_requirements["expected_badge_name"],
        "SpruceKit badge display name mismatch",
    )
    _require(
        credential.get("issuer_display_name") == spruce_requirements["expected_issuer_display_name"],
        "SpruceKit issuer display name mismatch",
    )
    _require(str(credential.get("issuer_did") or "").startswith("did:"), "SpruceKit evidence must record the issuer DID")
    _require("email" in (credential.get("requested_claims") or []), "Credential login must request email")
    _require("email" in (credential.get("disclosed_claims") or []), "SpruceKit must disclose the requested email")
    _require(bool(spruce.get("authenticated_email")), "SpruceKit evidence must record the authenticated user email")

    native_requirements = requirements["native_handoffs"]
    handoffs = evidence.get("native_handoffs") or []
    _require(isinstance(handoffs, list), "native_handoffs must be an array")
    by_wallet: dict[str, dict[str, Any]] = {}
    for handoff in handoffs:
        _require(isinstance(handoff, dict), "Each native handoff must be an object")
        wallet_id = str(handoff.get("wallet_id") or "")
        _require(wallet_id not in by_wallet, f"Duplicate native handoff evidence for {wallet_id}")
        by_wallet[wallet_id] = handoff
    for wallet_id in native_requirements["required_wallet_ids"]:
        _require(wallet_id in by_wallet, f"Missing native handoff evidence for {wallet_id}")
        handoff = by_wallet[wallet_id]
        _require(bool(handoff.get("wallet_build_revision")), f"{wallet_id} build revision is required")
        _require(handoff.get("platform") in {"ios", "android"}, f"{wallet_id} platform must be ios or android")
        for field in native_requirements["required_device_fields"]:
            _require(bool(handoff.get(field)), f"{wallet_id} {field} is required")
        for check in native_requirements["required_checks"]:
            _require((handoff.get("checks") or {}).get(check) is True, f"{wallet_id} check did not pass: {check}")

    attachments = evidence.get("attachments") or []
    _require(isinstance(attachments, list), "attachments must be an array")
    by_kind: dict[str, dict[str, Any]] = {}
    for attachment in attachments:
        _require(isinstance(attachment, dict), "Each protected attachment must be an object")
        kind = str(attachment.get("kind") or "")
        _require(kind not in by_kind, f"Duplicate protected evidence attachment: {kind}")
        by_kind[kind] = attachment
    for kind in requirements["required_attachment_kinds"]:
        _require(kind in by_kind, f"Missing protected evidence attachment: {kind}")
        attachment = by_kind[kind]
        _require(_is_https_url(attachment.get("uri")), f"Attachment {kind} must use an HTTPS URI")
        _require(SHA256_RE.fullmatch(str(attachment.get("sha256") or "")) is not None, f"Attachment {kind} SHA-256 is invalid")

    return {
        "tested_at": evidence["tested_at"],
        "device_lab": evidence["device_lab"],
        "approver": evidence["approver"],
        "sprucekit_wallet_build_revision": spruce["wallet_build_revision"],
        "native_wallet_ids": native_requirements["required_wallet_ids"],
    }


def validate_attachment_verification(
    report: dict[str, Any],
    evidence: dict[str, Any],
    requirements: dict[str, Any],
    *,
    evidence_sha256: str,
) -> list[dict[str, Any]]:
    _require(report.get("schema_version") == 1, "Attachment verification report schema mismatch")
    _require(
        report.get("evidence_content_sha256") == evidence_sha256,
        "Attachment verification report is not bound to the wallet evidence JSON",
    )
    evidence_attachments = {
        item.get("kind"): item
        for item in (evidence.get("attachments") or [])
        if isinstance(item, dict)
    }
    verified_attachments = report.get("attachments") or []
    _require(isinstance(verified_attachments, list), "Verified attachments must be an array")
    by_kind: dict[str, dict[str, Any]] = {}
    for item in verified_attachments:
        _require(isinstance(item, dict), "Each verified attachment must be an object")
        kind = str(item.get("kind") or "")
        _require(kind not in by_kind, f"Duplicate verified attachment: {kind}")
        by_kind[kind] = item
    required_kinds = requirements["required_attachment_kinds"]
    _require(set(by_kind) == set(required_kinds), "Verified attachment set does not match requirements")
    summary: list[dict[str, Any]] = []
    for kind in required_kinds:
        source = evidence_attachments.get(kind) or {}
        verified = by_kind[kind]
        _require(verified.get("verified") is True, f"Attachment was not verified: {kind}")
        _require(verified.get("uri") == source.get("uri"), f"Attachment URI mismatch: {kind}")
        _require(verified.get("sha256") == source.get("sha256"), f"Attachment checksum mismatch: {kind}")
        _require(int(verified.get("size_bytes") or 0) > 0, f"Attachment is empty: {kind}")
        summary.append({
            "kind": kind,
            "sha256": verified["sha256"],
            "size_bytes": int(verified["size_bytes"]),
        })
    return summary


def promote(args: argparse.Namespace) -> None:
    _require(str(args.cd_run_id).isdigit(), "CD workflow run ID must be numeric")
    _require(str(args.beta_run_id).isdigit(), "Beta lifecycle workflow run ID must be numeric")
    _require(str(args.promotion_run_id).isdigit(), "Promotion workflow run ID must be numeric")
    manifest = _load_json(args.build_manifest)
    requirements = _load_json(args.requirements)
    evidence = _load_json(args.wallet_evidence)
    attachment_verification = _load_json(args.attachment_verification)
    validate_build_manifest(
        manifest,
        release_version=args.release_version,
        marty_ui_sha=args.marty_ui_sha,
        mip_version=requirements["mip_version"],
        beta_origin=args.beta_origin,
    )
    beta_reports = validate_beta_lifecycle(
        args.beta_evidence,
        cd_run_id=args.cd_run_id,
        beta_run_id=args.beta_run_id,
        release_version=args.release_version,
        marty_ui_sha=args.marty_ui_sha,
        marty_core_sha=manifest["repositories"]["marty_core"],
        beta_origin=args.beta_origin,
        mip_version=requirements["mip_version"],
        browser_wallet_ids=requirements["coverage_accounting"]["historical_nine_wallet_handoffs"]["deterministic_browser"],
        spruce_requirements=requirements["sprucekit_login"],
    )
    wallet_summary = validate_wallet_evidence(
        evidence,
        requirements,
        release_version=args.release_version,
        beta_run_id=args.beta_run_id,
        marty_ui_sha=args.marty_ui_sha,
        beta_origin=args.beta_origin,
        mip_version=requirements["mip_version"],
    )
    evidence_sha = hashlib.sha256(args.wallet_evidence.read_bytes()).hexdigest()
    _require(evidence_sha == args.wallet_evidence_sha256, "Downloaded wallet evidence checksum mismatch")
    attachment_summary = validate_attachment_verification(
        attachment_verification,
        evidence,
        requirements,
        evidence_sha256=evidence_sha,
    )

    promoted = copy.deepcopy(manifest)
    promoted["release_ready"] = True
    promoted["released_at"] = datetime.now(timezone.utc).isoformat()
    promoted["release_attestation"] = {
        "build_ready": {
            "workflow_run_id": str(args.cd_run_id),
        },
        "beta_lifecycle": {
            "workflow_run_id": str(args.beta_run_id),
            "reports": beta_reports,
        },
        "promotion": {
            "workflow_run_id": str(args.promotion_run_id),
        },
        "wallet_conformance": {
            "evidence_sha256": evidence_sha,
            "attachments": attachment_summary,
            **wallet_summary,
        },
    }
    args.output.write_text(json.dumps(promoted, indent=2) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--beta-evidence", type=Path, required=True)
    parser.add_argument("--wallet-evidence", type=Path, required=True)
    parser.add_argument("--wallet-evidence-sha256", required=True)
    parser.add_argument("--attachment-verification", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--cd-run-id", required=True)
    parser.add_argument("--beta-run-id", required=True)
    parser.add_argument("--promotion-run-id", required=True)
    parser.add_argument("--marty-ui-sha", required=True)
    parser.add_argument("--beta-origin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


if __name__ == "__main__":
    try:
        promote(_parser().parse_args())
    except EvidenceError as exc:
        raise SystemExit(f"wallet conformance promotion failed: {exc}") from exc
