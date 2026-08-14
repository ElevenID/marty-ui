from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_PATH = ROOT / "deploy-config/catalog/wallet-conformance-requirements.json"
SPEC = importlib.util.spec_from_file_location(
    "promote_release_evidence",
    ROOT / "scripts/promote_release_evidence.py",
)
assert SPEC and SPEC.loader
PROMOTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROMOTION)
EvidenceError = PROMOTION.EvidenceError
promote = PROMOTION.promote
validate_wallet_evidence = PROMOTION.validate_wallet_evidence
UI_RELEASE_SHA = "a" * 40
BETA_SOURCE_ID = "b" * 40
MARTY_PROTOCOL_SHA = "c" * 40
EVIDENCE_TOOLING_SHA = "d" * 40
MARTY_CORE_SHA = "3" * 40
RELEASE_VERSION = "mip-0.4.1-beta-test"
BETA_RUN_ID = "123456"
STACK_RELEASE_RUN_ID = "123455"
PROMOTION_RUN_ID = "123457"
BETA_ORIGIN = "https://beta.elevenidllc.com"


def _write_json(path: Path, value: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return path


def _wallet_evidence(requirements: dict, stack_manifest_sha256: str) -> dict:
    request_sha = "e" * 64
    handoff_checks = {
        name: True for name in requirements["native_handoffs"]["required_checks"]
    }
    return {
        "schema_version": requirements["schema_version"],
        "release_version": RELEASE_VERSION,
        "mip_version": "0.4.1",
        "beta_origin": BETA_ORIGIN,
        "stack_release_run_id": STACK_RELEASE_RUN_ID,
        "marty_ui_release_sha": UI_RELEASE_SHA,
        "stack_manifest_sha256": stack_manifest_sha256,
        "beta_source_id": BETA_SOURCE_ID,
        "marty_protocol_sha": MARTY_PROTOCOL_SHA,
        "evidence_tooling_sha": EVIDENCE_TOOLING_SHA,
        "beta_lifecycle_run_id": BETA_RUN_ID,
        "tested_at": "2026-07-12T21:00:00Z",
        "device_lab": "Protected ElevenID device lab",
        "approver": "release-approver@example.test",
        "sprucekit_login": {
            "wallet_id": "wr-spruce-001",
            "wallet_build_revision": "spruce-mobile-1.2.3+456",
            "platform": "ios",
            "device_model": "iPhone test device",
            "os_version": "iOS 19.0",
            "signed_request_sha256": request_sha,
            "resolved_request_sha256": request_sha,
            "checks": {
                name: True
                for name in requirements["sprucekit_login"]["required_checks"]
            },
            "credential": {
                "badge_name": "Marty Verified Member Badge",
                "issuer_display_name": "ElevenID LLC",
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
                "requested_claims": ["email"],
                "disclosed_claims": ["email"],
            },
            "authenticated_email": "holder@example.test",
        },
        "native_handoffs": [
            {
                "wallet_id": wallet_id,
                "wallet_build_revision": f"{wallet_id}-test-build",
                "platform": "android"
                if wallet_id in {"wr-google-001", "wr-dc4eu-001"}
                else "ios",
                "device_model": f"{wallet_id}-device",
                "os_version": "test-os-1",
                "checks": handoff_checks,
            }
            for wallet_id in requirements["native_handoffs"]["required_wallet_ids"]
        ],
        "attachments": [
            {
                "kind": kind,
                "uri": f"https://evidence.example.test/{kind}",
                "sha256": "c" * 64,
            }
            for kind in requirements["required_attachment_kinds"]
        ],
    }


def _attachment_verification(evidence: dict, evidence_sha: str) -> dict:
    return {
        "schema_version": 1,
        "evidence_content_sha256": evidence_sha,
        "attachments": [
            {
                "kind": item["kind"],
                "uri": item["uri"],
                "sha256": item["sha256"],
                "size_bytes": 1024,
                "verified": True,
            }
            for item in evidence["attachments"]
        ],
    }


def _component(
    name: str, repository: str, commit: str, artifact_type: str = "python"
) -> dict:
    return {
        "name": name,
        "repository": repository,
        "version": "1.2.3",
        "commit": commit,
        "artifacts": [
            {
                "type": artifact_type,
                "uri": f"https://example.test/{name}"
                if artifact_type != "oci"
                else f"ghcr.io/elevenid/{name}",
                "digest": f"sha256:{'4' * 64}",
                "sbom": f"https://example.test/{name}.spdx.json",
                "provenance": "https://example.test/attestations",
            }
        ],
    }


def _stack_manifest() -> dict:
    components = [
        _component("marty-api-core", "ElevenID/marty-cli", "1" * 40, "npm"),
        _component("marty-blog", "ElevenID/marty-blog", "2" * 40, "npm"),
        _component("marty-cli", "ElevenID/marty-cli", "1" * 40, "npm"),
        _component("marty-common", "ElevenID/Marty", "5" * 40),
        _component("marty-core-python", "ElevenID/marty-core", MARTY_CORE_SHA),
        _component("marty-verification-python", "ElevenID/marty-core", MARTY_CORE_SHA),
        _component("marty-iso18013-python", "ElevenID/marty-core", MARTY_CORE_SHA),
        _component(
            "marty-credentials-issuance", "ElevenID/marty-credentials", "6" * 40, "oci"
        ),
        _component(
            "marty-integration-tests",
            "ElevenID/marty-integration-tests",
            "7" * 40,
            "release",
        ),
    ]
    ui = _component("marty-ui", "ElevenID/marty-ui", UI_RELEASE_SHA, "oci")
    ui["version"] = RELEASE_VERSION
    ui["artifacts"] = [
        {
            "type": "oci",
            "uri": f"ghcr.io/elevenid/marty-ui-oss/{name}",
            "digest": f"sha256:{digest * 64}",
            "sbom": f"https://example.test/{name}.spdx.json",
            "provenance": "https://example.test/attestations",
        }
        for name, digest in (("ui", "8"), ("services", "9"), ("migrations", "a"))
    ]
    components.append(ui)
    return {
        "schema": "marty.stack/v1",
        "release": f"marty-ui@{RELEASE_VERSION}",
        "generated_at": "2026-07-12T20:00:00Z",
        "components": components,
    }


def _beta_evidence(root: Path, stack_manifest_sha256: str) -> None:
    _write_json(
        root / "release-context.json",
        {
            "run_id": BETA_RUN_ID,
            "stack_release_run_id": STACK_RELEASE_RUN_ID,
            "release_version": RELEASE_VERSION,
            "marty_ui_release_sha": UI_RELEASE_SHA,
            "stack_manifest_sha256": stack_manifest_sha256,
            "beta_source_id": BETA_SOURCE_ID,
            "marty_core_sha": MARTY_CORE_SHA,
            "marty_protocol_sha": MARTY_PROTOCOL_SHA,
            "evidence_tooling_sha": EVIDENCE_TOOLING_SHA,
            "beta_origin": BETA_ORIGIN,
            "mip_version": "0.4.1",
        },
    )
    _write_json(
        root / "services-release.json",
        {
            "component": "services",
            "release_version": RELEASE_VERSION,
            "marty_ui_sha": BETA_SOURCE_ID,
        },
    )
    _write_json(
        root / "ui-release.json",
        {
            "component": "ui",
            "release_version": RELEASE_VERSION,
            "marty_ui_sha": BETA_SOURCE_ID,
        },
    )
    _write_json(
        root / "spruce-metadata.json",
        {
            "base": BETA_ORIGIN,
            "organization_id": "00000000-0000-0000-0000-000000000001",
            "credential_issuer": f"{BETA_ORIGIN}/org/00000000-0000-0000-0000-000000000001",
            "issuer_display_name": "ElevenID LLC",
            "configuration_count": 17,
            "member_configuration": "MemberCredential#sd-jwt",
            "member_vct": f"{BETA_ORIGIN}/credentials/marty-verified-member-badge",
            "member_badge_name": "Marty Verified Member Badge",
        },
    )
    _write_json(
        root / "beta-membership-probe-1/report.json",
        {"releaseReady": True, "finishedAt": "2026-07-12T21:01:00Z"},
    )
    _write_json(
        root / "beta-credential-login-1/report.json",
        {
            "releaseReady": True,
            "finishedAt": "2026-07-12T21:02:00Z",
            "completion": {"authenticated": True},
        },
    )
    _write_json(
        root / "beta-org-credential-paths-1/report.json",
        {
            "releaseReady": True,
            "finishedAt": "2026-07-12T21:03:00Z",
            "membershipBadge": {"walletId": "wr-default", "accepted": True},
            "credentialLogin": {"authenticated": True},
            "verification": {"poll": {"decision": "allow"}},
        },
    )
    _write_json(
        root / "beta-credential-lifecycle-1/report.json",
        {
            "releaseReady": True,
            "finishedAt": "2026-07-12T21:04:00Z",
            "renewal": {"ok": True},
            "statusListOwnership": {"ok": True},
            "crossOrg": {"denied": True},
            "suspend": {"verification": {"result": {"decision": "deny"}}},
            "reinstate": {"verification": {"result": {"decision": "allow"}}},
            "revoke": {"verification": {"result": {"decision": "deny"}}},
        },
    )
    _write_json(
        root / "beta-org-console-audit-1/report.json",
        {
            "created_at": "2026-07-12T21:05:00Z",
            "release_checks": {"status": "pass", "blockers": []},
            "page_errors": [],
            "failed_requests": [],
            "steps": [
                {
                    "label": "resource-inventory-verified",
                    "inventory": [
                        {"resource_type": resource_type, "status": "active"}
                        for resource_type in sorted(PROMOTION.FRESH_ORG_RESOURCE_TYPES)
                    ],
                }
            ],
        },
    )


def test_promotes_only_matching_build_browser_and_device_evidence(
    tmp_path: Path,
) -> None:
    requirements = json.loads(REQUIREMENTS_PATH.read_text(encoding="utf-8"))
    stack_path = _write_json(tmp_path / "stack-manifest.json", _stack_manifest())
    stack_sha = hashlib.sha256(stack_path.read_bytes()).hexdigest()
    beta_path = tmp_path / "beta-evidence"
    _beta_evidence(beta_path, stack_sha)
    wallet_evidence = _wallet_evidence(requirements, stack_sha)
    wallet_path = _write_json(tmp_path / "wallet-evidence.json", wallet_evidence)
    wallet_sha = hashlib.sha256(wallet_path.read_bytes()).hexdigest()
    attachment_verification = _write_json(
        tmp_path / "wallet-attachment-verification.json",
        _attachment_verification(wallet_evidence, wallet_sha),
    )
    output = tmp_path / "release-ready-manifest.json"

    promote(
        SimpleNamespace(
            stack_manifest=stack_path,
            stack_manifest_sha256=stack_sha,
            beta_evidence=beta_path,
            wallet_evidence=wallet_path,
            wallet_evidence_sha256=wallet_sha,
            attachment_verification=attachment_verification,
            requirements=REQUIREMENTS_PATH,
            release_version=RELEASE_VERSION,
            stack_release_run_id=STACK_RELEASE_RUN_ID,
            beta_run_id=BETA_RUN_ID,
            promotion_run_id=PROMOTION_RUN_ID,
            marty_ui_release_sha=UI_RELEASE_SHA,
            beta_origin=BETA_ORIGIN,
            output=output,
        )
    )

    promoted = json.loads(output.read_text(encoding="utf-8"))
    assert promoted["schema"] == "marty.release-ready/v1"
    assert promoted["release_ready"] is True
    assert (
        promoted["release_attestation"]["stack_release"]["workflow_run_id"]
        == STACK_RELEASE_RUN_ID
    )
    assert (
        promoted["release_attestation"]["stack_release"]["manifest_sha256"] == stack_sha
    )
    assert promoted["beta_evidence"]["beta_source_id"] == BETA_SOURCE_ID
    assert promoted["beta_evidence"]["marty_protocol_sha"] == MARTY_PROTOCOL_SHA
    assert promoted["beta_evidence"]["evidence_tooling_sha"] == EVIDENCE_TOOLING_SHA
    assert (
        promoted["release_attestation"]["beta_lifecycle"]["workflow_run_id"]
        == BETA_RUN_ID
    )
    assert (
        promoted["release_attestation"]["promotion"]["workflow_run_id"]
        == PROMOTION_RUN_ID
    )
    assert (
        promoted["release_attestation"]["wallet_conformance"]["evidence_sha256"]
        == wallet_sha
    )
    assert (
        len(promoted["release_attestation"]["wallet_conformance"]["attachments"]) == 4
    )
    assert (
        "fresh_organization"
        in promoted["release_attestation"]["beta_lifecycle"]["reports"]
    )
    assert "authenticated_email" not in json.dumps(promoted)
    assert "evidence.example.test" not in json.dumps(promoted)


def _promotion_args(tmp_path: Path) -> SimpleNamespace:
    requirements = json.loads(REQUIREMENTS_PATH.read_text(encoding="utf-8"))
    stack_path = _write_json(tmp_path / "stack-manifest.json", _stack_manifest())
    stack_sha = hashlib.sha256(stack_path.read_bytes()).hexdigest()
    beta_path = tmp_path / "beta-evidence"
    _beta_evidence(beta_path, stack_sha)
    wallet_evidence = _wallet_evidence(requirements, stack_sha)
    wallet_path = _write_json(tmp_path / "wallet-evidence.json", wallet_evidence)
    wallet_sha = hashlib.sha256(wallet_path.read_bytes()).hexdigest()
    attachment_verification = _write_json(
        tmp_path / "wallet-attachment-verification.json",
        _attachment_verification(wallet_evidence, wallet_sha),
    )
    return SimpleNamespace(
        stack_manifest=stack_path,
        stack_manifest_sha256=stack_sha,
        beta_evidence=beta_path,
        wallet_evidence=wallet_path,
        wallet_evidence_sha256=wallet_sha,
        attachment_verification=attachment_verification,
        requirements=REQUIREMENTS_PATH,
        release_version=RELEASE_VERSION,
        stack_release_run_id=STACK_RELEASE_RUN_ID,
        beta_run_id=BETA_RUN_ID,
        promotion_run_id=PROMOTION_RUN_ID,
        marty_ui_release_sha=UI_RELEASE_SHA,
        beta_origin=BETA_ORIGIN,
        output=tmp_path / "release-ready-manifest.json",
    )


def test_promotion_rejects_beta_artifact_from_another_commit(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    context_path = args.beta_evidence / "release-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["marty_ui_release_sha"] = "f" * 40
    _write_json(context_path, context)

    with pytest.raises(
        EvidenceError, match="Beta lifecycle Marty UI release SHA mismatch"
    ):
        promote(args)


def test_promotion_rejects_beta_wallet_from_another_core_revision(
    tmp_path: Path,
) -> None:
    args = _promotion_args(tmp_path)
    context_path = args.beta_evidence / "release-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["marty_core_sha"] = "f" * 40
    _write_json(context_path, context)

    with pytest.raises(EvidenceError, match="Beta lifecycle Marty Core SHA mismatch"):
        promote(args)


def test_promotion_rejects_incomplete_stack_component_set(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    manifest = json.loads(args.stack_manifest.read_text(encoding="utf-8"))
    manifest["components"] = [
        item for item in manifest["components"] if item["name"] != "marty-blog"
    ]
    _write_json(args.stack_manifest, manifest)
    args.stack_manifest_sha256 = hashlib.sha256(
        args.stack_manifest.read_bytes()
    ).hexdigest()

    with pytest.raises(EvidenceError, match="missing required components: marty-blog"):
        promote(args)


def test_promotion_rejects_truncated_image_digest(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    manifest = json.loads(args.stack_manifest.read_text(encoding="utf-8"))
    ui = next(item for item in manifest["components"] if item["name"] == "marty-ui")
    ui["artifacts"][0]["digest"] = "sha256:1234"
    _write_json(args.stack_manifest, manifest)
    args.stack_manifest_sha256 = hashlib.sha256(
        args.stack_manifest.read_bytes()
    ).hexdigest()

    with pytest.raises(EvidenceError, match="artifact digest is invalid"):
        promote(args)


def test_promotion_rejects_duplicate_stack_component(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    manifest = json.loads(args.stack_manifest.read_text(encoding="utf-8"))
    manifest["components"].append(dict(manifest["components"][0]))
    _write_json(args.stack_manifest, manifest)
    args.stack_manifest_sha256 = hashlib.sha256(
        args.stack_manifest.read_bytes()
    ).hexdigest()

    with pytest.raises(EvidenceError, match="Duplicate stack component"):
        promote(args)


def test_promotion_rejects_beta_running_another_ui_release(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    marker_path = args.beta_evidence / "ui-release.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["marty_ui_sha"] = "f" * 40
    _write_json(marker_path, marker)

    with pytest.raises(EvidenceError, match="Deployed ui beta source ID mismatch"):
        promote(args)


def test_promotion_rejects_a_newer_failed_beta_report(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    _write_json(
        args.beta_evidence / "beta-credential-lifecycle-2/report.json",
        {
            "releaseReady": False,
            "finishedAt": "2026-07-12T22:00:00Z",
        },
    )

    with pytest.raises(
        EvidenceError,
        match="Latest credential_lifecycle beta report is not release-ready",
    ):
        promote(args)


def test_promotion_rejects_failed_fresh_organization_report(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    report_path = args.beta_evidence / "beta-org-console-audit-1/report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["release_checks"] = {
        "status": "blocked",
        "blockers": [{"code": "inventory"}],
    }
    _write_json(report_path, report)

    with pytest.raises(
        EvidenceError, match="Fresh-organization beta report did not pass"
    ):
        promote(args)


def test_promotion_rejects_wallet_evidence_checksum_substitution(
    tmp_path: Path,
) -> None:
    args = _promotion_args(tmp_path)
    args.wallet_evidence_sha256 = "0" * 64

    with pytest.raises(EvidenceError, match="checksum mismatch"):
        promote(args)


def test_promotion_rejects_attachment_report_for_another_evidence_file(
    tmp_path: Path,
) -> None:
    args = _promotion_args(tmp_path)
    report = json.loads(args.attachment_verification.read_text(encoding="utf-8"))
    report["evidence_content_sha256"] = "f" * 64
    _write_json(args.attachment_verification, report)

    with pytest.raises(EvidenceError, match="not bound to the wallet evidence JSON"):
        promote(args)


def test_promotion_rejects_beta_evidence_for_another_public_origin(
    tmp_path: Path,
) -> None:
    args = _promotion_args(tmp_path)
    context_path = args.beta_evidence / "release-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["beta_origin"] = "https://other.example.test"
    _write_json(context_path, context)

    with pytest.raises(EvidenceError, match="Beta lifecycle origin mismatch"):
        promote(args)


def test_promotion_rejects_stack_manifest_checksum_substitution(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    args.stack_manifest_sha256 = "0" * 64

    with pytest.raises(EvidenceError, match="Stack manifest checksum mismatch"):
        promote(args)


@pytest.mark.parametrize(
    "field,message",
    [
        ("beta_source_id", "Wallet evidence beta source ID mismatch"),
        ("marty_protocol_sha", "Wallet evidence Marty Protocol SHA mismatch"),
        ("evidence_tooling_sha", "Wallet evidence tooling SHA mismatch"),
        ("stack_manifest_sha256", "Wallet evidence stack manifest SHA-256 mismatch"),
    ],
)
def test_promotion_rejects_wallet_evidence_from_another_lineage(
    tmp_path: Path,
    field: str,
    message: str,
) -> None:
    args = _promotion_args(tmp_path)
    evidence = json.loads(args.wallet_evidence.read_text(encoding="utf-8"))
    evidence[field] = "f" * (64 if field == "stack_manifest_sha256" else 40)
    _write_json(args.wallet_evidence, evidence)
    args.wallet_evidence_sha256 = hashlib.sha256(
        args.wallet_evidence.read_bytes()
    ).hexdigest()
    report = json.loads(args.attachment_verification.read_text(encoding="utf-8"))
    report["evidence_content_sha256"] = args.wallet_evidence_sha256
    _write_json(args.attachment_verification, report)

    with pytest.raises(EvidenceError, match=message):
        promote(args)


def test_promotion_requires_spruce_metadata_evidence(tmp_path: Path) -> None:
    args = _promotion_args(tmp_path)
    (args.beta_evidence / "spruce-metadata.json").unlink()

    with pytest.raises(EvidenceError, match="exactly one Spruce metadata report"):
        promote(args)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("issuer_display_name", "Unknown Issuer", "issuer display name mismatch"),
        (
            "member_configuration",
            "MemberCredential#wrong",
            "member configuration mismatch",
        ),
        ("member_vct", f"{BETA_ORIGIN}/credentials/wrong", "member VCT mismatch"),
        ("member_badge_name", "Wrong Badge", "member badge display name mismatch"),
    ],
)
def test_promotion_rejects_spruce_metadata_identity_mismatch(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    args = _promotion_args(tmp_path)
    metadata_path = args.beta_evidence / "spruce-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata[field] = value
    _write_json(metadata_path, metadata)

    with pytest.raises(EvidenceError, match=message):
        promote(args)


@pytest.mark.parametrize(
    "mutation, message",
    [
        (
            lambda evidence: evidence["sprucekit_login"].__setitem__(
                "resolved_request_sha256", "d" * 64
            ),
            "resolved request differs",
        ),
        (
            lambda evidence: evidence["sprucekit_login"]["checks"].__setitem__(
                "issuer_displayed", False
            ),
            "issuer_displayed",
        ),
        (
            lambda evidence: evidence.__setitem__(
                "native_handoffs", evidence["native_handoffs"][1:]
            ),
            "wr-spruce-001",
        ),
        (
            lambda evidence: evidence.__setitem__(
                "attachments", evidence["attachments"][1:]
            ),
            "spruce_issuance_recording",
        ),
        (
            lambda evidence: evidence["sprucekit_login"]["credential"].__setitem__(
                "issuer_display_name", "Unknown"
            ),
            "issuer display name mismatch",
        ),
        (
            lambda evidence: evidence["native_handoffs"][0].__setitem__(
                "device_model", ""
            ),
            "device_model is required",
        ),
        (
            lambda evidence: evidence["attachments"].append(
                dict(evidence["attachments"][0])
            ),
            "Duplicate protected evidence attachment",
        ),
    ],
)
def test_wallet_evidence_fails_closed(mutation, message: str) -> None:
    requirements = json.loads(REQUIREMENTS_PATH.read_text(encoding="utf-8"))
    stack_manifest_sha256 = "1" * 64
    evidence = _wallet_evidence(requirements, stack_manifest_sha256)
    mutation(evidence)

    with pytest.raises(EvidenceError, match=message):
        validate_wallet_evidence(
            evidence,
            requirements,
            release_version=RELEASE_VERSION,
            stack_release_run_id=STACK_RELEASE_RUN_ID,
            beta_run_id=BETA_RUN_ID,
            marty_ui_release_sha=UI_RELEASE_SHA,
            stack_manifest_sha256=stack_manifest_sha256,
            beta_source_id=BETA_SOURCE_ID,
            marty_protocol_sha=MARTY_PROTOCOL_SHA,
            evidence_tooling_sha=EVIDENCE_TOOLING_SHA,
            beta_origin=BETA_ORIGIN,
            mip_version="0.4.1",
        )


def test_native_requirement_catalog_excludes_generic_inactive_and_non_handoff_entries() -> (
    None
):
    requirements = json.loads(REQUIREMENTS_PATH.read_text(encoding="utf-8"))
    template = json.loads(
        (ROOT / "docs/wallet-conformance-evidence-template.json").read_text(
            encoding="utf-8"
        )
    )
    wallet_ids = requirements["native_handoffs"]["required_wallet_ids"]
    accounting = requirements["coverage_accounting"]["historical_nine_wallet_handoffs"]

    assert len(wallet_ids) == 7
    assert "wr-default" not in wallet_ids
    assert "wr-waltid-001" not in wallet_ids
    assert "wr-didcomm-001" not in wallet_ids
    accounted = (
        accounting["deterministic_browser"]
        + accounting["protected_device"]
        + accounting["inactive_external_blocker"]
    )
    assert len(accounted) == 9
    assert len(set(accounted)) == 9
    assert accounting["protected_device"] == wallet_ids
    assert [entry["wallet_id"] for entry in template["native_handoffs"]] == wallet_ids
    assert [entry["kind"] for entry in template["attachments"]] == requirements[
        "required_attachment_kinds"
    ]
