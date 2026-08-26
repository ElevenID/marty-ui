#!/usr/bin/env python3
"""Create the unbound MIP 0.5 demo catalog from the reviewed portfolio contract."""

from __future__ import annotations

import json
from pathlib import Path

if __package__:
    from .demo_asset_hashes import public_asset_sha256
else:
    from demo_asset_hashes import public_asset_sha256


ROOT = Path(__file__).resolve().parents[1]
VERSION = "2026.08.0"
MIP_VERSION = "0.5.0"
POSTER_URL = f"/images/demos/{VERSION}/portfolio-draft.svg"
POSTER_PATH = ROOT / "ui" / "public" / POSTER_URL.lstrip("/")
CONTRACT_PATH = ROOT / "deploy-config" / "catalog" / "demo-portfolio-v3.json"
OUTPUT_PATH = ROOT / "ui" / "public" / "demos" / "manifests" / f"{VERSION}.json"

PRESENTATION = {
    "passport-pre-boarding-clearance": (
        "Passport Pre-Boarding Clearance",
        "Validate a passport, issue a pre-boarding credential, and verify it rapidly at the gate.",
        ["Holder", "Issuer", "Verifier"],
        ["openid4vci-1.0", "openid4vp-1.0", "dcql-1.0", "sd-jwt-vc"],
    ),
    "stable-issuer-identity-pluggable-kms": (
        "Stable Issuer Identity with Pluggable KMS",
        "Keep one issuer identity stable while changing its managed signing provider.",
        ["Administrator", "Issuer", "Verifier"],
        ["openid4vci-1.0", "openid4vp-1.0", "dcql-1.0", "sd-jwt-vc"],
    ),
    "private-online-age-proof": (
        "Private Online Age Proof",
        "Request and verify only an age-over-21 fact from a trusted mobile document issuer.",
        ["Holder", "Verifier"],
        ["openid4vci-1.0", "openid4vp-1.0", "dcql-1.0", "sd-jwt-vc"],
    ),
    "employee-onboarding-secure-access": (
        "Employee Onboarding and Secure Access",
        "Approve an employee, issue an access credential, and enforce suspension immediately.",
        ["Holder", "Issuer", "Verifier"],
        ["openid4vci-1.0", "openid4vp-1.0", "dcql-1.0", "sd-jwt-vc"],
    ),
    "membership-badge-login": (
        "Membership Badge and Login",
        "Issue a governed Open Badge and use it for same-device passwordless account return.",
        ["Holder", "Issuer", "Verifier"],
        ["openid4vci-1.0", "openid4vp-1.0", "dcql-1.0", "sd-jwt-vc", "open-badges-3.0"],
    ),
    "credential-lifecycle": (
        "Credential Lifecycle",
        "Renew, suspend, reinstate, and revoke while verification follows current status.",
        ["Holder", "Issuer", "Verifier"],
        ["openid4vci-1.0", "openid4vp-1.0", "dcql-1.0", "sd-jwt-vc"],
    ),
    "canvas-learning-achievement": (
        "Portable Learning Achievement with Canvas",
        "Turn authoritative evidence from stock Canvas into a learner-claimed Open Badge.",
        ["Holder", "Issuer", "Administrator"],
        [
            "lti-1.3",
            "openid4vci-1.0",
            "openid4vp-1.0",
            "dcql-1.0",
            "sd-jwt-vc",
            "open-badges-3.0",
        ],
    ),
    "external-evidence-to-credential": (
        "External Evidence to Credential",
        "Normalize external evidence, evaluate policy, and issue only after governed review.",
        ["Holder", "Issuer", "Administrator"],
        ["openid4vci-1.0", "sd-jwt-vc"],
    ),
    "offline-facility-verification": (
        "Offline Facility Verification",
        "Verify against provisioned trust offline, buffer the audit, and synchronize after reconnection.",
        ["Holder", "Verifier", "Administrator"],
        ["openid4vp-1.0", "dcql-1.0", "sd-jwt-vc"],
    ),
    "organization-primitives": (
        "Organization and MIP Primitives",
        "Configure the organization, issuer, trust, policy, deployment, and flow primitives required to operate.",
        ["Administrator", "Issuer", "Verifier"],
        ["openid4vci-1.0", "openid4vp-1.0", "dcql-1.0", "sd-jwt-vc", "open-badges-3.0"],
    ),
}

LEGACY_PRESENTATION = {
    "first-party-browser-wallet": (
        "First-Party Browser Wallet",
        "Preserved historical first-party wallet demonstration; fresh MIP 0.5 evidence remains separate.",
        "FIRST_PARTY_CONTROL",
    ),
    "independent-wallet-interoperability": (
        "Independent Wallet Interoperability",
        "Preserved independent-wallet qualification surface for final-protocol interoperability.",
        "INDEPENDENT_WALLET",
    ),
}


def label(value: str) -> str:
    return value.replace("_", " ").strip().capitalize()


def draft_scenario(contract: dict[str, object]) -> dict[str, object]:
    slug = str(contract["slug"])
    title, summary, audiences, protocols = PRESENTATION[slug]
    happy = list(contract["happy_path"])
    failures = list(contract["failure_paths"])
    paths = happy + failures
    return {
        "demo_id": contract["demo_id"],
        "slug": slug,
        "title": title,
        "summary": summary,
        "scenario_revision": 1,
        "recording_classification": "FIRST_PARTY_CONTROL",
        "revision_history": [],
        "mip_version": MIP_VERSION,
        "state": "DRAFT",
        "audiences": audiences,
        "capabilities": [label(item) for item in paths],
        "protocols": protocols,
        "recording_plan": {
            "fresh_recording_required": True,
            "happy_path": happy,
            "failure_paths": failures,
        },
        "poster": {
            "src": POSTER_URL,
            "sha256": public_asset_sha256(POSTER_PATH),
            "alt": f"Draft release card for {title}; fresh recording pending",
        },
        "youtube_id": None,
        "media_evidence": None,
        "transcript": {
            "language": "en",
            "segments": [
                {
                    "start_seconds": index * 30,
                    "speaker": "Narrator",
                    "text": f"The fresh recording will demonstrate: {label(item)}.",
                }
                for index, item in enumerate(paths)
            ],
        },
        "chapters": [
            {
                "start_seconds": index * 30,
                "title": label(item),
                "role": audiences[0],
                "mip_primitives": ["Release acceptance path"],
                "standards": protocols,
                "documentation_links": [{"label": "MIP protocol", "href": "/protocol"}],
            }
            for index, item in enumerate(paths)
        ],
        "wallets": [],
        "assertions": [
            {
                "id": item,
                "label": label(item),
                "result": "NOT_RUN",
                "evidence_sha256": None,
            }
            for item in paths
        ],
        "limitations": [
            "Fresh release-bound recording and automated evidence are required before publication."
        ],
        "published_at": None,
        "publication_attestation": None,
        "inherited_evidence": None,
    }


def legacy_scenario(
    slug: str, title: str, summary: str, classification: str
) -> dict[str, object]:
    return {
        "slug": slug,
        "title": title,
        "summary": summary,
        "scenario_revision": 1,
        "recording_classification": classification,
        "revision_history": [],
        "mip_version": MIP_VERSION,
        "state": "DRAFT",
        "audiences": ["Holder", "Developer"],
        "capabilities": ["Historical behavior preservation"],
        "protocols": ["openid4vci-1.0", "openid4vp-1.0", "dcql-1.0", "sd-jwt-vc"],
        "poster": {
            "src": POSTER_URL,
            "sha256": public_asset_sha256(POSTER_PATH),
            "alt": f"Draft release card for {title}; historical capability preserved",
        },
        "youtube_id": None,
        "media_evidence": None,
        "transcript": {
            "language": "en",
            "segments": [{"start_seconds": 0, "speaker": "Narrator", "text": summary}],
        },
        "chapters": [
            {
                "start_seconds": 0,
                "title": "Preserved qualification surface",
                "role": "Developer",
                "mip_primitives": ["Issuance Flow", "Verification Flow"],
                "standards": ["OpenID4VCI 1.0", "OpenID4VP 1.0", "DCQL 1.0"],
                "documentation_links": [{"label": "Standards", "href": "/standards"}],
            }
        ],
        "wallets": [],
        "assertions": [
            {
                "id": "historical-capability-preserved",
                "label": "The historical qualification capability remains represented.",
                "result": "NOT_RUN",
                "evidence_sha256": None,
            }
        ],
        "limitations": [
            "This entry preserves the historical capability; it does not reuse prior media as MIP 0.5 evidence."
        ],
        "published_at": None,
        "publication_attestation": None,
        "inherited_evidence": None,
    }


def build_manifest() -> dict[str, object]:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    scenarios = [draft_scenario(item) for item in contract["scenarios"]]
    scenarios.extend(
        legacy_scenario(slug, *LEGACY_PRESENTATION[slug])
        for slug in contract["preserved_legacy_scenarios"]
    )
    return {
        "schema_version": 2,
        "stack_version": VERSION,
        "release_name": "Rust Platform Completion",
        "mip_version": MIP_VERSION,
        "publication_state": "DRAFT",
        "coverage_state": "PARTIAL",
        "release_ready": False,
        "public_demo_ready": False,
        "binding_state": "PENDING_DEPLOYMENT",
        "video_distribution": {
            "provider": "YOUTUBE",
            "status": "PENDING_CHANNEL_SETUP",
            "channel_name": "ElevenID LLC",
            "channel_id": None,
            "channel_handle": None,
            "channel_url": None,
            "playlist_id": None,
            "playlist_url": None,
            "privacy_enhanced_embeds": True,
            "verified_at": None,
        },
        "deployment_release_marker": None,
        "published_at": None,
        "publication_attestation": None,
        "superseded_by": None,
        "recorder_revision": {
            "kind": "git",
            "value": "b8571cbe69500c377f035b33d643b0e397c1640e",
        },
        "demo_application_revision": None,
        "component_revisions": [],
        "image_digests": [],
        "release_evidence": {
            "environment": "beta",
            "recorded_at": None,
            "displayed_offers_invalidated_at": None,
            "source_marker": None,
            "artifacts": [],
        },
        "release_differences": {
            "previous_stack_version": "2026.07.0",
            "ux": [
                "Adds a complete ten-scenario release catalog without removing historical wallet demonstrations."
            ],
            "services": [
                "Qualifies the Rust-native platform through explicit happy and denial paths."
            ],
            "wallets": ["Requires fresh wallet evidence under MIP 0.5."],
            "integrations": [
                "Retains stock Canvas and external-evidence portability coverage."
            ],
            "operations": [
                "Defers all release identity and digest binding until the aggregate beta deployment exists."
            ],
        },
        "scenarios": scenarios,
    }


def main() -> int:
    OUTPUT_PATH.write_text(
        json.dumps(build_manifest(), indent=2) + "\n", encoding="utf-8"
    )
    print(OUTPUT_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
