import copy
import json
import unittest
from pathlib import Path

from scripts.validate_demo_manifests import ManifestValidationError, validate_index, validate_manifest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "ui" / "public" / "demos" / "manifests" / "2026.07.0.json"
PORTFOLIO_MANIFEST_PATH = ROOT / "ui" / "public" / "demos" / "manifests" / "2026.08.0.json"


class DemoManifestValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_current_preview_is_valid(self):
        validate_manifest(copy.deepcopy(self.manifest))

    def test_elevenid_llc_releases_can_share_a_mip_version(self):
        second = copy.deepcopy(self.manifest)
        second["stack_version"] = "2026.07.1"
        second["release_name"] = "Credential Lifecycle Refinement"
        for scenario in second["scenarios"]:
            scenario["poster"]["src"] = scenario["poster"]["src"].replace("2026.07.0", "2026.07.1")
        validate_manifest(second)
        validate_index(
            {
                "schema_version": 2,
                "latest_approved_stack_version": None,
                "releases": [
                    {"stack_version": "2026.07.0", "release_name": "Credential Lifecycle Foundation", "mip_version": "0.3.1", "publication_state": "DRAFT", "coverage_state": "PARTIAL", "manifest_url": "/demos/manifests/2026.07.0.json"},
                    {"stack_version": "2026.07.1", "release_name": "Credential Lifecycle Refinement", "mip_version": "0.3.1", "publication_state": "DRAFT", "coverage_state": "PARTIAL", "manifest_url": "/demos/manifests/2026.07.1.json"},
                ],
            },
            {"2026.07.0": self.manifest, "2026.07.1": second},
        )

    def test_deprecated_protocol_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["scenarios"][0]["protocols"] = ["openid4vp-draft-24"]
        with self.assertRaisesRegex(ManifestValidationError, "unsupported or deprecated"):
            validate_manifest(manifest)

    def test_https_webhook_protocol_is_accepted(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["scenarios"][0]["protocols"] = ["https-webhooks"]
        validate_manifest(manifest)

    def test_published_video_requires_verified_youtube_distribution(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["video_distribution"]["status"] = "PENDING_CHANNEL_SETUP"
        for field in ("channel_id", "channel_handle", "channel_url", "playlist_id", "playlist_url", "verified_at"):
            manifest["video_distribution"][field] = None
        with self.assertRaisesRegex(ManifestValidationError, "verified ElevenID LLC YouTube channel"):
            validate_manifest(manifest)

    def test_post_july_releases_require_the_v3_portfolio_and_legacy_wallet_demos(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["stack_version"] = "2026.08.0"
        manifest["binding_state"] = "BOUND"
        for scenario in manifest["scenarios"]:
            scenario["poster"]["src"] = scenario["poster"]["src"].replace("2026.07.0", "2026.08.0")
        with self.assertRaisesRegex(ManifestValidationError, "required portfolio and preserved legacy"):
            validate_manifest(manifest)

    def test_mip_05_release_cannot_advertise_the_digital_passport_candidate(self):
        manifest = json.loads(PORTFOLIO_MANIFEST_PATH.read_text(encoding="utf-8"))
        candidate = copy.deepcopy(manifest["scenarios"][0])
        candidate["slug"] = "passport-digital-handoff-evidence"
        candidate["demo_id"] = "D-13"
        manifest["scenarios"].append(candidate)

        with self.assertRaisesRegex(ManifestValidationError, "candidate requires MIP 0.6.0-beta.1"):
            validate_manifest(manifest)

        manifest["mip_version"] = "0.6.0"
        for scenario in manifest["scenarios"]:
            scenario["mip_version"] = "0.6.0"
        with self.assertRaisesRegex(ManifestValidationError, "candidate requires MIP 0.6.0-beta.1"):
            validate_manifest(manifest)

        manifest["mip_version"] = "0.6.0-beta.1"
        for scenario in manifest["scenarios"]:
            scenario["mip_version"] = "0.6.0-beta.1"
        with self.assertRaisesRegex(ManifestValidationError, "happy path differs from the portfolio contract"):
            validate_manifest(manifest)

        contract = json.loads((ROOT / "deploy-config" / "catalog" / "demo-portfolio-v3.json").read_text(encoding="utf-8"))
        planned = contract["candidate_scenarios"][0]
        candidate["recording_plan"]["happy_path"] = planned["happy_path"]
        candidate["recording_plan"]["failure_paths"] = planned["failure_paths"]
        candidate["assertions"] = [
            {"id": path, "label": path.replace("_", " "), "result": "NOT_RUN", "evidence_sha256": None}
            for path in planned["happy_path"] + planned["failure_paths"]
        ]
        candidate["mip_version"] = "0.6.0-beta.1"
        validate_manifest(manifest)

    def test_historical_release_cannot_skip_digital_candidate_validation(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["mip_version"] = "0.6.0-beta.1"
        for scenario in manifest["scenarios"]:
            scenario["mip_version"] = "0.6.0-beta.1"
        candidate = copy.deepcopy(manifest["scenarios"][0])
        candidate["slug"] = "passport-digital-handoff-evidence"
        candidate["demo_id"] = "D-13"
        manifest["scenarios"].append(candidate)

        with self.assertRaisesRegex(ManifestValidationError, "candidate cannot appear in a historical"):
            validate_manifest(manifest)

    def test_complete_coverage_cannot_leave_present_digital_candidate_in_draft(self):
        manifest = json.loads(PORTFOLIO_MANIFEST_PATH.read_text(encoding="utf-8"))
        contract = json.loads((ROOT / "deploy-config" / "catalog" / "demo-portfolio-v3.json").read_text(encoding="utf-8"))["candidate_scenarios"][0]
        candidate = copy.deepcopy(manifest["scenarios"][0])
        candidate["slug"] = contract["slug"]
        candidate["demo_id"] = contract["demo_id"]
        candidate["recording_plan"]["happy_path"] = contract["happy_path"]
        candidate["recording_plan"]["failure_paths"] = contract["failure_paths"]
        candidate["assertions"] = [
            {"id": path, "label": path.replace("_", " "), "result": "NOT_RUN", "evidence_sha256": None}
            for path in contract["happy_path"] + contract["failure_paths"]
        ]
        manifest["scenarios"].append(candidate)
        manifest["mip_version"] = "0.6.0-beta.1"
        for scenario in manifest["scenarios"]:
            scenario["mip_version"] = manifest["mip_version"]
        manifest["coverage_state"] = "COMPLETE"
        manifest["publication_state"] = "PUBLIC"
        manifest["public_demo_ready"] = True
        manifest["release_ready"] = True
        manifest["binding_state"] = "BOUND"
        for field in ("deployment_release_marker", "recorder_revision", "component_revisions", "image_digests", "release_evidence"):
            manifest[field] = copy.deepcopy(self.manifest[field])
        with self.assertRaisesRegex(ManifestValidationError, "every present candidate scenario to be PUBLIC"):
            validate_manifest(manifest)

    def test_reserved_d13_id_cannot_hide_under_an_alias(self):
        for source in (self.manifest, json.loads(PORTFOLIO_MANIFEST_PATH.read_text(encoding="utf-8"))):
            manifest = copy.deepcopy(source)
            candidate = copy.deepcopy(manifest["scenarios"][0])
            candidate["slug"] = "passport-digital-handoff-alias"
            candidate["demo_id"] = "D-13"
            manifest["scenarios"].append(candidate)
            with self.subTest(stack_version=manifest["stack_version"]):
                with self.assertRaisesRegex(ManifestValidationError, "candidate demo ID and slug must match"):
                    validate_manifest(manifest)

    def test_reserved_digital_slug_requires_d13_id(self):
        manifest = json.loads(PORTFOLIO_MANIFEST_PATH.read_text(encoding="utf-8"))
        candidate = copy.deepcopy(manifest["scenarios"][0])
        candidate["slug"] = "passport-digital-handoff-evidence"
        candidate["demo_id"] = "D-99"
        manifest["scenarios"].append(candidate)
        with self.assertRaisesRegex(ManifestValidationError, "candidate demo ID and slug must match"):
            validate_manifest(manifest)

    def test_pending_deployment_draft_cannot_claim_release_evidence(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["binding_state"] = "PENDING_DEPLOYMENT"
        manifest["deployment_release_marker"] = None
        manifest["component_revisions"] = []
        manifest["image_digests"] = []
        manifest["release_evidence"]["source_marker"] = None
        manifest["release_evidence"]["recorded_at"] = None
        manifest["release_evidence"]["displayed_offers_invalidated_at"] = None
        manifest["release_evidence"]["artifacts"] = []
        validate_manifest(manifest)
        manifest["deployment_release_marker"] = "invented-release"
        with self.assertRaisesRegex(ManifestValidationError, "cannot claim a release marker"):
            validate_manifest(manifest)

    def test_deployed_binding_can_await_recording_without_invented_evidence(self):
        manifest = json.loads(PORTFOLIO_MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["binding_state"] = "DEPLOYED_PENDING_EVIDENCE"
        manifest["deployment_release_marker"] = "mip-0.5.0-local-test"
        manifest["demo_application_revision"] = "a" * 40
        manifest["component_revisions"] = [
            {
                "component": "marty-ui",
                "repository": "https://github.com/ElevenID/marty-ui",
                "revision": "a" * 40,
            }
        ]
        manifest["image_digests"] = [
            {"component": "ui-prod", "digest": f"sha256:{'b' * 64}"}
        ]
        manifest["release_evidence"]["source_marker"] = "c" * 40
        validate_manifest(manifest)
        manifest["release_evidence"]["recorded_at"] = "2026-08-26T12:00:00Z"
        with self.assertRaisesRegex(ManifestValidationError, "cannot claim recording times"):
            validate_manifest(manifest)

    def test_v3_portfolio_requires_exact_happy_denial_and_assertion_paths(self):
        manifest = json.loads(PORTFOLIO_MANIFEST_PATH.read_text(encoding="utf-8"))
        validate_manifest(copy.deepcopy(manifest))
        manifest["scenarios"][0]["recording_plan"]["failure_paths"] = []
        with self.assertRaisesRegex(ManifestValidationError, "failure paths differ"):
            validate_manifest(manifest)

    def test_sensitive_public_fields_are_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["scenarios"][0]["credential_offer_uri"] = "https://example.invalid/offer"
        with self.assertRaisesRegex(ManifestValidationError, "sensitive fields are forbidden"):
            validate_manifest(manifest)

    def test_cross_release_inheritance_requires_full_attestation(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["scenarios"][0]["inherited_evidence"] = {
            "source_stack_version": "2026.05.0",
            "source_scenario_revision": 2,
            "attested_at": "2026-07-13T12:00:00Z",
            "attestation_sha256": "a" * 64,
            "byte_identical_components": True,
            "unchanged_protocols": True,
            "unchanged_wallets": True,
            "unchanged_behavior": False,
        }
        with self.assertRaisesRegex(ManifestValidationError, "unchanged_behavior=true"):
            validate_manifest(manifest)

    def test_complete_coverage_requires_independent_wallet_pass(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["coverage_state"] = "COMPLETE"
        manifest["publication_state"] = "PUBLIC"
        manifest["release_ready"] = True
        manifest["public_demo_ready"] = True
        manifest["published_at"] = "2026-07-13T12:00:00Z"
        manifest["publication_attestation"] = {
            "kind": "AUTOMATED",
            "pipeline_revision": "a" * 40,
            "published_at": manifest["published_at"],
            "checks": [
                "accessibility", "canonical-urls", "metadata", "navigation", "playback", "privacy",
                "responsive-layouts", "version-selection",
            ],
            "verification_report_sha256": "1" * 64,
            "result_sha256": "2" * 64,
            "youtube_privacy_status": "public",
            "smoke_report_sha256": "3" * 64,
        }
        manifest["recorder_revision"] = {"kind": "git", "value": "a" * 40}
        manifest["video_distribution"] = {
            "provider": "YOUTUBE",
            "status": "CONFIGURED",
            "channel_name": "ElevenID LLC",
            "channel_id": "UC" + "a" * 22,
            "channel_handle": "@elevenidllc",
            "channel_url": "https://www.youtube.com/@elevenidllc",
            "playlist_id": "PL" + "b" * 24,
            "playlist_url": "https://www.youtube.com/playlist?list=PL" + "b" * 24,
            "privacy_enhanced_embeds": True,
            "verified_at": "2026-07-13T12:00:00Z",
        }
        for scenario in manifest["scenarios"]:
            scenario["state"] = "PUBLIC"
            scenario["youtube_id"] = "abcdefghijk"
            scenario["media_evidence"] = {
                "video_sha256": "1" * 64,
                "captions_sha256": "2" * 64,
                "thumbnail_sha256": "3" * 64,
                "privacy_scan_sha256": "4" * 64,
                "publication_config_sha256": "5" * 64,
                "youtube_uploaded_at": "2026-07-13T11:30:00Z",
            }
            scenario["published_at"] = "2026-07-13T12:00:00Z"
            scenario["publication_attestation"] = {
                "kind": "AUTOMATED",
                "pipeline_revision": "a" * 40,
                "published_at": scenario["published_at"],
                "checks": [
                    "accessibility", "captions", "evidence", "links", "playback", "privacy",
                    "thumbnail", "transcript",
                ],
                "verification_report_sha256": "1" * 64,
                "result_sha256": "2" * 64,
                "youtube_privacy_status": "public",
                "smoke_report_sha256": "3" * 64,
            }
            scenario["limitations"] = []
            for assertion in scenario["assertions"]:
                assertion["result"] = "PASS"
                assertion["evidence_sha256"] = "d" * 64
        with self.assertRaisesRegex(ManifestValidationError, "independent-wallet evidence"):
            validate_manifest(manifest)

    def test_public_scenario_requires_complete_editorial_and_assertion_evidence(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["video_distribution"] = {
            "provider": "YOUTUBE",
            "status": "CONFIGURED",
            "channel_name": "ElevenID LLC",
            "channel_id": "UC" + "a" * 22,
            "channel_handle": "@elevenidllc",
            "channel_url": "https://www.youtube.com/@elevenidllc",
            "playlist_id": "PL" + "b" * 24,
            "playlist_url": "https://www.youtube.com/playlist?list=PL" + "b" * 24,
            "privacy_enhanced_embeds": True,
            "verified_at": "2026-07-13T12:00:00Z",
        }
        scenario = manifest["scenarios"][0]
        scenario["state"] = "PUBLIC"
        scenario["youtube_id"] = "abcdefghijk"
        scenario["media_evidence"] = {
            "video_sha256": "1" * 64,
            "captions_sha256": "2" * 64,
            "thumbnail_sha256": "3" * 64,
            "privacy_scan_sha256": "4" * 64,
            "publication_config_sha256": "5" * 64,
            "youtube_uploaded_at": "2026-07-13T12:00:00Z",
        }
        scenario["published_at"] = "2026-07-13T12:30:00Z"
        scenario["publication_attestation"] = {
            "kind": "AUTOMATED",
            "pipeline_revision": "a" * 40,
            "published_at": scenario["published_at"],
            "checks": [
                "accessibility", "captions", "evidence", "links", "playback", "privacy",
                "thumbnail", "transcript",
            ],
            "verification_report_sha256": "1" * 64,
            "result_sha256": "2" * 64,
            "youtube_privacy_status": "public",
            "smoke_report_sha256": "3" * 64,
        }
        scenario["limitations"] = []
        scenario["assertions"][0]["result"] = "PENDING"
        with self.assertRaisesRegex(ManifestValidationError, "every PUBLIC assertion must PASS"):
            validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
