import copy
import json
import unittest
from pathlib import Path

from scripts.validate_demo_manifests import ManifestValidationError, validate_index, validate_manifest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "ui" / "public" / "demos" / "manifests" / "2026.07.0.json"


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

    def test_published_video_requires_verified_youtube_distribution(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["video_distribution"]["status"] = "PENDING_CHANNEL_SETUP"
        for field in ("channel_id", "channel_handle", "channel_url", "playlist_id", "playlist_url", "verified_at"):
            manifest["video_distribution"][field] = None
        with self.assertRaisesRegex(ManifestValidationError, "verified ElevenID LLC YouTube channel"):
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
