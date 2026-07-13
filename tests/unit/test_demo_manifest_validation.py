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
                "schema_version": 1,
                "latest_approved_stack_version": None,
                "releases": [
                    {"stack_version": "2026.07.0", "release_name": "Credential Lifecycle Foundation", "mip_version": "0.3.1", "coverage_state": "PARTIAL", "manifest_url": "/demos/manifests/2026.07.0.json"},
                    {"stack_version": "2026.07.1", "release_name": "Credential Lifecycle Refinement", "mip_version": "0.3.1", "coverage_state": "PARTIAL", "manifest_url": "/demos/manifests/2026.07.1.json"},
                ],
            },
            {"2026.07.0": self.manifest, "2026.07.1": second},
        )

    def test_deprecated_protocol_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["scenarios"][0]["protocols"] = ["openid4vp-draft-24"]
        with self.assertRaisesRegex(ManifestValidationError, "unsupported or deprecated"):
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
        manifest["recorder_revision"] = {"kind": "git", "value": "a" * 40}
        for scenario in manifest["scenarios"]:
            scenario["state"] = "PUBLIC"
            scenario["youtube_id"] = "abcdefghijk"
            scenario["published_at"] = "2026-07-13T12:00:00Z"
        with self.assertRaisesRegex(ManifestValidationError, "independent-wallet evidence"):
            validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
