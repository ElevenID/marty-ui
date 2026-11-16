"""Closed Issuance build profile and focused test receipts."""
import json
from pathlib import Path
from unittest.mock import patch
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_native_build as build


class IssuanceProfileTests(unittest.TestCase):
    def test_closed_one_role_source_and_bounded_recipe(self):
        profile = build.ISSUANCE_OFFER_PROFILE
        scope = build.build_scope(profile)
        self.assertEqual(scope["uiRevision"], "e836a700579a1dc0be4894c6bf416c26529d2564")
        self.assertEqual(scope["coreRevision"], "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac")
        self.assertEqual(scope["roles"], {"issuance-native": "marty-issuance-service"})
        self.assertEqual(scope["packages"], ("marty-issuance-service",))
        self.assertEqual(build.current_issuer_limits(profile), ("3g", 3 * 1024 ** 3, int(4.1 * 1024 * 1024)))
        self.assertEqual(build.current_issuer_limits(build.CURRENT_ISSUER_READY_PROFILE)[0], "2g")
        recipe = build.render_recipe(profile)
        self.assertEqual(recipe.count("cargo test -p marty-issuance-service"), 2)
        self.assertIn("--lib public_offer_uses_the_same_format_specific_configuration_id_as_application_offers --locked --offline -j1", recipe)
        self.assertIn("--test http_behavior native_offer_transaction_reads_match_the_python_oracle_contract --locked --offline -j1", recipe)
        self.assertNotIn("cargo test -p marty-signing-keys", recipe)
        self.assertNotIn("issuance-lib-test", build.render_recipe(build.CURRENT_ISSUER_POLICY_PROFILE))
        self.assertEqual(build.current_issuer_limits(build.CURRENT_ISSUER_POLICY_COMPACT_PROFILE)[0], "1536m")

    def test_issuance_created_limits_and_host_gate_are_closed(self):
        profile = build.ISSUANCE_OFFER_PROFILE
        scope = build.build_scope(profile)
        plan = {
            "buildProfile": profile, "profileSourceSha256": build.sha(Path(build.__file__).with_name("scoped_native_profiles.py")),
            "uiRevision": scope["uiRevision"], "coreRevision": scope["coreRevision"],
            "roleBinaries": scope["roles"], "releaseQualified": False, "recordingQualified": False,
            "runId": "11111111-1111-4111-8111-111111111111",
            "containerName": scope["prefix"] + "11111111-1111-4111-8111-111111111111",
            "sources": {"ui": {"directory": "/owned/ui"}, "core": {"directory": "/owned/core"}},
            "outputDirectory": "/owned/out", "recipe": {"path": "/owned/build.sh"},
            "builderImage": "sha256:" + "a" * 64,
        }
        args = build.build_arguments(plan, profile)
        self.assertEqual(args[args.index("--memory") + 1], "3g")
        self.assertEqual(args[args.index("--memory-swap") + 1], "3g")
        self.assertEqual(args[args.index("--pids-limit") + 1], "64")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--cpus") + 1], "1")
        threshold = build.current_issuer_limits(profile)[2]
        class Capacity:
            def __init__(self, kib): self.kib = kib
            def run(self, *args): return type("Result", (), {"stdout": str(self.kib)})()
        with patch.object(build.shutil, "disk_usage", return_value=type("Disk", (), {"free": 9 * 1024 ** 3})()):
            build.current_issuer_capacity(Capacity(threshold), Path("."), profile)
            with self.assertRaises(ValueError):
                build.current_issuer_capacity(Capacity(threshold - 1), Path("."), profile)

    def test_both_focused_receipts_reject_zero_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for prefix in ("issuance-lib-test", "issuance-http-test"):
                (output / (prefix + ".stdout.txt")).write_text(
                    "test result: ok. 1 passed; 0 failed; 0 ignored; 9 filtered out;\n")
                (output / (prefix + ".stderr.txt")).write_text("")
                (output / (prefix + ".exit-code")).write_text("0\n")
                row = build.focused_rust_test_receipt(output, prefix, prefix, 1)
                self.assertEqual(row["exitCode"], 0)
                (output / (prefix + ".stdout.txt")).write_text(
                    "test result: ok. 0 passed; 0 failed; 0 ignored; 10 filtered out;\n")
                with self.assertRaises(ValueError):
                    build.focused_rust_test_receipt(output, prefix, prefix, 1)


if __name__ == "__main__":
    unittest.main()
