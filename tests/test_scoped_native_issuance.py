"""Closed Issuance build profile and focused test receipts."""
import json
from pathlib import Path
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
        self.assertEqual(build.current_issuer_limits(profile), ("2g", 2 * 1024 ** 3, int(3.1 * 1024 * 1024)))
        recipe = build.render_recipe(profile)
        self.assertEqual(recipe.count("cargo test -p marty-issuance-service"), 2)
        self.assertIn("--lib public_offer_uses_the_same_format_specific_configuration_id_as_application_offers --locked --offline -j1", recipe)
        self.assertIn("--test http_behavior native_offer_transaction_reads_match_the_python_oracle_contract --locked --offline -j1", recipe)
        self.assertNotIn("cargo test -p marty-signing-keys", recipe)
        self.assertNotIn("issuance-lib-test", build.render_recipe(build.CURRENT_ISSUER_POLICY_PROFILE))
        self.assertEqual(build.current_issuer_limits(build.CURRENT_ISSUER_POLICY_COMPACT_PROFILE)[0], "1536m")

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
