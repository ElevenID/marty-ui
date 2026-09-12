"""Guards for captured observations, not a substitute for Rust adoption gates."""

import ast
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
_CAPTURE_TREE = ast.parse(
    (ROOT / "scripts/capture_signing_response_reference.py").read_text(encoding="utf-8")
)
_CAPTURE_LITERALS = {
    node.targets[0].id: ast.literal_eval(node.value)
    for node in _CAPTURE_TREE.body
    if isinstance(node, ast.Assign)
    and len(node.targets) == 1
    and isinstance(node.targets[0], ast.Name)
    and node.targets[0].id in {"REVISION", "SOURCES"}
}
REFERENCE = json.loads(
    (ROOT / "contracts/signing-response-python-reference.json").read_text(
        encoding="utf-8"
    )
)


def detail(name):
    return next(case for case in REFERENCE["details"] if case["name"] == name)


def outward(name, caller):
    return next(
        case
        for case in REFERENCE["outward_callers"]
        if case["name"] == name and case["caller"] == caller
    )


class SigningResponseReferenceTests(unittest.TestCase):
    def test_scope_counts_sources_and_original_corpus_unchanged(self):
        self.assertEqual(
            REFERENCE["reference"]["commit"], _CAPTURE_LITERALS["REVISION"]
        )
        self.assertEqual(
            {
                path: value["git_blob"]
                for path, value in REFERENCE["reference"]["sources"].items()
            },
            _CAPTURE_LITERALS["SOURCES"],
        )
        self.assertEqual(
            [
                len(REFERENCE[name])
                for name in (
                    "inputs",
                    "details",
                    "remote_operations",
                    "outward_callers",
                )
            ],
            [35, 16, 105, 102],
        )
        for section in ("inputs", "details"):
            self.assertEqual(
                len({case["name"] for case in REFERENCE[section]}),
                len(REFERENCE[section]),
            )
        original = (
            (ROOT / "contracts/canvas-worker-privacy-reference.json")
            .read_bytes()
            .replace(b"\r\n", b"\n")
        )
        self.assertEqual(
            hashlib.sha256(original).hexdigest(),
            "2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05",
        )
        self.assertEqual(json.loads(original)["counts"]["signing_error_detail"], 45)

    def test_diagnostic_codepoints_remain_lossless_without_ellipsis(self):
        self.assertEqual(detail("selected-surrogate")["observed"]["detail"], "\ud800")
        self.assertEqual(
            detail("surrogate-at-500")["observed"]["detail"], "x" * 499 + "\ud800"
        )
        self.assertEqual(detail("surrogate-after-500")["observed"]["detail"], "x" * 500)
        self.assertEqual(
            detail("discarded-surrogate")["observed"]["detail"], "selected"
        )
        self.assertEqual(
            detail("selected-supplementary-500")["observed"]["detail"],
            "\U0001f642" * 500,
        )
        self.assertEqual(
            detail("nested-surrogate")["observed"]["detail"],
            "{'\\ud800': '\\udfff', 'nested': ['\\ud800']}",
        )

    def test_order_and_nonfinite_python_representation(self):
        self.assertEqual(
            detail("duplicate-order")["observed"]["detail"], "{'b': 3, 'a': 2}"
        )
        self.assertEqual(
            detail("nonfinite-dictionary")["observed"]["detail"],
            "{'n': nan, 'p': inf, 'm': -inf, 'zero': 0}",
        )
        self.assertEqual(
            detail("nonfinite-falsey-selection")["observed"]["detail"],
            '{"detail":NaN,"error_description":"not-selected"}',
        )

    def test_decoding_order_and_deep_error_phase(self):
        self.assertEqual(
            detail("json-valid-text-codec-fails")["events"], ["json", "text"]
        )
        self.assertEqual(
            detail("json-valid-text-codec-fails")["observed"]["error_class"],
            "UnicodeError",
        )
        self.assertEqual(
            detail("json-depth-10000")["events"], ["json", "json:RecursionError"]
        )
        self.assertEqual(
            detail("json-depth-10000")["observed"]["error_class"], "RecursionError"
        )
        self.assertEqual(detail("json-depth-2048")["observed"]["codepoint_count"], 500)
        self.assertEqual(
            detail("json-utf16-independent-charset")["observed"]["detail"],
            "caf\u00e9\U0001f642",
        )

    def test_surrogate_fails_only_at_actual_lti_renderer(self):
        for caller in ("lti-resolve", "lti-sign"):
            observed = outward("selected-surrogate", caller)
            self.assertEqual(observed["direct"]["status"], 503)
            self.assertIn("\ud800", observed["direct"]["detail"])
            self.assertEqual(
                observed["controlled_asgi"]["error_class"], "UnicodeEncodeError"
            )
            self.assertEqual(
                outward("surrogate-after-500", caller)["controlled_asgi"]["status"], 503
            )
        self.assertEqual(
            outward("selected-surrogate", "proof-policy")["controlled_asgi"]["body"],
            {"detail": "Issuer proof policy is temporarily unavailable"},
        )
        self.assertIs(
            outward("selected-surrogate", "readiness")["direct"]["returned"], False
        )

    def test_proof_policy_exception_mask_is_not_overstated(self):
        for case, error in (
            ("json-valid-text-codec-fails", "UnicodeError"),
            ("redirect-302-malformed", "JSONDecodeError"),
        ):
            observed = outward(case, "proof-policy")
            self.assertEqual(observed["direct"]["error_class"], error)
            self.assertEqual(observed["controlled_asgi"]["error_class"], error)
        self.assertEqual(
            outward("json-depth-10000", "proof-policy")["controlled_asgi"]["status"],
            503,
        )

    def test_all_remote_operations_use_one_request_and_original_paths(self):
        paths = {
            "context": ("GET", "/internal/issuer-context"),
            "resolve": ("GET", "/internal/resolve-issuer-did"),
            "sign": ("POST", "/internal/issuer-dids/sign"),
        }
        for case in REFERENCE["remote_operations"]:
            method, path = paths[case["operation"]]
            self.assertEqual(case["requests"], [{"method": method, "path": path}])
            if case["name"].startswith("redirect-") and case["name"].endswith("-valid"):
                self.assertIs(case["observed"]["returned"]["ok"], True)
        missing_signature = next(
            case
            for case in REFERENCE["remote_operations"]
            if case["name"] == "redirect-302-invalid-signature_raw_b64"
            and case["operation"] == "sign"
        )
        self.assertEqual(
            missing_signature["observed"]["message"],
            "DID-mediated signer did not return a signature",
        )

    def test_redirect_success_reaches_actual_lti_and_proof_policy_validation(self):
        for mode, requirements in (
            ("required", {"key_storage": ["hardware"], "user_authentication": ["pin"]}),
            ("optional", {}),
        ):
            name = "redirect-302-profile-" + mode
            policy = outward(name, "proof-policy")
            expected = {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"],
                    "key_attestations_required": requirements,
                }
            }
            self.assertEqual(policy["direct"]["returned"], expected)
            self.assertEqual(policy["controlled_asgi"]["body"], expected)
            self.assertEqual(policy["controlled_asgi"]["status"], 200)
            lti = outward(name, "lti-resolve")
            self.assertEqual(lti["direct"]["return_type"], "tuple")
            self.assertEqual(lti["direct"]["returned"], lti["controlled_asgi"]["body"])
            self.assertEqual(lti["controlled_asgi"]["status"], 200)

    def test_nonraising_asgi_observes_actual_500_and_503_responses(self):
        rows = REFERENCE["outward_http_responses"]
        self.assertEqual(len(rows), 8)
        for row in rows:
            response = row["controlled_asgi"]
            if (
                row["name"] == "selected-surrogate" and row["caller"].startswith("lti-")
            ) or (
                row["caller"] == "proof-policy" and row["name"] != "selected-surrogate"
            ):
                self.assertEqual(
                    response,
                    {
                        "status": 500,
                        "content_type": "text/plain; charset=utf-8",
                        "body": "Internal Server Error",
                    },
                )
            else:
                self.assertEqual(response["status"], 503)
                self.assertEqual(response["content_type"], "application/json")
                self.assertEqual(response["body"], {"detail": row["direct"]["detail"]})


if __name__ == "__main__":
    unittest.main()
