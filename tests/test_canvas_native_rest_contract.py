"""Focused controls for the intentional native/frozen Python request delta."""

import copy
import http.client
import ssl
import unittest
import sys
import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace



class TestNativeRestContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_path = list(sys.path)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        global native_path, native_requests, TimeoutHttpsFixture
        from canvas_native_rest_contract import native_path, native_requests
        from canvas_worker_timeout_https_fixture import TimeoutHttpsFixture

    @classmethod
    def tearDownClass(cls):
        sys.path[:] = cls.original_path

    def test_only_two_frozen_unsupported_expansions_are_projected(self):
        for assignment in (9, 10):
            path = f"/api/v1/courses/42/assignments/{assignment}/submissions/7"
            self.assertEqual(native_path(path + "?include%5B%5D=assignment"), path)
        unchanged = (
            "/api/v1/courses/42/assignments/11/submissions/7?include%5B%5D=assignment",
            "/api/v1/courses/43/assignments/9/submissions/7?include%5B%5D=assignment",
            "/api/v1/courses/42/assignments/9/submissions/8?include%5B%5D=assignment",
            "/api/v1/courses/42/assignments/9/submissions/7?include[]=assignment",
            "/api/v1/courses/42/assignments/9/submissions/7?include%5B%5D=assignment&extra=1",
            "/api/v1/courses/42/modules/3?student_id=7",
            "/api/v1/courses/42/users?enrollment_type%5B%5D=student&per_page=100",
        )
        for path in unchanged:
            self.assertEqual(native_path(path), path)

    def test_projection_preserves_frozen_input_fields_order_and_cardinality(self):
        requests = [self.request(), {**self.request(), "method": "POST", "authorization": "foreign"}]
        frozen = copy.deepcopy(requests)
        projected = native_requests(requests)
        self.assertEqual(requests, frozen)
        self.assertEqual(len(projected), 2)
        for original, actual in zip(requests, projected):
            self.assertEqual({k: v for k, v in original.items() if k != "path"},
                             {k: v for k, v in actual.items() if k != "path"})
        self.assertNotEqual(projected[0], projected[1])

    @staticmethod
    def request():
        return {"method": "GET", "path": "/api/v1/courses/42/assignments/9/submissions/7?include%5B%5D=assignment",
                "authorization": "Bearer synthetic-worker-rest-token", "accept": "application/json"}

    def test_actual_https_observation_is_unmodified_and_strict(self):
        expected = native_requests([self.request()])[0]
        with TimeoutHttpsFixture(expected, {"status": 200, "body": {}}, delay_seconds=0.01) as fixture:
            connection = http.client.HTTPSConnection(
                fixture.origin.removeprefix("https://"),
                context=ssl.create_default_context(cafile=str(fixture.cert)), timeout=5)
            try:
                connection.request("GET", expected["path"], headers={
                    "Authorization": expected["authorization"], "Accept": expected["accept"]})
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 200)
                fixture.assert_requests()
                self.assertEqual(fixture.requests, [expected])
                self.assertNotEqual(fixture.requests, [self.request()])
            finally:
                connection.close()

    def test_fixture_rejects_foreign_auth_query_method_and_extra_request(self):
        expected = native_requests([self.request()])[0]
        for changed in ({"authorization": "Bearer foreign"}, {"method": "POST"},
                        {"accept": "text/plain"}, {"path": expected["path"] + "?extra=1"}):
            fixture = TimeoutHttpsFixture(expected, {"status": 200, "body": {}}, delay_seconds=0)
            actual = {**expected, **changed}
            fixture.requests = [actual]
            with self.assertRaises(AssertionError):
                fixture.wait_for_response(0, actual["path"], fixture.stage)
        fixture.requests = [expected, expected]
        with self.assertRaises(AssertionError):
            fixture.wait_for_response(1, expected["path"], fixture.stage)

    def test_native_controller_guards_keep_all_non_path_checks(self):
        import test_canvas_worker_timeout_https as header
        import test_canvas_worker_body_timeout_https as body
        import test_canvas_worker_deadline_https as deadline

        reference = {"requests": [self.request()]}
        frozen = copy.deepcopy(reference)
        expected = native_requests(reference["requests"])
        for guard in (header.assert_requests, body.assert_requests, deadline.assert_requests):
            guard(SimpleNamespace(failures=[], requests=expected), reference)
            for bad in ([self.request()], [], expected * 2,
                        [{**expected[0], "authorization": "foreign"}],
                        [{**expected[0], "path": expected[0]["path"] + "?extra=1"}],
                        [{**expected[0], "method": "POST"}]):
                with self.assertRaises(AssertionError):
                    guard(SimpleNamespace(failures=[], requests=bad), reference)
            with self.assertRaises(AssertionError):
                guard(SimpleNamespace(failures=["failure"], requests=expected), reference)
        self.assertEqual(reference, frozen)


class TestCurrentCaptureBinding(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "scripts").mkdir()
        (self.root / "contracts").mkdir()
        self.helper = self.root / "scripts/canvas_worker_https_fixture.py"
        self.helper.write_bytes(b"reviewed expectation helper\r\n")
        self.actual = hashlib.sha256(b"reviewed expectation helper\n").hexdigest()
        self.captured = "edf207e02a2e3a976f3a1b4cf15b7618038e60100fa51f0847797bcf92b65992"
        self.contract = {"schema": "marty.canvas-worker-timeout-current-inputs/v1",
                         "normalization": "UTF-8 text with CRLF and CR converted to LF before SHA-256",
                         "sha256": {"scripts/canvas_worker_https_fixture.py": self.actual}}
        self.contract_path = self.root / "contracts/canvas-worker-timeout-current-inputs.json"
        self.contract_path.write_text(json.dumps(self.contract), encoding="utf8")

    def bind(self, pins=None):
        from scripts.canvas_native_rest_contract import bind_current_capture_inputs
        return bind_current_capture_inputs(self.root, pins or {self.helper.name: self.captured})

    def test_current_and_historical_hashes_are_explicitly_different(self):
        binding = self.bind()[self.helper.name]
        self.assertEqual(binding, {"captured_sha256": self.captured,
                                  "current_sha256": self.actual, "reviewed_harness_delta": True})
        self.assertNotEqual(binding["captured_sha256"], binding["current_sha256"])

    def test_actual_current_helper_drift_cannot_reuse_capture(self):
        self.helper.write_text("unreviewed edit\n", encoding="utf8")
        with self.assertRaisesRegex(AssertionError, "Current Canvas replay input differs"):
            self.bind()

    def test_unknown_historical_pin_does_not_gain_compatibility(self):
        with self.assertRaisesRegex(AssertionError, "Unreviewed historical"):
            self.bind({self.helper.name: "a" * 64})

    def test_other_source_cannot_gain_helper_compatibility(self):
        (self.root / "scripts/other.py").write_text("different source\n", encoding="utf8")
        with self.assertRaisesRegex(AssertionError, "Unreviewed historical"):
            self.bind({"other.py": self.captured})

    def test_unchanged_source_retains_exact_digest(self):
        raw = "unchanged source\n"
        digest = hashlib.sha256(raw.encode()).hexdigest()
        (self.root / "scripts/other.py").write_text(raw, encoding="utf8")
        binding = self.bind({"other.py": digest})["other.py"]
        self.assertEqual(binding["current_sha256"], binding["captured_sha256"])
        self.assertIs(binding["reviewed_harness_delta"], False)

    def test_paths_cannot_escape_reviewed_root(self):
        with self.assertRaises(AssertionError):
            self.bind({"../other.py": self.captured})
        self.contract["sha256"] = {"../other.py": self.actual}
        self.contract_path.write_text(json.dumps(self.contract), encoding="utf8")
        with self.assertRaises(AssertionError):
            self.bind()


if __name__ == "__main__":
    unittest.main()
