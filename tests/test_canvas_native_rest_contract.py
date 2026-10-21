"""Focused controls for the intentional native/frozen Python request delta."""

import copy
import http.client
import ssl
import unittest
import sys
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


if __name__ == "__main__":
    unittest.main()
