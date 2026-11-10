import importlib.util
import urllib.error
import json
from pathlib import Path
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("candidate_lifecycle", Path(__file__).resolve().parents[1] / "scripts" / "canvas_oss_beta_lifecycle.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Response:
    def __init__(self, status, location=None):
        self.status = status
        self.headers = {"Location": location} if location else {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class Opener:
    def __init__(self, response):
        self.response = response

    def open(self, request, timeout):
        assert request.full_url == "https://beta.elevenidllc.com/v1/auth/login?redirect_uri=%2Fconsole"
        assert timeout == 20
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def public_static(url):
    if url.endswith("/ready"):
        return 200, b"ready"
    if url.endswith("marty-release"):
        return 200, json.dumps({"release_version": "v1", "marty_ui_sha": "a" * 40}).encode()
    if url.endswith("marty-ui-release.json"):
        return 200, json.dumps({"release_version": "v1", "marty_ui_sha": "a" * 40}).encode()
    raise AssertionError(url)


class BrowserReadinessTest(unittest.TestCase):
    def test_internal_health_and_markers_do_not_override_public_530(self):
        with patch.object(module, "get", public_static), patch.object(module.urllib.request, "build_opener", return_value=Opener(urllib.error.HTTPError("https://beta.elevenidllc.com/v1/auth/login", 530, "origin failure", {}, None))):
            with self.assertRaisesRegex(RuntimeError, "public beta auth redirect is unavailable"):
                module.assert_beta()

    def test_continuity_monitor_keeps_read_only_public_health_probe(self):
        with patch.object(module, "get", public_static), patch.object(module, "assert_public_auth_redirect", side_effect=AssertionError("unexpected auth initiation")):
            self.assertEqual(module.assert_beta(browser_ready=False), {"release_version": "v1", "source_id": "a" * 40})

    def test_public_auth_redirect_must_bind_canonical_issuer_and_callback(self):
        query = "client_id=owned&state=opaque&code_challenge=opaque&response_type=code&redirect_uri=https%3A%2F%2Fbeta.elevenidllc.com%2Fv1%2Fauth%2Fcallback"
        good = "https://beta.elevenidllc.com/realms/11id/protocol/openid-connect/auth?" + query
        with patch.object(module, "get", public_static):
            for location in (good.replace("beta.elevenidllc.com", "foreign.example", 1),
                             good.replace("/realms/11id/", "/realms/other/"),
                             good.replace("state=opaque&", "")):
                with patch.object(module.urllib.request, "build_opener", return_value=Opener(Response(302, location))):
                    with self.assertRaisesRegex(RuntimeError, "canonical issuer"):
                        module.assert_beta()
            with patch.object(module.urllib.request, "build_opener", return_value=Opener(Response(302, good))):
                self.assertEqual(module.assert_beta(), {"release_version": "v1", "source_id": "a" * 40})


if __name__ == "__main__":
    unittest.main()
