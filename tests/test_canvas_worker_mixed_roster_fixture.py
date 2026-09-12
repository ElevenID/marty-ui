"""Synthetic transport integrity, not worker parity or cryptographic qualification."""

import base64
from http.client import HTTPConnection, HTTPSConnection
import importlib
from io import BytesIO
import json
from pathlib import Path
import ssl
import time
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fixture_module(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("canvas_worker_mixed_roster_https_fixture")


@pytest.fixture
def matrix():
    return json.loads(
        (ROOT / "contracts/canvas-worker-mixed-roster-scenarios.json").read_text()
    )


def request(fixture, method, path, *, signer=False, body=None, headers=None):
    origin = urlsplit(fixture.signer_origin if signer else fixture.origin)
    assert origin.hostname == "127.0.0.1" and origin.port
    if signer:
        assert origin.scheme == "http"
        client = HTTPConnection(origin.hostname, origin.port, timeout=5)
    else:
        assert origin.scheme == "https"
        client = HTTPSConnection(
            origin.hostname,
            origin.port,
            context=ssl.create_default_context(cafile=str(fixture.cert)),
            timeout=5,
        )
    try:
        client.request(method, path, body=body, headers=headers or {})
        response = client.getresponse()
        payload = response.read()
        return response.status, None if response.status == 501 else json.loads(payload)
    finally:
        client.close()


def encoded(value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def signing_input(module, fixture):
    now = int(time.time())
    return ".".join(
        encoded(value)
        for value in (
            {"alg": "RS256", "typ": "JWT", "kid": module.VERIFICATION_METHOD},
            {
                "iss": "synthetic-client",
                "sub": "synthetic-client",
                "aud": fixture.origin + "/login/oauth2/token",
                "iat": now,
                "exp": now + 300,
                "jti": "synthetic-fixture-only",
            },
        )
    )


def test_every_frozen_stage_serves_distinct_roster_membership_and_scores(
    fixture_module, matrix
):
    stages = matrix["cases"][0]["stages"]
    assert len(stages) == len({stage["name"] for stage in stages}) == 7
    assert (
        0
        < matrix["batch_size"]
        < len(set(matrix["roster_users"]))
        <= matrix["roster_limit"]
    )
    with fixture_module.MixedRosterHttpsFixture(matrix) as fixture:
        for stage in stages:
            fixture.set_stage(stage)
            assert fixture.requests == fixture.signer_requests == []
            roster_path = (
                "/api/v1/courses/42/users?enrollment_type%5B%5D=student&per_page="
                + str(matrix["roster_limit"])
            )
            membership_path = "/api/lti/courses/42/memberships"
            rest_path = "/api/v1/courses/42/assignments/9/submissions/9?include%5B%5D=assignment"
            ags_path = "/api/lti/courses/42/line_items/5/results?user_id=subject-"
            status, roster = request(fixture, "GET", roster_path)
            assert status == 200
            assert [item["id"] for item in roster] == matrix["roster_users"]
            assert all(item["name"] == fixture_module.NAME_SENTINEL for item in roster)
            assert all(
                item["email"] == fixture_module.EMAIL_SENTINEL for item in roster
            )
            status, body = request(fixture, "GET", membership_path)
            assert status == 200
            members = {member["user_id"]: member for member in body["members"]}
            assert set(members) == {
                "subject-7",
                "subject-8",
                "subject-9",
                "subject-11",
                "subject-12",
                "unlinked-subject",
            }
            assert members["subject-12"]["status"] == (
                "Active" if stage["active_12"] else "Inactive"
            )
            rest = request(fixture, "GET", rest_path)
            ags = request(fixture, "GET", ags_path + "9")
            head = request(fixture, "GET", ags_path + "12")
            if stage.get("error"):
                assert rest == ags == head == (503, {})
            else:
                assert rest[0] == ags[0] == head[0] == 200
                assert rest[1]["score"] == 90
                assert rest[1]["assignment"] == {"points_possible": 100}
                for response, score in (
                    (ags, stage["score"]),
                    (head, stage.get("head_score", stage["score"])),
                ):
                    assert response[1] == [
                        {
                            "resultScore": score,
                            "resultMaximum": 100,
                            "resultStatus": "FullyGraded",
                        }
                    ]
            assert fixture.requests == [
                {"method": "GET", "path": path, "authorization": None, "accept": None}
                for path in (
                    roster_path,
                    membership_path,
                    rest_path,
                    ags_path + "9",
                    ags_path + "12",
                )
            ]
            assert fixture.failures == []
    assert not fixture.thread.is_alive() and not fixture.signer_thread.is_alive()
    assert fixture.server.socket.fileno() == fixture.signer_server.socket.fileno() == -1


def test_synthetic_signer_and_canvas_tokens_keep_exact_transport_observations(
    fixture_module, matrix
):
    with fixture_module.MixedRosterHttpsFixture(matrix) as fixture:
        fixture.set_stage(matrix["cases"][0]["stages"][0])
        selectors = {
            "issuer_did": fixture_module.ISSUER_DID,
            "credential_format": "lti_tool_jwt",
            "key_purpose": "lti_tool_signing",
            "algorithm": "RS256",
        }
        headers = {"X-API-Key": "synthetic-startup-api-key"}
        resolve_path = "/internal/signing-keys/resolve-issuer-did?" + urlencode(
            {"organization_id": "org-review", **selectors}
        )
        status, resolved = request(
            fixture, "GET", resolve_path, signer=True, headers=headers
        )
        assert status == 200 and resolved["ok"] is True
        assert resolved["issuer_did"] == fixture_module.ISSUER_DID
        assert resolved["verification_method_id"] == fixture_module.VERIFICATION_METHOD
        assert set(resolved["public_jwk"]) == {"kid", "kty", "alg", "use", "n", "e"}
        assertion_input = signing_input(fixture_module, fixture)
        sign_path = "/internal/signing-keys/issuer-dids/sign?organization_id=org-review"
        status, signed = request(
            fixture,
            "POST",
            sign_path,
            signer=True,
            headers=headers,
            body=json.dumps(
                {**selectors, "payload_b64": encoded(assertion_input.encode())}
            ),
        )
        assert status == 200
        assert signed == {
            "ok": True,
            "issuer_did": fixture_module.ISSUER_DID,
            "algorithm": "RS256",
            "verification_method_id": fixture_module.VERIFICATION_METHOD,
            "signature_raw_b64": fixture_module.SIGNATURE,
        }
        for scope, expected in (
            (fixture_module.NRPS_SCOPE, "synthetic-nrps-token"),
            (fixture_module.AGS_SCOPE, "synthetic-ags-token"),
        ):
            assert request(
                fixture,
                "POST",
                "/login/oauth2/token",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body=urlencode(
                    {
                        "grant_type": "client_credentials",
                        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        "client_assertion": assertion_input
                        + "."
                        + signed["signature_raw_b64"],
                        "client_id": "synthetic-client",
                        "scope": scope,
                    }
                ),
            ) == (200, {"access_token": expected})
        assert fixture.signer_operations == [
            "resolve_lti_tool_identity",
            "sign_lti_tool_assertion",
        ]
        assert fixture.token_scopes == [
            fixture_module.NRPS_SCOPE,
            fixture_module.AGS_SCOPE,
        ]
        assert fixture.signer_requests == [
            {"method": method, "path": path, "authorization": None, "accept": None}
            for method, path in (("GET", resolve_path), ("POST", sign_path))
        ]
        assert (
            fixture.requests
            == [
                {
                    "method": "POST",
                    "path": "/login/oauth2/token",
                    "authorization": None,
                    "accept": "application/json",
                }
            ]
            * 2
        )
        fixture.set_stage(matrix["cases"][0]["stages"][1])
        assert (
            fixture.requests
            == fixture.signer_requests
            == fixture.signer_operations
            == fixture.token_scopes
            == []
        )


@pytest.mark.parametrize("signer", [False, True])
def test_unsupported_requests_are_recorded_and_remain_unsupported(
    fixture_module, matrix, signer
):
    with fixture_module.MixedRosterHttpsFixture(matrix) as fixture:
        fixture.set_stage(matrix["cases"][0]["stages"][0])
        assert request(fixture, "PATCH", "/unsupported", signer=signer) == (501, None)
        observations = fixture.signer_requests if signer else fixture.requests
        assert observations == [
            {
                "method": "PATCH",
                "path": "/unsupported",
                "authorization": None,
                "accept": None,
            }
        ]
        assert fixture.signer_operations == fixture.token_scopes == []


@pytest.mark.parametrize("signer", [False, True])
def test_invalid_supported_requests_fail_without_retaining_body_details(
    fixture_module, matrix, signer
):
    failure = (
        "Synthetic signer resolution contract failed"
        if signer
        else "Synthetic Canvas token contract failed"
    )
    with pytest.raises(AssertionError, match=failure):
        with fixture_module.MixedRosterHttpsFixture(matrix) as fixture:
            fixture.set_stage(matrix["cases"][0]["stages"][0])
            assert request(
                fixture,
                "GET" if signer else "POST",
                "/wrong-contract",
                signer=signer,
                body=None if signer else "synthetic-secret-sentinel",
            ) == (500, {})
            assert fixture.failures == [failure]
            assert fixture.signer_operations == fixture.token_scopes == []
            with pytest.raises(AssertionError, match=failure):
                fixture.set_stage(matrix["cases"][0]["stages"][1])


@pytest.mark.parametrize("size", [1, 16384])
def test_body_accepts_exact_bounded_payload(fixture_module, size):
    payload = b"x" * size
    handler = SimpleNamespace(
        headers={"Content-Length": str(size)}, rfile=BytesIO(payload)
    )
    assert fixture_module._body(handler) == payload


@pytest.mark.parametrize(
    "declared,actual", [(0, 0), (-1, 0), (16385, 0), (2, 1), ("invalid", 0)]
)
def test_body_rejects_out_of_bounds_or_incomplete_payload(
    fixture_module, declared, actual
):
    handler = SimpleNamespace(
        headers={"Content-Length": str(declared)}, rfile=BytesIO(b"x" * actual)
    )
    with pytest.raises((AssertionError, ValueError)):
        fixture_module._body(handler)
