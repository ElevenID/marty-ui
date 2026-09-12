"""Synthetic Canvas/signer transports; no application or signing-code patches."""

import base64
from http.server import ThreadingHTTPServer
import json
from threading import Lock, Thread
import time
from urllib.parse import parse_qs, urlsplit

from canvas_worker_https_fixture import ObservedRequestHandler, WorkerHttpsFixture

NRPS_SCOPE = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
AGS_SCOPE = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
ISSUER_DID = "did:web:synthetic-worker.invalid:canvas"
VERIFICATION_METHOD = ISSUER_DID + "#lti"
SIGNATURE = "c3ludGhldGljLW5vdC1hLXJlYWwtUlMyNTYtc2lnbmF0dXJl"
NAME_SENTINEL = "SYNTHETIC_NAME_MUST_NOT_PERSIST"
EMAIL_SENTINEL = "synthetic-no-retention@example.invalid"


def _decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _respond(handler, payload, status=200):
    body = json.dumps(payload, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _body(handler):
    size = int(handler.headers.get("Content-Length", "0"))
    assert 0 < size <= 16384
    body = handler.rfile.read(size)
    assert len(body) == size
    return body


class MixedRosterHttpsFixture(WorkerHttpsFixture):
    def __init__(self, matrix):
        super().__init__()
        self.matrix = matrix
        self.signer_requests = []
        self.token_scopes = []
        self.signer_operations = []
        self.signer_server = None
        self.signer_thread = None

    def _validate_assertion(self, signing_input):
        header, claims = [
            json.loads(_decode(part)) for part in signing_input.split(".")
        ]
        assert header == {"alg": "RS256", "typ": "JWT", "kid": VERIFICATION_METHOD}
        assert set(claims) == {"iss", "sub", "aud", "iat", "exp", "jti"}
        assert claims["iss"] == claims["sub"] == "synthetic-client"
        assert claims["aud"] == self.origin + "/login/oauth2/token"
        assert type(claims["iat"]) is int and type(claims["exp"]) is int
        assert claims["exp"] - claims["iat"] == 300
        assert abs(time.time() - claims["iat"]) < 30
        assert isinstance(claims["jti"], str) and claims["jti"]

    def __enter__(self):
        owner = self
        super().__enter__()
        # Extend only this owned fixture's handler before any worker starts.
        # The shared base still owns TLS, request recording and GET responses.
        original_handler = self.server.RequestHandlerClass

        class CanvasHandler(original_handler):
            timeout = 10

            def do_POST(self):
                try:
                    assert self.path == "/login/oauth2/token"
                    assert self.headers["Accept"] == "application/json"
                    assert (
                        self.headers["Content-Type"].split(";")[0]
                        == "application/x-www-form-urlencoded"
                    )
                    form = parse_qs(_body(self).decode())
                    assert set(form) == {
                        "grant_type",
                        "client_assertion_type",
                        "client_assertion",
                        "client_id",
                        "scope",
                    }
                    assert all(len(values) == 1 for values in form.values())
                    assert form["grant_type"] == ["client_credentials"]
                    assert form["client_assertion_type"] == [
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ]
                    assert form["client_id"] == ["synthetic-client"]
                    assertion = form["client_assertion"][0]
                    signing_input, signature = assertion.rsplit(".", 1)
                    assert signature == SIGNATURE
                    owner._validate_assertion(signing_input)
                    scope = form["scope"][0]
                    assert scope in {NRPS_SCOPE, AGS_SCOPE}
                    owner.token_scopes.append(scope)
                    _respond(
                        self,
                        {
                            "access_token": "synthetic-nrps-token"
                            if scope == NRPS_SCOPE
                            else "synthetic-ags-token"
                        },
                    )
                except (AssertionError, KeyError, ValueError, TypeError):
                    owner.failures.append("Synthetic Canvas token contract failed")
                    _respond(self, {}, 500)

        self.server.RequestHandlerClass = CanvasHandler

        class SignerServer(ThreadingHTTPServer):
            daemon_threads = False

            def handle_error(self, *_):
                owner.failures.append("Synthetic signer handler failed")

        class SignerHandler(ObservedRequestHandler):
            timeout = 10
            observed_requests = owner.signer_requests
            request_observation_lock = Lock()

            def log_message(self, *_):
                pass

            def _request(self, path, expected_query):
                url = urlsplit(self.path)
                assert url.path == "/internal/signing-keys/" + path
                assert parse_qs(url.query) == expected_query
                assert self.headers.get("X-API-Key") == "synthetic-startup-api-key"

            def do_GET(self):
                try:
                    self._request(
                        "resolve-issuer-did",
                        {
                            "organization_id": ["org-review"],
                            "issuer_did": [ISSUER_DID],
                            "credential_format": ["lti_tool_jwt"],
                            "key_purpose": ["lti_tool_signing"],
                            "algorithm": ["RS256"],
                        },
                    )
                    owner.signer_operations.append("resolve_lti_tool_identity")
                    # Match the existing controlled signer contract's public
                    # selector shape. No key or credential is generated here.
                    _respond(
                        self,
                        {
                            "ok": True,
                            "issuer_did": ISSUER_DID,
                            "verification_method_id": VERIFICATION_METHOD,
                            "public_jwk": {
                                "kid": VERIFICATION_METHOD,
                                "kty": "RSA",
                                "alg": "RS256",
                                "use": "sig",
                                "n": "public-modulus",
                                "e": "AQAB",
                            },
                        },
                    )
                except (AssertionError, KeyError, ValueError, TypeError):
                    owner.failures.append("Synthetic signer resolution contract failed")
                    _respond(self, {}, 500)

            def do_POST(self):
                try:
                    self._request(
                        "issuer-dids/sign", {"organization_id": ["org-review"]}
                    )
                    body = json.loads(_body(self))
                    assert set(body) == {
                        "issuer_did",
                        "credential_format",
                        "key_purpose",
                        "payload_b64",
                        "algorithm",
                    }
                    assert body["issuer_did"] == ISSUER_DID
                    assert body["credential_format"] == "lti_tool_jwt"
                    assert body["key_purpose"] == "lti_tool_signing"
                    assert body["algorithm"] == "RS256"
                    owner._validate_assertion(
                        _decode(body["payload_b64"]).decode("ascii")
                    )
                    owner.signer_operations.append("sign_lti_tool_assertion")
                    _respond(
                        self,
                        {
                            "ok": True,
                            "issuer_did": ISSUER_DID,
                            "algorithm": "RS256",
                            "verification_method_id": VERIFICATION_METHOD,
                            "signature_raw_b64": SIGNATURE,
                        },
                    )
                except (AssertionError, KeyError, ValueError, TypeError):
                    owner.failures.append("Synthetic signer assertion contract failed")
                    _respond(self, {}, 500)

        try:
            self.signer_server = SignerServer(("127.0.0.1", 0), SignerHandler)
            self.signer_thread = Thread(
                target=self.signer_server.serve_forever, daemon=True
            )
            self.signer_thread.start()
            self.signer_origin = f"http://127.0.0.1:{self.signer_server.server_port}/internal/signing-keys"
            return self
        except BaseException:
            self.close()
            raise

    def set_stage(self, stage):
        assert not self.failures, self.failures
        self.requests.clear()
        self.signer_requests.clear()
        self.token_scopes.clear()
        self.signer_operations.clear()
        members = [
            {
                "user_id": f"subject-{user}",
                "status": "Active" if user != 12 or stage["active_12"] else "Inactive",
                "name": NAME_SENTINEL,
                "email": EMAIL_SENTINEL,
            }
            for user in [7, 8, 9, 11, 12]
        ] + [{"user_id": "unlinked-subject", "status": "Active"}]
        responses = {
            f"/api/v1/courses/42/users?enrollment_type%5B%5D=student&per_page={self.matrix['roster_limit']}": {
                "status": 200,
                "body": [
                    {"id": user, "name": NAME_SENTINEL, "email": EMAIL_SENTINEL}
                    for user in self.matrix["roster_users"]
                ],
            },
            "/api/lti/courses/42/memberships": {
                "status": 200,
                "body": {"members": members},
            },
        }
        for user in [7, 8, 9, 10, 11, 12]:
            failed = stage.get("error", False)
            score = (
                stage.get("head_score", stage["score"])
                if user == 12
                else stage["score"]
            )
            responses[
                f"/api/v1/courses/42/assignments/9/submissions/{user}?include%5B%5D=assignment"
            ] = {
                "status": 503 if failed else 200,
                "body": {}
                if failed
                else {
                    "id": 11,
                    "assignment_id": 9,
                    "score": 90,
                    "workflow_state": "graded",
                    "assignment": {"points_possible": 100},
                },
            }
            responses[
                f"/api/lti/courses/42/line_items/5/results?user_id=subject-{user}"
            ] = {
                "status": 503 if failed else 200,
                "body": {}
                if failed
                else [
                    {
                        "resultScore": score,
                        "resultMaximum": 100,
                        "resultStatus": "FullyGraded",
                    }
                ],
            }
        self.stage = {"responses": responses}

    def close(self):
        try:
            if self.signer_thread is not None and self.signer_thread.ident is not None:
                self.signer_server.shutdown()
                self.signer_thread.join(timeout=5)
                assert not self.signer_thread.is_alive()
            if self.signer_server is not None:
                self.signer_server.server_close()
        finally:
            super().close()
