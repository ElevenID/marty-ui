"""Synthetic Canvas/signer transports; no application or signing-code patches."""

import base64
import hashlib
import json
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import parse_qs, urlsplit

from canvas_worker_https_fixture import ObservedRequestHandler, WorkerHttpsFixture

NRPS_SCOPE = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
AGS_SCOPE = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
ISSUER_DID = "did:web:synthetic-worker.invalid:canvas"
VERIFICATION_METHOD = ISSUER_DID + "#lti"
SIGNING_KEY_REFERENCE = "transit/keys/synthetic-canvas"
SIGNATURE = "c3ludGhldGljLW5vdC1hLXJlYWwtUlMyNTYtc2lnbmF0dXJl"
ISSUER_SIGN_KEY = "synthetic-mixed-roster-issuer-sign-key-0001"
GRANT_MINT_TOKEN = "synthetic-canvas-grant-mint-token"
GRANT_DOMAIN = b"marty:issuer-signing-grant:v1\n"
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


def _bound_input(claims):
    return GRANT_DOMAIN + json.dumps(claims, separators=(",", ":")).encode()


def _synthetic_grant_hmac(bound_input):
    return "vault:v1:" + base64.b64encode(hashlib.sha256(bound_input).digest()).decode()


def _validate_signing_grant(value, payload, minted_inputs):
    envelope = json.loads(_decode(value))
    assert set(envelope) == {"claims", "hmac"}
    claims = envelope["claims"]
    assert set(claims) == {
        "version",
        "origin",
        "operation_id",
        "organization_id",
        "route",
        "service_id",
        "issuer_did",
        "key_reference",
        "key_purpose",
        "algorithm",
        "payload_sha256_b64",
        "issued_at",
        "expires_at",
        "nonce",
    }
    assert claims["version"] == 1
    assert claims["origin"] == "issuance_canvas"
    assert isinstance(claims["operation_id"], str) and claims["operation_id"]
    assert claims["organization_id"] == "org-review"
    assert claims["route"] == "/internal/compat/issuer-dids/sign"
    assert claims["service_id"] is None
    assert claims["issuer_did"] == ISSUER_DID
    assert claims["key_reference"] == SIGNING_KEY_REFERENCE
    assert claims["key_purpose"] == "lti_tool_signing"
    assert claims["algorithm"] == "RS256"
    digest = (
        base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip("=")
    )
    assert claims["payload_sha256_b64"] == digest
    assert type(claims["issued_at"]) is int and type(claims["expires_at"]) is int
    assert claims["expires_at"] - claims["issued_at"] == 30
    assert abs(time.time() - claims["issued_at"]) < 30
    assert isinstance(claims["nonce"], str) and claims["nonce"]
    expected_input = _bound_input(claims)
    assert envelope["hmac"] == _synthetic_grant_hmac(expected_input)
    assert expected_input in minted_inputs


class MixedRosterHttpsFixture(WorkerHttpsFixture):
    def __init__(self, matrix, *, signer_contract="grant_bound"):
        super().__init__()
        assert signer_contract in {"grant_bound", "pinned_published"}
        self.matrix = matrix
        self.signer_contract = signer_contract
        self.signer_requests = []
        self.token_scopes = []
        self.signer_operations = []
        self.signer_server = None
        self.signer_thread = None
        self.grant_operations = []
        self.grant_requests = []
        self.grant_inputs = []
        self.grant_server = None
        self.grant_thread = None
        self.grant_token_file = None

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
                expected_key = (
                    ISSUER_SIGN_KEY
                    if path == "issuer-dids/sign" and owner.signer_contract == "grant_bound"
                    else "synthetic-startup-api-key"
                )
                assert self.headers.get("X-API-Key") == expected_key

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
                    resolution = {
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
                    }
                    if owner.signer_contract == "grant_bound":
                        resolution["signing_key_reference"] = SIGNING_KEY_REFERENCE
                    _respond(self, resolution)
                except (AssertionError, KeyError, ValueError, TypeError):
                    owner.failures.append("Synthetic signer resolution contract failed")
                    _respond(self, {}, 500)

            def do_POST(self):
                try:
                    self._request(
                        "issuer-dids/sign", {"organization_id": ["org-review"]}
                    )
                    body = json.loads(_body(self))
                    expected_fields = {
                        "issuer_did",
                        "credential_format",
                        "key_purpose",
                        "payload_b64",
                        "algorithm",
                    }
                    if owner.signer_contract == "grant_bound":
                        expected_fields.update(
                            {"key_reference", "verification_method_id"}
                        )
                    assert set(body) == expected_fields
                    assert body["issuer_did"] == ISSUER_DID
                    assert body["credential_format"] == "lti_tool_jwt"
                    assert body["key_purpose"] == "lti_tool_signing"
                    assert body["algorithm"] == "RS256"
                    payload = _decode(body["payload_b64"])
                    owner._validate_assertion(payload.decode("ascii"))
                    if owner.signer_contract == "grant_bound":
                        assert body["key_reference"] == SIGNING_KEY_REFERENCE
                        assert body["verification_method_id"] == VERIFICATION_METHOD
                        with (
                            owner.grant_server.RequestHandlerClass.request_observation_lock
                        ):
                            _validate_signing_grant(
                                self.headers["X-Marty-Signing-Grant"],
                                payload,
                                owner.grant_inputs,
                            )
                    else:
                        assert self.headers.get("X-Marty-Signing-Grant") is None
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

            class GrantServer(ThreadingHTTPServer):
                daemon_threads = False

                def handle_error(self, *_):
                    owner.failures.append("Synthetic signing grant handler failed")

            class GrantHandler(ObservedRequestHandler):
                timeout = 10
                observed_requests = owner.grant_requests
                request_observation_lock = Lock()

                def log_message(self, *_):
                    pass

                def do_POST(self):
                    try:
                        assert self.path == (
                            "/v1/transit/hmac/"
                            "marty-sign-grant-issuance-canvas-v1/sha2-256"
                        )
                        assert self.headers["X-Vault-Token"] == GRANT_MINT_TOKEN
                        request = json.loads(_body(self))
                        assert set(request) == {"input"}
                        bound_input = base64.b64decode(request["input"], validate=True)
                        assert bound_input
                        with self.request_observation_lock:
                            owner.grant_inputs.append(bound_input)
                            owner.grant_operations.append("mint_issuance_canvas")
                        _respond(
                            self,
                            {"data": {"hmac": _synthetic_grant_hmac(bound_input)}},
                        )
                    except (AssertionError, KeyError, ValueError, TypeError):
                        owner.failures.append("Synthetic signing grant contract failed")
                        _respond(self, {}, 500)

            self.grant_server = GrantServer(("127.0.0.1", 0), GrantHandler)
            self.grant_server.socket = self.server.socket.context.wrap_socket(
                self.grant_server.socket, server_side=True
            )
            self.grant_thread = Thread(
                target=self.grant_server.serve_forever, daemon=True
            )
            self.grant_thread.start()
            self.grant_origin = f"https://127.0.0.1:{self.grant_server.server_port}"
            self.grant_token_file = Path(self.certificates.name) / "grant-mint-token"
            self.grant_token_file.write_text(GRANT_MINT_TOKEN + "\n", encoding="ascii")
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
        self.grant_operations.clear()
        self.grant_requests.clear()
        self.grant_inputs.clear()
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
            if self.grant_thread is not None and self.grant_thread.ident is not None:
                self.grant_server.shutdown()
                self.grant_thread.join(timeout=5)
                assert not self.grant_thread.is_alive()
            if self.grant_server is not None:
                self.grant_server.server_close()
            if self.signer_thread is not None and self.signer_thread.ident is not None:
                self.signer_server.shutdown()
                self.signer_thread.join(timeout=5)
                assert not self.signer_thread.is_alive()
            if self.signer_server is not None:
                self.signer_server.server_close()
        finally:
            super().close()
