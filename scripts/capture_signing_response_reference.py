"""Capture pinned signing diagnostics and actual caller error projections.

No service imports, live configuration, network connection or cryptography are
used. Exact source functions/classes are selected from pinned Git objects; the
outward HTTP boundary is a CONTROLLED FastAPI wrapper, not a deployed route.
Prints deterministic, ASCII-escaped synthetic observations; --check compares the
checked-in artifact. This script never writes files or changes a checkout.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
from collections.abc import Mapping
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi import FastAPI, HTTPException


REVISION = "d418ac0df283625f43b0c011fb1c72fd7d3013a9"
SOURCES = {
    "services/issuance/infrastructure/api/signing_context.py": "5e84cfdcbdf289ec0059eb39dd54c4a5c79c5b3a",
    "services/issuance/infrastructure/api/canvas_routes.py": "c8f13de8a604b82f013c92dbccc4978e4496305b",
    "services/issuance/application/canvas_readiness.py": "a7054038cb744bb9b2371b22ca5ecf00df6abf97",
    "services/issuance/main.py": "8fb1add009b1bdf400a0a8e1308eeb92d13d664f",
}
ROOT = "http://synthetic-signing.invalid/internal"
DID = "did:example:issuer"
KEY = "synthetic-service-api-key"
ENVIRONMENT = {
    "SIGNING_KEYS_INTERNAL_URL": ROOT,
    "SIGNING_KEYS_INTERNAL_API_KEY": KEY,
    "ISSUANCE_API_KEY": "synthetic-issuance-api-key",
}


def source_objects(checkout: Path) -> tuple[dict, dict]:
    sources, identities = {}, {}
    for path, expected in SOURCES.items():
        data = subprocess.run(
            ["git", "-C", str(checkout), "show", f"{REVISION}:{path}"],
            capture_output=True,
            check=True,
        ).stdout
        blob = hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data
        ).hexdigest()
        assert blob == expected, "Pinned reference Git blob differs"
        sources[path] = data.decode("utf-8")
        identities[path] = {
            "git_blob": blob,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return sources, identities


def selected(source: str, path: str, names: set[str], namespace: dict) -> None:
    tree = ast.parse(source, filename=path)
    nodes = [node for node in tree.body if getattr(node, "name", None) in names]
    assert {node.name for node in nodes} == names
    # Keep original nodes/line numbers and every method/body unchanged. Only
    # unrelated module initialization/imports are excluded from this boundary.
    future = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    module = ast.fix_missing_locations(
        ast.Module(body=[future, *nodes], type_ignores=[])
    )
    exec(compile(module, path, "exec"), namespace)


def caller_modules(sources: dict) -> tuple[ModuleType, dict, dict, dict]:
    signing_path, lti_path, readiness_path, policy_path = SOURCES
    signing = ModuleType("issuance.infrastructure.api.signing_context")
    signing.__file__ = signing_path
    exec(compile(sources[signing_path], signing_path, "exec"), signing.__dict__)
    lti = {
        "HTTPException": HTTPException,
        "resolve_remote_issuer_did": signing.resolve_remote_issuer_did,
        "sign_payload_with_issuer_did": signing.sign_payload_with_issuer_did,
        "_RSA_PRIVATE_JWK_FIELDS": frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"}),
    }
    selected(
        sources[lti_path],
        lti_path,
        {"IssuerDidToolJwtSigner", "_json_b64url", "_b64url_encode"},
        lti,
    )
    import base64

    lti.update(base64=base64, json=json)
    policy = {"HTTPException": HTTPException}
    selected(
        sources[policy_path],
        policy_path,
        {"_oid4vci_proof_types", "_oid4vci_proof_types_for_org"},
        policy,
    )
    readiness = {
        "signing_context": signing,
        "Mapping": Mapping,
        # Controlled configuration only. The original exception handler and
        # real remote resolver execute; downstream signing/crypto must not run.
        "_issuer_configuration_valid": lambda _: True,
        "_expected_issuer": lambda _: SimpleNamespace(
            issuer_did=DID,
            credential_format="jwt_vc_json",
            key_purpose="credential_signing",
            algorithm="ES256",
        ),
    }
    selected(
        sources[readiness_path],
        readiness_path,
        {"run_canvas_kms_did_challenge"},
        readiness,
    )
    return signing, lti, policy, readiness


def detail_inputs() -> list[dict]:
    cases = []

    def add(name, body, content_type="application/json"):
        cases.append(
            {
                "name": name,
                "status": 503,
                "body_hex": body.hex(),
                "content_type": content_type,
            }
        )

    add("selected-surrogate", b'{"detail":"\\ud800"}')
    add("surrogate-at-500", json.dumps({"detail": "x" * 499 + "\ud800"}).encode())
    add("surrogate-after-500", json.dumps({"detail": "x" * 500 + "\ud800"}).encode())
    add("discarded-surrogate", b'{"detail":"selected","unused":"\\ud800"}')
    add("nested-surrogate", b'{"detail":{"\\ud800":"\\udfff","nested":["\\ud800"]}}')
    add(
        "nonfinite-dictionary",
        b'{"detail":{"n":NaN,"p":Infinity,"m":-Infinity,"zero":-0}}',
    )
    add(
        "nonfinite-falsey-selection",
        b'{"detail":NaN,"error_description":"not-selected"}',
    )
    add("duplicate-order", b'{"detail":{"b":1,"a":2,"b":3}}')
    for name, depth in (
        ("nested-depth-32", 32),
        ("json-depth-2048", 2048),
        ("json-depth-10000", 10000),
    ):
        cases.append(
            {
                "name": name,
                "status": 503,
                "nested_detail_depth": depth,
                "content_type": "application/json",
            }
        )
    add(
        "json-valid-text-codec-fails",
        b'{"detail":"selected"}',
        "application/json; charset=utf-16",
    )
    add(
        "json-utf16-independent-charset",
        '{"detail":"caf\u00e9\U0001f642"}'.encode("utf-16"),
        "application/json; charset=ascii",
    )
    add("text-cp1252", b" \x80\xe9 ", "text/plain; charset=cp1252")
    add(
        "selected-supplementary-500",
        json.dumps({"detail": "\U0001f642" * 501}).encode(),
    )
    add("reason-fallback", b" \t\r\n ", "text/plain")
    return cases


def response_for(case: dict, request: httpx.Request | None = None) -> httpx.Response:
    if "nested_detail_depth" in case:
        depth = case["nested_detail_depth"]
        assert depth in {32, 2048, 10000}
        content = b'{"detail":' + b'{"a":' * depth + b"0" + b"}" * depth + b"}"
    else:
        content = bytes.fromhex(case["body_hex"])
    return httpx.Response(
        case["status"],
        content=content,
        headers={
            "Content-Type": case["content_type"],
            "Location": ROOT + "/must-not-follow",
        },
        request=request,
    )


def error_record(error: Exception) -> dict:
    return {"error_class": type(error).__name__, "message": str(error)}


def detail_observation(signing: ModuleType, case: dict) -> dict:
    response = response_for(case)
    events = []
    original_json = response.json

    def observe_json(*args, **kwargs):
        events.append("json")
        try:
            return original_json(*args, **kwargs)
        except Exception as error:
            events.append("json:" + type(error).__name__)
            raise

    response.json = observe_json

    # Property observation delegates to HTTPX's actual decoder unchanged.
    class ObservedResponse(httpx.Response):
        @property
        def text(self):
            events.append("text")
            return super().text

    response.__class__ = ObservedResponse
    try:
        detail = signing._response_error_detail(response)
        result = {
            "detail": detail,
            "codepoint_count": len(detail),
            "contains_surrogate": any(0xD800 <= ord(c) <= 0xDFFF for c in detail),
        }
    except Exception as error:
        result = error_record(error)
    return {"name": case["name"], "events": events, "observed": result}


async def operation(signing, name):
    if name == "context":
        return await signing.resolve_remote_issuer_context("synthetic-org")
    if name == "resolve":
        return await signing.resolve_remote_issuer_did("synthetic-org", issuer_did=DID)
    assert name == "sign"
    return await signing.sign_payload_with_issuer_did(
        organization_id="synthetic-org",
        issuer_did=DID,
        credential_format="jwt_vc_json",
        key_purpose="credential_signing",
        payload=b"synthetic-payload",
        algorithm="ES256",
        expected_verification_method_id=DID + "#key",
    )


async def remote_observation(signing, case, operation_name, client_type):
    requests = []

    def respond(request):
        assert request.url.host == "synthetic-signing.invalid"
        assert request.headers["X-API-Key"] == KEY
        assert request.url.params["organization_id"] == "synthetic-org"
        assert request.url.path != "/internal/must-not-follow", "unexpected redirect"
        requests.append({"method": request.method, "path": request.url.path})
        return response_for(case, request)

    def controlled_client(**kwargs):
        return client_type(
            transport=httpx.MockTransport(respond), trust_env=False, **kwargs
        )

    with patch.object(signing.httpx, "AsyncClient", controlled_client):
        try:
            value = await operation(signing, operation_name)
            result = {"returned": value}
        except Exception as error:
            result = error_record(error)
    assert len(requests) == 1
    return {
        "name": case["name"],
        "operation": operation_name,
        "requests": requests,
        "observed": result,
    }


async def outward_observation(
    signing,
    lti,
    policy,
    readiness,
    case,
    caller,
    client_type,
    *,
    raise_app_exceptions=True,
):
    requests = []

    def respond(request):
        assert request.url.host == "synthetic-signing.invalid"
        assert request.headers["X-API-Key"] == KEY
        assert request.url.params["organization_id"] == "synthetic-org"
        requests.append({"method": request.method, "path": request.url.path})
        if caller == "lti-sign" and request.method == "GET":
            # Real unchanged identity validation precedes the signing error;
            # public fixture material is not used for cryptographic operations.
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "issuer_did": DID,
                    "verification_method_id": DID + "#key",
                    "public_jwk": {
                        "kid": DID + "#key",
                        "kty": "RSA",
                        "alg": "RS256",
                        "n": "AQAB",
                        "e": "AQAB",
                    },
                },
                request=request,
            )
        assert request.method == ("POST" if caller == "lti-sign" else "GET")
        return response_for(case, request)

    def controlled_client(**kwargs):
        return client_type(
            transport=httpx.MockTransport(respond), trust_env=False, **kwargs
        )

    async def call():
        if caller in {"lti-resolve", "lti-sign"}:
            signer = object.__new__(lti["IssuerDidToolJwtSigner"])
            signer.organization_id, signer.issuer_did = "synthetic-org", DID
            if caller == "lti-sign":
                return await signer.sign_jwt({"synthetic": "payload"})
            return await signer._resolved_identity()
        if caller == "proof-policy":
            return await policy["_oid4vci_proof_types_for_org"](
                "synthetic-org", credential_format="jwt_vc_json", issuer_did=DID
            )
        assert caller == "readiness"
        return await readiness["run_canvas_kms_did_challenge"](
            organization_id="synthetic-org", credential_template={}
        )

    with patch.object(signing.httpx, "AsyncClient", controlled_client):
        try:
            value = await call()
            direct = {"returned": value}
            if isinstance(value, tuple):
                direct = {"return_type": "tuple", "returned": list(value)}
        except HTTPException as error:
            direct = {
                "error_class": type(error).__name__,
                "status": error.status_code,
                "detail": error.detail,
            }
        except Exception as error:
            direct = error_record(error)
        # Actual unchanged caller executes again through FastAPI's real default
        # exception handler/JSON renderer. This wrapper adds no error mapping.
        app = FastAPI()
        app.get("/controlled-caller")(call)
        transport = httpx.ASGITransport(
            app=app, raise_app_exceptions=raise_app_exceptions
        )
        async with client_type(
            transport=transport, base_url="http://controlled.invalid", trust_env=False
        ) as client:
            try:
                response = await client.get("/controlled-caller")
                rendered = {
                    "status": response.status_code,
                    "content_type": response.headers["content-type"],
                    "body": response.json()
                    if response.headers["content-type"].startswith("application/json")
                    else response.text,
                }
            except Exception as error:
                rendered = error_record(error)
    assert len(requests) == (4 if caller == "lti-sign" else 2), (
        case["name"],
        caller,
        direct,
        rendered,
        requests,
    )
    return {
        "name": case["name"],
        "caller": caller,
        "requests": requests,
        "direct": direct,
        "controlled_asgi": rendered,
    }


def redirect_inputs() -> list[dict]:
    valid = {
        "ok": True,
        "issuer_did": DID,
        "algorithm": "ES256",
        "verification_method_id": DID + "#key",
        "signature_raw_b64": "c3ludGhldGlj",
    }
    cases = []
    for status in (301, 302, 303, 307, 308, 399):
        cases.append(
            {
                "name": f"redirect-{status}-valid",
                "status": status,
                "body_hex": json.dumps(valid).encode().hex(),
                "content_type": "application/json",
            }
        )
    variants = [
        ("malformed", b"{invalid"),
        ("empty", b""),
        ("nonobject", b"[]"),
        ("ok-false", b'{"ok":false}'),
        ("ok-missing", b"{}"),
    ]
    for key, value in (
        ("issuer_did", "did:example:other"),
        ("algorithm", "RS256"),
        ("verification_method_id", DID + "#other"),
        ("signature_raw_b64", ""),
        ("issuer_profile_id", "synthetic-private-selector"),
    ):
        variants.append(("invalid-" + key, json.dumps({**valid, key: value}).encode()))
    for name, body in variants:
        cases.append(
            {
                "name": "redirect-302-" + name,
                "status": 302,
                "body_hex": body.hex(),
                "content_type": "application/json",
            }
        )
    cases.append(
        {
            "name": "not-modified-empty",
            "status": 304,
            "body_hex": "",
            "content_type": "application/json",
        }
    )
    for mode in ("required", "optional"):
        payload = {
            **valid,
            "issuer_profile": {
                "id": "synthetic-profile",
                "key_attestation_policy": {
                    "mode": mode,
                    "required_key_storage": ["hardware"],
                    "required_user_authentication": ["pin"],
                },
            },
            "public_jwk": {
                "kid": DID + "#key",
                "kty": "RSA",
                "alg": "RS256",
                "n": "AQAB",
                "e": "AQAB",
            },
        }
        cases.append(
            {
                "name": "redirect-302-profile-" + mode,
                "status": 302,
                "body_hex": json.dumps(payload).encode().hex(),
                "content_type": "application/json",
            }
        )
    return cases


async def capture(checkout: Path) -> dict:
    sources, identities = source_objects(checkout)
    signing, lti, policy, readiness = caller_modules(sources)
    modules = {}
    for name in ("issuance", "issuance.infrastructure", "issuance.infrastructure.api"):
        modules[name] = ModuleType(name)
        modules[name].__path__ = []
    modules[signing.__name__] = signing
    client_type = httpx.AsyncClient
    details, redirects = detail_inputs(), redirect_inputs()
    with (
        patch.dict(os.environ, ENVIRONMENT, clear=True),
        patch.dict(sys.modules, modules),
        patch.object(
            socket.socket,
            "connect",
            side_effect=AssertionError("network forbidden in reference capture"),
        ),
    ):
        detail_results = [detail_observation(signing, case) for case in details]
        remote_results = [
            await remote_observation(signing, case, name, client_type)
            for case in details + redirects
            for name in ("context", "resolve", "sign")
        ]
        outward_results = [
            await outward_observation(
                signing, lti, policy, readiness, case, caller, client_type
            )
            for case in details
            for caller in ("lti-resolve", "lti-sign", "proof-policy", "readiness")
        ]
        outward_results += [
            await outward_observation(
                signing, lti, policy, readiness, case, caller, client_type
            )
            for case in redirects
            for caller in ("lti-resolve", "proof-policy")
        ]
        outward_http_responses = [
            await outward_observation(
                signing,
                lti,
                policy,
                readiness,
                case,
                caller,
                client_type,
                raise_app_exceptions=False,
            )
            for case in details + redirects
            if case["name"]
            in {
                "selected-surrogate",
                "json-valid-text-codec-fails",
                "redirect-302-malformed",
            }
            for caller in (
                ("lti-resolve", "proof-policy")
                if case["name"].startswith("redirect-")
                else ("lti-resolve", "lti-sign", "proof-policy")
            )
        ]
    return {
        "schema": "marty.signing-response-python-reference/v1",
        "reference": {
            "repository": "ElevenID/marty-credentials",
            "commit": REVISION,
            "sources": identities,
            "python": platform.python_version(),
            "python_recursion_limit": sys.getrecursionlimit(),
            "dependencies": {
                name: importlib.metadata.version(name)
                for name in ("httpx", "fastapi", "starlette", "pydantic")
            },
            "scope": "Unchanged pinned signing module and exact AST-selected actual callers; controlled configuration/HTTPX MockTransport. Controlled FastAPI wrapper uses real default exception serialization; not deployed routing, sockets, crypto, database or production-adapter qualification.",
            "environment": "Cleared capture environment; nonempty synthetic URL and both direct service API keys; no operator secret-file fallback.",
            "selected_callers": [
                "IssuerDidToolJwtSigner._resolved_identity",
                "IssuerDidToolJwtSigner.sign_jwt",
                "_oid4vci_proof_types_for_org",
                "run_canvas_kms_did_challenge",
            ],
        },
        "inputs": details + redirects,
        "details": detail_results,
        "remote_operations": remote_results,
        "outward_callers": outward_results,
        "outward_http_responses": outward_http_responses,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("credentials_checkout", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    result = asyncio.run(capture(args.credentials_checkout.resolve(strict=True)))
    if args.check:
        path = (
            Path(__file__).resolve().parents[1]
            / "contracts/signing-response-python-reference.json"
        )
        assert result == json.loads(path.read_text(encoding="utf-8")), (
            "Signing reference drifted"
        )
    if args.summary:
        result = {
            "inputs": len(result["inputs"]),
            "details": len(result["details"]),
            "remote_operations": len(result["remote_operations"]),
            "outward_callers": len(result["outward_callers"]),
            "outward_http_responses": len(result["outward_http_responses"]),
            "check": args.check,
        }
    print(json.dumps(result, ensure_ascii=True, allow_nan=False, indent=2))


if __name__ == "__main__":
    main()
