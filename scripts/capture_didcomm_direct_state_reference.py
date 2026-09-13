"""Print or verify the existing five-case direct-state Python reference.

Usage: python scripts/capture_didcomm_direct_state_reference.py <credentials-checkout> [--check]
The checkout supplies pinned Git objects, not imported application configuration.
Only route-body/exception rendering observations: no deployed HTTP, DB or crypto.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PATH = "contracts/didcomm-direct-state-python-reference.json"
SOURCE_COMMIT = "87eae30788924921a42848425d315e2f33f7ae41"
SOURCES = {
    "routes": (
        "services/issuance/infrastructure/api/routes.py",
        "6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a",
    ),
    "setup": (
        "tests/unit/test_didcomm_boundary.py",
        "f373c4d1762f916b616e4b83a38101112ec78e85",
    ),
    "entities": (
        "services/issuance/domain/entities.py",
        "1b5e2eba90c1ec13c1a38135f4da92813f1d1073",
    ),
}
STATES = ("issued", "signing", "failed", "expired", "revoked")


def validate_reference(reference):
    assert reference["schema"] == "marty.didcomm-direct-state-python-reference/v1"
    source = reference["reference"]
    assert source["repository"] == "ElevenID/marty-credentials"
    assert source["source_commit"] == SOURCE_COMMIT
    assert (source["source_path"], source["source_blob"]) == SOURCES["routes"]
    cases = reference["cases"]
    assert [case["state"] for case in cases] == list(STATES)
    for case in cases:
        assert set(case) == {
            "state",
            "status",
            "body",
            "lookup_calls",
            "delivery_calls",
        }
        state = case["state"]
        assert case["status"] == (409 if state == "issued" else 400)
        assert case["body"] == {
            "detail": "Credential already issued"
            if state == "issued"
            else f"Transaction in {state} state"
        }
        assert case["lookup_calls"] == 1 and case["delivery_calls"] == 0


def read_sources(checkout):
    result = {}
    for key, (path, expected_blob) in SOURCES.items():
        process = subprocess.run(
            ["git", "-C", str(checkout), "show", f"{SOURCE_COMMIT}:{path}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if process.returncode:
            raise ValueError("Pinned reference Git objects are unavailable")
        raw = process.stdout
        actual = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw
        ).hexdigest()
        if actual != expected_blob:
            raise ValueError("Pinned reference source identity differs")
        result[key] = raw.decode("utf-8")
    return result


def selected_definitions(source, names):
    nodes = [
        copy.deepcopy(node)
        for node in ast.parse(source).body
        if getattr(node, "name", None) in names
    ]
    assert len(nodes) == len(names) and {node.name for node in nodes} == set(names)
    for node in nodes:
        if node.name == "didcomm_deliver":
            # Registration/dependency injection is outside this direct-body
            # observation; every statement and default in the body is unchanged.
            node.decorator_list = []
    future = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    return ast.fix_missing_locations(ast.Module(body=[future, *nodes], type_ignores=[]))


def capture(checkout):
    # Dependencies are intentionally lazy: root artifact guards need no FastAPI.
    from datetime import datetime, timezone
    import hmac
    from fastapi import Depends, HTTPException
    from fastapi.exception_handlers import http_exception_handler
    from pydantic import BaseModel, ConfigDict, Field
    from starlette.requests import Request

    sources = read_sources(checkout)
    # Create the local event-loop self-pipe before blocking outbound APIs.
    # Do not replace socket.socket's type: Windows Proactor uses isinstance.
    loop = asyncio.new_event_loop()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Network use is forbidden during reference capture")

    with (
        patch.dict(
            os.environ,
            {
                "ISSUANCE_OFFER_TTL_MINUTES": "10080",
                "ISSUANCE_AUTH_SESSION_TTL_MINUTES": "60",
                "CANVAS_LTI_STATE_TTL_MINUTES": "10",
                "ISSUANCE_API_KEY": "synthetic-reference-key",
                "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-reference-signing-key",
            },
            clear=True,
        ),
        patch.object(socket.socket, "connect", forbidden),
        patch.object(socket.socket, "connect_ex", forbidden),
        patch.object(socket.socket, "sendto", forbidden),
        patch.object(socket.socket, "bind", forbidden),
        patch.object(socket, "create_connection", forbidden),
        patch.object(socket, "getaddrinfo", forbidden),
    ):
        module = ModuleType("_didcomm_state_reference_entities")
        try:
            with patch.dict(sys.modules, {module.__name__: module}):
                exec(
                    compile(sources["entities"], SOURCES["entities"][0], "exec"),
                    module.__dict__,
                )
                namespace = {
                    "__name__": "_didcomm_state_reference_route",
                    "hmac": hmac,
                    "HTTPException": HTTPException,
                    "Depends": Depends,
                    "BaseModel": BaseModel,
                    "ConfigDict": ConfigDict,
                    "Field": Field,
                    "Request": Request,
                    "SimpleNamespace": SimpleNamespace,
                    "IssuanceStatus": module.IssuanceStatus,
                }
                exec(
                    compile(
                        selected_definitions(
                            sources["routes"],
                            [
                                "_trusted_organization_id",
                                "_require_trusted_organization",
                                "DidcommDeliverRequest",
                                "DidcommDeliveryResponse",
                                "didcomm_deliver",
                            ],
                        ),
                        SOURCES["routes"][0],
                        "exec",
                    ),
                    namespace,
                )
                exec(
                    compile(
                        selected_definitions(sources["setup"], ["_request"]),
                        SOURCES["setup"][0],
                        "exec",
                    ),
                    namespace,
                )

                async def observe():
                    cases = []
                    for state in STATES:
                        tx = module.IssuanceTransaction(
                            id="transaction-1",
                            organization_id="org-a",
                            credential_template_id="template-a",
                            status=module.IssuanceStatus(state),
                            claims={},
                            pre_auth_code="synthetic-reference-code",
                            created_at=datetime(2026, 9, 12, tzinfo=timezone.utc),
                            expires_at=datetime(2026, 9, 19, tzinfo=timezone.utc),
                        )
                        repo = SimpleNamespace(
                            get_transaction=AsyncMock(return_value=tx)
                        )
                        delivery = AsyncMock(
                            side_effect=AssertionError("delivery must not run")
                        )
                        namespace["_didcomm_sign_and_deliver"] = delivery
                        request = namespace["DidcommDeliverRequest"](
                            organization_id="org-a",
                            transaction_id="transaction-1",
                            holder_did="did:example:holder",
                        )
                        http_request = namespace["_request"]("org-a")
                        try:
                            await namespace["didcomm_deliver"](
                                request, http_request, repo
                            )
                        except HTTPException as error:
                            response = await http_exception_handler(http_request, error)
                            cases.append(
                                {
                                    "state": state,
                                    "status": response.status_code,
                                    "body": json.loads(response.body),
                                    "lookup_calls": repo.get_transaction.await_count,
                                    "delivery_calls": delivery.await_count,
                                }
                            )
                        else:
                            raise AssertionError("Unexpected successful state")
                        repo.get_transaction.assert_awaited_once_with("transaction-1")
                        delivery.assert_not_awaited()
                    return cases

                return loop.run_until_complete(observe())
        finally:
            loop.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("credentials_checkout", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    reference = json.loads((ROOT / REFERENCE_PATH).read_text(encoding="utf-8"))
    validate_reference(reference)
    cases = capture(args.credentials_checkout.resolve(strict=True))
    assert cases == reference["cases"], (
        "Python observations differ from frozen reference"
    )
    if args.check:
        print(
            "PASS: five pinned direct-state observations, one lookup and zero deliveries each; no deployed-route claim"
        )
    else:
        print(json.dumps(cases, indent=2))


if __name__ == "__main__":
    main()
