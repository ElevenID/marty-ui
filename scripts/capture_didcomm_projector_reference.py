"""Capture unchanged Credentials HTTP/gRPC projectors, not admission or transport.

Run with Python 3.12, the reference service dependencies, and marty-rs 0.1.60:
  python scripts/capture_didcomm_projector_reference.py <credentials-checkout>
The only substituted projector dependency is the synthetic delivery callback.
Idempotency observations execute source-extracted guard statements in isolation.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import importlib.metadata
import json
import logging
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch


SOURCE_COMMIT = "87eae30788924921a42848425d315e2f33f7ae41"
HTTP = "services/issuance/infrastructure/api/routes.py"
GRPC = "services/issuance/infrastructure/adapters/grpc_adapter.py"
SOURCES = {
    HTTP: "6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a",
    GRPC: "1fdd58e8e5f57954a8a48f6a6726354914d7be8d",
    "services/issuance/application/rust_integration.py": "d04c283c279fc9f6d020d25627bad990a49100ee",
    "services/issuance/domain/entities.py": "1b5e2eba90c1ec13c1a38135f4da92813f1d1073",
    "contracts/issuance-initiation.json": "27fca8ce6f8be71042c0f1e518817cc8302b6e43",
}
GUARD_DETAIL = "idempotent initiation does not support DIDComm push delivery"
CASES = [
    ("explicit-holder", "pending", "did:example:holder", None, False, False),
    ("subject-fallback", "pending", None, "did:example:subject", False, False),
    ("missing-holder", "pending", None, None, False, False),
    ("delivery-failure", "pending", "did:example:holder", None, True, False),
    ("mixed-wallets", "pending", "did:example:holder", None, False, True),
    ("recovered-pending-snapshot", "pending", "did:example:holder", None, False, False),
    ("recovered-issued-snapshot", "issued", "did:example:holder", None, False, False),
    ("recovered-failed-snapshot", "failed", "did:example:holder", None, True, False),
]


def git_blob(data: bytes) -> str:
    data = data.replace(b"\r\n", b"\n")
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def verify_sources(root: Path, sources: dict[str, str] | None = None) -> None:
    for relative, expected in (SOURCES if sources is None else sources).items():
        if git_blob((root / relative).read_bytes()) != expected:
            raise ValueError(f"Reference source blob differs: {relative}")


def isolated_guard(source: str, function_name: str):
    """Compile the original unique rejection If, without running admission peers."""
    tree = ast.parse(source)
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == function_name
    ]
    if len(functions) != 1:
        raise ValueError("Reference admission function is not unique")
    guards = [
        node
        for node in ast.walk(functions[0])
        if isinstance(node, ast.If)
        and any(
            isinstance(part, ast.Constant) and part.value == GUARD_DETAIL
            for statement in node.body
            for part in ast.walk(statement)
        )
    ]
    # Parent Ifs may contain the same message in a nested guard. Select its
    # immediate statement owner, never a larger admission/control-plane block.
    guards = [
        node
        for node in guards
        if not any(
            isinstance(child, ast.If)
            and child is not node
            and any(
                isinstance(part, ast.Constant) and part.value == GUARD_DETAIL
                for part in ast.walk(child)
            )
            for statement in node.body
            for child in ast.walk(statement)
        )
    ]
    if len(guards) != 1:
        raise ValueError("Reference DIDComm idempotency guard is not unique")
    wrapper = ast.parse("def observed_guard():\n    pass\n")
    wrapper.body[0].body = [guards[0]]
    ast.fix_missing_locations(wrapper)
    return compile(wrapper, "<source-hashed-idempotency-guard>", "exec")


def capture(root: Path) -> dict:
    root = root.resolve(strict=True)
    verify_sources(root)
    for package in ("services", "python", "packages"):
        sys.path.insert(0, str(root / package))

    from datetime import UTC, datetime
    from fastapi import HTTPException
    from google.protobuf.json_format import MessageToDict
    import grpc
    from issuance.domain.entities import IssuanceStatus, IssuanceTransaction
    from issuance.infrastructure.api import routes
    from issuance.infrastructure.adapters import grpc_adapter

    for module, relative in ((routes, HTTP), (grpc_adapter, GRPC)):
        if Path(module.__file__).resolve() != root / relative:
            raise ValueError("Imported reference is from a different checkout")
    if importlib.metadata.version("marty-rs") != "0.1.60":
        raise ValueError("Capture requires the observed marty-rs 0.1.60 binding")

    def transaction(state: str, mixed: bool):
        wallets = [
            {
                "wallet_id": "didcomm",
                "format_variant": "didcomm_v2",
                "display_name": "Synthetic Wallet",
            }
        ]
        if mixed:
            wallets.extend(
                [
                    {
                        "wallet_id": "default",
                        "format_variant": "w3c_vcdm_v2_sd_jwt",
                        "display_name": "Default Wallet",
                    },
                    {
                        "wallet_id": "manager",
                        "format_variant": "credential-manager",
                        "deep_link_scheme": "custom://open?existing=yes",
                        "display_name": "Manager",
                    },
                    {
                        "wallet_id": "apple",
                        "format_variant": "apple-wallet",
                        "display_name": "Apple",
                    },
                ]
            )
        return IssuanceTransaction(
            id="synthetic-tx",
            organization_id="synthetic-org",
            credential_template_id="synthetic-template",
            status=IssuanceStatus(state),
            claims={},
            credential_type="EmployeeCredential",
            wallet_configs=wallets,
            pre_auth_code="synthetic-pre-auth-code",
            created_at=datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC),
            expires_at=datetime(2023, 11, 14, 23, 13, 20, tzinfo=UTC),
        )

    async def projectors():
        observations = []
        for name, state, holder, subject, fail, mixed in CASES:
            calls = []

            async def delivered(**kwargs):
                tx = kwargs["tx"]
                calls.append(
                    {
                        "transaction_id": tx.id,
                        "holder_did": kwargs["holder_did"],
                        "status_before": tx.status.value,
                    }
                )
                if fail:
                    raise RuntimeError("synthetic controlled delivery failure")
                if tx.status in (IssuanceStatus.PENDING, IssuanceStatus.AUTHORIZED):
                    tx.status = IssuanceStatus.ISSUED
                return SimpleNamespace(service_endpoint="https://wallet.example/inbox")

            delivery = AsyncMock(side_effect=delivered)
            request = routes.InitiateIssuanceRequest(
                organization_id="synthetic-org",
                credential_template_id="synthetic-template",
                issuer_did="did:example:issuer",
                holder_did=holder,
                subject_did=subject,
                claims={},
            )
            with (
                patch.object(routes, "ISSUER_BASE_URL", "https://issuer.example"),
                patch.object(grpc_adapter, "ISSUER_BASE_URL", "https://issuer.example"),
                patch.object(routes, "_didcomm_sign_and_deliver", delivery),
            ):
                http = await routes._issuance_response_from_transaction(
                    tx=transaction(state, mixed),
                    request=request,
                    repo=SimpleNamespace(),
                )
                http_calls = list(calls)
                calls.clear()
                before_grpc_calls = delivery.call_count
                grpc_response = grpc_adapter.IssuanceServiceGrpc._issuance_response_from_transaction(
                    transaction(state, mixed),
                )
                grpc_calls = delivery.call_count - before_grpc_calls
            observations.append(
                {
                    "case": name,
                    "input": {
                        "transaction_status": state,
                        "holder_did": holder,
                        "subject_did": subject,
                        "delivery_fails": fail,
                        "mixed_wallets": mixed,
                        "snapshot_only": name.startswith("recovered-"),
                    },
                    "http": {
                        "response": http.model_dump(mode="json"),
                        "delivery_calls": http_calls,
                    },
                    "grpc": {
                        "response": MessageToDict(
                            grpc_response, preserving_proto_field_name=True
                        ),
                        "delivery_call_count": grpc_calls,
                    },
                }
            )
        return observations

    guards = {
        "http": isolated_guard(
            (root / HTTP).read_text(encoding="utf-8"), "initiate_issuance"
        ),
        "grpc": isolated_guard(
            (root / GRPC).read_text(encoding="utf-8"), "InitiateIssuance"
        ),
    }
    guard_observations = []
    for name, key, wallets in [
        ("didcomm-with-key", "synthetic-key", [{"format_variant": "didcomm_v2"}]),
        (
            "mixed-with-key",
            "synthetic-key",
            [{"format_variant": "default"}, {"format_variant": "didcomm_v2"}],
        ),
        ("ordinary-with-key", "synthetic-key", [{"format_variant": "default"}]),
        ("didcomm-without-key", None, [{"format_variant": "didcomm_v2"}]),
    ]:
        result = {}
        for kind, code in guards.items():
            context = SimpleNamespace(code=None, detail=None)
            context.set_code = lambda value: setattr(context, "code", value.name)
            context.set_details = lambda value: setattr(context, "detail", value)
            environment = {
                "normalized_idempotency_key": key,
                "idempotency_key": key,
                "wallet_configs": wallets,
                "HTTPException": HTTPException,
                "context": context,
                "grpc": grpc,
                "pb2": grpc_adapter.pb2,
            }
            exec(code, environment)
            try:
                response = environment["observed_guard"]()
            except HTTPException as error:
                result[kind] = {
                    "rejected": True,
                    "status": error.status_code,
                    "body": {"detail": error.detail},
                }
            else:
                result[kind] = (
                    {
                        "rejected": True,
                        "status": context.code,
                        "detail": context.detail,
                        "response": MessageToDict(
                            response, preserving_proto_field_name=True
                        ),
                    }
                    if context.code
                    else {"rejected": False, "scope": "guard-fallthrough-only"}
                )
        guard_observations.append(
            {"case": name, "key": key, "wallets": wallets, **result}
        )
    governed = json.loads(
        (root / "contracts/issuance-initiation.json").read_text(encoding="utf-8")
    )
    return {
        "schema": "marty.didcomm-projector-python-reference/v1",
        "reference": {
            "repository": "ElevenID/marty-credentials",
            "source_commit": SOURCE_COMMIT,
            "source_blobs": SOURCES,
            "native_offer_binding": "marty-rs 0.1.60",
            "capture_command": "python scripts/capture_didcomm_projector_reference.py <credentials-checkout>",
            "scope": "Actual unchanged Python projectors and native offer construction. Fixed issuer URL, transaction snapshot and controlled delivery callback; no database, crypto delivery, admission, gateway projection, or KMS qualification. Full service DTOs retain pre_auth_code; public gateway redaction is separate. Recovered cases are snapshot inputs, not executed repository recovery.",
            "idempotency_scope": "Original source-hashed If nodes executed in isolation; no admission/control-plane execution. Fallthrough is not proof of successful initiation.",
            "governed_didcomm_target": governed["response"]["didcomm"],
        },
        "projector_cases": asyncio.run(projectors()),
        "idempotency_guard_cases": guard_observations,
    }


def verify_observations(observed: dict, frozen: dict) -> None:
    if observed != frozen:
        raise ValueError("Exact reference observations differ from the frozen corpus")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("credentials_checkout", type=Path)
    parser.add_argument(
        "--check", action="store_true", help="Replay and compare the checked-in corpus"
    )
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    observed = capture(args.credentials_checkout)
    if args.check:
        corpus_path = (
            Path(__file__).resolve().parents[1]
            / "contracts/didcomm-projector-python-reference.json"
        )
        verify_observations(
            observed, json.loads(corpus_path.read_text(encoding="utf-8"))
        )
        print(
            "Exact unchanged Python replay matched: 8 projector pairs and 4 isolated guards"
        )
    else:
        print(json.dumps(observed, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
