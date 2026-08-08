from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from marty_proto.v1 import verification_service_pb2 as vs_pb2
from services.verification import main as verification
from services.verification.infrastructure.adapters.grpc_adapter import (
    VerificationServiceGrpc,
)


class _Context:
    def __init__(self) -> None:
        self.code = None
        self.details = ""

    def set_code(self, code) -> None:
        self.code = code

    def set_details(self, details: str) -> None:
        self.details = details


@pytest.mark.asyncio
async def test_grpc_session_store_is_awaited_and_terminal_data_is_minimized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The production image imports the service as ``verification.main`` while
    # repository tests import it through ``services.verification``.
    monkeypatch.setitem(
        sys.modules,
        "verification",
        SimpleNamespace(main=verification),
    )
    monkeypatch.setitem(sys.modules, "verification.main", verification)
    monkeypatch.setattr(verification, "INSPECTION_SYSTEM_TARGET", "")

    async def evaluate(**_kwargs):
        return {
            "result": "passed",
            "decision": "allow",
            "decision_reason": "All checks passed",
            "verified_claims": {"email": "alice@example.com"},
            "credential_results": [
                {
                    "satisfied": True,
                    "claim_results": [
                        {
                            "claim_name": "email",
                            "satisfied": True,
                            "presented_value": "alice@example.com",
                        }
                    ],
                }
            ],
        }

    monkeypatch.setattr(verification, "_evaluate_via_grpc", evaluate)
    store = verification.SessionStore()
    servicer = VerificationServiceGrpc(lambda: store)
    context = _Context()

    started = await servicer.StartVerification(
        vs_pb2.StartVerificationRequest(
            organization_id="org-1",
            presentation_policy_id="policy-1",
        ),
        context,
    )
    result = await servicer.SubmitPresentation(
        vs_pb2.SubmitPresentationRequest(
            session_id=started.session_id,
            vp_token="raw-vp-token",
        ),
        context,
    )
    stored = await store.get(started.session_id)

    assert context.code is None
    assert json.loads(result.verified_claims_json) == {
        "email": "alice@example.com"
    }
    assert stored is not None
    assert stored.verified_claims == {"email": True}
    assert "alice@example.com" not in json.dumps(stored.credential_results)
    assert stored.vp_token_sha256 == verification._sha256_text("raw-vp-token")
    assert not hasattr(stored, "vp_token")
