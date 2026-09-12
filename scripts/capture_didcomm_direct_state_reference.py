"""Print five direct-route state observations from the unchanged Python reference.

Run with the reference service's test dependencies installed:
  python scripts/capture_didcomm_direct_state_reference.py <credentials-checkout>
Only synthetic requests and controlled repository/delivery ports are used.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch


def main() -> None:
    root = Path(sys.argv[1]).resolve(strict=True)
    source = root / "services/issuance/infrastructure/api/routes.py"
    # Git hashes normalized repository bytes; Windows checkouts may use CRLF.
    data = source.read_bytes().replace(b"\r\n", b"\n")
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    assert blob == "6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a", blob
    for package in ("services", "python", "packages"):
        sys.path.insert(0, str(root / package))

    from fastapi import HTTPException
    from issuance.domain.entities import IssuanceStatus, IssuanceTransaction
    from issuance.infrastructure.api import routes
    from starlette.requests import Request

    assert Path(routes.__file__).resolve() == source

    async def capture() -> list[dict]:
        cases = []
        for state in ("issued", "signing", "failed", "expired", "revoked"):
            tx = IssuanceTransaction(
                id="transaction-1",
                organization_id="org-a",
                credential_template_id="template-a",
                status=IssuanceStatus(state),
                claims={},
            )
            repo = SimpleNamespace(get_transaction=AsyncMock(return_value=tx))
            delivery = AsyncMock(side_effect=AssertionError("delivery must not run"))
            request = routes.DidcommDeliverRequest(
                organization_id="org-a",
                transaction_id="transaction-1",
                holder_did="did:example:holder",
            )
            http_request = Request(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/v1/issuance/didcomm/deliver",
                    "headers": [(b"x-organization-id", b"org-a")],
                    "app": SimpleNamespace(state=SimpleNamespace()),
                }
            )
            with patch.object(routes, "_didcomm_sign_and_deliver", delivery):
                try:
                    await routes.didcomm_deliver(request, http_request, repo)
                except HTTPException as error:
                    cases.append(
                        {
                            "state": state,
                            "status": error.status_code,
                            "body": {"detail": error.detail},
                            "lookup_calls": repo.get_transaction.await_count,
                            "delivery_calls": delivery.await_count,
                        }
                    )
                else:
                    raise AssertionError(f"unexpected successful state: {state}")
            repo.get_transaction.assert_awaited_once_with("transaction-1")
            delivery.assert_not_awaited()
        return cases

    print(json.dumps(asyncio.run(capture()), indent=2))


if __name__ == "__main__":
    main()
