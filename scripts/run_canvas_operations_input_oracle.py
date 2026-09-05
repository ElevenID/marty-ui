"""Published ASGI request validation, with an empty in-memory repository.

This supplements the real PostgreSQL baseline; it does not qualify persistence.
All calls are in-process using a synthetic key and no external services.
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path

import httpx
import pydantic
from fastapi import FastAPI


async def observe():
    os.environ["ISSUANCE_API_KEY"] = "synthetic-operations-key"
    from issuance.domain.ports import IIssuanceRepository
    from issuance.infrastructure.adapters.memory_repository import (
        InMemoryIssuanceRepository,
    )
    from issuance.infrastructure.api import canvas_operations_routes as operations

    cases = json.loads(
        Path(
            "/verification/contracts/canvas-operations-input-scenarios.json"
        ).read_text()
    )["cases"]
    app = FastAPI()
    app.include_router(operations.canvas_operations_router)
    repo = InMemoryIssuanceRepository()
    app.dependency_overrides[IIssuanceRepository] = lambda: repo
    observations = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://synthetic.invalid"
    ) as client:
        for case in cases:
            headers = {
                "X-API-Key": "synthetic-operations-key",
                "X-Organization-ID": "org-review",
            }
            headers.update(case.get("headers", {}))
            for name in case.get("omit_headers", []):
                headers.pop(name)
            response = await client.get(case["path"], headers=headers)
            observations.append(
                {
                    "name": case["name"],
                    "status": response.status_code,
                    "body": response.json(),
                }
            )
    return {
        "boundary": "published ASGI/auth/input validation; empty memory repository, not persistence",
        "pydantic_version": pydantic.__version__,
        "operations_sha256": hashlib.sha256(
            Path(operations.__file__).read_text(encoding="utf-8").encode()
        ).hexdigest(),
        "observations": observations,
    }


def run():
    return asyncio.run(asyncio.wait_for(observe(), timeout=30))


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
