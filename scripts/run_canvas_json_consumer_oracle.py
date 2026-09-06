"""Published JSON consumer boundaries; not native parser qualification.

Actual app, provider, authenticated credential routes and PostgreSQL execute
before JSON-safe observation encoding. The input file and synthetic ports are
fixed by the disposable pinned-image fixture, never deployment configuration.
"""

import asyncio
import json
from pathlib import Path

from canvas_observation_values import encode_observation
import run_canvas_status_provider_oracle as provider
import run_canvas_validation_boundary_oracle as validation


async def observe():
    cases = json.loads(
        Path("/verification/contracts/canvas-json-consumer-scenarios.json").read_text()
    )
    result = {
        "schema": "marty.canvas-json-consumers/v1",
        "normalization": "post-observation codepoint/non-finite/object-entry markers; reserved marker keys are escaped as object entries; application values unchanged",
        "validation": await validation.observe(
            cases["validation"], capture_diagnostics=True
        ),
        "provider": await provider.observe(
            cases["provider"], delivery_lifecycle=True, credential_routes=True
        ),
    }
    encoded = encode_observation(result)
    json.dumps(encoded, allow_nan=False)
    return encoded


def run():
    return asyncio.run(asyncio.wait_for(observe(), timeout=120))
