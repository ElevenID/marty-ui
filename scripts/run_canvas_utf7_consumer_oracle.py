"""Diagnostic published UTF-7 consumers; not a native adoption gate.

Reuses the actual managed-app and status-provider fixtures. Only observation
serialization changes: non-scalar strings become explicitly marked codepoints.
No adapter, renderer, decoder or persistence behavior is substituted.
"""

import asyncio
import json
from pathlib import Path

import run_canvas_status_provider_oracle as provider
import run_canvas_validation_boundary_oracle as validation
from canvas_observation_values import encode_observation


async def observe():
    cases = json.loads(
        Path("/verification/contracts/canvas-utf7-consumer-scenarios.json").read_text()
    )
    return {
        "schema": "marty.canvas-utf7-consumers/v1",
        "normalization": "only non-scalar observation strings become python_codepoints; application values are unchanged",
        "validation": await validation.observe(cases["validation"]),
        "provider": encode_observation(
            await provider.observe(
                cases["provider"], delivery_lifecycle=True, credential_routes=True
            )
        ),
    }


def run():
    return asyncio.run(asyncio.wait_for(observe(), timeout=60))
