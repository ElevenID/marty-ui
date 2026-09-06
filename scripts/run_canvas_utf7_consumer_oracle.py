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


def encode_surrogates(value):
    if isinstance(value, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        return {"python_codepoints": [ord(c) for c in value]}
    if isinstance(value, dict):
        # The fixture's controlled keys are scalar text. Do not silently turn a
        # non-scalar object key into a different application key.
        assert all(not any(0xD800 <= ord(c) <= 0xDFFF for c in key) for key in value)
        return {key: encode_surrogates(item) for key, item in value.items()}
    if isinstance(value, list):
        return [encode_surrogates(item) for item in value]
    return value


async def observe():
    cases = json.loads(
        Path("/verification/contracts/canvas-utf7-consumer-scenarios.json").read_text()
    )
    return {
        "schema": "marty.canvas-utf7-consumers/v1",
        "normalization": "only non-scalar observation strings become python_codepoints; application values are unchanged",
        "validation": await validation.observe(cases["validation"]),
        "provider": encode_surrogates(
            await provider.observe(
                cases["provider"], delivery_lifecycle=True, credential_routes=True
            )
        ),
    }


def run():
    return asyncio.run(asyncio.wait_for(observe(), timeout=60))
