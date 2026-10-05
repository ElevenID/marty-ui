"""Published JSON consumer boundaries; not native parser qualification.

Actual app, provider, authenticated credential routes and PostgreSQL execute
before JSON-safe observation encoding. The input file and synthetic ports are
fixed by the disposable pinned-image fixture, never deployment configuration.
"""

import asyncio
import json
from pathlib import Path

import run_canvas_status_provider_oracle as provider
import run_canvas_validation_boundary_oracle as validation
from canvas_observation_values import encode_observation

DEFAULT_TIMEOUT_SECONDS = 120


class JsonConsumerValidationTimeout(TimeoutError):
    """The fixed published validation phase exhausted the overall deadline."""


class JsonConsumerProviderTimeout(TimeoutError):
    """The fixed published provider phase exhausted the overall deadline."""


class JsonConsumerSetupTimeout(TimeoutError):
    """The fixed published setup phase exhausted the overall deadline."""


async def observe(phase):
    cases = json.loads(
        Path("/verification/contracts/canvas-json-consumer-scenarios.json").read_text()
    )
    phase["name"] = "validation"
    validation_result = await validation.observe(
        cases["validation"], capture_diagnostics=True
    )
    phase["name"] = "provider"
    provider_result = await provider.observe(
        cases["provider"], delivery_lifecycle=True, credential_routes=True
    )
    result = {
        "schema": "marty.canvas-json-consumers/v1",
        "normalization": "post-observation codepoint/non-finite/object-entry markers; reserved marker keys are escaped as object entries; application values unchanged",
        "validation": validation_result,
        "provider": provider_result,
    }
    encoded = encode_observation(result)
    json.dumps(encoded, allow_nan=False)
    return encoded


async def observe_with_deadline(timeout, observation=observe):
    phase = {"name": "setup"}
    task = asyncio.create_task(observation(phase))
    try:
        return await asyncio.wait_for(task, timeout=timeout)
    except TimeoutError:
        # Only reclassify expiry of our outer deadline. An inner transport or
        # database TimeoutError retains its original class and traceback.
        if not task.cancelled():
            raise
        timeout_type = {
            "setup": JsonConsumerSetupTimeout,
            "validation": JsonConsumerValidationTimeout,
            "provider": JsonConsumerProviderTimeout,
        }[phase["name"]]
        raise timeout_type() from None


def run():
    return asyncio.run(observe_with_deadline(DEFAULT_TIMEOUT_SECONDS))
