"""Published JSON consumer boundaries; not native parser qualification.

Actual app, provider, authenticated credential routes and PostgreSQL execute
before JSON-safe observation encoding. The input file and synthetic ports are
fixed by the disposable pinned-image fixture, never deployment configuration.
"""

import asyncio
import json
from pathlib import Path
from time import monotonic_ns

import run_canvas_status_provider_oracle as provider
import run_canvas_validation_boundary_oracle as validation
from canvas_observation_values import encode_observation

DEFAULT_TIMEOUT_SECONDS = 120
# Test-only diagnostics. The returned frozen oracle value never includes these.
CASE_TIMINGS = []


def timed_cases(phase, cases):
    for case in cases:
        started = monotonic_ns()
        yield case
        CASE_TIMINGS.append(
            {
                "name": f"json_consumer.{phase}.{case['name']}",
                "duration_ms": (monotonic_ns() - started) // 1_000_000,
            }
        )


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
        timed_cases("validation", cases["validation"]), capture_diagnostics=True
    )
    phase["name"] = "provider"
    provider_result = await provider.observe(
        timed_cases("provider", cases["provider"]),
        delivery_lifecycle=True,
        credential_routes=True,
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
    CASE_TIMINGS.clear()
    oracle = asyncio.run(observe_with_deadline(DEFAULT_TIMEOUT_SECONDS))
    # The preparer is a pinned historical input. Keep it unchanged and carry
    # diagnostics beside the oracle; Rust unwraps the latter for comparison.
    return {"oracle": oracle, "ci_case_timing": CASE_TIMINGS}
