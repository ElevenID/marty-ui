"""Measure published depth boundaries without changing application stack limits."""

import asyncio
import json
from pathlib import Path
import sys
from time import monotonic_ns

from canvas_json_tree_observation import observe_tree
from canvas_observation_values import encode_observation
import run_canvas_status_provider_oracle as provider
import run_canvas_validation_boundary_oracle as validation


# Test-only elapsed diagnostics; the frozen observation never contains them.
PHASE_TIMINGS = []


async def timed_phase(name, observation):
    started = monotonic_ns()
    result = await observation
    PHASE_TIMINGS.append(
        {
            "name": f"json_depth.{name}",
            "duration_ms": (monotonic_ns() - started) // 1_000_000,
        }
    )
    return result


def scenarios(spec):
    assert spec["schema"] == "marty.canvas-json-depth-scenarios/v1"
    assert spec["leaf_json"] == "0"
    assert spec["shapes"] == ["array", "object"]
    assert spec["statuses"] == [200, 403]
    validation_cases, provider_cases = [], []
    for shape in spec["shapes"]:
        opening, closing = ("[", "]") if shape == "array" else ('{"nested":', "}")
        for depth in spec["depths"]:
            assert isinstance(depth, int) and 1 <= depth <= 1600
            body = (opening * depth + spec["leaf_json"] + closing * depth).encode(
                "ascii"
            )
            for status in spec["statuses"]:
                common = {
                    "name": f"json_depth_{shape}_{depth}_{status}",
                    "response_status": status,
                    "response_content_type": "application/json; charset=latin1",
                    "response_hex": body.hex(),
                }
                validation_cases.append(
                    {**common, "provider": "badgr_api", "direct": "synthetic-direct"}
                )
                provider_cases.append(
                    {**common, "provider": "bridge", "action": "suspend"}
                )
    return validation_cases, provider_cases


async def observe():
    setup_started = monotonic_ns()
    spec = json.loads(
        Path("/verification/contracts/canvas-json-depth-scenarios.json").read_text()
    )
    validation_cases, provider_cases = scenarios(spec)
    recursion_limit = sys.getrecursionlimit()
    PHASE_TIMINGS.append(
        {
            "name": "json_depth.setup",
            "duration_ms": (monotonic_ns() - setup_started) // 1_000_000,
        }
    )
    result = {
        "schema": "marty.canvas-json-depth/v1",
        "python_version": sys.version.split()[0],
        "recursion_limit": recursion_limit,
        "normalization": "selected response trees use nonrecursive typed SHA256 witnesses after execution; complete validation wire bodies and full route rows retained",
        "validation": await timed_phase(
            "validation",
            validation.observe(
                validation_cases,
                capture_diagnostics=True,
                response_projection=observe_tree,
            ),
        ),
        "provider": await timed_phase(
            "provider",
            provider.observe(
                provider_cases,
                delivery_lifecycle=True,
                credential_routes=True,
                capture_diagnostics=True,
                response_projection=observe_tree,
            ),
        ),
    }
    assert sys.getrecursionlimit() == recursion_limit
    encoding_started = monotonic_ns()
    encoded = encode_observation(result)
    PHASE_TIMINGS.append(
        {
            "name": "json_depth.encoding",
            "duration_ms": (monotonic_ns() - encoding_started) // 1_000_000,
        }
    )
    return encoded


def run():
    PHASE_TIMINGS.clear()
    oracle = asyncio.run(asyncio.wait_for(observe(), timeout=180))
    return {"oracle": oracle, "ci_phase_timing": PHASE_TIMINGS}
