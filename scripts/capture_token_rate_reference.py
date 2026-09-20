"""Replay pinned Python token configuration, limiter and default HTTP boundary.

Only exact AST-selected source executes. Git objects, synthetic environment,
controlled monotonic clock and in-process ASGI transport are used; no deployment,
database, native crypto, ambient configuration or network service is accessed.
This script prints observations or compares a frozen artifact; it writes nothing.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import contextvars
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import sys
from types import SimpleNamespace
import uuid

REVISION = "ddd6b4e4383fe1000e3255f3e4237dc5b6020a2a"
SOURCES = {
    "services/issuance/infrastructure/api/routes.py": "6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a",
    "services/issuance/main.py": "8fb1add009b1bdf400a0a8e1308eeb92d13d664f",
}
ARTIFACT = "contracts/token-rate-python-reference.json"
DEFAULT_TIMES = [100.0, 100.0, 100.0]


def cases() -> list[dict]:
    result = []

    def add(name, limit=None, window=None, times=None):
        result.append(
            {
                "case": name,
                "limit": limit,
                "window": window,
                "times": [value.hex() for value in (times or DEFAULT_TIMES)],
                "time_bits": [
                    struct.pack(">d", value).hex() for value in (times or DEFAULT_TIMES)
                ],
            }
        )

    add("defaults")
    for name, value in [
        ("zero", "0"),
        ("negative", "-1"),
        ("negative-zero", "-0"),
        ("plus", "+2"),
        ("separator", "1_0"),
        ("ascii-whitespace", " \t2\n"),
        ("unicode-whitespace", "\u00a02\u3000"),
        ("unicode-digits", "\u0662"),
        ("mixed-digits", "1\u0662"),
        ("above-u64", "18446744073709551616"),
        ("maximum-digits", "9" * 4300),
        ("above-maximum-digits", "9" * 4301),
        ("double-separator", "1__0"),
        ("superscript", "\u00b2"),
        ("sign-whitespace", "+ 2"),
        ("internal-whitespace", "1 0"),
        ("nondecimal", "0x10"),
        ("empty", ""),
        ("float", "2.0"),
        ("malformed-canary", "synthetic-rate-config-private-canary"),
    ]:
        add(f"limit-{name}", value, "60")
    for name, value in [
        ("zero", "0"),
        ("negative", "-1"),
        ("positive", "2"),
        ("separator", "6_0"),
        ("unicode", "\u00a0\u0666\u0660\u3000"),
        ("above-u64", "18446744073709551616"),
        ("float-overflow", "9" * 400),
        ("negative-float-overflow", "-" + "9" * 400),
        ("maximum-digits", "9" * 4300),
        ("above-maximum-digits", "9" * 4301),
        ("malformed", "synthetic-window-config-private-canary"),
    ]:
        add(f"window-{name}", "2", value)
    add("negative-limit-negative-window", "-1", "-1")
    add("zero-limit-negative-window", "0", "-1")
    add("zero-limit-huge-window-header", "0", "18446744073709551616")
    add("overflow-before-zero-limit", "0", "9" * 400)
    add("overflow-before-negative-limit", "-1", "9" * 400)
    add("boundary", "2", "60", [100.0, 101.0, 159.999, 160.0, 161.0])
    add("rounded-large-clock", "1", "1", [float(2**53), float(2**53), float(2**53 + 2)])
    add(
        "rounded-window", "1", "9007199254740993", [0.0, float(2**53), float(2**53 + 2)]
    )
    return result


def sources(checkout: Path) -> tuple[dict, dict]:
    texts, identities = {}, {}
    for path, expected in SOURCES.items():
        result = subprocess.run(
            ["git", "-C", str(checkout), "show", f"{REVISION}:{path}"],
            capture_output=True,
            check=True,
            timeout=30,
        )
        data = result.stdout
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("Reference source exceeds its byte limit")
        blob = hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data,
            usedforsecurity=False,
        ).hexdigest()
        if blob != expected:
            raise ValueError("Pinned source identity differs")
        texts[path] = data.decode("utf-8")
        identities[path] = {
            "git_blob": blob,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return texts, identities


def selected(source: str, path: str, names: set[str], namespace: dict) -> None:
    nodes, found = [], []
    for node in ast.parse(source, filename=path).body:
        name = getattr(node, "name", None)
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = getattr(node.targets[0], "id", None)
        if name in names:
            nodes.append(node)
            found.append(name)
    if set(found) != names or len(found) != len(names):
        raise ValueError("Exact source selection differs")
    future = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    module = ast.fix_missing_locations(
        ast.Module(body=[future, *nodes], type_ignores=[])
    )
    exec(compile(module, path, "exec"), namespace)


def configured(texts: dict, case: dict) -> dict:
    from fastapi import HTTPException, Request, Response

    environment = {}
    for key, field in [("TOKEN_RATE_LIMIT", "limit"), ("TOKEN_RATE_WINDOW", "window")]:
        if case[field] is not None:
            environment[key] = case[field]
    clock = SimpleNamespace(value=0.0)
    namespace = {
        "os": SimpleNamespace(environ=environment),
        "asyncio": asyncio,
        "time": SimpleNamespace(monotonic=lambda: clock.value),
        "clock": clock,
        "HTTPException": HTTPException,
        "Request": Request,
        "Response": Response,
    }
    path = next(iter(SOURCES))
    selected(
        texts[path],
        path,
        {
            "_TOKEN_RATE_LIMIT",
            "_TOKEN_RATE_WINDOW",
            "_InMemoryRateLimiter",
            "_token_limiter",
            "_enforce_token_rate_limit",
        },
        namespace,
    )
    return namespace


async def observe(texts: dict, case: dict) -> dict:
    import httpx
    from fastapi import Depends, FastAPI, HTTPException
    from starlette.middleware.base import BaseHTTPMiddleware

    result = dict(case)
    try:
        direct = configured(texts, case)
    except ValueError as error:
        # Classify startup errors without serializing private input or traceback.
        result.update(phase="configuration", error_type=type(error).__name__)
        return result
    result.update(
        phase="requests",
        parsed_limit=str(direct["_TOKEN_RATE_LIMIT"]),
        parsed_window=str(direct["_TOKEN_RATE_WINDOW"]),
        direct=[],
        stored_state=[],
        http=[],
    )
    for now in case["times"]:
        direct["clock"].value = float.fromhex(now)
        try:
            await direct["_token_limiter"].check("token:synthetic-client")
        except HTTPException as error:
            result["direct"].append(
                {
                    "status": error.status_code,
                    "body": {"detail": error.detail},
                    "headers": error.headers,
                }
            )
        except OverflowError as error:
            result["direct"].append({"error_type": type(error).__name__})
        else:
            result["direct"].append({"allowed": True})
        hits = direct["_token_limiter"]._hits
        result["stored_state"].append(
            {
                "clients": len(hits),
                "timestamp_bits": [
                    struct.pack(">d", value).hex()
                    for value in hits.get("token:synthetic-client", [])
                ],
            }
        )

    live = configured(texts, case)
    main_path = list(SOURCES)[1]
    middleware = {
        "BaseHTTPMiddleware": BaseHTTPMiddleware,
        "uuid": uuid,
        "request_id_var": contextvars.ContextVar("synthetic-rate-request-id"),
    }
    selected(texts[main_path], main_path, {"RequestIdMiddleware"}, middleware)
    app = FastAPI()
    app.add_middleware(middleware["RequestIdMiddleware"])
    calls = 0

    @app.post(
        "/synthetic-token-boundary",
        dependencies=[Depends(live["_enforce_token_rate_limit"])],
    )
    async def endpoint():
        nonlocal calls
        calls += 1
        return {"accepted": True}

    transport = httpx.ASGITransport(
        app=app, raise_app_exceptions=False, client=("synthetic-client", 1234)
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://synthetic.invalid"
    ) as client:
        for now in case["times"]:
            live["clock"].value = float.fromhex(now)
            response = await client.post(
                "/synthetic-token-boundary",
                headers={"X-Request-ID": "synthetic-request"},
            )
            media_type = response.headers["content-type"]
            result["http"].append(
                {
                    "status": response.status_code,
                    "body": response.json()
                    if media_type.startswith("application/json")
                    else response.text,
                    "headers": {
                        name: response.headers[name]
                        for name in ["content-type", "retry-after", "x-request-id"]
                        if name in response.headers
                    },
                    "downstream_calls": calls,
                }
            )
    return result


async def capture(checkout: Path) -> dict:
    if sys.get_int_max_str_digits() != 4300:
        raise ValueError("Reference runtime requires the 4300-digit policy")
    texts, identities = sources(checkout)
    observations = [await observe(texts, case) for case in cases()]
    # Execute the selected CPython runtime's C conversion, not a reimplementation.
    # The fixed argument/result declarations prevent pointer or vararg ambiguity.
    convert = ctypes.pythonapi._PyTime_AsSecondsDouble
    convert.argtypes = [ctypes.c_int64]
    convert.restype = ctypes.c_double
    clock_vectors = [
        {
            "nanoseconds": str(value),
            "seconds_bits": struct.pack(">d", convert(value)).hex(),
        }
        for value in [
            0,
            1,
            -1,
            999_999_999,
            1_000_000_000,
            1_000_000_001,
            -1_000_000_000,
            -1_000_000_001,
            2**53 - 1,
            2**53,
            2**53 + 1,
            9_223_372_036_000_000_000,
            9_223_372_036_000_000_001,
            2**63 - 1,
            -(2**63),
        ]
    ]
    return {
        "schema": "marty.token-rate-python-reference/v1",
        "reference": {
            "repository": "ElevenID/marty-credentials",
            "source_commit": REVISION,
            "sources": identities,
            "integer_digit_limit": 4300,
            "scope": "Exact configuration assignments, unchanged limiter/enforcer and RequestIdMiddleware; controlled FastAPI default error stack and stand-in successful endpoint. No actual token business route, database, socket, gateway or deployed service qualification.",
        },
        "clock_vectors": clock_vectors,
        "cases": observations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("credentials_checkout", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = asyncio.run(capture(args.credentials_checkout))
    if args.check:
        expected = json.loads(
            (Path(__file__).resolve().parents[1] / ARTIFACT).read_text(encoding="utf-8")
        )
        if result != expected:
            raise ValueError("Exact token rate reference differs")
        print(f"Exact token rate reference matched: {len(result['cases'])} cases")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
