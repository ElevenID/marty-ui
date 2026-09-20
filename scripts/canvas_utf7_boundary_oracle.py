"""Observe UTF-7 text and JSON rendering without discarding Python surrogates."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import httpx
from starlette.responses import JSONResponse
from run_canvas_timeout_consumer_oracle import RESPONSE_SOURCE_SHA256, response_owner


def neutral(value):
    if isinstance(value, str):
        return {"python_codepoints": [ord(character) for character in value]}
    if isinstance(value, dict):
        return {key: neutral(item) for key, item in value.items()}
    if isinstance(value, list):
        return [neutral(item) for item in value]
    return value


def observe():
    spec = importlib.util.find_spec(
        "issuance.infrastructure.adapters.canvas_credentials_adapter"
    )
    source = Path(spec.origin).read_text(encoding="utf-8").replace("\r\n", "\n")
    assert hashlib.sha256(source.encode()).hexdigest() == RESPONSE_SOURCE_SHA256
    published_excerpt = response_owner(source)
    cases = []
    units = (
        [],
        [0],
        [0x41],
        [0xFFFF],
        [0xD800],
        [0xDBFF],
        [0xDC00],
        [0xDFFF],
        [0xD800, 0xDC00],
        [0xDBFF, 0xDFFF],
        [0xD800, 0x41],
        [0xDC00, 0xD800],
        [0xD800, 0xD800, 0xDC00],
    )
    for values in units:
        data = b"".join(value.to_bytes(2, "big") for value in values)
        encoded = b"+" + base64.b64encode(data).rstrip(b"=") + b"-"
        for prefix, suffix in ((b"", b""), (b"A", b"B"), (b"x" * 1000, b"")):
            payload = prefix + encoded + suffix
            response = httpx.Response(
                403,
                content=payload,
                headers={"content-type": "text/plain; charset=utf-7"},
            )
            text = response.text
            # Exact published helper; rendering is recorded separately and is
            # not a claim about the full managed-app middleware boundary.
            excerpt = published_excerpt(response)
            try:
                rendered = JSONResponse(excerpt).body.decode("utf-8")
                rendering = {"body": rendered}
            except UnicodeEncodeError as failure:
                rendering = {
                    "error_class": type(failure).__name__,
                    "error": str(failure),
                    "start": failure.start,
                    "end": failure.end,
                    "reason": failure.reason,
                }
            cases.append(
                {
                    "body_hex": payload.hex(),
                    "text": neutral(text),
                    "excerpt": neutral(excerpt),
                    "rendering": rendering,
                }
            )
    return {
        "schema": "marty.canvas-utf7-boundary/v1",
        "response_source_sha256": RESPONSE_SOURCE_SHA256,
        "cases": cases,
    }


if __name__ == "__main__":
    print(json.dumps(observe(), ensure_ascii=True, separators=(",", ":")))
