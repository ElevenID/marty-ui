"""Published decimal continuation-ordinal limits, including bypass behavior."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from run_canvas_timeout_consumer_oracle import (
    RESPONSE_SOURCE_SHA256,
    observe_charset,
    response_owner,
)


def header(spec):
    name = spec["base"] + "*" + spec["digit"] * spec["digits"] + spec["suffix"]
    return "text/plain; charset=latin1; " + name + "=latin1"


def observe(response_source=None):
    if response_source is None:
        spec = importlib.util.find_spec(
            "issuance.infrastructure.adapters.canvas_credentials_adapter"
        )
        response_source = Path(spec.origin).read_text(encoding="utf-8")
    source = response_source.replace("\r\n", "\n")
    assert hashlib.sha256(source.encode()).hexdigest() == RESPONSE_SOURCE_SHA256
    project = response_owner(source)
    limit = sys.get_int_max_str_digits()
    assert limit > 0
    specs = [
        {"digits": digits, "digit": digit, "base": base, "suffix": ""}
        for digits in (limit - 1, limit, limit + 1, limit + 2)
        for digit in ("0", "9")
        for base in ("charset", "other")
    ]
    specs += [
        {"digits": limit + 1, "digit": digit, "base": "charset", "suffix": "*"}
        for digit in ("0", "9")
    ]
    specs += [
        {"digits": limit + 1, "digit": "9", "base": "other", "suffix": "x"},
        {"digits": limit + 1, "digit": "9", "base": "invalid-name", "suffix": ""},
    ]
    cases = []
    for index, spec in enumerate(specs):
        for kind, payload in (
            ("text", b"caf\xe9"),
            ("json", b'{"accepted":true}'),
            ("empty", b""),
        ):
            cases.append(
                {
                    "name": f"ordinal_{index}_{kind}",
                    "spec": spec,
                    "body_hex": payload.hex(),
                    **observe_charset(header(spec), payload, project),
                }
            )
    return {
        "schema": "marty.canvas-charset-ordinals/v1",
        "int_max_str_digits": limit,
        "response_source_sha256": RESPONSE_SOURCE_SHA256,
        "cases": cases,
    }


if __name__ == "__main__":
    print(json.dumps(observe(), ensure_ascii=True, separators=(",", ":")))
