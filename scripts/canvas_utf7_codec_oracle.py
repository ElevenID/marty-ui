"""Freeze actual UTF-7 strict/HTTPX codepoint behavior, never a native model."""

import base64
import codecs
import encodings.aliases
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct
from urllib.parse import quote_from_bytes

from httpx._decoders import TextDecoder

from run_canvas_timeout_consumer_oracle import (
    RESPONSE_SOURCE_SHA256,
    observe_charset,
    response_owner,
)


ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
REPRESENTATIVES = (0, 33, 43, 45, 47, 48, 50, 65, 127, 128, 255)
SPECIAL_UNITS = (0xD800, 0xDBFF, 0xDC00, 0xDFFF)
TERMINATOR_SEEDS = tuple(
    prefix + suffix
    for prefix in (b"", b"2AA", b"3AA", b"2ADcAA")
    for suffix in (b"", b"A", b"/", b"AA", b"AAA", b"AAAA", b"AAAAA")
)


def shift(units):
    data = b"".join(unit.to_bytes(2, "big") for unit in units)
    return b"+" + base64.b64encode(data).rstrip(b"=") + b"-"


def inputs(group):
    if group == "short":
        for width in range(3):
            for values in itertools.product(range(256), repeat=width):
                yield bytes(values)
    elif group == "units":
        for unit in range(65536):
            data = bytearray(shift([unit])[1:-1])
            last = ALPHABET.index(data[-1])
            for padding in range(4):
                data[-1] = ALPHABET[last | padding]
                for ending in (b"", b"-"):
                    yield b"+" + data + ending
    elif group == "pairs":
        for special in SPECIAL_UNITS:
            for unit in range(65536):
                yield shift([special, unit])
                yield shift([unit, special])
    elif group == "supplementary":
        for point in range(0x10000, 0x110000):
            value = point - 0x10000
            yield shift([0xD800 + (value >> 10), 0xDC00 + (value & 1023)])
    elif group == "terminators":
        for seed in TERMINATOR_SEEDS:
            for byte in range(256):
                yield b"+" + seed + bytes([byte]) + b"tail"
    elif group == "grid":
        for width in range(6):
            for values in itertools.product(REPRESENTATIVES, repeat=width):
                yield bytes(values)
    else:
        raise AssertionError("unknown fixed corpus")


def result(payload, *, strict):
    try:
        if strict:
            value = payload.decode("utf-7")
        else:
            decoder = TextDecoder("utf-7")
            value = decoder.decode(payload) + decoder.flush()
        return value
    except UnicodeDecodeError as error:
        assert strict
        return {"start": error.start, "end": error.end, "reason": error.reason}


def record(digest, value):
    if isinstance(value, str):
        digest.update(b"\x01" + struct.pack("<I", len(value)))
        digest.update(value.encode("utf-32-le", errors="surrogatepass"))
    else:
        reason = value["reason"].encode("ascii")
        digest.update(
            b"\x00" + struct.pack("<III", value["start"], value["end"], len(reason))
        )
        digest.update(reason)


def neutral(value):
    return {"codepoints": [ord(c) for c in value]} if isinstance(value, str) else value


def observe(response_source=None):
    if response_source is None:
        spec = importlib.util.find_spec(
            "issuance.infrastructure.adapters.canvas_credentials_adapter"
        )
        response_source = Path(spec.origin).read_text(encoding="utf-8")
    response_source = response_source.replace("\r\n", "\n")
    assert (
        hashlib.sha256(response_source.encode()).hexdigest() == RESPONSE_SOURCE_SHA256
    )
    project = response_owner(response_source)
    groups = {}
    for group in ("short", "units", "pairs", "supplementary", "terminators", "grid"):
        hashes = [hashlib.sha256(), hashlib.sha256()]
        count = 0
        for payload in inputs(group):
            record(hashes[0], result(payload, strict=False))
            record(hashes[1], result(payload, strict=True))
            count += 1
        groups[group] = {"count": count, "hashes": [h.hexdigest() for h in hashes]}
    payloads = [b"", b"+", b"+-", bytes(range(256)), b"A+!B", b"+A-tail"]
    for units in (
        [],
        [0],
        [65],
        [0xD800],
        [0xDC00],
        [0xD800, 0xDC00],
        [0xDC00, 0xD800],
    ):
        encoded = shift(units)
        for end in range(len(encoded) + 1):
            for tail in (b"", b"!", b"\xff", b"+2AA-", b"A"):
                payloads.append(b"start" + encoded[:end] + tail)
    cases = []
    for payload in dict.fromkeys(payloads):
        complete = result(payload, strict=False)
        # Final client text must be independent of any two-part byte delivery.
        for cut in range(len(payload) + 1):
            decoder = TextDecoder("utf-7")
            value = (
                decoder.decode(payload[:cut])
                + decoder.decode(payload[cut:])
                + decoder.flush()
            )
            assert value == complete
        cases.append(
            {
                "body_hex": payload.hex(),
                "replacement": neutral(complete),
                "strict": neutral(result(payload, strict=True)),
            }
        )
    aliases = sorted(
        {"utf-7", "utf_7", "utf7"}
        | {
            name
            for name, target in encodings.aliases.aliases.items()
            if target == "utf_7"
        }
    )
    assert all(codecs.lookup(alias).name == "utf-7" for alias in aliases)
    labels = (
        shift(map(ord, "latin1")),
        shift([0xD800]),
        shift([0xDC00]),
        shift([0xD800, 0xDC00]),
        shift([0xE9]),
        b"latin1",
        b"+",
        b"+!",
        b"+A-",
        b"+AAB-",
        b"latin1" + shift([0xD800]),
        b"\xff",
        shift([0]),
    )
    headers = []
    for alias in aliases:
        for label in labels:
            content_type = (
                "text/plain; charset*="
                + alias
                + "''"
                + quote_from_bytes(label, safe="")
            )
            for kind, payload in (
                ("text", b"caf\xe9"),
                ("json", b'{"accepted":true}'),
                ("empty", b""),
            ):
                headers.append(
                    {
                        "name": f"utf7_label_{len(headers)}_{kind}",
                        "content_type": content_type,
                        "body_hex": payload.hex(),
                        **observe_charset(content_type, payload, project),
                    }
                )
    for content_type in (
        "text/plain; charset*=%00''latin1",
        "text/plain; charset*=utf-7%00''latin1",
    ):
        for kind, payload in (
            ("text", b"caf\xe9"),
            ("json", b'{"accepted":true}'),
            ("empty", b""),
        ):
            headers.append(
                {
                    "name": f"utf7_label_{len(headers)}_{kind}",
                    "content_type": content_type,
                    "body_hex": payload.hex(),
                    **observe_charset(content_type, payload, project),
                }
            )
    return {
        "schema": "marty.canvas-utf7-codec/v1",
        "response_source_sha256": RESPONSE_SOURCE_SHA256,
        "groups": groups,
        "representatives": REPRESENTATIVES,
        "special_units": SPECIAL_UNITS,
        "terminator_seeds_hex": [value.hex() for value in TERMINATOR_SEEDS],
        "aliases": aliases,
        "cases": cases,
        "headers": headers,
    }


if __name__ == "__main__":
    print(json.dumps(observe(), ensure_ascii=True, separators=(",", ":")))
