"""Freeze published ISO-2022 mappings and state/escape behavior, not a decoder."""

import argparse
import codecs
import encodings.aliases
import hashlib
import itertools
import json
import struct

import httpx
from httpx._decoders import TextDecoder

from canvas_multibyte_codec_oracle import compressed, record


NAMES = (
    "iso2022_kr",
    "iso2022_jp",
    "iso2022_jp_1",
    "iso2022_jp_2",
    "iso2022_jp_2004",
    "iso2022_jp_3",
    "iso2022_jp_ext",
)
ESC = b"\x1b"
TAILS = (b"", b"!@", b"\xffA", ESC + b"(Btail")
ESCAPE_SEEDS = (
    ESC + b"(B",
    ESC + b")B",
    ESC + b"$B",
    ESC + b".A",
    ESC + b"&@",
    ESC + b"$(B",
    ESC + b"$)C",
    ESC + b"$.B",
    ESC + b"&@" + ESC + b"$B",
    ESC + b"&!" + ESC + b"$B",
    ESC + b"N!",
    ESC + b"!A",
)


def strict_result(name, payload):
    try:
        return payload.decode(name, errors="strict")
    except UnicodeDecodeError:
        return None
    except (UnicodeError, RuntimeError) as failure:
        return {"error_class": type(failure).__name__, "error": str(failure)}


def text_result(name, payload):
    try:
        decoder = TextDecoder(name)
        return decoder.decode(payload) + decoder.flush()
    except (UnicodeError, RuntimeError) as failure:
        return {"error_class": type(failure).__name__, "error": str(failure)}


def record_result(digest, value):
    if isinstance(value, dict):
        digest.update(b"\x02")
        record(digest, json.dumps(value, sort_keys=True, separators=(",", ":")))
    else:
        record(digest, value)


def observe(name):
    assert name in NAMES

    def hashes():
        return hashlib.sha256(), hashlib.sha256()

    def observe_payload(digests, payload):
        record_result(digests[0], text_result(name, payload))
        record_result(digests[1], strict_result(name, payload))

    # Discover accepted marks and widths through complete/incremental decoders.
    sets = {}
    for double, marker in itertools.product(
        (False, True), b"@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ):
        prefix = ESC + (b"$" if double else b"(") + bytes([marker])
        if strict_result(name, prefix) != "":
            continue
        probe = codecs.getincrementaldecoder(name)(errors="replace")
        probe.decode(prefix + b"!")
        width = 1 + len(probe.getstate()[0])
        assert width in (1, 2)
        mark = marker | (128 if double else 0)
        if mark == ord("B"):
            continue
        outputs, indices, rows = [None], {None: 0}, []
        for first in range(32, 128):
            for suffix in (
                map(bytes, itertools.product(range(256), repeat=1))
                if width == 2
                else (b"",)
            ):
                value = strict_result(name, prefix + bytes([first]) + suffix)
                assert value is None or (
                    isinstance(value, str) and 1 <= len(value) <= 2
                )
                if value not in indices:
                    indices[value] = len(outputs)
                    outputs.append(value)
                rows.append(indices[value])
        output_json = json.dumps(
            outputs, ensure_ascii=False, separators=(",", ":")
        ).encode()
        sets[str(mark)] = {
            "prefix_hex": prefix.hex(),
            "width": width,
            "indices_zlib_base64": compressed(struct.pack(f"<{len(rows)}I", *rows)),
            "outputs_zlib_base64": compressed(output_json),
            "outputs_size": len(output_json),
        }

    shift = strict_result(name, b"\x0e") == ""
    g2 = strict_result(name, ESC + b".A") == ""
    extension = strict_result(name, ESC + b"&@" + ESC + b"$B") == ""
    g0_prefixes = [b""] + [
        bytes.fromhex(value["prefix_hex"]) for value in sets.values()
    ]
    g1_prefixes = [b""]
    if shift:
        g1_prefixes += [
            ESC + (b"$)" if value["width"] == 2 else b")") + bytes([int(mark) & 127])
            for mark, value in sets.items()
        ]
    g2_prefixes = [b""]
    if g2:
        g2_prefixes += [
            ESC + b"." + bytes([int(mark)]) for mark in sets if int(mark) < 128
        ]

    # Canonical witnesses for active designation/shift/throughout combinations.
    # G1 is unobservable in NO_SHIFT variants; escape mutations still exercise
    # their G1 designations, but need not multiply identical decoding behavior.
    prefixes, states = [], set()
    for pieces in itertools.product(
        g0_prefixes,
        g1_prefixes,
        g2_prefixes,
        (b"", b"\x0e") if shift else (b"",),
        (b"", ESC + b"!"),
    ):
        prefix = b"".join(pieces)
        decoder = codecs.getincrementaldecoder(name)(errors="strict")
        decoder.decode(prefix)
        state = decoder.getstate()
        assert state[0] == b""
        if state not in states:
            states.add(state)
            prefixes.append(prefix)
    assert len(prefixes) <= 512, "do not silently truncate qualification states"
    state_hashes = hashes()
    for prefix in prefixes:
        observe_payload(state_hashes, prefix)
        for first in range(256):
            observe_payload(state_hashes, prefix + bytes([first]))
            for second in range(256):
                observe_payload(state_hashes, prefix + bytes([first, second]))

    escape_hashes = hashes()
    for prefix in prefixes:
        for seed in ESCAPE_SEEDS:
            for width in range(len(seed) + 1):
                observe_payload(escape_hashes, prefix + seed[:width])
            for position in range(len(seed)):
                for byte in range(256):
                    payload = bytearray(seed)
                    payload[position] = byte
                    for tail in TAILS:
                        observe_payload(escape_hashes, prefix + payload + tail)
        for header in b"()$.&":
            for middle in (b"!", b"\xff", b"&@", ESC):
                for count in range(19):
                    for tail in TAILS:
                        observe_payload(
                            escape_hashes,
                            prefix + ESC + bytes([header]) + middle * count + tail,
                        )

    # Exercise every G2 third byte, including internal-codec errors when a valid
    # ordinary designation is used in G2. Store actual outcomes, not substitutions.
    g2_cases = {}
    g2_strict = {}
    if g2:
        for mark in [ord("B")] + [int(mark) for mark in sets if int(mark) < 128]:
            prefix = ESC + b"." + bytes([mark]) + ESC + b"N"
            g2_cases[str(mark)] = [
                text_result(name, prefix + bytes([byte])) for byte in range(256)
            ]
            g2_strict[str(mark)] = [
                strict_result(name, prefix + bytes([byte])) for byte in range(256)
            ]

    payloads = [
        b"",
        b'{"accepted":true}',
        bytes(range(256)),
        bytes(range(255, -1, -1)),
        bytes(range(256)) * 5,
    ]
    for prefix in prefixes:
        for tail in (
            b"!@\\~",
            b"\xffA",
            b"\x0e!@\n!@\x0f!@",
            ESC + b"N!",
            ESC + b"N\xff",
            ESC + b"$",
        ):
            payloads.append(prefix + tail)
    payloads.append(g0_prefixes[-1] + b"!@" * 1001)
    payloads.extend(seed + tail for seed in ESCAPE_SEEDS for tail in TAILS)
    aliases = sorted(
        {name}
        | {
            alias
            for alias, target in encodings.aliases.aliases.items()
            if target == name
        }
    )
    cases = []
    for payload in dict.fromkeys(payloads):
        results = []
        for alias in aliases:
            try:
                value = httpx.Response(
                    403,
                    content=payload,
                    headers={"content-type": "text/plain; charset=" + alias},
                ).text
            except (UnicodeError, RuntimeError) as failure:
                value = {"error_class": type(failure).__name__, "error": str(failure)}
            results.append(value)
        assert all(value == results[0] for value in results)
        cases.append({"body_hex": payload.hex(), "text": results[0]})
    return {
        "schema": "marty.canvas-iso2022-codec/v1",
        "name": name,
        "shift": shift,
        "g2": g2,
        "extension": extension,
        "sets": sets,
        "prefixes": [prefix.hex() for prefix in prefixes],
        "escape_seeds": [seed.hex() for seed in ESCAPE_SEEDS],
        "tails": [tail.hex() for tail in TAILS],
        "state_hashes": [digest.hexdigest() for digest in state_hashes],
        "escape_hashes": [digest.hexdigest() for digest in escape_hashes],
        "g2_cases": g2_cases,
        "g2_strict": g2_strict,
        "aliases": aliases,
        "cases": cases,
    }


def run():
    return {name: observe(name) for name in NAMES}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--codec", required=True, choices=NAMES)
    arguments = parser.parse_args()
    print(
        json.dumps(observe(arguments.codec), ensure_ascii=True, separators=(",", ":"))
    )
