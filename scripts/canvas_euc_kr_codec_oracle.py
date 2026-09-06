"""Observe published EUC-KR pair mappings and eight-byte Hangul compositions."""

import itertools
import json

from canvas_multibyte_codec_oracle import CompleteInputOracle


BASELINE = bytes.fromhex("a4d4a4a1a4bfa4d4")
MUTATION_BASES = (
    BASELINE,
    bytes.fromhex("a4d4a4bea4d3a4be"),
    bytes.fromhex("a4d441a1a4bfa4d4"),
    bytes.fromhex("a4d4a4d4a4bfa4d4"),
)


def observe():
    oracle = CompleteInputOracle("euc_kr")
    pairs, short_hashes = oracle.pairs()
    component_hashes = oracle.hashes()
    components = []
    base = oracle.observe(component_hashes, BASELINE)
    assert base is not None and len(base) == 1
    for position in (3, 5, 7):
        values = []
        for byte in range(256):
            payload = bytearray(BASELINE)
            payload[position] = byte
            value = oracle.observe(component_hashes, payload)
            assert value is None or len(value) == 1
            values.append(None if value is None else ord(value) - ord(base))
        components.append(values)

    # All 256^3 component-byte combinations: expectations come from independent
    # decoders, not the additive representation. Validate that representation
    # separately rather than silently assuming the decomposition is sufficient.
    composition_hashes = oracle.hashes()
    valid_count = 0
    for first, middle, final in itertools.product(range(256), repeat=3):
        payload = bytes((0xA4, 0xD4, 0xA4, first, 0xA4, middle, 0xA4, final))
        value = oracle.observe(composition_hashes, payload)
        offsets = [components[0][first], components[1][middle], components[2][final]]
        if any(offset is None for offset in offsets):
            assert value is None
        else:
            assert value == chr(ord(base) + sum(offsets))
            valid_count += 1

    mutation_hashes = oracle.hashes()
    for initial in MUTATION_BASES:
        for position in range(8):
            for byte in range(256):
                payload = bytearray(initial)
                payload[position] = byte
                for width in range(9):
                    oracle.observe(mutation_hashes, payload[:width])
                for suffix in (b"A", BASELINE, b"\xa4\xd4"):
                    oracle.observe(mutation_hashes, payload + suffix)

    payloads = [
        b"",
        b'{"accepted":true}',
        bytes(range(256)),
        bytes(range(255, -1, -1)),
        bytes(range(256)) * 5,
    ]
    for initial in MUTATION_BASES:
        for width in range(9):
            for suffix in (b"", b"A", BASELINE, b"\xa4\xd4"):
                payloads.append(initial[:width] + suffix)
    # Repeated composed/non-composed syllables cross the excerpt boundary.
    payloads.append(
        ("".join(chr(scalar) for scalar in range(0xAC00, 0xAC40)) * 20).encode("euc_kr")
    )
    aliases, cases = oracle.responses(payloads)
    return {
        "schema": "marty.canvas-euc-kr-codec/v1",
        "pairs_zlib_base64": pairs,
        "base_scalar": ord(base),
        "components": components,
        "valid_compositions": valid_count,
        "mutation_bases": [payload.hex() for payload in MUTATION_BASES],
        "short_hashes": [digest.hexdigest() for digest in short_hashes],
        "component_hashes": [digest.hexdigest() for digest in component_hashes],
        "composition_hashes": [digest.hexdigest() for digest in composition_hashes],
        "mutation_hashes": [digest.hexdigest() for digest in mutation_hashes],
        "aliases": aliases,
        "cases": cases,
    }


if __name__ == "__main__":
    print(json.dumps(observe(), ensure_ascii=True, separators=(",", ":")))
