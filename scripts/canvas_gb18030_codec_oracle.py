"""Published GB18030 mappings and complete-input observations; no native model."""

import itertools
import json

from canvas_multibyte_codec_oracle import CompleteInputOracle


POINTER_COUNT = 126 * 10 * 126 * 10
REPRESENTATIVES = (
    0,
    0x2F,
    0x30,
    0x31,
    0x39,
    0x3A,
    0x40,
    0x7F,
    0x80,
    0x81,
    0x84,
    0x85,
    0x8F,
    0x90,
    0xE3,
    0xFE,
    0xFF,
)


def pointer_bytes(pointer):
    return bytes(
        (
            pointer // 12600 + 0x81,
            pointer // 1260 % 10 + 0x30,
            pointer // 10 % 126 + 0x81,
            pointer % 10 + 0x30,
        )
    )


def observe():
    oracle = CompleteInputOracle("gb18030")
    pairs, short_hashes = oracle.pairs()
    pointer_hashes, grid_hashes = oracle.hashes(), oracle.hashes()
    ranges = []
    for pointer in range(POINTER_COUNT):
        value = oracle.observe(pointer_hashes, pointer_bytes(pointer))
        if value is None:
            continue
        assert len(value) == 1 and not 0xD800 <= ord(value) <= 0xDFFF
        scalar = ord(value)
        if (
            ranges
            and ranges[-1][1] == pointer
            and scalar == ranges[-1][2] + pointer - ranges[-1][0]
        ):
            ranges[-1][1] += 1
        else:
            ranges.append([pointer, pointer + 1, scalar])
    for width in range(5):
        for values in itertools.product(REPRESENTATIVES, repeat=width):
            oracle.observe(grid_hashes, bytes(values))

    payloads = [
        b"",
        b'{"accepted":true}',
        bytes(range(256)),
        bytes(range(255, -1, -1)),
        bytes(range(256)) * 5,
    ]
    for raw in (
        "80",
        "8030",
        "803041",
        "80304141",
        "8130",
        "813041",
        "81304141",
        "ff30ff30",
        "8431a530",
        "90308130",
        "e3329a35",
        "e3329a36",
    ):
        for suffix in (b"", b"A", b"\x81", pointer_bytes(189000)):
            payloads.append(bytes.fromhex(raw) + suffix)
    for start, end, _ in ranges:
        for pointer in (start - 1, start, end - 1, end):
            if 0 <= pointer < POINTER_COUNT:
                payloads.append(pointer_bytes(pointer))
    aliases, cases = oracle.responses(payloads)
    return {
        "schema": "marty.canvas-gb18030-codec/v1",
        "pointer_count": POINTER_COUNT,
        "pairs_zlib_base64": pairs,
        "ranges": ranges,
        "representatives": REPRESENTATIVES,
        "short_hashes": [digest.hexdigest() for digest in short_hashes],
        "pointer_hashes": [digest.hexdigest() for digest in pointer_hashes],
        "grid_hashes": [digest.hexdigest() for digest in grid_hashes],
        "aliases": aliases,
        "cases": cases,
    }


if __name__ == "__main__":
    print(json.dumps(observe(), ensure_ascii=True, separators=(",", ":")))
