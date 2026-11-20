"""Freeze reachable published decoder transitions, not a replacement Python codec.

Production uses only language-neutral tables. This capture runs against the
installed published codecs/HTTPX and never accepts a deployment endpoint.
"""

import argparse
import base64
import codecs
import encodings.aliases
import hashlib
import json
import struct
import zlib

import httpx
from httpx._decoders import TextDecoder


NAMES = (
    "big5",
    "big5hkscs",
    "cp932",
    "cp949",
    "cp950",
    "gb2312",
    "gbk",
    "johab",
    "shift_jis",
    "shift_jis_2004",
    "shift_jisx0213",
    "euc_jp",
    "euc_jis_2004",
    "euc_jisx0213",
    "hz",
)
VALID = 1 << 31


def compressed(data):
    return base64.b64encode(zlib.compress(data, 9)).decode("ascii")


def record(digest, value):
    if value is None:
        digest.update(b"\x00")
    else:
        encoded = value.encode("utf-8")
        digest.update(b"\x01" + struct.pack("<I", len(encoded)) + encoded)


class CompleteInputOracle:
    """Fresh published decoders shared by compact variable-width captures."""

    def __init__(self, name):
        self.name = name

    @staticmethod
    def hashes():
        return hashlib.sha256(), hashlib.sha256()

    def observe(self, digests, payload):
        decoder = TextDecoder(self.name)
        record(digests[0], decoder.decode(payload) + decoder.flush())
        try:
            value = payload.decode(self.name, errors="strict")
        except UnicodeDecodeError:
            value = None
        record(digests[1], value)
        return value

    def pairs(self):
        digests, pairs = self.hashes(), []
        for first in range(256):
            self.observe(digests, bytes([first]))
            for second in range(256):
                value = self.observe(digests, bytes([first, second]))
                if first >= 128:
                    assert value is None or len(value) == 1
                    pairs.append(0xFFFFFFFF if value is None else ord(value))
        return compressed(struct.pack(f"<{len(pairs)}I", *pairs)), digests

    def responses(self, payloads):
        aliases = sorted(
            {self.name}
            | {
                alias
                for alias, target in encodings.aliases.aliases.items()
                if target == self.name
            }
        )
        cases = []
        for payload in dict.fromkeys(payloads):
            text = httpx.Response(
                403,
                content=payload,
                headers={"content-type": "text/plain; charset=" + self.name},
            ).text
            for alias in aliases:
                assert (
                    httpx.Response(
                        403,
                        content=payload,
                        headers={"content-type": "text/plain; charset=" + alias},
                    ).text
                    == text
                )
            cases.append({"body_hex": payload.hex(), "text": text})
        return aliases, cases


def observe(name):
    assert name in NAMES
    decoder_type = codecs.getincrementaldecoder(name)
    replacement = decoder_type(errors="replace")
    strict = decoder_type(errors="strict")
    initial = replacement.getstate()
    states, prefixes, indices = [initial], [b""], {initial: 0}
    outputs, output_indices, transitions, finals = [""], {"": 0}, [], []
    text_hash, strict_hash = hashlib.sha256(), hashlib.sha256()

    def output_index(value):
        if value not in output_indices:
            output_indices[value] = len(outputs)
            outputs.append(value)
        assert len(outputs) <= 65536, "table output index overflow"
        return output_indices[value]

    def terminal(payload):
        # Independent fresh HTTPX decoder and Python strict text decode. Do not
        # compute these expected values by replaying the captured transition table.
        text = TextDecoder(name)
        record(text_hash, text.decode(payload) + text.flush())
        try:
            value = payload.decode(name, errors="strict")
        except UnicodeDecodeError:
            value = None
        record(strict_hash, value)

    index = 0
    while index < len(states):
        assert len(states) < 32768, "qualification cannot silently truncate states"
        state, prefix = states[index], prefixes[index]
        replacement.setstate(state)
        value = replacement.decode(b"", final=True)
        strict.setstate(state)
        try:
            assert strict.decode(b"", final=True) == value
            valid = VALID
        except UnicodeDecodeError:
            valid = 0
        finals.append(output_index(value) | valid)
        terminal(prefix)
        for byte in range(256):
            data = bytes([byte])
            replacement.setstate(state)
            value = replacement.decode(data)
            after = replacement.getstate()
            strict.setstate(state)
            try:
                assert strict.decode(data) == value
                assert strict.getstate() == after
                valid = VALID
            except UnicodeDecodeError:
                valid = 0
            if after not in indices:
                indices[after] = len(states)
                states.append(after)
                prefixes.append(prefix + data)
            transitions.append(output_index(value) | (indices[after] << 16) | valid)
            terminal(prefix + data)
        index += 1
    assert len(transitions) == len(states) * 256
    packed = struct.pack(f"<{len(transitions)}I", *transitions)
    output_json = json.dumps(
        outputs, ensure_ascii=False, separators=(",", ":")
    ).encode()
    aliases = sorted(
        {name}
        | {
            alias
            for alias, target in encodings.aliases.aliases.items()
            if target == name
        }
    )
    # Full HTTPX response selection, aliases, multichar mappings and long input.
    payloads = [b"", b'{"accepted":true}', bytes(range(256)), bytes(range(255, -1, -1))]
    payloads += [b"\x81\x40", b"\x88\x62", b"\x8f\xa2\xaf", b"~{VP~}", b"~{VP", b"~"]
    payloads += [bytes(range(256)) * 5]
    cases = []
    for payload in payloads:
        result = httpx.Response(
            403,
            content=payload,
            headers={"content-type": "text/plain; charset=" + name},
        ).text
        for alias in aliases:
            assert (
                httpx.Response(
                    403,
                    content=payload,
                    headers={"content-type": "text/plain; charset=" + alias},
                ).text
                == result
            )
        cases.append({"body_hex": payload.hex(), "text": result})
    return {
        "schema": "marty.canvas-multibyte-machine/v1",
        "name": name,
        "aliases": aliases,
        "state_count": len(states),
        "prefixes": [prefix.hex() for prefix in prefixes],
        "finals": finals,
        "transitions_zlib_base64": compressed(packed),
        "outputs_zlib_base64": compressed(output_json),
        "outputs_size": len(output_json),
        "text_sha256": text_hash.hexdigest(),
        "strict_sha256": strict_hash.hexdigest(),
        "cases": cases,
    }


def run():
    return {name: observe(name) for name in NAMES}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--codec", choices=NAMES, required=True)
    arguments = parser.parse_args()
    print(
        json.dumps(observe(arguments.codec), ensure_ascii=True, separators=(",", ":"))
    )
