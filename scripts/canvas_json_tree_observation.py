"""Nonrecursive, language-neutral structural witness, AFTER consumer execution.

Only selected response fields use this explicit representation. Literal app
objects are always hashed as objects, never recognized as witness markers.
No recursion limit or production decoder/serializer is changed by this observer.
"""

import hashlib
import json
import math
import struct


def observe_tree(value):
    digest = hashlib.sha256(b"marty.json-tree/v1\n")
    nodes, max_depth = 0, 0
    pending = [(value, 0)]
    while pending:
        item, parent_depth = pending.pop()
        nodes += 1
        if isinstance(item, dict):
            assert all(isinstance(key, str) for key in item)
            keys = sorted(item)
            token = ["object", [[ord(character) for character in key] for key in keys]]
            depth = parent_depth + 1
            max_depth = max(max_depth, depth)
            pending.extend((item[key], depth) for key in reversed(keys))
        elif isinstance(item, list):
            token = ["array", len(item)]
            depth = parent_depth + 1
            max_depth = max(max_depth, depth)
            pending.extend((child, depth) for child in reversed(item))
        elif item is None:
            token = ["null"]
        elif isinstance(item, bool):
            token = ["bool", item]
        elif isinstance(item, int):
            token = ["integer", str(item)]
        elif isinstance(item, float):
            token = [
                "float",
                "nan" if math.isnan(item) else struct.pack(">d", item).hex(),
            ]
        elif isinstance(item, str):
            token = ["text", [ord(character) for character in item]]
        else:
            raise TypeError(f"unsupported observation value: {type(item).__name__}")
        digest.update(
            json.dumps(token, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        )
        digest.update(b"\n")
    return {
        "representation": "marty.json-tree/v1",
        "sha256": digest.hexdigest(),
        "nodes": nodes,
        "container_depth": max_depth,
    }
