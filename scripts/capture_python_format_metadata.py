"""Fixed CPython builtin metadata observations, without invoking attributes.

Deterministic outcomes, host/state values, and address-bearing representations
are separate evidence classes. Identity shapes are NOT exact-output parity.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "contracts/python-format-metadata-reference.json"
INVENTORY_SHA256 = "8cf2f72d0e1ee010f1b01a68357ea3f5f0637a292a67bd3428d12ccdd4a269c7"
LAYOUT = {
    "__basicsize__",
    "__dictoffset__",
    "__flags__",
    "__itemsize__",
    "__weakrefoffset__",
}
OWNERS = {
    "str_instance": "value",
    "str_type": "value.__class__",
    "type_type": "value.__class__.__class__",
}
ADDRESS = re.compile(r"0x[0-9A-Fa-f]+")


def cases():
    raw = (ROOT / "contracts/python-string-attribute-inventory.json").read_text(
        encoding="utf-8"
    )
    if hashlib.sha256(raw.encode()).hexdigest() != INVENTORY_SHA256:
        raise RuntimeError("Builtin inventory source changed")
    inventory = json.loads(raw)
    templates = {}
    for owner, prefix in OWNERS.items():
        for name in inventory["owners"][owner]:
            templates["{" + prefix + "." + name + "}"] = name in LAYOUT
    paths = (
        "value.__doc__",
        "value.__class__.__doc__",
        "value.__class__.__base__",
        "value.__class__.__base__.__name__",
        "value.__class__.__bases__",
        "value.__class__.__bases__[0]",
        "value.__class__.__mro__[1].__name__",
        "value.__class__.__mro__[2]",
        "value.__class__.__mro__[missing]",
        "value.__class__.__type_params__",
        "value.__class__.__type_params__[0]",
        "value.__class__.__text_signature__",
        "value.__class__.__text_signature__.__class__.__name__",
        "value.__class__[0]",
        "value.__class__.__class__[0]",
        "value.__class__.__dict__[upper]",
        "value.__class__.__dict__[__doc__]",
        "value.__class__.__dict__[missing]",
        "value.__class__.__dict__.__class__.__name__",
        "value.__class__.__abstractmethods__",
        "value.__class__.__annotations__",
        "value.upper.__name__",
        "value.upper.__qualname__",
        "value.upper.__self__",
        "value.upper.__doc__",
        "value.upper.__text_signature__",
        "value.upper.__module__",
        "value.upper.__objclass__",
        "value.__len__.__name__",
        "value.__len__.__self__",
        "value.__class__.upper",
        "value.__class__.upper.__objclass__.__name__",
        "value.__class__.upper.__self__",
        "value.__class__.upper.__doc__",
    )
    for path in paths:
        for suffix in ("", "!s", "!r", "!a", ":>8", ":.3", "!s:.12"):
            templates["{" + path + suffix + "}"] = False
    return [
        {
            "id": f"metadata-{index:04}",
            "template": template,
            "platform_state_bound": platform,
        }
        for index, (template, platform) in enumerate(sorted(templates.items()))
    ]


def render(template, value):
    try:
        result = {"value": template.format(value=value)}
    except (AttributeError, IndexError, KeyError, ValueError, TypeError) as error:
        result = {"error": {"type": type(error).__name__, "message": str(error)}}
    if len(json.dumps(result, ensure_ascii=True)) > 65536:
        raise RuntimeError("Fixed metadata outcome exceeded its bound")
    return result


def identity_shape(value, identities):
    matches = list(ADDRESS.finditer(value))
    return {
        "literals": ADDRESS.split(value),
        "owners": [
            identities.get(int(match.group(), 16), "unqualified_object")
            for match in matches
        ],
        "address_count": len(matches),
        "qualification": "shape observation only; not exact output or complete object support",
    }


def observe():
    if sys.version_info[:3] != (3, 12, 10) or sys.implementation.name != "cpython":
        raise RuntimeError("Exact CPython 3.12.10 is required")
    value = "metadata-" + str(1234)
    identities = {
        id(value): "input_string",
        id(str): "str_type",
        id(type): "type_type",
        id(object): "object_type",
    }
    inputs = cases()
    if not 234 <= len(inputs) <= 600:
        raise RuntimeError("Unexpected fixed metadata case count")
    deterministic, platform, identity = [], [], []
    for case in inputs:
        first = render(case["template"], value)
        second = render(case["template"], value)
        if case["platform_state_bound"]:
            if ("value" in first) != ("value" in second):
                raise RuntimeError("Platform observation changed outcome class")
            platform.append(
                {
                    **case,
                    "qualification": (
                        "platform/build state only; no exact value or Rust parity claim"
                    ),
                }
            )
        elif "value" in first and ADDRESS.search(first["value"]):
            if "value" not in second:
                raise RuntimeError("Identity observation changed outcome class")
            identity.append(
                {
                    **case,
                    "first_shape": identity_shape(first["value"], identities),
                    "repeat_shape": identity_shape(second["value"], identities),
                }
            )
        else:
            if first != second:
                raise RuntimeError("Claimed deterministic observation changed")
            deterministic.append({**case, **first})
    return {
        "schema": "marty.python-format-metadata-reference/v2",
        "python_version": "3.12.10",
        "inventory_sha256": INVENTORY_SHA256,
        "input": value,
        "cases": inputs,
        "deterministic": deterministic,
        "platform_state_bound": platform,
        "identity_observations_not_exact_parity": identity,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.check and args.write:
        parser.error("--check and --write are mutually exclusive")
    encoded = (
        json.dumps(
            observe(), ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2
        )
        + "\n"
    )
    if len(encoded.encode()) > 4 * 1024 * 1024:
        raise RuntimeError("Metadata reference exceeded its fixed bound")
    if args.write:
        REFERENCE.write_text(encoded, encoding="utf-8", newline="\n")
        print(f"Wrote {REFERENCE.relative_to(ROOT)}")
    elif args.check:
        if REFERENCE.read_text(encoding="utf-8") != encoded:
            raise ValueError(
                "Metadata reference differs; host/state and identity classes are not portable exact values"
            )
        print("Pinned metadata reference PASS")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
