"""Bounded, deterministic CPython 3.12.10 string-only format observations.

Only literal generated templates and fixed string arguments are evaluated.
No user input, environment settings, attribute calls, or application imports.
"""

import argparse
import itertools
import json
from pathlib import Path
import sys

REFERENCE = (
    Path(__file__).resolve().parents[1] / "contracts/python-named-format-reference.json"
)
FIELDS = {
    "value": "a\u00e9\U0001f600\ud800",
    "width": "6",
    "precision": "2",
    "empty": "",
}
AXES = (
    ("", "<", ">", "^", "=", "*<", "0>", "\u96ea^", "\ud800>"),
    ("", "+", "-", " "),
    ("", "z", "#", "z#"),
    ("", "0"),
    ("", "4", "04", "\u0664", "\uff14"),
    ("", ",", "_", ",_", "_,"),
    ("", ".", ".0", ".2", ".\u0662"),
    ("", "s", "d", "n", "x", "%", "\x00", "\x7f", "\u96ea", "\ud800"),
)


def cases():
    templates = set()
    # All two-axis interactions, not a hand-selected success/error subset.
    for left, right in itertools.combinations(range(len(AXES)), 2):
        for first, second in itertools.product(AXES[left], AXES[right]):
            pieces = [""] * len(AXES)
            pieces[left], pieces[right] = first, second
            templates.add("{value:" + "".join(pieces) + "}")
    for prefix, grouping, presentation in itertools.product(
        ("+z#04", "0>04", "*^04", " =04"),
        ("", ",", "_", ",_"),
        ("", "s", "d", "n", "x"),
    ):
        templates.add("{value:" + prefix + grouping + ".2" + presentation + "}")
    for number in ("0", "\u0660", "\uff10", "2", "\u00b2", "9" * 30, "\u0669" * 30):
        for suffix in ("", "x", "\u96ea", "\x00"):
            templates.add("{" + number + suffix + "}")
            templates.add("{value[" + number + suffix + "]}")
    for conversion in (
        "s",
        "r",
        "a",
        "\x00",
        "\x01",
        "\x7f",
        "\u00e9",
        "\u96ea",
        "\ud800",
    ):
        for suffix in ("", ":>8", ":{missing}", "x", ":{width:{precision}}"):
            templates.add("{value!" + conversion + suffix + "}")
    templates.update(
        (
            "{value:{width}.{precision}}",
            "{value:{width:{precision}}}",
            "{missing:{width:{precision}}}",
            "{value!q:{width:{precision}}}",
            "{value:{missing!q}}",
            "{value:{width!q}}",
            "{value:{{}}}",
            "{value:{empty}}",
            "{value:{width",
            "{value[missing].}",
            "{value[0]x}",
            "{value..missing}",
            "{value!}",
            "{value!",
            "{",
            "}",
            "{{}}",
            "{value:{value:{value}}}",
        )
    )
    return [
        {"id": f"format-{index:04}", "template": template}
        for index, template in enumerate(sorted(templates))
    ]


def observe():
    if sys.version_info[:3] != (3, 12, 10) or sys.implementation.name != "cpython":
        raise RuntimeError("Exact CPython 3.12.10 is required")
    inputs = cases()
    if not 500 <= len(inputs) <= 2000:
        raise RuntimeError("Unexpected bounded case count")
    rows = []
    for case in inputs:
        try:
            output = case["template"].format(**FIELDS)
            if len(output) > 1024:
                raise RuntimeError("Output exceeds fixed string fixture bound")
            result = {"value": output}
        except (ValueError, TypeError, IndexError, KeyError, AttributeError) as error:
            result = {"error": {"type": type(error).__name__, "message": str(error)}}
        rows.append({**case, **result})
    return {
        "schema": "marty.python-named-format-reference/v1",
        "python_version": "3.12.10",
        "coverage": "fixed pairwise string format axes and targeted precedence; not full object grammar",
        "fields": FIELDS,
        "observations": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = (
        json.dumps(
            observe(), ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2
        )
        + "\n"
    )
    if len(encoded.encode("utf-8")) > 2 * 1024 * 1024:
        raise RuntimeError("Reference exceeds fixed artifact bound")
    if args.check:
        if REFERENCE.read_text(encoding="utf-8") != encoded:
            raise ValueError("Named format reference differs")
        print("Pinned named format reference PASS")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
