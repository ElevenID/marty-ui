"""Observe only Python 3.12.10 builtin str/type attribute existence, not methods.

Never call attributes or serialize their values/repr: bound-method addresses are
intentionally excluded. This is semantic inventory, not formatted-result lookup.
"""

import argparse
import json
from pathlib import Path
import sys

REFERENCE = (
    Path(__file__).resolve().parents[1]
    / "contracts/python-string-attribute-inventory.json"
)


def observe():
    if sys.version_info[:3] != (3, 12, 10) or sys.implementation.name != "cpython":
        raise RuntimeError("Exact CPython 3.12.10 is required for builtin inventory")
    owners = {}
    for name, owner in (("str_instance", ""), ("str_type", str), ("type_type", type)):
        attributes = {}
        # dir(str) intentionally omits metaclass attributes such as __name__.
        # Use both exact builtin MRO dictionaries, not dir() as an existence oracle.
        classes = (
            *type(owner).__mro__,
            *(owner.__mro__ if isinstance(owner, type) else ()),
        )
        candidates = {attribute for cls in classes for attribute in vars(cls)}
        for attribute in sorted(candidates):
            try:
                value = getattr(owner, attribute)
                attributes[attribute] = {"value_type": type(value).__name__}
            except AttributeError as error:
                attributes[attribute] = {
                    "error_type": "AttributeError",
                    "message": str(error),
                }
        owners[name] = attributes
    absent = {}
    for name, owner in (("str_instance", ""), ("str_type", str), ("type_type", type)):
        rows = []
        for attribute in ("missing", "雪", "a'b", "\ud800", "a\x00b", "x" * 250):
            try:
                getattr(owner, attribute)
            except AttributeError as error:
                rows.append({"name": attribute, "message": str(error)})
            else:
                raise AssertionError("Negative builtin attribute unexpectedly exists")
        absent[name] = rows
    return {
        "schema": "marty.python-string-attribute-inventory/v1",
        "python_version": "3.12.10",
        "owners": owners,
        "absent": absent,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = observe()
    encoded = (
        json.dumps(result, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2)
        + "\n"
    )
    if args.check:
        if REFERENCE.read_text(encoding="utf-8") != encoded:
            raise ValueError("Builtin string attribute inventory differs")
        print("Python builtin attribute inventory PASS")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
