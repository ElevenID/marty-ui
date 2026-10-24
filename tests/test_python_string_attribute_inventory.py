"""Builtin metadata evidence does not import or execute retired services."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_frozen_builtin_inventory_covers_metaclass_and_absent_attribute_boundaries():
    raw = (ROOT / "contracts/python-string-attribute-inventory.json").read_text(
        encoding="utf-8"
    )
    assert (
        hashlib.sha256(raw.encode()).hexdigest()
        == "8cf2f72d0e1ee010f1b01a68357ea3f5f0637a292a67bd3428d12ccdd4a269c7"
    )
    value = json.loads(raw)
    assert value["python_version"] == "3.12.10"
    assert {k: len(v) for k, v in value["owners"].items()} == {
        "str_instance": 81,
        "str_type": 105,
        "type_type": 48,
    }
    assert "__name__" not in value["owners"]["str_instance"]
    assert value["owners"]["str_type"]["__name__"] == {"value_type": "str"}
    assert value["owners"]["str_instance"]["upper"] == {
        "value_type": "builtin_function_or_method"
    }
    assert all(len(v) == 6 for v in value["absent"].values())
    for attributes in value["owners"].values():
        for item in attributes.values():
            assert set(item) in ({"value_type"}, {"error_type", "message"})
            assert "repr" not in item and "value" not in item


def test_native_formatter_is_private_and_connected_to_canvas_urls():
    library = (ROOT / "rust/services/issuance/src/lib.rs").read_text(encoding="utf-8")
    assert "mod python_format;" in library
    assert "#[cfg(test)]\nmod python_format;" not in library
    assert "pub mod python_format;" not in library
    canvas_urls = (
        ROOT / "rust/services/issuance/src/canvas_credentials_urls.rs"
    ).read_text(encoding="utf-8")
    assert "python_format::{format_named, PythonFormatError" in canvas_urls
    formatter = (ROOT / "rust/services/issuance/src/python_format.rs").read_text(
        encoding="utf-8"
    )
    assert "UnmodeledCapability" in formatter and "ResourceFailure" in formatter
    assert "representation_points(ReprText(value))" in formatter
    assert "parse::<PythonConfigInteger>()" in formatter


def test_pairwise_reference_is_frozen_and_complete():
    path = ROOT / "contracts/python-named-format-reference.json"
    raw = path.read_text(encoding="utf-8")
    assert hashlib.sha256(raw.encode()).hexdigest() == (
        "8389260d8bd8e0e07ee67ac334c365e1a078cf58b893724b8206377f5e90582d"
    )
    value = json.loads(raw)
    rows = value["observations"]
    assert len(rows) == 777
    assert sum("error" in row for row in rows) == 652
    inventory = [(row["id"], row["template"]) for row in rows]
    assert len({name for name, _ in inventory}) == len(rows)
    encoded = json.dumps(inventory, ensure_ascii=True, separators=(",", ":"))
    assert hashlib.sha256(encoded.encode()).hexdigest() == (
        "34557b1d0da58cde277400ac317f1005e2e1abfa10ffe6251ab151af8bd9b971"
    )
    assert value["python_version"] == "3.12.10"
