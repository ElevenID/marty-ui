"""Builtin metadata evidence does not import or execute retired services."""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture_python_string_attributes.py"


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


def test_capture_is_version_pinned_builtin_metadata_only_and_candidate_is_unselected():
    spec = importlib.util.spec_from_file_location("string_attribute_inventory", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports == {"argparse", "json", "pathlib", "sys"}
    source = SCRIPT.read_text(encoding="utf-8")
    assert "sys.version_info[:3] != (3, 12, 10)" in source
    assert "type(owner).__mro__" in source and "vars(cls)" in source
    assert "getattr(owner, attribute)" in source
    assert "repr(value)" not in source
    library = (ROOT / "rust/services/issuance/src/lib.rs").read_text(encoding="utf-8")
    assert "#[cfg(test)]\nmod python_format;" in library
    formatter = (ROOT / "rust/services/issuance/src/python_format.rs").read_text(
        encoding="utf-8"
    )
    assert "UnmodeledCapability" in formatter and "ResourceFailure" in formatter
    assert "representation_points(ReprText(value))" in formatter
    assert "parse::<PythonConfigInteger>()" in formatter


def test_pairwise_reference_is_frozen_complete_and_exactly_regenerated():
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
    script = ROOT / "scripts/capture_python_named_format_reference.py"
    spec = importlib.util.spec_from_file_location("named_format_reference", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.cases() == [
        {"id": name, "template": template} for name, template in inventory
    ]
    assert value["fields"] == module.FIELDS
    assert value["python_version"] == "3.12.10"
    source = script.read_text(encoding="utf-8")
    assert "itertools.combinations(range(len(AXES)), 2)" in source
    assert "sys.version_info[:3] != (3, 12, 10)" in source
    assert (
        "except (ValueError, TypeError, IndexError, KeyError, AttributeError)" in source
    )
    assert "except Exception" not in source


def test_reference_capture_does_not_accept_infrastructure_failure(monkeypatch):
    script = ROOT / "scripts/capture_python_named_format_reference.py"
    spec = importlib.util.spec_from_file_location("named_format_reference", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.sys, "version_info", (3, 12, 10))

    class InfrastructureFailure:
        def __format__(self, _spec):
            raise RuntimeError("controlled infrastructure refusal")

    monkeypatch.setattr(module, "FIELDS", {"value": InfrastructureFailure()})
    with pytest.raises(RuntimeError, match="controlled infrastructure refusal"):
        module.observe()


def test_format_metadata_reference_is_partitioned_portable_and_reproducible():
    path = ROOT / "contracts/python-format-metadata-reference.json"
    raw = path.read_text(encoding="utf-8")
    assert hashlib.sha256(raw.encode()).hexdigest() == (
        "4424fd7d967eea587ff516dd7bca6f0fa326ec94bb80176d23d57321f669f8b1"
    )
    value = json.loads(raw)
    assert value["schema"] == "marty.python-format-metadata-reference/v2"
    assert value["python_version"] == "3.12.10"
    assert "host" not in value
    assert len(value["cases"]) == 463
    assert len(value["deterministic"]) == 356
    assert len(value["platform_state_bound"]) == 10
    assert len(value["identity_observations_not_exact_parity"]) == 97
    partitions = [
        value["deterministic"],
        value["platform_state_bound"],
        value["identity_observations_not_exact_parity"],
    ]
    assert sorted(row["id"] for rows in partitions for row in rows) == sorted(
        row["id"] for row in value["cases"]
    )
    assert all(
        set(row) == {"id", "template", "platform_state_bound", "qualification"}
        for row in value["platform_state_bound"]
    )
    for row in value["identity_observations_not_exact_parity"]:
        for shape in (row["first_shape"], row["repeat_shape"]):
            assert all("0x" not in literal for literal in shape["literals"])
            assert set(shape["owners"]) <= {
                "input_string",
                "str_type",
                "type_type",
                "object_type",
                "unqualified_object",
            }

    script = ROOT / "scripts/capture_python_format_metadata.py"
    spec = importlib.util.spec_from_file_location("python_format_metadata", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.observe() == value
    assert module.identity_shape("before 0xABCDEF after", {}) == {
        "literals": ["before ", " after"],
        "owners": ["unqualified_object"],
        "address_count": 1,
        "qualification": "shape observation only; not exact output or complete object support",
    }
