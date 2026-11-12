"""Complete row inventory cannot silently omit or truncate retained relations."""

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parents[1] / "scripts"),
    str(Path(__file__).resolve().parent),
]
import selfhost_windows_product_probe as probe  # noqa: E402
from test_windows_product_probe import PROJECT, item  # noqa: E402


def records():
    return [
        {
            "kind": "inventory",
            "supported": True,
            "tables": [
                {"schema": "custom", "name": "accounts"},
                {"schema": "custom", "name": "sequence"},
            ],
        },
        {
            "kind": "rows",
            "schema": "custom",
            "name": "accounts",
            "rows": 2,
            "sha256": "a" * 64,
        },
        {
            "kind": "rows",
            "schema": "custom",
            "name": "sequence",
            "rows": 1,
            "sha256": "b" * 64,
        },
    ]


def capture(monkeypatch, values):
    def text(docker, args, *, stdin_bytes):
        assert docker is sentinel
        assert args[:4] == ["exec", "--interactive", "--user", "postgres"]
        assert probe.PG_OPTIONS in args and args[-3:] == [
            "--dbname",
            "marty",
            "--file=-",
        ]
        script = stdin_bytes.decode()
        assert script.startswith(
            "\\set ON_ERROR_STOP on\nBEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;"
        )
        assert script.endswith("\\gexec\nCOMMIT;\n")
        assert "%I.%I" in script and "'r','p','m','S'" in script
        assert 'jsonb_agg(t::text ORDER BY t::text COLLATE "C")' in script
        assert (
            "pg_largeobject_metadata" in script
            and "tn.nspname <> 'pg_catalog'" in script
        )
        assert (
            "SET LOCAL TimeZone='UTC'" in script
            and "SET LOCAL extra_float_digits=3" in script
        )
        assert "LIMIT 2049" in script and "LIMIT 257" in script
        assert "DELETE" not in script and "UPDATE" not in script
        return "\n".join(map(json.dumps, values))

    sentinel = object()
    monkeypatch.setattr(probe, "_text", text)
    return probe.retained_rows_snapshot(sentinel, [item("postgres")], PROJECT)


def test_all_physical_fields_and_sequence_rows_have_no_exclusion_input(monkeypatch):
    result = capture(monkeypatch, records())
    assert result == {
        "schema": "marty.windows-retained-application-rows/v1",
        "database": "marty",
        "tables": {
            "custom.accounts": {"rows": 2, "sha256": "a" * 64},
            "custom.sequence": {"rows": 1, "sha256": "b" * 64},
        },
    }


@pytest.mark.parametrize(
    "fault",
    [
        "missing-inventory",
        "empty",
        "missing-row",
        "extra-row",
        "duplicate",
        "reordered",
        "foreign",
        "string-support",
        "extra-inventory",
        "extra-row-field",
        "wrong-kind",
        "wrong-table",
        "bool-count",
        "negative-count",
        "too-many-rows",
        "invalid-hash",
        "injectable-name",
        "bad-inventory-shape",
        "too-many-relations",
    ],
)
def test_incomplete_ambiguous_or_truncated_snapshots_refuse(monkeypatch, fault):
    value = deepcopy(records())
    if fault == "missing-inventory":
        value.pop(0)
    elif fault == "empty":
        value = [{"kind": "inventory", "supported": True, "tables": []}]
    elif fault == "missing-row":
        value.pop()
    elif fault == "extra-row":
        value.append(deepcopy(value[-1]))
    elif fault == "duplicate":
        value[0]["tables"][1] = deepcopy(value[0]["tables"][0])
    elif fault == "reordered":
        value[0]["tables"].reverse()
    elif fault == "foreign":
        value[0]["supported"] = False
    elif fault == "string-support":
        value[0]["supported"] = "true"
    elif fault == "extra-inventory":
        value[0]["extra"] = True
    elif fault == "extra-row-field":
        value[1]["payload"] = "must not leave PostgreSQL"
    elif fault == "wrong-kind":
        value[1]["kind"] = "inventory"
    elif fault == "wrong-table":
        value[1]["name"] = "other"
    elif fault == "bool-count":
        value[1]["rows"] = True
    elif fault == "negative-count":
        value[1]["rows"] = -1
    elif fault == "too-many-rows":
        value[1]["rows"] = probe.ROW_LIMIT + 1
    elif fault == "invalid-hash":
        value[1]["sha256"] = "ordinary row payload"
    elif fault == "injectable-name":
        value[0]["tables"][0]["name"] = "accounts;DELETE"
    elif fault == "bad-inventory-shape":
        value[0]["tables"] = {"custom": "accounts"}
    else:
        value += [deepcopy(value[-1]) for _ in range(probe.RELATION_LIMIT)]
    with pytest.raises(ValueError):
        capture(monkeypatch, value)
