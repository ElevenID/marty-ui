"""Check the immutable renewal corpus without importing legacy key-handling code."""

import hashlib
import json
from pathlib import Path


CORPUS = json.loads(
    (Path(__file__).resolve().parents[1] / "contracts/credential-renewal-python-reference.json")
    .read_text(encoding="utf-8")
)


def test_frozen_renewal_corpus_is_complete_and_lossless():
    assert CORPUS["schema"] == "marty.credential-renewal-python-reference/v1"
    names = [case["case"] for case in CORPUS["cases"]]
    assert len(names) == len(set(names)) == 31
    assert CORPUS["reference"]["source_commit"] == "87eae30788924921a42848425d315e2f33f7ae41"

    referenced = set()

    def visit(value):
        if isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            if "$ref" in value:
                assert set(value) == {"$ref"}
                prefix = "#/states/"
                assert value["$ref"].startswith(prefix)
                referenced.add(value["$ref"].removeprefix(prefix))
            else:
                for child in value.values():
                    visit(child)

    visit(CORPUS["cases"])
    assert len(referenced) == 22
    assert referenced == set(CORPUS["states"])
    for digest, snapshot in CORPUS["states"].items():
        encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(encoded).hexdigest() == digest
        assert set(snapshot) == {"transactions", "credentials", "delivery_records", "events"}
