"""Keep the extracted fast owner and retained signing boundaries explicitly mapped."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.ci.check_python_value_fast_obligations import validate

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads(
    (ROOT / "contracts/python-value-fast-obligations.json").read_text(encoding="utf-8")
)


def test_current_source_and_targets_match_bounded_inventory() -> None:
    validate(MANIFEST)
    assert len(MANIFEST["cases"]) == 4
    assert len(MANIFEST["retained_signing_detail"]["tests"]) == 12
    assert len(MANIFEST["retained_http"]["tests"]) == 7
    assert all(
        case["cheapest_proving_layer"] == "pure unit" for case in MANIFEST["cases"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "missing_unit",
        "duplicate_unit",
        "missing_assertion",
        "wrong_owner",
        "missing_unicode_input",
        "missing_signing_case",
        "wrong_http_case",
    ],
)
def test_inventory_drift_fails_closed(change: str) -> None:
    manifest = deepcopy(MANIFEST)
    if change == "missing_unit":
        manifest["cases"].pop()
    elif change == "duplicate_unit":
        manifest["cases"][1]["test"] = manifest["cases"][0]["test"]
    elif change == "missing_assertion":
        manifest["cases"][0]["assertion"] = ""
    elif change == "wrong_owner":
        manifest["owner"]["package"] = "marty-issuance-service"
    elif change == "missing_unicode_input":
        manifest["owner"]["common_inputs"].remove(
            "contracts/python-text-semantics.json"
        )
    elif change == "missing_signing_case":
        manifest["retained_signing_detail"]["tests"].pop()
    else:
        manifest["retained_http"]["tests"][0] = "signing_http_response::tests::unknown"
    with pytest.raises(ValueError):
        validate(manifest)
