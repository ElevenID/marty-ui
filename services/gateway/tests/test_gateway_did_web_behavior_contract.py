"""Run public did:web adapter fixtures against the Python baseline."""

from __future__ import annotations

import json
from pathlib import Path

from gateway.routes import signing_keys


CONTRACT = json.loads(
    (Path(__file__).parents[3] / "contracts" / "gateway-did-web-behavior.json").read_text(
        encoding="utf-8"
    )
)


def test_python_did_web_adapter_matches_shared_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    for case in CONTRACT["authority_cases"]:
        assert signing_keys._did_web_method_authority(case["input"]) == case["expected"]
    for case in CONTRACT["slug_cases"]:
        normalized = case["input"].strip().lower()
        actual = normalized if signing_keys._SLUG_PATTERN.fullmatch(normalized) else None
        assert actual == case["expected"]
    for case in CONTRACT["retarget_cases"]:
        assert signing_keys._retarget_did_document(
            case["input"], case["target"]
        ) == case["expected"]
