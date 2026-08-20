"""Freeze the service-to-service signing compatibility surface."""

from __future__ import annotations

import json
from pathlib import Path

from gateway.main import create_app


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-internal-signing-behavior.json"
    ).read_text(encoding="utf-8")
)


def test_python_internal_signing_routes_match_shared_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    actual = {
        (method, route.path)
        for route in create_app().routes
        for method in getattr(route, "methods", set())
    }
    expected = {(case["method"], case["path"]) for case in CONTRACT["routes"]}
    assert len(expected) == 14
    assert expected <= actual
