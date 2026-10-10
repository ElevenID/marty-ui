"""The published provider route app is reused only within one mutable case."""

import ast
import runpy
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
PROVIDER_SOURCE = ROOT / "scripts/run_canvas_status_provider_oracle.py"


def test_route_app_is_once_per_case_and_keeps_repository_override() -> None:
    case_route_app = runpy.run_path(str(PROVIDER_SOURCE))["case_route_app"]
    calls = []
    port = object()
    repository = object()

    def factory():
        app = SimpleNamespace(dependency_overrides={})
        calls.append(app)
        return app

    first_case = [None]
    for _ in range(3):
        app = case_route_app(first_case, factory, port, repository)
        assert app is calls[0]
        assert app.dependency_overrides[port]() is repository
    assert len(calls) == 1

    second_case = [None]
    second_app = case_route_app(second_case, factory, port, repository)
    assert second_app is not first_case[0]
    assert len(calls) == 2


def test_all_three_routes_share_the_case_app_holder() -> None:
    tree = ast.parse(PROVIDER_SOURCE.read_text(encoding="utf-8"))
    observe = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "observe"
    )
    route_blocks = [
        node
        for node in ast.walk(observe)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "credential_routes"
    ]
    assert len(route_blocks) == 1
    expected = ast.parse(
        """if credential_routes:
    app_holder = [None]
    outcome["credential_routes"] = [
        await observe_credential_route(
            route_action, case, requests, sequence, app_holder
        )
        for route_action in ("suspend", "reinstate", "revoke")
    ]
"""
    ).body[0]
    assert ast.dump(route_blocks[0], include_attributes=False) == ast.dump(
        expected, include_attributes=False
    )
