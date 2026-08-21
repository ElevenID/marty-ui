import ast
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "contracts" / "credential-template-service-surface.json"
GRPC_FIXTURE = ROOT / "contracts" / "credential-template-grpc-behavior.json"
MAIN = ROOT / "services" / "credential_template" / "main.py"
PROTO = ROOT / "proto" / "v1" / "credential_template_service.proto"


def _contract() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _python_http_routes() -> set[str]:
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    prefixes: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(node.value, ast.Call):
            continue
        if not isinstance(node.value.func, ast.Name) or node.value.func.id != "APIRouter":
            continue
        for keyword in node.value.keywords:
            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                prefixes[target.id] = str(keyword.value.value)

    routes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            owner = decorator.func.value
            if not isinstance(owner, ast.Name) or owner.id not in prefixes:
                continue
            if decorator.func.attr not in {"get", "post", "put", "patch", "delete"}:
                continue
            if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                continue
            routes.add(
                f"{decorator.func.attr.upper()} {prefixes[owner.id]}{decorator.args[0].value}"
            )
    return routes


def test_python_http_surface_matches_the_language_neutral_contract() -> None:
    assert _python_http_routes() == set(_contract()["http_routes"])


def test_proto_surface_matches_the_language_neutral_contract() -> None:
    methods = set(re.findall(r"\brpc\s+(\w+)\s*\(", PROTO.read_text(encoding="utf-8")))
    assert methods == set(_contract()["grpc_methods"])


def test_grpc_behavior_oracle_covers_every_declared_method() -> None:
    behavior = json.loads(GRPC_FIXTURE.read_text(encoding="utf-8"))
    assert set(behavior["methods"]) == set(_contract()["grpc_methods"])
