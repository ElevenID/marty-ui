"""Generate or verify the language-neutral gateway route contract.

The extractor deliberately uses only Python's AST. It does not import the
gateway, connect to providers, or depend on FastAPI internals, so the same JSON
can gate the Rust router while the Python implementation is being removed.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "services" / "gateway"
CONTRACT = ROOT / "contracts" / "gateway-routes.json"
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}


class ContractError(RuntimeError):
    """Raised when route source cannot be represented without guessing."""


@dataclass(frozen=True, order=True)
class Route:
    path: str
    method: str
    status_code: int
    include_in_schema: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "include_in_schema": self.include_in_schema,
        }


def _source_files() -> list[Path]:
    return [GATEWAY / "main.py", *sorted((GATEWAY / "routes").glob("*.py"))]


def _assignment_constants(tree: ast.AST) -> dict[str, str]:
    constants: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            target = node.target if isinstance(node, ast.AnnAssign) else node.targets[0]
            value = node.value
            if not isinstance(target, ast.Name) or value is None or target.id in constants:
                continue
            resolved = _string_value(value, constants)
            if resolved is not None:
                constants[target.id] = resolved
                changed = True
    return constants


def _string_value(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_value(node.left, constants)
        right = _string_value(node.right, constants)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
                continue
            if isinstance(value, ast.FormattedValue):
                resolved = _string_value(value.value, constants)
                if resolved is not None:
                    parts.append(resolved)
                    continue
            return None
        return "".join(parts)
    return None


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return node.attr if parent is None else f"{parent}.{node.attr}"
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _router_prefixes(path: Path, tree: ast.AST, constants: dict[str, str]) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        target = node.target if isinstance(node, ast.AnnAssign) else node.targets[0]
        value = node.value
        if not isinstance(target, ast.Name) or not isinstance(value, ast.Call):
            continue
        if _call_name(value.func) != "APIRouter":
            continue
        prefix_node = _keyword(value, "prefix")
        prefix = "" if prefix_node is None else _string_value(prefix_node, constants)
        if prefix is None:
            raise ContractError(f"{path}: unresolved prefix for router {target.id}")
        prefixes[target.id] = prefix
    return prefixes


def _declared_status(call: ast.Call) -> int:
    node = _keyword(call, "status_code")
    if node is None:
        return 200
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    name = _call_name(node)
    if name:
        match = re.search(r"HTTP_(\d{3})_", name)
        if match:
            return int(match.group(1))
    raise ContractError(f"unresolved declared status: {ast.unparse(node)}")


def _declared_schema_visibility(call: ast.Call) -> bool:
    node = _keyword(call, "include_in_schema")
    if node is None:
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    raise ContractError(f"unresolved include_in_schema: {ast.unparse(node)}")


def _decorator_methods(call: ast.Call, attribute: str) -> list[str]:
    if attribute in HTTP_METHODS:
        return [attribute.upper()]
    if attribute != "api_route":
        return []
    node = _keyword(call, "methods")
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        raise ContractError("api_route must declare a literal methods collection")
    methods: list[str] = []
    for item in node.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            raise ContractError("api_route method must be a string literal")
        methods.append(item.value.upper())
    return methods


def _routes_for_file(path: Path) -> list[Route]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    constants = _assignment_constants(tree)
    prefixes = _router_prefixes(path, tree, constants)
    routes: list[Route] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            owner = _call_name(decorator.func.value)
            if owner is None or (owner != "app" and owner not in prefixes):
                continue
            methods = _decorator_methods(decorator, decorator.func.attr)
            if not methods:
                continue
            if not decorator.args:
                raise ContractError(f"{path}:{node.lineno}: route has no path")
            relative = _string_value(decorator.args[0], constants)
            if relative is None:
                raise ContractError(f"{path}:{node.lineno}: unresolved route path")
            prefix = "" if owner == "app" else prefixes[owner]
            full_path = f"{prefix}{relative}" or "/"
            for method in methods:
                routes.append(
                    Route(
                        path=full_path,
                        method=method,
                        status_code=_declared_status(decorator),
                        include_in_schema=_declared_schema_visibility(decorator),
                    )
                )
    return routes


def _middleware_contract() -> dict[str, list[str]]:
    path = GATEWAY / "main.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    registration: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if _call_name(node.func.value) != "app" or node.func.attr != "add_middleware":
            continue
        if not node.args or (name := _call_name(node.args[0])) is None:
            raise ContractError(f"{path}:{node.lineno}: unresolved middleware")
        registration.append(name)
    return {
        "registration_order": registration,
        "execution_order": list(reversed(registration)),
    }


def generate() -> dict[str, Any]:
    routes = sorted(route for path in _source_files() for route in _routes_for_file(path))
    duplicates = sorted({route for route in routes if routes.count(route) > 1})
    if duplicates:
        rendered = ", ".join(f"{route.method} {route.path}" for route in duplicates)
        raise ContractError(f"duplicate route declarations: {rendered}")
    return {
        "schema_version": 1,
        "route_count": len(routes),
        "middleware": _middleware_contract(),
        "routes": [route.as_dict() for route in routes],
    }


def _serialized(contract: dict[str, Any]) -> str:
    return json.dumps(contract, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="replace the checked-in contract")
    mode.add_argument("--check", action="store_true", help="verify the checked-in contract")
    args = parser.parse_args()

    generated = _serialized(generate())
    if args.write:
        CONTRACT.parent.mkdir(parents=True, exist_ok=True)
        CONTRACT.write_text(generated, encoding="utf-8", newline="\n")
        print(f"wrote {CONTRACT.relative_to(ROOT)}")
        return 0

    if not CONTRACT.exists():
        print(f"missing {CONTRACT.relative_to(ROOT)}", file=sys.stderr)
        return 1
    current = CONTRACT.read_text(encoding="utf-8")
    if current != generated:
        print(
            "gateway route contract drifted; run scripts/gateway_route_contract.py --write "
            "only for a reviewed public-contract change",
            file=sys.stderr,
        )
        return 1
    print(f"gateway route contract valid ({generate()['route_count']} routes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
