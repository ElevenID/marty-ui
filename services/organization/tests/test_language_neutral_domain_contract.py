from __future__ import annotations

import ast
from datetime import datetime as RealDateTime, timedelta, timezone
import json
from pathlib import Path
import re

import pytest

from services.organization.domain import entities as entities_module
from services.organization.domain.entities import ApiKey, JoinCode, Member, Permission, Role
from services.organization.infrastructure.adapters import scim_http_adapter


ROOT = Path(__file__).resolve().parents[3]
DOMAIN_CONTRACT = json.loads(
    (ROOT / "contracts" / "organization-domain-behavior.json").read_text(encoding="utf-8")
)
SURFACE_CONTRACT = json.loads(
    (ROOT / "contracts" / "organization-service-surface.json").read_text(encoding="utf-8")
)
NOW = RealDateTime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


class FixedDateTime(RealDateTime):
    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return NOW.replace(tzinfo=None)
        return NOW.astimezone(tz)


def _permission(key: str) -> Permission:
    resource, action = key.split(":", 1)
    return Permission(resource=resource, action=action)


def test_python_domain_matches_language_neutral_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(entities_module, "datetime", FixedDateTime)

    for case in DOMAIN_CONTRACT["slug_cases"]:
        slug = entities_module.Organization._generate_slug(case["input"])
        assert slug.startswith(case["expected_prefix"]), case["name"]
        assert re.fullmatch(r".+-[0-9a-f]{8}", slug)

    join_contract = DOMAIN_CONTRACT["join_code"]
    for _ in range(64):
        code = JoinCode.generate_code()
        assert len(code) == join_contract["length"]
        assert set(code) <= set(join_contract["alphabet"])
    for case in join_contract["validity_cases"]:
        offset = case["expires_offset_seconds"]
        code = JoinCode(
            organization_id="20000000-0000-4000-8000-000000000001",
            code="ABCDEFGH",
            created_by="creator",
            expires_at=NOW + timedelta(seconds=offset) if offset is not None else None,
            max_uses=case["max_uses"],
            use_count=case["use_count"],
            is_active=case["active"],
        )
        assert code.is_valid() is case["valid"], case["name"]

    for case in DOMAIN_CONTRACT["member_cases"]:
        roles = [
            Role(
                organization_id="20000000-0000-4000-8000-000000000001",
                name=item["name"],
                permissions=[_permission(key) for key in item["permissions"]],
            )
            for item in case["roles"]
        ]
        member = Member(
            organization_id="20000000-0000-4000-8000-000000000001",
            user_id="subject",
            roles=roles,
        )
        assert member.has_org_console_access is case["has_console_access"], case["name"]
        assert member.is_owner is case["is_owner"], case["name"]

    for case in DOMAIN_CONTRACT["api_key_cases"]:
        key = ApiKey(
            organization_id="20000000-0000-4000-8000-000000000001",
            name="contract-key",
            key_prefix="mk_test_",
            key_hash=ApiKey.hash_key("mk_test_contract-secret"),
            scopes=case["stored_scopes"],
            created_by="creator",
        )
        assert key.verify("mk_test_contract-secret")
        assert not key.verify("mk_test_wrong-secret")
        assert key.has_scope(case["query"]) is case["allowed"], case["name"]


def test_python_scim_helpers_match_language_neutral_contract() -> None:
    for case in DOMAIN_CONTRACT["scim"]["pagination_cases"]:
        page, normalized_start, items_per_page = scim_http_adapter._paginate(
            list(range(case["total"])), case["start_index"], case["count"]
        )
        assert normalized_start == case["normalized_start"], case["name"]
        assert items_per_page == case["end_offset"] - case["start_offset"], case["name"]
        assert page == list(range(case["start_offset"], case["end_offset"])), case["name"]

    for case in DOMAIN_CONTRACT["scim"]["role_slugs"]:
        assert scim_http_adapter._slugify_role_name(case["input"]) == case["expected"]

    member = Member(
        organization_id="20000000-0000-4000-8000-000000000001",
        user_id="subject-1",
        email="person@example.com",
    )
    for filter_expression in DOMAIN_CONTRACT["scim"]["valid_user_filters"]:
        _matches, error = scim_http_adapter._user_matches_filter(
            member, [], filter_expression
        )
        assert error is None, filter_expression
    for filter_expression in DOMAIN_CONTRACT["scim"]["invalid_user_filters"]:
        _matches, error = scim_http_adapter._user_matches_filter(
            member, [], filter_expression
        )
        assert error is not None, filter_expression


def _python_http_routes() -> set[str]:
    routes: set[str] = set()
    for path in (ROOT / "services" / "organization").rglob("*.py"):
        if "migrations" in path.parts or "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prefixes: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if not (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "APIRouter"
            ):
                continue
            prefix = next(
                (
                    keyword.value.value
                    for keyword in value.keywords
                    if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant)
                ),
                "",
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    prefixes[target.id] = prefix
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in {"get", "post", "put", "patch", "delete"}
                ):
                    continue
                owner = decorator.func.value
                if not isinstance(owner, ast.Name):
                    continue
                route_path = ""
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    route_path = decorator.args[0].value
                routes.add(
                    f"{decorator.func.attr.upper()} {prefixes.get(owner.id, '')}{route_path}"
                )
    return routes


def test_frozen_surface_matches_python_and_declared_proto() -> None:
    assert _python_http_routes() == set(SURFACE_CONTRACT["http_routes"])

    proto = (ROOT / "proto" / "v1" / "organization_service.proto").read_text(
        encoding="utf-8"
    )
    declared_methods = set(re.findall(r"^\s*rpc\s+([A-Za-z0-9_]+)\s*\(", proto, re.MULTILINE))
    assert declared_methods == set(SURFACE_CONTRACT["grpc_methods"])

    grpc_source = (
        ROOT
        / "services"
        / "organization"
        / "infrastructure"
        / "adapters"
        / "grpc_adapter.py"
    ).read_text(encoding="utf-8")
    implemented_methods = set(
        re.findall(r"^\s+async def\s+([A-Z][A-Za-z0-9_]+)\s*\(", grpc_source, re.MULTILINE)
    )
    assert declared_methods - implemented_methods == set(
        SURFACE_CONTRACT["legacy_python_grpc_gap"]
    )
