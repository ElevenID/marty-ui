import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from services.auth.domain.entities import AuthenticatedUser, OIDCUserInfo, Session, SessionStatus


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "contracts" / "auth-behavior.json").read_text(encoding="utf-8"))


def _http_routes() -> set[tuple[str, str]]:
    source = ROOT / "services" / "auth" / "infrastructure" / "adapters" / "http_adapter.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    prefixes = {"router": "/v1/auth", "internal_router": "/internal/v1/auth"}
    routes: set[tuple[str, str]] = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            owner = decorator.func.value
            if not isinstance(owner, ast.Name) or owner.id not in prefixes or not decorator.args:
                continue
            path = ast.literal_eval(decorator.args[0])
            routes.add((decorator.func.attr.upper(), prefixes[owner.id] + path))
    return routes


def test_python_http_surface_matches_language_neutral_contract() -> None:
    expected = {(route["method"], route["path"]) for route in CONTRACT["http_routes"]}
    assert _http_routes() == expected


def test_python_claim_mapping_matches_language_neutral_contract() -> None:
    for case in CONTRACT["claim_cases"]:
        actual = OIDCUserInfo.from_claims(case["primary"], case["secondary"])
        expected = case["expected"]
        assert actual.sub == expected["sub"]
        assert actual.email == expected["email"]
        assert actual.email_verified == expected.get("email_verified", False)
        assert actual.organization_id == expected["organization_id"]
        assert actual.organization_name == expected["organization_name"]
        assert actual.roles == expected["roles"]


def test_python_display_and_session_behavior_matches_language_neutral_contract() -> None:
    for case in CONTRACT["display_name_cases"]:
        user = AuthenticatedUser(
            user_id="user-1",
            email=case["email"],
            username=case["username"],
            given_name=case["given_name"],
            family_name=case["family_name"],
        )
        assert user.display_name == case["expected"]

    user = AuthenticatedUser(user_id="user-1", email="alice@example.com")
    for case in CONTRACT["session_validity_cases"]:
        now = datetime.now(timezone.utc)
        session = Session(
            session_id="session-1",
            user=user,
            created_at=now,
            expires_at=now + timedelta(seconds=case["expires_offset_seconds"]),
            last_activity=now,
            status=SessionStatus(case["status"]),
        )
        assert session.is_valid == case["valid"]
        if not case["valid"]:
            assert session.remaining_ttl_seconds == case["remaining_ttl_seconds"]
