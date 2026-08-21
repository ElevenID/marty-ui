import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "contracts" / "credential-template-system-catalog.json"
MAIN = ROOT / "services" / "credential_template" / "main.py"


def _contract() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _catalog_ids(name: str) -> set[str]:
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == name
    )
    assert isinstance(assignment.value, ast.Tuple)
    ids: set[str] = set()
    for item in assignment.value.elts:
        assert isinstance(item, ast.Call)
        identifier = next(keyword.value for keyword in item.keywords if keyword.arg == "id")
        assert isinstance(identifier, ast.Constant)
        ids.add(str(identifier.value))
    return ids


def test_python_system_wallet_catalog_matches_the_language_neutral_contract() -> None:
    assert _catalog_ids("SYSTEM_WALLET_CATALOG") == set(_contract()["wallet_ids"])


def test_python_delivery_catalog_matches_the_language_neutral_contract() -> None:
    assert _catalog_ids("SYSTEM_DELIVERY_DESTINATION_CATALOG") == set(
        _contract()["destination_ids"]
    )
