import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "contracts" / "credential-template-system-catalog.json"
WALLET_FIXTURE = ROOT / "contracts" / "credential-template-wallet-compatibility.json"
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


def test_python_derived_wallet_profiles_match_the_language_neutral_contract() -> None:
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "DERIVED_WALLET_PROFILES"
    )
    assert isinstance(assignment.value, ast.Dict)
    actual_names = {
        str(next(keyword.value.value for keyword in value.keywords if keyword.arg == "name"))
        for value in assignment.value.values
        if isinstance(value, ast.Call)
    }
    contract = json.loads(WALLET_FIXTURE.read_text(encoding="utf-8"))
    expected_names = {
        profile["name"]
        for profile in contract["profiles"]
        if profile["format"] != "VDS_NC"
    }
    assert actual_names == expected_names
