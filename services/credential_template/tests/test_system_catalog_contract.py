import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "contracts" / "credential-template-system-catalog.json"
WALLET_FIXTURE = ROOT / "contracts" / "credential-template-wallet-compatibility.json"
REGISTRY_FIXTURE = ROOT / "contracts" / "credential-template-registry-behavior.json"
INTERNAL_FIXTURE = ROOT / "contracts" / "credential-template-internal-behavior.json"
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


def test_python_registry_behavior_matches_the_language_neutral_contract() -> None:
    from services.credential_template import main as credential_template

    contract = json.loads(REGISTRY_FIXTURE.read_text(encoding="utf-8"))
    active_wallets = [
        wallet
        for wallet in credential_template.SYSTEM_WALLET_CATALOG
        if wallet.is_active
    ]
    assert len(credential_template.SYSTEM_WALLET_CATALOG) == contract["catalog"][
        "total_global_wallets"
    ]
    assert len(active_wallets) == contract["catalog"]["active_global_wallets"]
    assert len(credential_template.SYSTEM_DELIVERY_DESTINATION_CATALOG) == contract[
        "catalog"
    ]["system_delivery_destinations"]
    for source, expected in (
        contract["normalization"]["authorization_code_protocol"],
        contract["normalization"]["pre_authorized_protocol"],
    ):
        assert credential_template._normalize_issuance_protocol(source) == expected


def test_python_internal_oid4vci_behavior_matches_the_language_neutral_contract() -> None:
    from services.credential_template import main as credential_template

    contract = json.loads(INTERNAL_FIXTURE.read_text(encoding="utf-8"))
    for case in contract["credential_configurations"]:
        template = credential_template.CredentialTemplate(
            name=case["credential_type"],
            credential_type=case["credential_type"],
            credential_payload_format=case["credential_format"],
            supported_formats=[credential_template.CredentialFormat(case["credential_format"])],
            vct=case.get("vct", ""),
            doctype=case.get("doctype"),
            issuer_did="did:web:issuer.example",
            issuer_algorithm="ES256",
        )
        configuration = credential_template._oid4vci_configuration(template)
        assert configuration is not None
        assert configuration["format"] == case["expected_format"]
        assert case["expected_identifier_field"] in configuration

    for credential_format in contract["skipped_formats"]:
        template = credential_template.CredentialTemplate(
            credential_type="UnsupportedCredential",
            credential_payload_format=credential_format,
            supported_formats=[credential_template.CredentialFormat(credential_format)],
            issuer_did="did:web:issuer.example",
        )
        assert credential_template._oid4vci_configuration(template) is None
