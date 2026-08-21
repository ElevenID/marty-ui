import ast
import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from trust_profile import main as trust_profile
from trust_profile.infrastructure import models


ROOT = Path(__file__).resolve().parents[3]
CONTRACT = json.loads(
    (ROOT / "contracts" / "trust-profile-service-behavior.json").read_text()
)


def test_complete_http_surface_matches_language_neutral_contract() -> None:
    prefixes = (
        "/v1/trust-profiles",
        "/internal/v1/trust-profiles",
        "/internal/v1/resource-owners",
        "/v1/organizations/",
        "/v1/trust-frameworks",
        "/v1/trust-registry",
        "/v1/issuer-entities",
    )
    actual = {
        (method, route.path)
        for route in trust_profile.app.routes
        if route.path.startswith(prefixes)
        for method in route.methods
        if method in {"GET", "POST", "PUT", "PATCH", "DELETE"}
    }
    expected = {tuple(operation) for operation in CONTRACT["http_operations"]}
    assert actual == expected


def test_domain_enums_and_system_frameworks_match_shared_contract() -> None:
    enum_types = {
        "trust_profile_status": trust_profile.TrustProfileStatus,
        "trust_profile_type": trust_profile.TrustProfileType,
        "compliance_status": trust_profile.ComplianceStatus,
        "trust_source_type": trust_profile.TrustSourceType,
        "revocation_check_mode": trust_profile.RevocationCheckMode,
        "issuer_entity_type": trust_profile.IssuerEntityType,
        "issuer_compliance_status": trust_profile.IssuerEntityComplianceStatus,
        "relationship_status": trust_profile.TrustRelationshipStatus,
        "cascade_revocation_policy": trust_profile.CascadeRevocationPolicy,
        "trust_anchor_type": trust_profile.TrustAnchorType,
        "registry_operation": trust_profile.TrustRegistryOperation,
        "registry_source": trust_profile.TrustRegistrySource,
    }
    assert {
        name: [member.value for member in enum_type]
        for name, enum_type in enum_types.items()
    } == CONTRACT["domain_enums"]

    frameworks = {framework.code: framework for framework in trust_profile.SYSTEM_TRUST_FRAMEWORKS}
    assert set(frameworks) == set(CONTRACT["system_frameworks"])
    for code, expected in CONTRACT["system_frameworks"].items():
        assert frameworks[code].default_formats == expected["formats"]
        assert frameworks[code].sync_config["mode"] == expected["sync_mode"]


def test_storage_and_all_historical_revisions_have_one_native_owner() -> None:
    tables = {
        table.name
        for table in models.mapper_registry.metadata.tables.values()
    }
    assert tables == set(CONTRACT["persistence_tables"])

    revisions: dict[str, str | None] = {}
    migration_directory = (
        ROOT / "services" / "trust_profile" / "infrastructure" / "migrations" / "versions"
    )
    for path in migration_directory.glob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        values: dict[str, str | None] = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in {"revision", "down_revision"}:
                values[target.id] = ast.literal_eval(node.value)
        revisions[values["revision"]] = values["down_revision"]

    assert revisions == dict(CONTRACT["migration_chain"])


def test_registry_transport_and_security_obligations_are_frozen() -> None:
    registry = CONTRACT["registry_sync"]
    assert registry["protocol"] == "MARTY_TRUST_REGISTRY_SYNC_V1"
    assert registry["max_response_bytes"] == 2 * 1024 * 1024
    assert registry["max_pages"] == 100
    assert all(registry[key] is True for key in registry if key not in {
        "protocol", "max_response_bytes", "max_pages"
    })
    assert all(CONTRACT["security"].values())


def test_security_domain_vectors_match_the_surviving_python_oracle() -> None:
    domain = CONTRACT["domain_cases"]
    for case in domain["accreditations"]:
        if "error" in case:
            with pytest.raises(ValueError):
                trust_profile._normalize_accreditations(case["input"])
        else:
            assert trust_profile._normalize_accreditations(case["input"]) == case["expected"]

    for case in domain["jurisdictions"]:
        if "error" in case:
            with pytest.raises(HTTPException):
                trust_profile._normalize_jurisdiction_filter(case["input"])
        else:
            assert trust_profile._normalize_jurisdiction_filter(case["input"]) == case["expected"]

    for case in domain["custody_metadata"]:
        with pytest.raises(ValueError, match=case["rejected_field"]):
            trust_profile._reject_private_custody_metadata(case["input"])
        assert trust_profile._sanitize_private_custody_metadata(case["input"]) == case["sanitized"]
