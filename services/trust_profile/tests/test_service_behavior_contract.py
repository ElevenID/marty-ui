import ast
import json
from datetime import datetime, timedelta, timezone
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

    frameworks = {
        framework.code: framework for framework in trust_profile.SYSTEM_TRUST_FRAMEWORKS
    }
    assert set(frameworks) == set(CONTRACT["system_frameworks"])
    for code, expected in CONTRACT["system_frameworks"].items():
        assert frameworks[code].default_formats == expected["formats"]
        assert frameworks[code].sync_config["mode"] == expected["sync_mode"]


def test_storage_and_all_historical_revisions_have_one_native_owner() -> None:
    tables = {table.name for table in models.mapper_registry.metadata.tables.values()}
    assert tables == set(CONTRACT["persistence_tables"])

    revisions: dict[str, str | None] = {}
    migration_directory = (
        ROOT
        / "services"
        / "trust_profile"
        / "infrastructure"
        / "migrations"
        / "versions"
    )
    for path in migration_directory.glob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        values: dict[str, str | None] = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in {
                "revision",
                "down_revision",
            }:
                values[target.id] = ast.literal_eval(node.value)
        revisions[values["revision"]] = values["down_revision"]

    assert revisions == dict(CONTRACT["migration_chain"])

    registry_imports = CONTRACT["registry_import_storage_capabilities"]
    assert set(models.trust_registry_sources_table.c.keys()) == set(
        registry_imports["source_fields"]
    )
    assert set(models.trust_registry_issuers_table.c.keys()) == set(
        registry_imports["issuer_fields"]
    )


def test_registry_transport_and_security_obligations_are_frozen() -> None:
    registry = CONTRACT["registry_sync"]
    assert registry["protocol"] == "MARTY_TRUST_REGISTRY_SYNC_V1"
    assert registry["max_response_bytes"] == 2 * 1024 * 1024
    assert registry["max_pages"] == 100
    assert all(
        registry[key] is True
        for key in registry
        if key not in {"protocol", "max_response_bytes", "max_pages"}
    )
    assert all(CONTRACT["security"].values())


def test_security_domain_vectors_match_the_surviving_python_oracle() -> None:
    domain = CONTRACT["domain_cases"]
    for case in domain["accreditations"]:
        if "error" in case:
            with pytest.raises(ValueError):
                trust_profile._normalize_accreditations(case["input"])
        else:
            assert (
                trust_profile._normalize_accreditations(case["input"])
                == case["expected"]
            )

    for case in domain["jurisdictions"]:
        if "error" in case:
            with pytest.raises(HTTPException):
                trust_profile._normalize_jurisdiction_filter(case["input"])
        else:
            assert (
                trust_profile._normalize_jurisdiction_filter(case["input"])
                == case["expected"]
            )

    for case in domain["custody_metadata"]:
        with pytest.raises(ValueError, match=case["rejected_field"]):
            trust_profile._reject_private_custody_metadata(case["input"])
        assert (
            trust_profile._sanitize_private_custody_metadata(case["input"])
            == case["sanitized"]
        )


@pytest.mark.asyncio
async def test_repository_vectors_match_the_surviving_python_oracle() -> None:
    expected = CONTRACT["repository_cases"]
    repo = trust_profile.InMemoryTrustProfileRepository()
    now = datetime(2026, 8, 21, tzinfo=timezone.utc)

    for code, system in (("CUSTOM", False), ("ICAO", True), ("AAMVA", True)):
        await repo.save_framework(
            trust_profile.TrustFramework(code=code, display_name=code, is_system=system)
        )
    assert [item.code for item in await repo.list_frameworks()] == expected[
        "framework_order"
    ]

    registry_ids = [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
    ]
    entries = [
        trust_profile.TrustRegistryEntry(
            id=registry_ids[0],
            anchor_type=trust_profile.TrustAnchorType.CSCA,
            country_code="US",
            sequence=1,
            is_current=True,
        ),
        trust_profile.TrustRegistryEntry(
            id=registry_ids[1],
            anchor_type=trust_profile.TrustAnchorType.CSCA,
            country_code="US",
            sequence=2,
            is_current=False,
        ),
        trust_profile.TrustRegistryEntry(
            id=registry_ids[2],
            anchor_type=trust_profile.TrustAnchorType.DSC,
            country_code="US",
            sequence=3,
            is_current=True,
        ),
    ]
    for entry in entries:
        await repo.save_registry_entry(entry)
    selected = await repo.list_registry_entries(
        country_code="us", current_only=True, since_sequence=1
    )
    assert [entry.id for entry in selected] == expected["registry"][
        "current_country_after_sequence"
    ]
    assert await repo.get_registry_status() == expected["registry"]["status"]

    profile_id = "44444444-4444-4444-8444-444444444444"
    profile = trust_profile.TrustProfile(
        id=profile_id, organization_id="org-a", name="Profile", updated_at=now
    )
    assert await repo.save_profile(profile)
    stale = now - timedelta(seconds=1)
    assert (
        await repo.save_profile(profile, expected_updated_at=stale)
        is expected["optimistic_update_conflict"]
    )

    issuers = [
        trust_profile.IssuerEntity(
            id="55555555-5555-4555-8555-555555555555",
            organization_id="org-a",
            issuer_id="did:web:org-a.example",
            display_name="A",
        ),
        trust_profile.IssuerEntity(
            id="66666666-6666-4666-8666-666666666666",
            organization_id=None,
            issuer_id="did:web:global.example",
            display_name="B",
        ),
        trust_profile.IssuerEntity(
            id="77777777-7777-4777-8777-777777777777",
            organization_id="org-b",
            issuer_id="did:web:system.example",
            display_name="C",
            is_system_issuer=True,
        ),
        trust_profile.IssuerEntity(
            id="88888888-8888-4888-8888-888888888888",
            organization_id="org-b",
            issuer_id="did:web:private.example",
            display_name="D",
        ),
    ]
    for issuer in issuers:
        await repo.save_issuer_entity(issuer)
    visible = await repo.list_issuer_entities("org-a")
    assert [issuer.id for issuer in visible] == expected["organization_visibility"]

    first_link = trust_profile.TrustProfileIssuer(
        trust_profile_id=profile_id, issuer_id=issuers[0].id
    )
    await repo.save_profile_issuer(first_link)
    await repo.delete_profile(profile_id)
    assert (await repo.get_profile_issuer(first_link.id) is None) is expected[
        "profile_delete_cascades_relationships"
    ]

    second_profile = trust_profile.TrustProfile(organization_id="org-a", name="Second")
    await repo.save_profile(second_profile)
    second_link = trust_profile.TrustProfileIssuer(
        trust_profile_id=second_profile.id, issuer_id=issuers[0].id
    )
    await repo.save_profile_issuer(second_link)
    await repo.delete_issuer_entity(issuers[0].id)
    assert (await repo.get_profile_issuer(second_link.id) is None) is expected[
        "issuer_delete_cascades_relationships"
    ]
