import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from services.organization.application.ports import (
    CreateOrganizationCommand,
    UpdateOrganizationCommand,
)
from services.organization.application.use_cases import OrganizationUseCase
from services.organization.domain.entities import (
    JoinMechanism,
    MemberStatus,
    OrganizationType,
)
from services.organization.infrastructure.adapters.http_adapter import (
    CreateOrganizationRequest,
)


def _fixture() -> dict:
    root = Path(__file__).resolve().parents[3]
    return json.loads(
        (root / "contracts" / "organization-application-behavior.json").read_text(
            encoding="utf-8"
        )
    )


class _OrganizationRepository:
    def __init__(self) -> None:
        self.organizations = {}

    async def save(self, organization) -> None:
        self.organizations[organization.id] = organization

    async def get_by_id(self, organization_id):
        return self.organizations.get(organization_id)

    async def list_all(self, limit=100, offset=0):
        return list(self.organizations.values())[offset : offset + limit]


class _MemberRepository:
    def __init__(self) -> None:
        self.members = []

    async def save(self, member) -> None:
        self.members.append(member)

    async def list_by_user(self, user_id):
        return [member for member in self.members if member.user_id == user_id]


class _EventPublisher:
    def __init__(self) -> None:
        self.events = []

    async def publish(self, event) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_python_and_rust_share_organization_application_behavior() -> None:
    fixture = _fixture()
    assert fixture["schema_version"] == 1
    organizations = _OrganizationRepository()
    members = _MemberRepository()
    events = _EventPublisher()
    use_case = OrganizationUseCase(organizations, members, events)

    create = fixture["create"]
    organization = await use_case.create_organization(
        CreateOrganizationCommand(
            name=create["name"],
            owner_id=create["owner_id"],
            org_type=OrganizationType(create["org_type"]),
            display_name=create["display_name"],
            description=create["description"],
            contact_email=create["contact_email"],
            visibility=create["visibility"],
            join_mechanism=JoinMechanism(create["join_mechanism"]),
            requires_approval=create["requires_approval"],
        )
    )
    expected = create["expected"]
    assert organization.display_name == expected["display_name"]
    assert organization.slug.startswith(expected["slug_prefix"])
    assert organization.status.value == expected["status"]
    assert organization.plan == expected["plan"]
    assert organization.is_discoverable is expected["is_discoverable"]
    assert organization.contact_email == create["contact_email"]
    assert members.members[0].organization_id == organization.id
    assert members.members[0].user_id == create["owner_id"]
    assert members.members[0].status == MemberStatus.ACTIVE
    assert events.events[-1].name == create["name"]

    update = fixture["update"]
    expected_existing = update["expected_existing_setting"]
    organization.settings["existing_setting"] = expected_existing
    updated = await use_case.update_organization(
        UpdateOrganizationCommand(
            organization_id=organization.id,
            name=update["name"],
            description=update["description"],
            contact_phone=update["contact_phone"],
            visibility=update["visibility"],
            join_mechanism=JoinMechanism(update["join_mechanism"]),
            settings=update["settings"],
            fields_set=frozenset(update["fields_set"]),
        )
    )
    assert events.events[-1].updated_fields == update["expected_updated_fields"]
    assert updated.description is None
    assert updated.contact_phone == update["contact_phone"]
    assert updated.is_discoverable is True
    assert updated.join_mechanism == JoinMechanism.OPEN
    assert updated.settings["existing_setting"] == expected_existing
    assert updated.settings["new_setting"] == "enabled"


def test_private_open_admission_contract_fails_closed() -> None:
    fixture = _fixture()["invalid_admission"]
    with pytest.raises(ValidationError, match="open join requires PUBLIC visibility"):
        CreateOrganizationRequest(
            name="private-open",
            display_name="Private Open",
            visibility=fixture["visibility"],
            join_mechanism=fixture["join_mechanism"],
        )
