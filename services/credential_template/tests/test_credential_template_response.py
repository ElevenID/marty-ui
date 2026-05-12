from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrganizationRoleSummary

from services.credential_template import main as credential_template


def _build_client(
	repo: credential_template.InMemoryCredentialTemplateRepository,
	wallet_repo: credential_template.InMemoryWalletRegistryRepository | None = None,
) -> tuple[TestClient, AsyncMock]:
	app = FastAPI()
	app.include_router(credential_template.router)
	app.include_router(credential_template.wallet_router)

	credential_template._repo = repo
	credential_template._wallet_repo = wallet_repo or credential_template.InMemoryWalletRegistryRepository()

	get_membership = AsyncMock(
		return_value=OrganizationMembership(
			user_id="user-1",
			organization_id="org-1",
			status="active",
			roles=[OrganizationRoleSummary(id="role-admin", name="admin", display_name="Admin")],
			has_org_console_access=True,
		)
	)
	org_client = SimpleNamespace(get_membership=get_membership)
	app.state.org_client = org_client
	return TestClient(app), get_membership


async def _save_template(
	repo: credential_template.InMemoryCredentialTemplateRepository,
) -> credential_template.CredentialTemplate:
	template = credential_template.CredentialTemplate(
		organization_id="org-1",
		name="Employee Badge",
		description="Protocol credential template",
		credential_type="EmployeeBadge",
		vct="https://credentials.example.com/EmployeeBadge",
		compliance_profile_id="123e4567-e89b-12d3-a456-426614174000",
		supported_formats=[credential_template.CredentialFormat.SD_JWT_VC],
		privacy_posture=credential_template.PrivacyPosture.SELECTIVE_DISCLOSURE,
		zk_predicate_claims=["age_over_18"],
	)
	template.claims.append(
		credential_template.ClaimDefinition(
			name="given_name",
			display_name="Given Name",
			description="Holder given name",
			claim_type=credential_template.ClaimType.STRING,
			required=True,
			selectively_disclosable=True,
		)
	)
	template.claims.append(
		credential_template.ClaimDefinition(
			name="birth_date",
			display_name="Birth Date",
			claim_type=credential_template.ClaimType.DATE,
			required=False,
			derivable=True,
		)
	)
	template.validity_rules.default_validity_days = 30
	template.validity_rules.renewable = True
	template.validity_rules.renewal_window_days = 7
	await repo.save(template)
	return template


def test_get_credential_template_returns_protocol_shape_only() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	client, _ = _build_client(repo)

	response = client.get(f"/v1/credential-templates/{template.id}")

	assert response.status_code == 200
	body = response.json()
	assert set(body) == {
		"id",
		"organization_id",
		"name",
		"description",
		"status",
		"credential_type",
		"compliance_profile_id",
		"vct",
		"credential_payload_format",
		"claims",
		"validity_rules",
		"privacy_posture",
		"auto_generate_artifacts",
		"created_at",
		"updated_at",
	}
	assert body["status"] == "DRAFT"
	assert body["credential_payload_format"] == "SD_JWT_VC"
	assert body["claims"] == [
		{
			"name": "given_name",
			"type": "STRING",
			"description": "Holder given name",
			"required": True,
			"selectively_disclosable": True,
			"display": {"label": "Given Name"},
		},
		{
			"name": "birth_date",
			"type": "DATE",
			"required": False,
			"selectively_disclosable": True,
			"derived_from": "birth_date",
			"display": {"label": "Birth Date"},
		},
	]
	assert body["validity_rules"] == {
		"ttl_seconds": 30 * 86400,
		"renewable": True,
		"reissue_within_seconds": 7 * 86400,
	}
	assert body["privacy_posture"] == {
		"default_disclose_all": False,
		"prefer_predicates": True,
		"sd_alg": "sha-256",
	}
	assert "doctype" not in body
	assert "supported_formats" not in body
	assert "wallet_configs" not in body


def test_create_credential_template_returns_canonical_protocol_fields() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	client, get_membership = _build_client(repo)

	response = client.post(
		"/v1/credential-templates",
		headers={"x-user-id": "user-1"},
		json={
			"organization_id": "org-1",
			"name": "PID Template",
			"description": "Canonical response contract",
			"credential_type": "PersonIdentificationData",
			"compliance_profile_id": "123e4567-e89b-12d3-a456-426614174000",
			"claims": [
				{
					"name": "given_name",
					"display_name": "Given Name",
					"claim_type": "string",
					"required": True,
				}
			],
			"supported_formats": ["sd_jwt_vc"],
			"credential_payload_format": "w3c_vcdm_v2_sd_jwt",
			"validity_rules": {
				"default_validity_days": 90,
				"renewable": False,
			},
		},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["status"] == "DRAFT"
	assert body["compliance_profile_id"] == "123e4567-e89b-12d3-a456-426614174000"
	assert body["credential_payload_format"] == "SD_JWT_VC"
	assert body["validity_rules"] == {
		"ttl_seconds": 90 * 86400,
		"renewable": False,
		"reissue_within_seconds": 30 * 86400,
	}
	assert body["claims"] == [
		{
			"name": "given_name",
			"type": "STRING",
			"required": True,
			"selectively_disclosable": True,
			"display": {"label": "Given Name"},
		}
	]
	get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_credential_template_accepts_canonical_validity_rule_fields() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	client, _ = _build_client(repo)

	response = client.post(
		"/v1/credential-templates",
		headers={"x-user-id": "user-1"},
		json={
			"organization_id": "org-1",
			"name": "Canonical validity template",
			"credential_type": "PersonIdentificationData",
			"compliance_profile_id": "123e4567-e89b-12d3-a456-426614174000",
			"claims": [
				{
					"name": "given_name",
					"display_name": "Given Name",
					"claim_type": "string",
					"required": True,
				}
			],
			"supported_formats": ["sd_jwt_vc"],
			"validity_rules": {
				"ttl_seconds": 14 * 86400,
				"renewable": True,
				"reissue_within_seconds": 2 * 86400,
				"not_before_offset_seconds": 900,
			},
		},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["validity_rules"] == {
		"ttl_seconds": 14 * 86400,
		"renewable": True,
		"reissue_within_seconds": 2 * 86400,
		"not_before_offset_seconds": 900,
	}


def test_update_credential_template_applies_canonical_validity_rule_changes() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	client, _ = _build_client(repo)

	response = client.patch(
		f"/v1/credential-templates/{template.id}",
		headers={"x-user-id": "user-1"},
		json={
			"validity_rules": {
				"ttl_seconds": 45 * 86400,
				"renewable": False,
				"reissue_within_seconds": 5 * 86400,
			}
		},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["validity_rules"] == {
		"ttl_seconds": 45 * 86400,
		"renewable": False,
		"reissue_within_seconds": 5 * 86400,
	}


def test_activate_credential_template_keeps_protocol_shape_stable() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	client, _ = _build_client(repo)

	response = client.post(
		f"/v1/credential-templates/{template.id}/activate",
		headers={"x-user-id": "user-1"},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["status"] == "ACTIVE"
	assert body["credential_type"] == "EmployeeBadge"
	assert body["updated_at"] != ""
	assert "issuer_requirements" not in body
	assert "version" not in body
