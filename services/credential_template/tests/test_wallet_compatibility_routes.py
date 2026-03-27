from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrgRole

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
			role=OrgRole.ADMIN,
			status="active",
		)
	)
	app.state.org_client = SimpleNamespace(get_membership=get_membership)
	return TestClient(app), get_membership


def _save_template(
	repo: credential_template.InMemoryCredentialTemplateRepository,
	*,
	organization_id: str = "org-1",
	compliance_code: str = "EUDI_PID",
	supported_format: credential_template.CredentialFormat = credential_template.CredentialFormat.SD_JWT_VC,
	wallet_configs: list[credential_template.WalletConfig] | None = None,
) -> credential_template.CredentialTemplate:
	template = credential_template.CredentialTemplate(
		organization_id=organization_id,
		name="PID Template",
		credential_type="PersonIdentificationData",
		supported_formats=[supported_format],
		compliance_profile={
			"compliance_code": compliance_code,
			"credential_format": supported_format.value,
		},
		issuance_protocol="oid4vci",
		wallet_configs=wallet_configs or [],
	)
	asyncio.run(repo.save(template))
	return template


def _save_override(
	repo: credential_template.InMemoryWalletRegistryRepository,
	*,
	organization_id: str = "org-1",
	merge_strategy: credential_template.MergeStrategy = credential_template.MergeStrategy.APPEND,
) -> credential_template.WalletRegistryEntry:
	entry = credential_template.WalletRegistryEntry(
		organization_id=organization_id,
		is_override=True,
		override_precedence=90,
		merge_strategy=merge_strategy,
		credential_format="SD_JWT_VC",
		issuance_protocol="OID4VCI_PRE_AUTH",
		compliance_profile_code="EUDI_PID",
		name="Org Wallet Overlay",
		description="Organization-specific overlay",
		wallet_apps=["Org Preferred Wallet"],
		specifications=["Org Spec"],
		platforms=["web"],
		deep_link_template="org-wallet://offer?uri={offer_uri}",
		supported_formats=["sd_jwt_vc"],
	)
	asyncio.run(repo.save(entry))
	return entry


def test_get_wallet_compatibility_derives_profile_from_template_fields():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = _save_template(
		repo,
		wallet_configs=[
			credential_template.WalletConfig(
				wallet_id="wr-eudi-wallet",
				deep_link_scheme="openid-credential-offer://",
				format_variant="sd_jwt_vc",
			)
		],
	)
	client, get_membership = _build_client(repo)

	response = client.get(
		f"/v1/credential-templates/{template.id}/wallet-compatibility",
		headers={"x-user-id": "user-1"},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["derived_from"] == {
		"credential_format": "SD_JWT_VC",
		"issuance_protocol": "OID4VCI_PRE_AUTH",
		"compliance_profile_code": "EUDI_PID",
	}
	# id and organization_id are None → excluded by exclude_none
	assert "id" not in body
	assert "organization_id" not in body
	assert body["name"] == "EUDI PID Wallet"
	assert body["is_override"] is False
	assert body["override_precedence"] == 0
	assert body["merge_strategy"] == "APPEND"
	assert "EUDI Wallet" in body["wallet_apps"]
	assert body["created_at"]
	assert body["updated_at"]
	assert body["template_wallet_configs"] == [
		{
			"wallet_id": "wr-eudi-wallet",
			"deep_link_scheme": "openid-credential-offer://",
			"format_variant": "sd_jwt_vc",
		}
	]
	get_membership.assert_awaited_once_with("user-1", "org-1")


def test_get_wallet_compatibility_applies_append_override_without_losing_template_configs():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	template = _save_template(
		repo,
		wallet_configs=[credential_template.WalletConfig(wallet_id="wr-lissi-001")],
	)
	override = _save_override(wallet_repo, merge_strategy=credential_template.MergeStrategy.APPEND)
	client, _ = _build_client(repo, wallet_repo)

	response = client.get(
		f"/v1/credential-templates/{template.id}/wallet-compatibility",
		headers={"x-user-id": "user-1"},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["is_override"] is True
	assert body["id"] == override.id
	assert body["organization_id"] == "org-1"
	assert body["applied_override_ids"] == [override.id]
	assert body["name"] == "Org Wallet Overlay"
	assert body["override_precedence"] == 90
	assert body["merge_strategy"] == "APPEND"
	assert "EUDI Wallet" in body["wallet_apps"]
	assert "Org Preferred Wallet" in body["wallet_apps"]
	assert body["deep_link_pattern"] == "org-wallet://offer?uri={offer_uri}"
	assert body["template_wallet_configs"] == [{"wallet_id": "wr-lissi-001", "deep_link_scheme": "openid-credential-offer://"}]


def test_resolve_wallet_profile_supports_replace_override_strategy():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	override = _save_override(wallet_repo, merge_strategy=credential_template.MergeStrategy.REPLACE)
	client, get_membership = _build_client(repo, wallet_repo)

	response = client.get(
		"/v1/wallet-registry/resolve/profile",
		headers={"x-user-id": "user-1"},
		params={
			"organization_id": "org-1",
			"credential_format": "sd_jwt_vc",
			"issuance_protocol": "oid4vci",
			"compliance_profile_code": "eudi_pid",
		},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["is_override"] is True
	assert body["id"] == override.id
	assert body["organization_id"] == "org-1"
	assert body["applied_override_ids"] == [override.id]
	assert body["wallet_apps"] == ["Org Preferred Wallet"]
	assert body["specifications"] == ["Org Spec"]
	assert body["supported_platforms"] == ["web"]
	assert body["override_precedence"] == 90
	assert body["merge_strategy"] == "REPLACE"
	assert body["template_wallet_configs"] == []
	get_membership.assert_awaited_once_with("user-1", "org-1")


def test_create_wallet_accepts_canonical_wallet_profile_alias_fields():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	client, _ = _build_client(repo, wallet_repo)

	response = client.post(
		"/v1/wallet-registry",
		headers={"x-user-id": "user-1"},
		json={
			"organization_id": "org-1",
			"credential_format": "SD_JWT_VC",
			"issuance_protocol": "OID4VCI_PRE_AUTH",
			"name": "Canonical Wallet Alias",
			"wallet_apps": ["Alias Wallet"],
			"supported_platforms": ["ios", "web"],
			"deep_link_pattern": "alias-wallet://offer?uri={offer_uri}",
		},
	)

	assert response.status_code == 201
	body = response.json()
	assert body["deep_link_pattern"] == "alias-wallet://offer?uri={offer_uri}"
	assert body["supported_platforms"] == ["ios", "web"]
	assert "deep_link_template" not in body
	assert "platforms" not in body


def test_get_wallet_exposes_protocol_aligned_shape_only():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	entry = credential_template.WalletRegistryEntry(
		organization_id="org-1",
		is_override=True,
		override_precedence=75,
		merge_strategy=credential_template.MergeStrategy.APPEND,
		credential_format="SD_JWT_VC",
		issuance_protocol="OID4VCI_PRE_AUTH",
		compliance_profile_code="EUDI_PID",
		name="Protocol Wallet",
		description="Protocol-aligned wallet entry",
		wallet_apps=["Protocol Wallet App"],
		specifications=["OID4VCI_PRE_AUTH"],
		logo_url="https://example.com/logo.svg",
		deep_link_template="protocol-wallet://offer?uri={offer_uri}",
		supported_formats=["sd_jwt_vc"],
		supported_protocols=["OID4VCI_PRE_AUTH"],
		platforms=["ios", "android"],
		supports_qr=True,
		supports_deeplink=True,
		docs_url="https://example.com/docs",
	)
	asyncio.run(wallet_repo.save(entry))
	client, _ = _build_client(repo, wallet_repo)

	response = client.get(f"/v1/wallet-registry/{entry.id}")

	assert response.status_code == 200
	body = response.json()
	assert set(body.keys()) == {
		"id",
		"organization_id",
		"is_override",
		"override_precedence",
		"merge_strategy",
		"credential_format",
		"issuance_protocol",
		"compliance_profile_code",
		"name",
		"description",
		"wallet_apps",
		"specifications",
		"deep_link_pattern",
		"supported_platforms",
		"created_at",
		"updated_at",
	}
	assert body["deep_link_pattern"] == "protocol-wallet://offer?uri={offer_uri}"
	assert body["supported_platforms"] == ["ios", "android"]


def test_create_template_requires_compliance_binding_even_in_compatibility_mode():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	client, _ = _build_client(repo)

	response = client.post(
		"/v1/credential-templates",
		headers={"x-user-id": "user-1"},
		json={
			"organization_id": "org-1",
			"name": "Missing compliance binding",
			"credential_type": "PersonIdentificationData",
			"claims": [{"name": "given_name", "display_name": "Given Name", "claim_type": "string", "required": True}],
			"supported_formats": ["sd_jwt_vc"],
		},
	)

	assert response.status_code == 422
	assert "compliance_profile_id is required" in response.json()["detail"]


def test_create_template_normalizes_legacy_payload_format_aliases():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	client, _ = _build_client(repo)

	response = client.post(
		"/v1/credential-templates",
		headers={"x-user-id": "user-1"},
		json={
			"organization_id": "org-1",
			"name": "Legacy payload format template",
			"credential_type": "PersonIdentificationData",
			"claims": [{"name": "given_name", "display_name": "Given Name", "claim_type": "string", "required": True}],
			"supported_formats": ["sd_jwt_vc"],
			"credential_payload_format": "w3c_vcdm_v2_sd_jwt",
			"compliance_profile": {"compliance_code": "EUDI_PID"},
		},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["status"] == "DRAFT"
	assert body["credential_payload_format"] == "SD_JWT_VC"
	assert body["validity_rules"]["ttl_seconds"] == 365 * 86400
	assert body["claims"] == [
		{
			"name": "given_name",
			"type": "STRING",
			"required": True,
			"selectively_disclosable": True,
			"display": {"label": "Given Name"},
		}
	]
