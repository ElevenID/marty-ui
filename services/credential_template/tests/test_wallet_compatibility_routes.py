from __future__ import annotations

import asyncio
from types import SimpleNamespace
from urllib.parse import quote
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


def test_create_wallet_accepts_routing_metadata_and_capability_flags():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	client, _ = _build_client(repo, wallet_repo)

	response = client.post(
		"/v1/wallet-registry",
		headers={"x-user-id": "user-1"},
		json={
			"organization_id": "org-1",
			"name": "DC API Wallet",
			"wallet_apps": ["DC API Wallet"],
			"routing_templates": {
				"ios": "dc-wallet://open?inner={inner_uri_encoded}",
			},
			"install_urls": {"ios": "https://example.com/install"},
			"ios_scheme": "dc-wallet",
			"supports_digital_credentials": True,
			"supports_haip": True,
		},
	)

	assert response.status_code == 201
	body = response.json()
	assert body["routing_templates"]["ios"] == "dc-wallet://open?inner={inner_uri_encoded}"
	assert body["install_urls"] == {"ios": "https://example.com/install"}
	assert body["ios_scheme"] == "dc-wallet"
	assert body["supports_digital_credentials"] is True
	assert body["supports_haip"] is True
	assert body["ios_same_device_mode"] == "digital_credentials"
	assert body["ios_same_device_single_wallet_only"] is False
	assert body["capabilities"]["digital_credentials"] is True
	assert body["capabilities"]["haip"] is True


def test_wallet_response_derives_universal_link_ios_mode_without_warning():
	response = credential_template._wallet_to_response(
		credential_template.WalletRegistryEntry(
			name="Universal Wallet",
			wallet_apps=["Universal Wallet"],
			platforms=["ios", "web"],
			universal_link_template="https://wallet.example/open?inner={inner_uri_encoded}",
		)
	)

	assert response.ios_same_device_mode == "universal_link"
	assert response.ios_same_device_single_wallet_only is False


def test_get_wallet_marks_raw_protocol_ios_routes_as_single_wallet_only():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	entry = credential_template.WalletRegistryEntry(
		name="Raw Protocol Wallet",
		wallet_apps=["Raw Protocol Wallet"],
		platforms=["ios", "android"],
	)
	asyncio.run(wallet_repo.save(entry))
	client, _ = _build_client(repo, wallet_repo)

	response = client.get(f"/v1/wallet-registry/{entry.id}")

	assert response.status_code == 200
	body = response.json()
	assert body["ios_same_device_mode"] == "protocol_only"
	assert body["ios_same_device_single_wallet_only"] is True


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
		"logo_url",
		"deep_link_pattern",
		"routing_templates",
		"install_urls",
		"supported_formats",
		"supported_protocols",
		"supported_platforms",
		"supports_qr",
		"supports_deeplink",
		"supports_digital_credentials",
		"supports_haip",
		"ios_same_device_mode",
		"ios_same_device_single_wallet_only",
		"docs_url",
		"capabilities",
		"created_at",
		"updated_at",
	}
	assert body["deep_link_pattern"] == "protocol-wallet://offer?uri={offer_uri}"
	assert body["routing_templates"] == {
		"generic": "protocol-wallet://offer?uri={offer_uri}",
		"ios": "protocol-wallet://offer?uri={offer_uri}",
		"android": "protocol-wallet://offer?uri={offer_uri}",
	}
	assert body["install_urls"] == {}
	assert "ios_scheme" not in body
	assert "universal_link_template" not in body
	assert "android_package" not in body
	assert body["supported_formats"] == ["sd_jwt_vc"]
	assert body["supported_protocols"] == ["OID4VCI_PRE_AUTH"]
	assert body["supported_platforms"] == ["ios", "android"]
	assert body["supports_qr"] is True
	assert body["supports_deeplink"] is True
	assert body["supports_digital_credentials"] is False
	assert body["supports_haip"] is False
	assert body["ios_same_device_mode"] == "nested_link"
	assert body["ios_same_device_single_wallet_only"] is False
	assert body["docs_url"] == "https://example.com/docs"
	assert body["capabilities"] == {
		"oid4vci": True,
		"oid4vp": False,
		"digital_credentials": False,
		"haip": False,
		"same_device": True,
		"qr": True,
	}


def test_wallet_open_link_wraps_standard_inner_uri_without_mutating_it():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	entry = credential_template.WalletRegistryEntry(
		name="Nested Route Wallet",
		wallet_apps=["Nested Route Wallet"],
		deep_link_template="nested-wallet://open?inner={inner_uri_encoded}&offer={offer_uri_encoded}&platform={platform}",
		platforms=["ios"],
	)
	asyncio.run(wallet_repo.save(entry))
	client, _ = _build_client(repo, wallet_repo)
	inner_uri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123"

	response = client.get(
		f"/v1/wallet-registry/{entry.id}/open-link",
		params={"inner_uri": inner_uri, "platform": "ios"},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["wallet_id"] == entry.id
	assert body["inner_uri"] == inner_uri
	assert body["platform"] == "ios"
	assert body["transport"] == "wallet_deeplink"
	assert body["open_uri"] == (
		"nested-wallet://open?"
		"inner=openid-credential-offer%3A%2F%2F%3Fcredential_offer_uri%3Dhttps%253A%252F%252Fissuer.example%252Foffers%252F123"
		"&offer=https%3A%2F%2Fissuer.example%2Foffers%2F123"
		"&platform=ios"
	)


def test_wallet_open_link_prefers_platform_routing_template():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	entry = credential_template.WalletRegistryEntry(
		name="Platform Route Wallet",
		wallet_apps=["Platform Route Wallet"],
		deep_link_template="platform-wallet://generic?inner={inner_uri_encoded}",
		routing_templates={"ios": "platform-wallet://ios?inner={inner_uri_encoded}"},
		platforms=["ios", "android"],
	)
	asyncio.run(wallet_repo.save(entry))
	client, _ = _build_client(repo, wallet_repo)
	inner_uri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123"

	response = client.get(
		f"/v1/wallet-registry/{entry.id}/open-link",
		params={"inner_uri": inner_uri, "platform": "ios"},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["inner_uri"] == inner_uri
	assert body["open_uri"] == (
		"platform-wallet://ios?"
		"inner=openid-credential-offer%3A%2F%2F%3Fcredential_offer_uri%3Dhttps%253A%252F%252Fissuer.example%252Foffers%252F123"
	)


def test_wallet_open_link_uses_spruce_android_intent_without_wrapping_inner_uri():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	entry = credential_template.WalletRegistryEntry(
		name="Spruce Route Wallet",
		wallet_apps=["Spruce Route Wallet"],
		routing_templates={
				"generic": "openid-credential-offer://?credential_offer_uri={offer_uri_encoded}",
				"ios": "openid-credential-offer://?credential_offer_uri={offer_uri_encoded}",
				"android": "intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end",
		},
		platforms=["ios", "android"],
	)
	asyncio.run(wallet_repo.save(entry))
	client, _ = _build_client(repo, wallet_repo)
	inner_uri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123"

	response = client.get(
		f"/v1/wallet-registry/{entry.id}/open-link",
		params={"inner_uri": inner_uri, "platform": "android"},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["inner_uri"] == inner_uri
	assert body["open_uri"] == (
		"intent://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123"
		"#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end"
	)


def test_wallet_open_link_preserves_inline_credential_offer_param_for_stale_templates():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	entry = credential_template.WalletRegistryEntry(
		name="Spruce Route Wallet",
		wallet_apps=["Spruce Route Wallet"],
		routing_templates={
			"android": "intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end",
		},
		platforms=["android"],
	)
	asyncio.run(wallet_repo.save(entry))
	client, _ = _build_client(repo, wallet_repo)
	offer_json = '{"credential_issuer":"https://issuer.example/org/org-1/spruce","credential_configuration_ids":["open_badge#spruce-sd-jwt"],"grants":{}}'
	inner_uri = "openid-credential-offer://?credential_offer=" + quote(offer_json, safe="")

	response = client.get(
		f"/v1/wallet-registry/{entry.id}/open-link",
		params={"inner_uri": inner_uri, "platform": "android"},
	)

	assert response.status_code == 200
	body = response.json()
	assert "credential_offer=" in body["open_uri"]
	assert "credential_offer_uri=" not in body["open_uri"]
	assert body["open_uri"] == (
		"intent://?credential_offer="
		+ quote(offer_json, safe="")
		+ "#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end"
	)


def test_wallet_registry_response_exposes_oid4vci_profile_from_supported_formats():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	client, _ = _build_client(repo, wallet_repo)

	response = client.get("/v1/wallet-registry/wr-spruce-001")

	assert response.status_code == 200
	body = response.json()
	assert body["oid4vci_profile"] == {
		"format_variant": "spruce-vc+sd-jwt",
		"issuer_path": "spruce",
		"credential_configuration_suffix": "spruce-sd-jwt",
	}


def test_wallet_open_link_rejects_unsafe_inner_uri_scheme():
	repo = credential_template.InMemoryCredentialTemplateRepository()
	wallet_repo = credential_template.InMemoryWalletRegistryRepository()
	entry = credential_template.WalletRegistryEntry(
		name="Nested Route Wallet",
		wallet_apps=["Nested Route Wallet"],
		deep_link_template="nested-wallet://open?inner={inner_uri_encoded}",
		platforms=["ios"],
	)
	asyncio.run(wallet_repo.save(entry))
	client, _ = _build_client(repo, wallet_repo)

	response = client.get(
		f"/v1/wallet-registry/{entry.id}/open-link",
		params={"inner_uri": "javascript:alert(1)"},
	)

	assert response.status_code == 400


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
