from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership, OrganizationRoleSummary
from pydantic import ValidationError

from services.credential_template import main as credential_template
from services.credential_template.infrastructure.models import credential_templates_table


@pytest.mark.parametrize("removed_field", ["issuer_requirements", "artifacts_auto_generate"])
def test_credential_template_requests_reject_removed_fields(removed_field: str) -> None:
	payload = {
		"organization_id": "org-1",
		"name": "Member badge",
		"credential_type": "MemberCredential",
		"claims": [],
		removed_field: {},
	}
	with pytest.raises(ValidationError, match=removed_field):
		credential_template.CreateCredentialTemplateRequest.model_validate(payload)
	with pytest.raises(ValidationError, match=removed_field):
		credential_template.UpdateCredentialTemplateRequest.model_validate({removed_field: {}})


def test_credential_template_schema_persists_compliance_contract() -> None:
	assert credential_templates_table.c.compliance_profile.type.python_type is dict
	assert credential_templates_table.c.compliance_profile_id.type.python_type is str


def _build_client(
	repo: credential_template.InMemoryCredentialTemplateRepository,
	wallet_repo: credential_template.InMemoryWalletRegistryRepository | None = None,
) -> tuple[TestClient, AsyncMock]:
	app = FastAPI()
	app.include_router(credential_template.router)
	app.include_router(credential_template.wallet_router)
	app.include_router(credential_template.internal_router)

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

	async def fake_require_active_issuer_profile(
		request,
		*,
		organization_id: str,
		issuer_profile_id: str | None,
		credential_format: str | None = None,
		algorithm: str | None = None,
	) -> dict:
		if not issuer_profile_id:
			raise credential_template.HTTPException(
				status_code=422,
				detail="issuer_profile_id is required.",
			)
		return {
			"ok": True,
			"organization_id": organization_id,
			"issuer_profile_id": issuer_profile_id,
			"issuer_did": "did:web:beta.elevenidllc.com:orgs:test",
			"signing_service_id": "managed-openbao-transit",
			"signing_key_reference": "cred-issuer-test-es256",
			"verification_method_id": "did:web:beta.elevenidllc.com:orgs:test#cred-issuer-test-es256",
			"key_purpose": "vc_jwt_issuer",
			"service": {
				"id": "managed-openbao-transit",
				"algorithm": "ES256",
				"key_reference": "cred-issuer-test-es256",
			},
		}

	credential_template._require_active_issuer_profile = AsyncMock(
		side_effect=fake_require_active_issuer_profile
	)
	credential_template._require_trust_profile_accepts_issuer = AsyncMock(return_value=None)
	credential_template._require_active_revocation_profile = AsyncMock(return_value=None)
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
		issuer_profile_id="issuer-profile-1",
		revocation_profile_id="revocation-profile-1",
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
		"issuer_profile_id",
		"revocation_profile_id",
		"claims",
		"validity_rules",
		"issuer_certificate_chain_configured",
		"artifacts_status",
		"hasArtifacts",
		"artifactsValidated",
		"usedByFlowsCount",
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
	assert body["artifacts_status"] == "missing"
	assert body["hasArtifacts"] is False
	assert body["artifactsValidated"] is False
	assert "doctype" not in body
	assert "supported_formats" not in body
	assert "wallet_configs" not in body


def test_issuer_profile_validation_uses_format_specific_key_purpose() -> None:
	assert credential_template._key_purpose_for_credential_format("SD_JWT_VC") == "vc_jwt_issuer"
	assert credential_template._key_purpose_for_credential_format("mso_mdoc") == "mdoc_dsc"
	assert credential_template._key_purpose_for_credential_format("vds_nc") == "vdsnc_signing"


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
			"issuer_profile_id": "issuer-profile-1",
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


def test_create_credential_template_rejects_missing_issuer_profile() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	client, _ = _build_client(repo)

	response = client.post(
		"/v1/credential-templates",
		headers={"x-user-id": "user-1"},
		json={
			"organization_id": "org-1",
			"name": "Missing issuer",
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
		},
	)

	assert response.status_code == 422
	assert "issuer_profile_id is required" in response.json()["detail"]


def test_create_credential_template_persists_artifact_pipeline_fields() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	client, _ = _build_client(repo)

	response = client.post(
		"/v1/credential-templates",
		headers={"x-user-id": "user-1"},
		json={
			"organization_id": "org-1",
			"name": "Issuer-bound template",
			"credential_type": "IssuerBoundCredential",
			"compliance_profile_id": "123e4567-e89b-12d3-a456-426614174000",
			"claims": [
				{
					"name": "subject_id",
					"display_name": "Subject ID",
					"claim_type": "string",
					"required": True,
				}
			],
			"supported_formats": ["sd_jwt_vc"],
			"trust_profile_id": "trust-profile-1",
			"revocation_profile_id": "revocation-profile-1",
			"issuer_profile_id": "issuer-profile-1",
			"issuer_key_id": "stale-client-key",
			"issuer_did": "did:web:attacker.example:orgs:evil",
			"signing_algorithm": "ES256",
			"key_access_mode": "LOCAL",
			"remote_signing_config": {
				"signing_service_id": "stale-client-service",
				"signing_key_reference": "stale-client-key",
			},
			"auto_generate_artifacts": False,
		},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["trust_profile_id"] == "trust-profile-1"
	assert body["revocation_profile_id"] == "revocation-profile-1"
	assert body["issuer_profile_id"] == "issuer-profile-1"
	assert body["issuer_key_id"] == "cred-issuer-test-es256"
	assert body["issuer_did"] == "did:web:beta.elevenidllc.com:orgs:test"
	assert body["issuer_algorithm"] == "ES256"
	assert body["key_access_mode"] == "REMOTE_SIGNING"
	assert body["artifacts_status"] == "valid"
	assert body["hasArtifacts"] is True
	assert body["artifactsValidated"] is True
	stored = asyncio.run(repo.get(body["id"]))
	assert stored.remote_signing_config == {
		"provider": "managed-signing-service",
		"signing_service_id": "managed-openbao-transit",
		"signing_key_reference": "cred-issuer-test-es256",
		"verification_method_id": "did:web:beta.elevenidllc.com:orgs:test#cred-issuer-test-es256",
		"key_purpose": "vc_jwt_issuer",
	}


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
			"issuer_profile_id": "issuer-profile-1",
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


def test_delete_credential_template_is_draft_only_and_returns_204() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	client, _ = _build_client(repo)
	headers = {"X-User-Id": "user-1"}

	response = client.delete(f"/v1/credential-templates/{template.id}", headers=headers)

	assert response.status_code == 204
	assert response.content == b""
	assert asyncio.run(repo.get(template.id)) is None
	assert client.delete("/v1/credential-templates/missing", headers=headers).status_code == 404


def test_delete_active_credential_template_is_rejected() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	template.status = credential_template.TemplateStatus.ACTIVE
	asyncio.run(repo.save(template))
	client, _ = _build_client(repo)

	response = client.delete(
		f"/v1/credential-templates/{template.id}",
		headers={"X-User-Id": "user-1"},
	)

	assert response.status_code == 409
	assert asyncio.run(repo.get(template.id)) is not None


def test_update_credential_template_canonicalizes_issuer_metadata() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	client, _ = _build_client(repo)

	response = client.patch(
		f"/v1/credential-templates/{template.id}",
		headers={"x-user-id": "user-1"},
		json={
			"issuer_profile_id": "issuer-profile-2",
			"issuer_key_id": "stale-client-key",
			"issuer_did": "did:web:attacker.example:orgs:evil",
			"key_access_mode": "LOCAL",
			"remote_signing_config": {
				"signing_service_id": "stale-client-service",
				"signing_key_reference": "stale-client-key",
			},
		},
	)

	assert response.status_code == 200
	body = response.json()
	assert body["issuer_profile_id"] == "issuer-profile-2"
	assert body["issuer_key_id"] == "cred-issuer-test-es256"
	assert body["issuer_did"] == "did:web:beta.elevenidllc.com:orgs:test"
	assert body["key_access_mode"] == "REMOTE_SIGNING"
	stored = asyncio.run(repo.get(template.id))
	assert stored.remote_signing_config["signing_service_id"] == "managed-openbao-transit"
	assert stored.remote_signing_config["signing_key_reference"] == "cred-issuer-test-es256"


def test_update_credential_template_validation_failure_does_not_dirty_stored_template() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	client, _ = _build_client(repo)

	async def reject_profile(*args, **kwargs):
		raise credential_template.HTTPException(
			status_code=422,
			detail="issuer_profile_id must reference an active issuer profile.",
		)

	credential_template._require_active_issuer_profile = AsyncMock(side_effect=reject_profile)

	response = client.patch(
		f"/v1/credential-templates/{template.id}",
		headers={"x-user-id": "user-1"},
		json={
			"name": "Should Not Persist",
			"issuer_profile_id": "missing-profile",
			"issuer_key_id": "stale-client-key",
			"issuer_did": "did:web:attacker.example:orgs:evil",
		},
	)

	assert response.status_code == 422
	stored = asyncio.run(repo.get(template.id))
	assert stored.name == "Employee Badge"
	assert stored.issuer_profile_id == "issuer-profile-1"
	assert stored.issuer_key_id is None
	assert stored.issuer_did is None


@pytest.mark.parametrize(
	("method", "suffix", "payload"),
	[
		("patch", "", {"name": "Blocked update"}),
		("post", "/activate", None),
		("post", "/deprecate", None),
		("post", "/new-version", None),
		("delete", "", None),
		(
			"post",
			"/claims",
			{
				"name": "family_name",
				"display_name": "Family Name",
				"claim_type": "string",
				"required": False,
			},
		),
	],
)
def test_credential_template_mutations_require_org_membership(method: str, suffix: str, payload: dict | None) -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	client, get_membership = _build_client(repo)
	get_membership.return_value = None

	request = getattr(client, method)
	kwargs = {"headers": {"x-user-id": "user-1"}}
	if payload is not None:
		kwargs["json"] = payload

	response = request(f"/v1/credential-templates/{template.id}{suffix}", **kwargs)

	assert response.status_code == 403
	assert response.json()["detail"] == "Not a member of this organization"
	get_membership.assert_awaited_with("user-1", "org-1")


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


def test_activate_credential_template_rejects_legacy_placeholder_vct() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	template.vct = "https://marty.example/credentials/EmployeeBadge"
	asyncio.run(repo.save(template))
	client, _ = _build_client(repo)

	response = client.post(
		f"/v1/credential-templates/{template.id}/activate",
		headers={"x-user-id": "user-1"},
	)

	assert response.status_code == 422
	assert "marty.example is forbidden" in response.json()["detail"]
	assert asyncio.run(repo.get(template.id)).status == credential_template.TemplateStatus.DRAFT


def test_activate_credential_template_rejects_mismatched_trust_profile() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	template.trust_profile_id = "trust-profile-1"
	asyncio.run(repo.save(template))
	client, _ = _build_client(repo)
	credential_template._require_trust_profile_accepts_issuer = AsyncMock(
		side_effect=credential_template.HTTPException(
			status_code=422,
			detail="The selected Trust Profile does not trust the selected issuer profile.",
		)
	)

	response = client.post(
		f"/v1/credential-templates/{template.id}/activate",
		headers={"x-user-id": "user-1"},
	)

	assert response.status_code == 422
	stored = asyncio.run(repo.get(template.id))
	assert stored.status == credential_template.TemplateStatus.DRAFT
	credential_template._require_trust_profile_accepts_issuer.assert_awaited_once_with(
		trust_profile_id="trust-profile-1",
		issuer_did="did:web:beta.elevenidllc.com:orgs:test",
	)


def test_activate_credential_template_requires_active_revocation_profile() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	template = asyncio.run(_save_template(repo))
	client, _ = _build_client(repo)
	credential_template._require_active_revocation_profile = AsyncMock(
		side_effect=credential_template.HTTPException(
			status_code=422,
			detail="Credential Templates require an active Revocation Profile.",
		)
	)

	response = client.post(
		f"/v1/credential-templates/{template.id}/activate",
		headers={"x-user-id": "user-1"},
	)

	assert response.status_code == 422
	assert response.json()["detail"] == "Credential Templates require an active Revocation Profile."
	stored = asyncio.run(repo.get(template.id))
	assert stored.status == credential_template.TemplateStatus.DRAFT


def test_trust_profile_issuer_identifiers_use_only_enabled_direct_issuers() -> None:
	identifiers = credential_template._trust_profile_issuer_identifiers({
		"allowed_issuers": ["did:web:allowed.example#key-1"],
		"trust_sources": [
			{"enabled": True, "issuer_did": "did:jwk:trusted"},
			{"enabled": False, "issuer_did": "did:jwk:disabled"},
		],
	})

	assert identifiers == {
		"did:web:allowed.example#key-1",
		"did:web:allowed.example",
		"did:jwk:trusted",
	}


def test_internal_credential_configurations_do_not_emit_default_fallback() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()
	client, _ = _build_client(repo)

	response = client.get("/internal/credential-configurations")

	assert response.status_code == 200
	body = response.json()
	assert body["credential_configurations_supported"] == {}
	assert "default" not in body["credential_configurations_supported"]


def test_internal_credential_configurations_preserves_envelope_without_repo() -> None:
	app = FastAPI()
	app.include_router(credential_template.internal_router)
	previous_repo = credential_template._repo
	credential_template._repo = None
	try:
		response = TestClient(app).get("/internal/credential-configurations")
	finally:
		credential_template._repo = previous_repo

	assert response.status_code == 200
	assert response.json() == {
		"credential_configurations_supported": {},
		"issuer_display_name": None,
	}


def test_internal_credential_configurations_only_advertise_kms_backed_templates() -> None:
	repo = credential_template.InMemoryCredentialTemplateRepository()

	valid = credential_template.CredentialTemplate(
		organization_id="org-1",
		name="Employee Badge",
		credential_type="EmployeeBadge",
		issuer_profile_id="issuer-profile-1",
		key_access_mode="REMOTE_SIGNING",
	)
	valid.claims.append(
		credential_template.ClaimDefinition(
			name="given_name",
			claim_type=credential_template.ClaimType.STRING,
			required=True,
		)
	)
	valid.activate()

	legacy = credential_template.CredentialTemplate(
		organization_id="org-1",
		name="Legacy Badge",
		credential_type="LegacyBadge",
		issuer_profile_id=None,
		key_access_mode="LOCAL",
	)
	legacy.claims.append(
		credential_template.ClaimDefinition(
			name="given_name",
			claim_type=credential_template.ClaimType.STRING,
			required=True,
		)
	)
	legacy.activate()

	asyncio.run(repo.save(valid))
	asyncio.run(repo.save(legacy))
	client, _ = _build_client(repo)

	response = client.get("/internal/credential-configurations")

	assert response.status_code == 200
	configs = response.json()["credential_configurations_supported"]
	assert "EmployeeBadge" in configs
	assert "LegacyBadge" not in configs
	assert "default" not in configs
