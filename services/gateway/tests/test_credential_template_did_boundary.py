from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from gateway.models import CredentialTemplateCreate, CredentialTemplateUpdate
from gateway.routes import credentials, issuance


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/credential-templates",
            "headers": [],
            "query_string": b"",
        }
    )


def _body(**updates) -> CredentialTemplateCreate:
    payload = {
        "organization_id": "org-1",
        "name": "Member credential",
        "credential_type": "MemberCredential",
        "vct": "https://credentials.example/member",
        "compliance_profile_id": "compliance-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "claims": [{"name": "given_name", "type": "string"}],
    }
    payload.update(updates)
    return CredentialTemplateCreate.model_validate(payload)


@pytest.mark.asyncio
async def test_template_create_resolves_did_and_hides_profile_from_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    async def exists(*_args, **_kwargs):
        return True

    async def owner(*_args, **_kwargs):
        return "org-1"

    async def resolve(
        request,
        organization_id,
        issuer_did,
        credential_format=None,
        key_purpose=None,
        algorithm=None,
    ):
        captured["resolution"] = {
            "organization_id": organization_id,
            "issuer_did": issuer_did,
            "credential_format": credential_format,
            "algorithm": algorithm,
        }
        return {
            "issuer_profile_id": "internal-profile-1",
            "issuer_did": issuer_did,
        }

    class Registry:
        @staticmethod
        def get_service_url(name: str) -> str:
            assert name == "credential-templates"
            return "http://credential-templates"

    async def proxy(request, service_url, path, body_override=None, **_kwargs):
        captured["internal_body"] = json.loads(body_override)
        return JSONResponse(
            {
                "id": "template-1",
                "issuer_did": "did:web:issuer.example:orgs:org-1",
                "issuer_algorithm": "ES256",
                "issuer_profile_id": "internal-profile-1",
                "issuer_key_id": "managed-key-reference",
                "key_access_mode": "REMOTE_SIGNING",
                "remote_signing_config": {
                    "signing_service_id": "managed-openbao",
                    "signing_key_reference": "managed-key-reference",
                },
            }
        )

    monkeypatch.setattr(credentials, "_resource_exists", exists)
    monkeypatch.setattr(credentials, "_resource_org_id", owner)
    monkeypatch.setattr(issuance, "_resolve_issuer_identity", resolve)
    monkeypatch.setattr(credentials, "get_registry", lambda: Registry())
    monkeypatch.setattr(credentials, "proxy_request", proxy)

    response = await credentials.create_credential_template(_body(), _request())

    assert response.status_code == 200
    assert captured["resolution"] == {
        "organization_id": "org-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
        "credential_format": "dc+sd-jwt",
        "algorithm": None,
    }
    assert captured["internal_body"]["issuer_did"] == (
        "did:web:issuer.example:orgs:org-1"
    )
    assert "signing_service_id" not in captured["internal_body"]
    assert "signing_key_reference" not in captured["internal_body"]
    public_body = json.loads(response.body)
    assert public_body == {
        "id": "template-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
        "issuer_algorithm": "ES256",
    }


def test_template_list_response_hides_internal_custody_metadata() -> None:
    response = credentials._sanitize_credential_template_response(
        JSONResponse(
            [
                {
                    "id": "template-1",
                    "issuer_did": "did:web:issuer.example:orgs:org-1",
                    "issuer_profile_id": "internal-profile-1",
                    "issuer_key_id": "managed-key-reference",
                    "key_access_mode": "REMOTE_SIGNING",
                    "remote_signing_config": {"signing_service_id": "managed-openbao"},
                }
            ],
            headers={"ETag": '"template-list-v1"'},
        )
    )

    assert json.loads(response.body) == [
        {
            "id": "template-1",
            "issuer_did": "did:web:issuer.example:orgs:org-1",
        }
    ]
    assert response.headers["etag"] == '"template-list-v1"'


def test_public_template_response_schema_has_no_custody_routing_fields() -> None:
    schema = CredentialTemplateCreate.model_json_schema()
    response_schema = credentials.CredentialTemplateResponse.model_json_schema()

    for field in (
        "issuer_profile_id",
        "issuer_key_id",
        "key_access_mode",
        "remote_signing_config",
        "signing_service_id",
        "signing_key_reference",
        "auto_generate_artifacts",
    ):
        assert field not in schema["properties"]
        assert field not in response_schema["properties"]


@pytest.mark.asyncio
async def test_mdoc_template_infers_signing_wire_format_from_supported_formats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    async def exists(*_args, **_kwargs):
        return True

    async def owner(*_args, **_kwargs):
        return "org-1"

    async def resolve(
        request,
        organization_id,
        issuer_did,
        legacy_issuer_profile_id=None,
        credential_format=None,
        key_purpose=None,
        algorithm=None,
    ):
        captured["credential_format"] = credential_format
        return {
            "issuer_profile_id": "internal-mdoc-profile",
            "issuer_did": issuer_did,
        }

    class Registry:
        @staticmethod
        def get_service_url(_name: str) -> str:
            return "http://credential-templates"

    async def proxy(*_args, **_kwargs):
        return JSONResponse({"id": "template-mdoc"})

    monkeypatch.setattr(credentials, "_resource_exists", exists)
    monkeypatch.setattr(credentials, "_resource_org_id", owner)
    monkeypatch.setattr(issuance, "_resolve_issuer_identity", resolve)
    monkeypatch.setattr(credentials, "get_registry", lambda: Registry())
    monkeypatch.setattr(credentials, "proxy_request", proxy)

    await credentials.create_credential_template(
        _body(
            credential_type="org.iso.18013.5.1.mDL",
            vct=None,
            doctype="org.iso.18013.5.1.mDL",
            supported_formats=["MDOC"],
            credential_payload_format="MDOC",
        ),
        _request(),
    )

    assert captured["credential_format"] == "mso_mdoc"


def test_public_template_model_uses_format_specific_identity_fields() -> None:
    mdoc = _body(
        credential_type="org.iso.18013.5.1.mDL",
        vct=None,
        doctype="org.iso.18013.5.1.mDL",
        supported_formats=["MDOC"],
        credential_payload_format="MDOC",
    )
    assert mdoc.vct is None
    assert mdoc.doctype == "org.iso.18013.5.1.mDL"

    with pytest.raises(ValidationError, match="doctype is required"):
        _body(
            credential_type="org.iso.18013.5.1.mDL",
            vct=None,
            doctype=None,
            supported_formats=["MDOC"],
            credential_payload_format="MDOC",
        )

    with pytest.raises(ValidationError, match="vct is required"):
        _body(vct=None)


def test_public_template_response_schema_exposes_mdoc_doctype() -> None:
    response_schema = credentials.CredentialTemplateResponse.model_json_schema()
    assert "doctype" in response_schema["properties"]


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "issuer_key_id",
        "issuer_key_algorithm",
        "issuer_algorithm",
        "key_access_mode",
        "remote_signing_config",
        "issuer_certificate_chain_pem",
        "signing_service_id",
        "signing_key_reference",
        "auto_generate_artifacts",
    ],
)
def test_template_public_contract_rejects_custody_selectors(
    forbidden_field: str,
) -> None:
    with pytest.raises(ValidationError, match=forbidden_field):
        CredentialTemplateCreate.model_validate(
            {
                **_body().model_dump(),
                forbidden_field: "caller-selected",
            }
        )


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "issuer_key_id",
        "issuer_algorithm",
        "key_access_mode",
        "remote_signing_config",
        "issuer_certificate_chain_pem",
        "signing_service_id",
        "signing_key_reference",
    ],
)
def test_template_update_contract_rejects_custody_selectors(
    forbidden_field: str,
) -> None:
    with pytest.raises(ValidationError, match=forbidden_field):
        CredentialTemplateUpdate.model_validate({forbidden_field: "caller-selected"})
