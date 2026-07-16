import httpx
import pytest

import gateway.main as gateway_main
from gateway.mip_configuration import mip_configuration_document


ALLOWED_KEYS = {
    "mip_version",
    "issuer",
    "mip_configuration_endpoint",
    "supported_versions",
    "implementation_classes",
    "issuance_endpoint",
    "openid_credential_issuer",
    "presentation_endpoint",
    "token_endpoint",
    "authorization_endpoint",
    "supported_credential_formats",
    "supported_compliance_profiles",
    "active_compliance_profiles",
    "supported_flow_types",
    "supported_signing_algorithms",
    "proximity_supported",
    "scim_endpoint",
    "revocation_endpoint",
    "jwks_uri",
    "service_documentation",
}


def test_mip_configuration_uses_only_canonical_v031_fields() -> None:
    document = mip_configuration_document(
        "https://beta.elevenidllc.com/",
        [
            {
                "compliance_code": "OPEN_BADGES_3",
                "credential_format": "VC_JWT",
                "issuance_protocol": "OID4VCI_PRE_AUTH",
                "api_surface": [
                    {
                        "rel": "credential",
                        "path_template": "/v1/issuance/credential",
                        "method": "POST",
                        "auth_required": False,
                        "discoverable": True,
                        "internal_note": "must not leak",
                    },
                    {
                        "rel": "internal",
                        "path_template": "/internal",
                        "method": "GET",
                        "auth_required": True,
                        "discoverable": False,
                    },
                ],
            },
            {"compliance_code": "AAMVA_MDL", "api_surface": []},
            {"compliance_code": "OPEN_BADGES_3"},
            {"compliance_code": ""},
        ],
    )

    assert set(document) == ALLOWED_KEYS
    assert document["mip_version"] == "0.3.1"
    assert document["supported_versions"] == ["0.3.1"]
    assert document["issuer"] == "https://beta.elevenidllc.com"
    assert document["mip_configuration_endpoint"] == (
        "https://beta.elevenidllc.com/.well-known/mip-configuration"
    )
    assert document["supported_compliance_profiles"] == ["AAMVA_MDL", "OPEN_BADGES_3"]
    assert document["active_compliance_profiles"] == [
        {"compliance_code": "AAMVA_MDL", "api_surface": []},
        {
            "compliance_code": "OPEN_BADGES_3",
            "credential_format": "VC_JWT",
            "issuance_protocol": "OID4VCI_PRE_AUTH",
            "api_surface": [{
                "rel": "credential",
                "path_template": "/v1/issuance/credential",
                "method": "POST",
                "auth_required": False,
                "discoverable": True,
            }],
        },
        {"compliance_code": "OPEN_BADGES_3", "api_surface": []},
    ]
    assert "ZK_MDOC" not in document["supported_credential_formats"]
    assert "api_base_url" not in document
    assert "wallet_facing_endpoints" not in document


def test_mip_configuration_drops_malformed_compliance_profiles() -> None:
    document = mip_configuration_document(
        "https://issuer.example.test",
        [None, "wrong", {}, {"compliance_code": None}],
    )

    assert document["supported_compliance_profiles"] == []
    assert document["active_compliance_profiles"] == []


@pytest.mark.asyncio
async def test_gateway_serves_canonical_mip_configuration(monkeypatch) -> None:
    class Registry:
        @staticmethod
        def get_service_url(_name: str):
            return None

    monkeypatch.setenv("ISSUER_BASE_URL", "https://issuer.example.test")
    monkeypatch.setattr(gateway_main, "get_registry", Registry)
    transport = httpx.ASGITransport(app=gateway_main.create_app())

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/.well-known/mip-configuration")

    assert response.status_code == 200
    assert set(response.json()) == ALLOWED_KEYS
    assert response.headers["x-mip-version"] == "0.3.1"
