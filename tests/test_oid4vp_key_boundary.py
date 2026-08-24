import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_marty_oid4vp_services_do_not_accept_private_signing_key_files() -> None:
    checked = [
        ROOT / "rust" / "services" / "flow" / "src",
        ROOT / "docker-compose.base.yml",
        ROOT / "docker-compose.profile.oidf-haip.yml",
        ROOT / ".env.example",
    ]
    combined = "\n".join(
        "\n".join(
            source.read_text(encoding="utf-8") for source in path.rglob("*.rs")
        )
        if path.is_dir()
        else path.read_text(encoding="utf-8")
        for path in checked
    )

    assert "VERIFIER_" + "SIGNING_KEY_PEM" not in combined
    assert "VERIFIER_" + "SIGNING_KEY_FILE" not in combined
    assert "haip_response_encryption_" + "private_jwk" not in combined


def test_oid4vp_signing_and_flow_envelopes_have_dedicated_kms_keys() -> None:
    migrations = (ROOT / "services" / "run_all_migrations.py").read_text(
        encoding="utf-8"
    )

    assert '"ip-marty-oid4vp-verifier"' in migrations
    assert '"oid4vp-verifier-marty-es256"' in migrations
    assert '"oid4vp_request_signing"' in migrations
    assert '"flow-response-envelope-marty-aes256"' in migrations
    assert '"exportable": False' in migrations


def test_openbao_initializer_provisions_and_authorizes_purpose_bound_protocol_keys() -> None:
    init_script = (ROOT / "docker" / "openbao-init.sh").read_text(
        encoding="utf-8"
    )

    for key_id, key_type in (
        ("oid4vp-verifier-marty-es256", "ecdsa-p256"),
        ("lti-tool-marty-rs256", "rsa-2048"),
    ):
        assert f"transit/keys/{key_id}" in init_script
        assert f"type={key_type}" in init_script
        assert f'path "transit/sign/{key_id}"' in init_script
        assert f'path "transit/verify/{key_id}"' in init_script
        assert f'path "transit/keys/{key_id}"' in init_script


def test_protocol_services_cannot_select_an_issuer_profile_for_signing() -> None:
    gateway_routes = json.loads(
        (ROOT / "contracts" / "gateway-routes.json").read_text(encoding="utf-8")
    )
    gateway_paths = {route["path"] for route in gateway_routes["routes"]}
    gateway = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "rust" / "services" / "gateway").rglob("*.rs")
    )
    flow = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "rust" / "services" / "flow").rglob("*.rs")
    )

    obsolete_route = "/issuer-" + "profiles/{issuer_profile_id}/sign"
    obsolete_helper = "sign_payload_with_" + "issuer_profile"
    assert obsolete_route not in gateway_paths
    assert obsolete_route not in flow
    assert obsolete_helper not in gateway
    assert obsolete_helper not in flow
    assert '"issuer-dids/sign"' in flow
    assert 'REQUEST_FORMAT: &str = "oauth-authz-req+jwt"' in flow
    assert 'REQUEST_PURPOSE: &str = "oid4vp_request_signing"' in flow
    assert '"oid4vp_issuer_profile_id"' not in flow
