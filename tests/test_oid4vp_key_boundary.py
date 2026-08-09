from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_marty_oid4vp_services_do_not_accept_private_signing_key_files() -> None:
    checked = [
        ROOT / "services" / "flow" / "main.py",
        ROOT / "docker-compose.base.yml",
        ROOT / "docker-compose.profile.oidf-haip.yml",
        ROOT / ".env.example",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in checked)

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


def test_protocol_services_cannot_select_an_issuer_profile_for_signing() -> None:
    gateway = (ROOT / "services" / "gateway" / "routes" / "signing_keys.py").read_text(
        encoding="utf-8"
    )
    flow = (ROOT / "services" / "flow" / "main.py").read_text(encoding="utf-8")

    obsolete_route = "/issuer-" + "profiles/{issuer_profile_id}/sign"
    obsolete_helper = "sign_payload_with_" + "issuer_profile"
    assert obsolete_route not in gateway
    assert obsolete_route not in flow
    assert obsolete_helper not in gateway
    assert obsolete_helper not in flow
    assert 'f"{base_url}/issuer-dids/sign"' in flow
    assert '"credential_format": "oauth-authz-req+jwt"' in flow
    assert '"key_purpose": "oid4vp_request_signing"' in flow
    assert '"oid4vp_issuer_profile_id"' not in flow
