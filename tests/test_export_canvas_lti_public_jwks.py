import json
import sys
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts.export_canvas_lti_public_jwks import export_public_jwks, main


def public_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def transit_response(*, key_type: str = "rsa-2048") -> dict:
    return {
        "data": {
            "name": "lti-tool-marty-rs256",
            "type": key_type,
            "latest_version": 2,
            "keys": {
                "1": {
                    "creation_time": "2026-07-01T00:00:00Z",
                    "public_key": public_pem(),
                },
                "2": {
                    "creation_time": "2026-07-14T08:00:00-06:00",
                    "public_key": public_pem(),
                },
            },
        }
    }


def test_exports_only_public_rs256_fields_and_versioned_active_kid() -> None:
    jwks, active_kid = export_public_jwks(
        transit_response(), key_name="lti-tool-marty-rs256"
    )

    assert active_kid == "lti-tool-marty-rs256-v2"
    assert [key["kid"] for key in jwks["keys"]] == [
        "lti-tool-marty-rs256-v2",
        "lti-tool-marty-rs256-v1",
    ]
    assert set(jwks["keys"][0]) == {"alg", "e", "kid", "kty", "n", "use"}
    assert jwks["keys"][0]["alg"] == "RS256"
    assert jwks["keys"][0]["kty"] == "RSA"
    assert jwks["keys"][0]["use"] == "sig"
    assert jwks["keys"][1]["retired_at"] == "2026-07-14T14:00:00Z"
    assert datetime.fromisoformat(
        jwks["keys"][1]["retired_at"].replace("Z", "+00:00")
    ).tzinfo == timezone.utc
    assert not ({"d", "p", "q", "dp", "dq", "qi"} & set(jwks["keys"][0]))


def test_exports_active_key_under_issuer_did_verification_method() -> None:
    verification_method_id = "did:web:issuer.example:orgs:marty#lti-tool-marty-rs256"
    jwks, active_kid = export_public_jwks(
        transit_response(),
        key_name="lti-tool-marty-rs256",
        verification_method_id=verification_method_id,
    )

    assert active_kid == verification_method_id
    assert jwks["keys"][0]["kid"] == verification_method_id
    assert jwks["keys"][1]["kid"] == "lti-tool-marty-rs256-v1"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda doc: doc["data"].update(type="ed25519"), "must be RSA"),
        (lambda doc: doc["data"].update(name="credential-issuer"), "does not match"),
        (lambda doc: doc["data"].update(latest_version=3), "active public key"),
        (
            lambda doc: doc["data"]["keys"]["2"].update(public_key="PRIVATE KEY"),
            "safe public key",
        ),
    ],
)
def test_rejects_untrusted_or_mismatched_transit_metadata(mutate, message: str) -> None:
    document = transit_response()
    mutate(document)

    with pytest.raises(ValueError, match=message):
        export_public_jwks(document, key_name="lti-tool-marty-rs256")


def test_cli_accepts_windows_utf8_bom(tmp_path, monkeypatch) -> None:
    source = tmp_path / "transit.json"
    output = tmp_path / "jwks.json"
    kid = tmp_path / "kid.txt"
    source.write_text(json.dumps(transit_response()), encoding="utf-8-sig")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "export_canvas_lti_public_jwks.py",
            "--input",
            str(source),
            "--output",
            str(output),
            "--active-kid-output",
            str(kid),
        ],
    )

    assert main() == 0
    assert json.loads(output.read_text(encoding="utf-8"))["keys"]
    assert kid.read_text(encoding="utf-8") == "lti-tool-marty-rs256-v2"
