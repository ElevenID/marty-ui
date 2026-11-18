"""Regression checks for the Keycloak realm import contract."""

import json
from pathlib import Path


REALM = Path(__file__).resolve().parents[1] / "config" / "keycloak" / "11id-realm.json"


def test_realm_uses_no_uploaded_javascript_authorization_policies() -> None:
    """Keycloak refuses realm imports containing uploaded JavaScript policies."""
    realm = json.loads(REALM.read_text(encoding="utf-8"))
    client = next(item for item in realm["clients"] if item["clientId"] == "marty-api")

    assert client["authorizationServicesEnabled"] is False
    assert "authorizationSettings" not in client
