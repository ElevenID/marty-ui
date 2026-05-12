"""Tests for public credential type metadata routes."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.routes.credential_metadata import credential_metadata_router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(credential_metadata_router)
    return TestClient(app)


def test_marty_badge_type_metadata_is_official_and_image_backed(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_API_URL", "https://beta.elevenidllc.com")
    client = _client()

    response = client.get("/credentials/marty-verified-member-badge")

    assert response.status_code == 200
    body = response.json()
    assert body["vct"] == "https://beta.elevenidllc.com/credentials/marty-verified-member-badge"
    assert body["name"] == "Marty Verified Member Badge"
    assert "example" not in body["vct"].lower()
    assert "example" not in body["name"].lower()
    assert "experimental" not in body["description"].lower()
    display = body["display"][0]
    assert display["logo"]["uri"] == "https://beta.elevenidllc.com/credentials/marty-verified-member-badge/image.svg"
    assert display["rendering"]["simple"]["logo"]["alt_text"] == "Marty Verified Member Badge"


def test_marty_badge_image_is_svg() -> None:
    client = _client()

    response = client.get("/credentials/marty-verified-member-badge/image.svg")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "MARTY" in response.text
    assert "VERIFIED MEMBER" in response.text
