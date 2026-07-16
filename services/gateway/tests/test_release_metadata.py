import httpx
import pytest

import gateway.main as gateway_main
from gateway.release_metadata import release_metadata


def test_release_metadata_reports_embedded_runtime_identity(monkeypatch) -> None:
    monkeypatch.setenv("MARTY_RELEASE_VERSION", "mip-0.3.1-beta-test")
    monkeypatch.setenv("MARTY_UI_SHA", "a" * 40)
    monkeypatch.setenv("ELEVENID_STACK_VERSION", "2026.07.0")
    monkeypatch.setenv(
        "ELEVENID_IMAGE_DIGESTS_JSON",
        '{"gateway":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
    )

    assert release_metadata() == {
        "component": "services",
        "release_version": "mip-0.3.1-beta-test",
        "deployment_release_marker": "mip-0.3.1-beta-test",
        "stack_version": "2026.07.0",
        "mip_version": "0.3.1",
        "marty_ui_sha": "a" * 40,
        "image_digests": {
            "gateway": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
    }


def test_release_metadata_is_explicitly_non_release_without_build_args(monkeypatch) -> None:
    monkeypatch.delenv("MARTY_RELEASE_VERSION", raising=False)
    monkeypatch.delenv("MARTY_UI_SHA", raising=False)
    monkeypatch.delenv("ELEVENID_STACK_VERSION", raising=False)
    monkeypatch.delenv("ELEVENID_IMAGE_DIGESTS_JSON", raising=False)

    assert release_metadata() == {
        "component": "services",
        "release_version": "development",
        "deployment_release_marker": "development",
        "stack_version": "development",
        "mip_version": "0.3.1",
        "marty_ui_sha": "unknown",
        "image_digests": {},
    }


def test_release_metadata_ignores_malformed_image_digest_json(monkeypatch) -> None:
    monkeypatch.setenv("ELEVENID_IMAGE_DIGESTS_JSON", "not-json")

    assert release_metadata()["image_digests"] == {}


@pytest.mark.asyncio
async def test_release_metadata_route_exposes_embedded_identity(monkeypatch) -> None:
    monkeypatch.setenv("MARTY_RELEASE_VERSION", "mip-0.3.1-beta-test")
    monkeypatch.setenv("MARTY_UI_SHA", "b" * 40)
    monkeypatch.setenv("ELEVENID_STACK_VERSION", "2026.07.0")
    monkeypatch.setenv("ELEVENID_IMAGE_DIGESTS_JSON", "{}")
    transport = httpx.ASGITransport(app=gateway_main.create_app())

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/.well-known/marty-release")

    assert response.status_code == 200
    assert response.json() == {
        "component": "services",
        "release_version": "mip-0.3.1-beta-test",
        "deployment_release_marker": "mip-0.3.1-beta-test",
        "stack_version": "2026.07.0",
        "mip_version": "0.3.1",
        "marty_ui_sha": "b" * 40,
        "image_digests": {},
    }
