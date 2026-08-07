from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from trust_profile.registry_sync import (
    RegistryImportState,
    RegistrySyncError,
    fetch_registry_page,
    require_public_registry_destination,
    synchronize_registry,
    validate_registry_url_structure,
)

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)
CSCA_ID = "c6d7e8f9-a0b1-4234-9678-901234abcdef"
DSC_ID = "d7e8f9a0-b1c2-4345-a789-012345abcdef"


async def allow_test_destination(_url: str) -> str | None:
    return None


def certificate_pem(*, ca: bool) -> str:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Registry test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def add_entry(entry_id: str, anchor_type: str, pem: str) -> dict[str, object]:
    return {
        "entry_id": entry_id,
        "anchor_type": anchor_type,
        "operation": "ADD",
        "country_code": "US",
        "certificate_pem": pem,
        "source": "MANUAL",
    }


def feed(
    *,
    token: str,
    sequence: int,
    entries: list[dict[str, object]],
    has_more: bool = False,
) -> dict[str, object]:
    return {
        "sync_token": token,
        "sequence": sequence,
        "entries": entries,
        "has_more": has_more,
        "generated_at": NOW.isoformat(),
    }


def json_response(request: httpx.Request, body: dict[str, object]) -> httpx.Response:
    return httpx.Response(
        200,
        request=request,
        json=body,
        headers={"content-type": "application/json"},
    )


@pytest.mark.asyncio
async def test_initial_and_delta_sync_are_independently_validated_and_atomic() -> None:
    csca = certificate_pem(ca=True)
    dsc = certificate_pem(ca=False)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        since = parse_qs(urlsplit(str(request.url)).query).get("since")
        if calls == 1:
            assert since is None
            return json_response(
                request,
                feed(
                    token="1",
                    sequence=1,
                    entries=[
                        add_entry(CSCA_ID, "CSCA", csca),
                        add_entry(DSC_ID, "DSC", dsc),
                    ],
                ),
            )
        assert since == ["1"]
        return json_response(
            request,
            feed(
                token="2",
                sequence=2,
                entries=[
                    {
                        "entry_id": CSCA_ID,
                        "anchor_type": "CSCA",
                        "operation": "REMOVE",
                        "country_code": "US",
                        "source": "MANUAL",
                    }
                ],
            ),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        initial = await synchronize_registry(
            "https://registry.example/v1/trust-registry/sync",
            RegistryImportState(),
            client=client,
            validate_destination=allow_test_destination,
            now=NOW,
        )
        assert set(initial.state.entries) == {CSCA_ID, DSC_ID}
        assert initial.state.sequence == 1

        delta = await synchronize_registry(
            "https://registry.example/v1/trust-registry/sync",
            initial.state,
            client=client,
            validate_destination=allow_test_destination,
            now=NOW,
        )

    assert set(delta.state.entries) == {DSC_ID}
    assert delta.state.sequence == 2
    assert delta.state.sync_token == "2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            feed(
                token="old",
                sequence=4,
                entries=[],
            ),
            "sequence rollback",
        ),
        (
            feed(
                token="6",
                sequence=6,
                entries=[
                    {
                        "entry_id": CSCA_ID,
                        "anchor_type": "CSCA",
                        "operation": "REMOVE",
                        "country_code": "US",
                        "source": "MANUAL",
                    }
                ],
            ),
            "unknown source entry",
        ),
    ],
)
async def test_delta_sync_rejects_rollback_and_unknown_removal(
    body: dict[str, object], message: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(request, body)

    previous = RegistryImportState(sync_token="5", sequence=5)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RegistrySyncError, match=message):
            await synchronize_registry(
                "https://registry.example/v1/trust-registry/sync",
                previous,
                client=client,
                validate_destination=allow_test_destination,
                now=NOW,
            )

    assert previous.sequence == 5
    assert previous.entries == {}


@pytest.mark.asyncio
async def test_delta_changes_must_advance_the_sequence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            request,
            feed(
                token="next",
                sequence=5,
                entries=[add_entry(CSCA_ID, "CSCA", certificate_pem(ca=True))],
            ),
        )

    previous = RegistryImportState(sync_token="current", sequence=5)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RegistrySyncError, match="did not advance"):
            await synchronize_registry(
                "https://registry.example/v1/trust-registry/sync",
                previous,
                client=client,
                validate_destination=allow_test_destination,
                now=NOW,
            )


@pytest.mark.asyncio
async def test_duplicate_entry_across_pages_is_rejected() -> None:
    csca = certificate_pem(ca=True)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return json_response(
            request,
            feed(
                token=str(calls),
                sequence=1,
                entries=[add_entry(CSCA_ID, "CSCA", csca)],
                has_more=calls == 1,
            ),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RegistrySyncError, match="duplicate entry"):
            await synchronize_registry(
                "https://registry.example/v1/trust-registry/sync",
                RegistryImportState(),
                client=client,
                validate_destination=allow_test_destination,
                now=NOW,
            )


@pytest.mark.asyncio
async def test_invalid_certificate_constraints_are_rejected() -> None:
    dsc_presented_as_csca = certificate_pem(ca=False)

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            request,
            feed(
                token="1",
                sequence=1,
                entries=[add_entry(CSCA_ID, "CSCA", dsc_presented_as_csca)],
            ),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RegistrySyncError, match="certificate-signing CA"):
            await synchronize_registry(
                "https://registry.example/v1/trust-registry/sync",
                RegistryImportState(),
                client=client,
                validate_destination=allow_test_destination,
                now=NOW,
            )


@pytest.mark.parametrize(
    "url",
    [
        "http://registry.example/sync",
        "https://user:not-a-real-value@registry.example/sync",
        "https://registry.example:8443/sync",
        "https://registry.example/sync?token=secret",
        "https://registry.example/sync#fragment",
    ],
)
def test_registry_url_structure_rejects_unsafe_forms(url: str) -> None:
    with pytest.raises(ValueError):
        validate_registry_url_structure(url)


@pytest.mark.asyncio
async def test_destination_validation_rejects_non_public_addresses(monkeypatch) -> None:
    def private_lookup(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [(None, None, None, None, (str(ipaddress.ip_address("127.0.0.1")), 443))]

    monkeypatch.setattr(
        "trust_profile.registry_sync.socket.getaddrinfo", private_lookup
    )
    with pytest.raises(RegistrySyncError, match="non-public"):
        await require_public_registry_destination("https://registry.example/sync")


@pytest.mark.asyncio
async def test_redirect_is_rejected_without_following_location() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            request=request,
            headers={"location": "https://other.example/sync"},
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        with pytest.raises(RegistrySyncError, match="redirects"):
            await synchronize_registry(
                "https://registry.example/v1/trust-registry/sync",
                RegistryImportState(),
                client=client,
                validate_destination=allow_test_destination,
                now=NOW,
            )


@pytest.mark.asyncio
async def test_request_uses_the_validated_address_with_original_host_and_sni() -> None:
    async def resolve_to_reviewed_address(_url: str) -> str:
        return "198.51.100.8"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "198.51.100.8"
        assert request.headers["host"] == "registry.example"
        assert request.extensions["sni_hostname"] == "registry.example"
        assert parse_qs(request.url.query.decode()) == {"since": ["cursor-1"]}
        return json_response(
            request,
            feed(token="cursor-2", sequence=2, entries=[]),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        page = await fetch_registry_page(
            "https://registry.example/v1/trust-registry/sync",
            "cursor-1",
            client=client,
            validate_destination=resolve_to_reviewed_address,
        )

    assert page.sync_token == "cursor-2"


@pytest.mark.asyncio
async def test_naive_feed_timestamp_is_rejected_as_contract_error() -> None:
    body = feed(token="1", sequence=1, entries=[])
    body["generated_at"] = "2026-08-07T12:00:00"

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(request, body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RegistrySyncError, match="violates the sync contract"):
            await synchronize_registry(
                "https://registry.example/v1/trust-registry/sync",
                RegistryImportState(),
                client=client,
                validate_destination=allow_test_destination,
                now=NOW,
            )


@pytest.mark.asyncio
async def test_repeated_pagination_token_is_rejected_atomically() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return json_response(
            request,
            feed(token="same", sequence=calls, entries=[], has_more=True),
        )

    previous = RegistryImportState()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RegistrySyncError, match="repeated a pagination token"):
            await synchronize_registry(
                "https://registry.example/v1/trust-registry/sync",
                previous,
                client=client,
                validate_destination=allow_test_destination,
                now=NOW,
            )

    assert previous.sync_token is None
    assert previous.entries == {}


@pytest.mark.asyncio
async def test_oversized_response_is_rejected_before_parsing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            content=b"{}",
            headers={
                "content-type": "application/json",
                "content-length": str(2 * 1024 * 1024 + 1),
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RegistrySyncError, match="size limit"):
            await fetch_registry_page(
                "https://registry.example/v1/trust-registry/sync",
                None,
                client=client,
                validate_destination=allow_test_destination,
            )


def test_fixture_ids_remain_valid_uuids() -> None:
    assert str(UUID(CSCA_ID)) == CSCA_ID
    assert str(UUID(DSC_ID)) == DSC_ID
