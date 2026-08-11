from __future__ import annotations

import base64
from pathlib import Path

import pytest

from common.native_backend import NativeBackendUnavailable
from services.revocation_profile.native_status_list import (
    NativeStatusListAdapter,
    NativeStatusListOperationError,
)
from services.revocation_profile.status_list_manager import (
    StatusList,
    StatusListFormat,
    StatusListManager,
)


class InMemoryStatusRepository:
    def __init__(self) -> None:
        self.status_lists: dict[tuple[str, StatusListFormat], StatusList] = {}
        self.next_indices: dict[tuple[str, StatusListFormat], int] = {}

    async def get(
        self,
        tenant_id: str,
        format: StatusListFormat,
    ) -> StatusList | None:
        return self.status_lists.get((tenant_id, format))

    async def save(self, status_list: StatusList) -> bool:
        self.status_lists[(status_list.tenant_id, status_list.format)] = status_list
        return True

    async def get_next_index(
        self,
        tenant_id: str,
        format: StatusListFormat,
    ) -> int:
        key = (tenant_id, format)
        index = self.next_indices.get(key, 0)
        self.next_indices[key] = index + 1
        return index

    async def record_allocation(
        self,
        tenant_id: str,
        format: StatusListFormat,
        index: int,
        credential_id: str,
    ) -> bool:
        return bool(tenant_id and format and index >= 0 and credential_id)


def test_native_adapter_requires_raw_byte_constructors() -> None:
    class MissingBackend:
        TokenStatusList = object
        BitstringStatusList = object

    with pytest.raises(NativeBackendUnavailable, match="TokenStatusList.from_bytes"):
        NativeStatusListAdapter(MissingBackend())


def test_native_adapter_rejects_invalid_persisted_shape() -> None:
    adapter = NativeStatusListAdapter()

    with pytest.raises(NativeStatusListOperationError):
        adapter.get_token_status(b"\x00", 2, 8, 0)

    with pytest.raises(NativeStatusListOperationError):
        adapter.get_bitstring_status(b"\x00", 9, 0)


@pytest.mark.asyncio
async def test_manager_mutates_and_encodes_only_through_rust() -> None:
    repository = InMemoryStatusRepository()
    manager = StatusListManager(repository=repository)

    await manager.set_status("org-1", 7, 1, StatusListFormat.BITSTRING)
    assert await manager.get_status("org-1", 7, StatusListFormat.BITSTRING) == 1
    bitstring = await manager.get_or_create("org-1", StatusListFormat.BITSTRING)
    assert bitstring.data[0] == 0b0000_0001

    credential = manager.encode_bitstring_status_list(
        bitstring,
        "did:web:issuer.example",
    )
    encoded = credential["credentialSubject"]["encodedList"]
    assert encoded.startswith("u")
    compressed = base64.urlsafe_b64decode(
        encoded[1:] + "=" * (-len(encoded[1:]) % 4)
    )
    assert compressed.startswith(b"\x1f\x8b")

    await manager.set_status("org-1", 1, 7, StatusListFormat.TOKEN_STATUS_LIST)
    assert (
        await manager.get_status("org-1", 1, StatusListFormat.TOKEN_STATUS_LIST)
        == 7
    )
    token = await manager.get_or_create("org-1", StatusListFormat.TOKEN_STATUS_LIST)
    claim = manager.encode_status_list_token(token, "issuer", "subject")
    assert claim["status_list"]["bits"] == 8
    assert isinstance(claim["status_list"]["lst"], str)


def test_python_manager_contains_no_status_kernel() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "status_list_manager.py"
    ).read_text(encoding="utf-8")

    forbidden = (
        "import zlib",
        "bytearray(status_list.data)",
        "1 << (7 - bit_index)",
        "urlsafe_b64encode(compressed)",
    )
    assert all(fragment not in source for fragment in forbidden)
