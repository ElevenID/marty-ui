"""Fail-closed adapter for the canonical Rust status-list implementation."""

from __future__ import annotations

import json
from types import ModuleType
from typing import Any

from common.native_backend import (
    NativeBackendUnavailable,
    NativeOperationError,
    get_marty_rs_diagnostics,
    load_marty_rs,
)


NATIVE_STATUS_LIST_CAPABILITY = "status_list"


class NativeStatusListOperationError(NativeOperationError):
    """The native status-list kernel rejected an operation."""


class NativeStatusListAdapter:
    """Map persisted service bytes to the sole canonical Rust status kernel."""

    def __init__(self, backend: ModuleType | Any | None = None) -> None:
        if backend is None:
            backend = load_marty_rs(
                required_capability=NATIVE_STATUS_LIST_CAPABILITY,
            )
            diagnostics = get_marty_rs_diagnostics(
                backend,
                required_capability=NATIVE_STATUS_LIST_CAPABILITY,
            )
        else:
            diagnostics = {
                "available": True,
                "backend": "injected-test-backend",
                "version": "test",
                "capabilities": [NATIVE_STATUS_LIST_CAPABILITY],
            }

        token_type = getattr(backend, "TokenStatusList", None)
        bitstring_type = getattr(backend, "BitstringStatusList", None)
        create_token_claim = getattr(backend, "create_status_list_claim", None)
        create_bitstring_subject = getattr(
            backend,
            "create_bitstring_credential_subject",
            None,
        )
        if token_type is None or not callable(getattr(token_type, "from_bytes", None)):
            raise NativeBackendUnavailable(
                "The Marty Rust backend does not expose TokenStatusList.from_bytes"
            )
        if bitstring_type is None or not callable(
            getattr(bitstring_type, "from_bytes", None)
        ):
            raise NativeBackendUnavailable(
                "The Marty Rust backend does not expose BitstringStatusList.from_bytes"
            )
        if not callable(create_token_claim) or not callable(create_bitstring_subject):
            raise NativeBackendUnavailable(
                "The Marty Rust backend does not expose canonical status-list encoders"
            )

        self._token_type = token_type
        self._bitstring_type = bitstring_type
        self._create_token_claim = create_token_claim
        self._create_bitstring_subject = create_bitstring_subject
        self.native_backend_diagnostics = diagnostics

    def empty_token_bytes(self, size: int, bits: int) -> bytes:
        return self._call_bytes(lambda: self._token_type(size, bits).to_bytes())

    def empty_bitstring_bytes(self, size: int) -> bytes:
        return self._call_bytes(lambda: self._bitstring_type(size).to_bytes())

    def set_token_status(
        self,
        data: bytes,
        size: int,
        bits: int,
        index: int,
        status: int,
    ) -> bytes:
        def operation() -> Any:
            status_list = self._token_type.from_bytes(data, size, bits)
            status_list.set(index, status)
            return status_list.to_bytes()

        return self._call_bytes(operation)

    def set_bitstring_status(
        self,
        data: bytes,
        size: int,
        index: int,
        revoked: bool,
    ) -> bytes:
        def operation() -> Any:
            status_list = self._bitstring_type.from_bytes(data, size)
            status_list.set(index, revoked)
            return status_list.to_bytes()

        return self._call_bytes(operation)

    def get_token_status(
        self,
        data: bytes,
        size: int,
        bits: int,
        index: int,
    ) -> int:
        try:
            result = self._token_type.from_bytes(data, size, bits).get(index)
        except Exception as error:
            raise NativeStatusListOperationError(
                "Native token status-list lookup failed"
            ) from error
        if not isinstance(result, int) or isinstance(result, bool):
            raise NativeStatusListOperationError(
                "Native token status-list lookup returned an invalid value"
            )
        return result

    def get_bitstring_status(self, data: bytes, size: int, index: int) -> int:
        try:
            result = self._bitstring_type.from_bytes(data, size).get(index)
        except Exception as error:
            raise NativeStatusListOperationError(
                "Native bitstring status-list lookup failed"
            ) from error
        if not isinstance(result, bool):
            raise NativeStatusListOperationError(
                "Native bitstring status-list lookup returned an invalid value"
            )
        return int(result)

    def compress_token(self, data: bytes, size: int, bits: int) -> bytes:
        return self._call_bytes(
            lambda: self._token_type.from_bytes(data, size, bits).compress()
        )

    def encode_bitstring(self, data: bytes, size: int) -> str:
        try:
            encoded = self._bitstring_type.from_bytes(data, size).to_base64url()
        except Exception as error:
            raise NativeStatusListOperationError(
                "Native bitstring status-list encoding failed"
            ) from error
        if not isinstance(encoded, str) or not encoded.startswith("u"):
            raise NativeStatusListOperationError(
                "Native bitstring status-list encoding returned an invalid value"
            )
        return encoded

    def token_claim(self, data: bytes, size: int, bits: int) -> dict[str, Any]:
        try:
            status_list = self._token_type.from_bytes(data, size, bits)
            claim = json.loads(self._create_token_claim(status_list))
        except Exception as error:
            raise NativeStatusListOperationError(
                "Native token status-list claim encoding failed"
            ) from error
        if not isinstance(claim, dict) or set(claim) != {"bits", "lst"}:
            raise NativeStatusListOperationError(
                "Native token status-list claim returned an invalid value"
            )
        return claim

    def bitstring_subject(
        self,
        data: bytes,
        size: int,
        subject_id: str,
        status_purpose: str,
    ) -> dict[str, Any]:
        try:
            status_list = self._bitstring_type.from_bytes(data, size)
            subject = json.loads(
                self._create_bitstring_subject(
                    status_list,
                    subject_id,
                    status_purpose,
                )
            )
        except Exception as error:
            raise NativeStatusListOperationError(
                "Native bitstring credential-subject encoding failed"
            ) from error
        required = {"id", "type", "statusPurpose", "encodedList"}
        if not isinstance(subject, dict) or set(subject) != required:
            raise NativeStatusListOperationError(
                "Native bitstring credential subject returned an invalid value"
            )
        return subject

    @staticmethod
    def _call_bytes(operation: Any) -> bytes:
        try:
            result = operation()
        except Exception as error:
            raise NativeStatusListOperationError(
                "Native status-list operation failed"
            ) from error
        try:
            return bytes(result)
        except (TypeError, ValueError) as error:
            raise NativeStatusListOperationError(
                "Native status-list operation returned invalid bytes"
            ) from error
