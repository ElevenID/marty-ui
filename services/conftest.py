"""Shared test fixtures for gRPC adapter tests."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import grpc
import pytest

# Ensure packages/ and services/ are importable
REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGES_ROOT = REPO_ROOT / "packages"
SERVICES_ROOT = REPO_ROOT / "services"

for p in (str(REPO_ROOT), str(PACKAGES_ROOT), str(SERVICES_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)


class FakeServicerContext:
    """Minimal stand-in for ``grpc.aio.ServicerContext``.

    Records code/details set during the RPC so tests can assert on them.
    """

    def __init__(self):
        self._code: grpc.StatusCode | None = None
        self._details: str | None = None

    def set_code(self, code: grpc.StatusCode) -> None:
        self._code = code

    def set_details(self, details: str) -> None:
        self._details = details

    @property
    def code(self) -> grpc.StatusCode | None:
        return self._code

    @property
    def details(self) -> str | None:
        return self._details


@pytest.fixture
def ctx() -> FakeServicerContext:
    """Fresh gRPC servicer context for each test."""
    return FakeServicerContext()
