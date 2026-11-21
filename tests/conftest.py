"""Explicit runtime fixtures for tests that mock Docker operations."""

import pytest

from scripts import local_docker


@pytest.fixture
def rootful_docker_environment(monkeypatch):
    """Keep mocked legacy-daemon tests independent of the machine running them."""
    local_docker._selected_endpoint.cache_clear()
    monkeypatch.setattr(local_docker, "_rootless_candidate", lambda: None)
    try:
        yield
    finally:
        local_docker._selected_endpoint.cache_clear()
