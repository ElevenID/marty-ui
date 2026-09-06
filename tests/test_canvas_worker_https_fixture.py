"""Fixture ownership/failure tests; not application worker parity evidence."""

from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPSConnection, RemoteDisconnected
import importlib
import json
from pathlib import Path
import ssl
from types import SimpleNamespace

import pytest


@pytest.fixture
def fixture_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("canvas_worker_https_fixture")


def client_for(fixture):
    return HTTPSConnection(
        "127.0.0.1",
        fixture.server.server_port,
        context=ssl.create_default_context(cafile=str(fixture.cert)),
        timeout=5,
    )


def test_real_https_response_and_owned_cleanup(fixture_module):
    with fixture_module.WorkerHttpsFixture() as fixture:
        fixture.stage = {"status": 200, "body": {"score": 90.0}}
        client = client_for(fixture)
        try:
            client.request("GET", "/synthetic", headers={"Accept": "application/json"})
            response = client.getresponse()
            assert response.status == 200
            assert json.loads(response.read()) == {"score": 90.0}
            assert fixture.requests == [
                {
                    "method": "GET",
                    "path": "/synthetic",
                    "authorization": None,
                    "accept": "application/json",
                }
            ]
        finally:
            client.close()
        certificate_directory = Path(fixture.certificates.name)
    assert not fixture.thread.is_alive()
    assert fixture.server.fileno() == -1
    assert not certificate_directory.exists()
    fixture.close()  # Repeated ownership cleanup is harmless.


def test_exit_releases_and_joins_pending_response(fixture_module):
    with ThreadPoolExecutor(max_workers=1) as executor:
        with fixture_module.WorkerHttpsFixture() as fixture:
            fixture.stage = {"status": 200, "body": {}, "hold_response": True}

            def request():
                client = client_for(fixture)
                try:
                    client.request("GET", "/held")
                    return client.getresponse().read()
                finally:
                    client.close()

            pending = executor.submit(request)
            assert fixture.received.wait(3)
            assert not pending.done()
        assert pending.result(timeout=3) == b"{}"
    assert fixture.release.is_set()
    assert not fixture.thread.is_alive()


def test_handler_failure_is_reported_to_owner(fixture_module):
    with pytest.raises(AssertionError, match="request handler failed"):
        with fixture_module.WorkerHttpsFixture() as fixture:
            fixture.stage = {}  # Invalid fixture input must not silently pass.
            client = client_for(fixture)
            try:
                client.request("GET", "/invalid")
                with pytest.raises(RemoteDisconnected):
                    client.getresponse()
            finally:
                client.close()
    assert not fixture.thread.is_alive()


def test_certificate_failure_removes_owned_temporary_directory(
    fixture_module, monkeypatch
):
    directories = []

    def fail(directory):
        directories.append(directory)
        raise RuntimeError("synthetic certificate failure")

    monkeypatch.setattr(fixture_module, "create_loopback_certificate", fail)
    with pytest.raises(RuntimeError, match="synthetic certificate failure"):
        with fixture_module.WorkerHttpsFixture():
            pytest.fail("Failed fixture must not enter its body")
    assert len(directories) == 1
    assert not directories[0].exists()


def test_native_marker_wait_stops_on_observed_condition(fixture_module):
    native = importlib.import_module("test_canvas_worker_provider_signals_https")
    native.wait_for(SimpleNamespace(), lambda: True, "already observed")


def test_native_marker_wait_reports_terminal_child_diagnostic(fixture_module):
    native = importlib.import_module("test_canvas_worker_provider_signals_https")
    child = SimpleNamespace(
        poll=lambda: 1, communicate=lambda **_: ("synthetic-out", "synthetic-error")
    )
    with pytest.raises(AssertionError, match="synthetic-out synthetic-error"):
        native.wait_for(child, lambda: False, "request")


def test_native_marker_wait_has_a_bounded_deadline(fixture_module):
    native = importlib.import_module("test_canvas_worker_provider_signals_https")
    with pytest.raises(AssertionError, match="Timed out waiting for request"):
        native.wait_for(
            SimpleNamespace(poll=lambda: None), lambda: False, "request", timeout=0
        )
