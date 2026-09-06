"""Fixture ownership/failure tests; not application worker parity evidence."""

from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime
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


@pytest.mark.parametrize("offset", [-60, 60])
def test_response_time_retry_after_date(fixture_module, offset):
    stage = {
        "headers": {"X-Synthetic": "retained"},
        "retry_after_offset_seconds": offset,
    }
    headers = fixture_module.response_headers(stage, now=1700000000)
    assert (
        parsedate_to_datetime(headers["Retry-After"]).timestamp() == 1700000000 + offset
    )
    assert headers["Retry-After"].endswith(" GMT")
    assert headers["X-Synthetic"] == "retained"
    assert stage["headers"] == {"X-Synthetic": "retained"}


@pytest.mark.parametrize("offset", [True, False, "60", 0.5, -86402, 86402])
def test_invalid_retry_after_date_offset_is_rejected(fixture_module, offset):
    with pytest.raises(AssertionError):
        fixture_module.response_headers({"retry_after_offset_seconds": offset}, now=0)


@pytest.mark.parametrize("header", ["Retry-After", "retry-after", "RETRY-AFTER"])
def test_conflicting_retry_after_headers_are_rejected(fixture_module, header):
    with pytest.raises(AssertionError):
        fixture_module.response_headers(
            {"headers": {header: "37"}, "retry_after_offset_seconds": 60}, now=0
        )


def test_static_headers_remain_unchanged(fixture_module):
    stage = {"headers": {"Retry-After": "37"}}
    headers = fixture_module.response_headers(stage)
    assert headers == stage["headers"]
    assert headers is not stage["headers"]
    assert fixture_module.response_headers({}) == {}


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_actual_https_emits_recorded_retry_after_date(fixture_module, monkeypatch, method):
    monkeypatch.setattr(fixture_module.time, "time", lambda: 1700000000)
    with fixture_module.WorkerHttpsFixture() as fixture:
        fixture.stage = {"status": 429, "body": {}, "retry_after_offset_seconds": 60}
        client = client_for(fixture)
        try:
            client.request(method, "/synthetic-rate-limit")
            response = client.getresponse()
            assert response.status == 429
            assert response.read() == b"{}"
            header = response.getheader("Retry-After")
            assert fixture.retry_after_dates == [header]
            assert parsedate_to_datetime(header).timestamp() == 1700000060
        finally:
            client.close()


@pytest.mark.parametrize(
    "method,path,authorization",
    [("GET", "/synthetic", None),
     ("DELETE", "/login/oauth2/token", "Bearer synthetic-fixture-token")],
)
def test_real_https_response_and_owned_cleanup(fixture_module, method, path, authorization):
    with fixture_module.WorkerHttpsFixture() as fixture:
        fixture.stage = {"status": 200, "body": {"score": 90.0}}
        client = client_for(fixture)
        try:
            headers = {"Accept": "application/json"}
            if authorization is not None:
                headers["Authorization"] = authorization
            client.request(method, path, headers=headers)
            response = client.getresponse()
            assert response.status == 200
            assert json.loads(response.read()) == {"score": 90.0}
            assert fixture.requests == [
                {
                    "method": method,
                    "path": path,
                    "authorization": authorization,
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


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_exit_releases_and_joins_pending_response(fixture_module, method):
    with ThreadPoolExecutor(max_workers=1) as executor:
        with fixture_module.WorkerHttpsFixture() as fixture:
            fixture.stage = {"status": 200, "body": {}, "hold_response": True}

            def request():
                client = client_for(fixture)
                try:
                    client.request(method, "/held")
                    return client.getresponse().read()
                finally:
                    client.close()

            pending = executor.submit(request)
            assert fixture.received.wait(3)
            assert not pending.done()
        assert pending.result(timeout=3) == b"{}"
    assert fixture.release.is_set()
    assert not fixture.thread.is_alive()


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_handler_failure_is_reported_to_owner(fixture_module, method):
    with pytest.raises(AssertionError, match="request handler failed"):
        with fixture_module.WorkerHttpsFixture() as fixture:
            fixture.stage = {}  # Invalid fixture input must not silently pass.
            client = client_for(fixture)
            try:
                client.request(method, "/invalid")
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
