"""Real loopback streaming-fixture tests, not whole-worker qualification."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http.client import HTTPSConnection, IncompleteRead, RemoteDisconnected
import importlib
import json
from pathlib import Path
import ssl
from threading import Event
import time
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return (
        importlib.import_module("canvas_worker_body_timeout_https_fixture"),
        importlib.import_module("canvas_worker_https_fixture"),
    )


def expected_request():
    return {
        "method": "GET",
        "path": "/owned",
        "authorization": "Bearer synthetic-body-token",
        "accept": "application/json",
    }


def client_for(fixture, *, trusted=True):
    context = (
        ssl.create_default_context(cafile=str(fixture.cert))
        if trusted
        else ssl.create_default_context()
    )
    return HTTPSConnection(
        "127.0.0.1", fixture.server.server_port, context=context, timeout=3
    )


def send(client, *, method="GET", path="/owned", token="synthetic-body-token"):
    client.request(
        method,
        path,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    return client.getresponse()


@pytest.mark.parametrize("method", ["GET", "DELETE"])
@pytest.mark.parametrize("status,body", [(200, {"retained": True}), (204, None)])
def test_existing_base_get_delete_framing_and_observation_are_unchanged(
    modules, method, status, body
):
    _, base = modules
    with base.WorkerHttpsFixture() as fixture:
        fixture.stage = {
            "status": status,
            "body": body,
            "headers": {"X-Synthetic": "retained"},
        }
        with closing(client_for(fixture)) as client:
            response = send(client, method=method)
            payload = response.read()
        expected = (
            b"" if status == 204 else json.dumps(body, separators=(",", ":")).encode()
        )
        assert response.status == status and payload == expected
        assert response.getheader("Content-Length") == str(len(expected))
        assert response.getheader("Content-Type") == "application/json"
        assert response.getheader("X-Synthetic") == "retained"
        assert fixture.requests == [{**expected_request(), "method": method}]
        assert fixture.failures == []


@pytest.mark.parametrize("body", [{"accepted": True, "score": 90.0}, [], {}])
def test_actual_https_partial_progress_completes_framed_valid_json(modules, body):
    body_module, _ = modules
    with body_module.BodyTimeoutHttpsFixture(
        expected_request(),
        {"status": 200, "body": body},
        chunk_offsets=[0, 0.25, 0.5, 0.75],
    ) as fixture:
        first_byte = Event()

        def read():
            with closing(client_for(fixture)) as client:
                response = send(client)
                first = response.read(1)
                assert len(first) == 1
                first_byte.set()
                return response, first + response.read()

        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(read)
            assert fixture.request_started.wait(2)
            assert not fixture.body_started.is_set()
            fixture.initial_ready.set()
            assert first_byte.wait(2)
            assert not fixture.chunk_events[-1].is_set()
            assert not pending.done()
            response, raw = pending.result(timeout=3)
        assert response.status == 200
        assert response.getheader("Content-Type") == "application/json"
        assert int(response.getheader("Content-Length")) == len(raw)
        assert json.loads(raw) == body
        assert b"".join(fixture.chunks) == raw
        assert fixture.schedule_completed.wait(1) and fixture.handler_finished.wait(1)
        assert all(event.is_set() for event in fixture.chunk_events)
        assert fixture.requests == [expected_request()] and fixture.failures == []
        observations = fixture.observations()
        assert [item["index"] for item in observations] == list(range(4))
        assert [item["scheduled_offset_seconds"] for item in observations] == [
            0,
            0.25,
            0.5,
            0.75,
        ]
        assert all(item["outcome"] == "flushed" for item in observations)
        assert sum(item["byte_count"] for item in observations) == len(raw)
        assert observations[-1]["write_started_seconds"] >= 0.75
        assert all(
            item["write_completed_seconds"]
            >= item["write_started_seconds"]
            >= item["scheduled_offset_seconds"]
            for item in observations
        )
        for prefix_length in range(1, len(fixture.chunks)):
            with pytest.raises(json.JSONDecodeError):
                json.loads(b"".join(fixture.chunks[:prefix_length]))
        assert all(
            item["flushed_byte_count"] == item["byte_count"] for item in observations
        )
        assert "synthetic-body-token" not in json.dumps(observations)
        certificate_directory = fixture.cert.parent
    assert not certificate_directory.exists()
    assert not fixture.thread.is_alive()


@pytest.mark.parametrize(
    "offsets",
    [
        [],
        [0],
        [1, 2],
        [0, 0],
        [0, -1],
        [0, 1, 0.5],
        [0, float("nan")],
        [0, float("inf")],
        [False, 1],
        [0, True],
        [0, "1"],
        [0, 60.001],
        list(range(17)),
        [0, 10**1000],
    ],
)
def test_invalid_schedule_rejected_before_server_creation(modules, offsets):
    body_module, _ = modules
    with pytest.raises((AssertionError, ValueError)):
        body_module.BodyTimeoutHttpsFixture(
            expected_request(),
            {"status": 200, "body": []},
            chunk_offsets=offsets,
        )


@pytest.mark.parametrize("disconnect_index", [-1, 0, 1, 3, True, "2"])
def test_only_declared_final_chunk_can_allow_peer_close(modules, disconnect_index):
    body_module, _ = modules
    with pytest.raises((AssertionError, ValueError)):
        body_module.BodyTimeoutHttpsFixture(
            expected_request(),
            {"status": 200, "body": []},
            chunk_offsets=[0, 1, 2],
            late_disconnect_from_index=disconnect_index,
        )


@pytest.mark.parametrize(
    "wait", [-1, 0, True, float("nan"), float("inf"), 10**1000, 30.001]
)
def test_invalid_initial_wait_is_rejected(modules, wait):
    body_module, _ = modules
    with pytest.raises((AssertionError, ValueError)):
        body_module.BodyTimeoutHttpsFixture(
            expected_request(),
            {"status": 200, "body": []},
            chunk_offsets=[0, 0.1],
            initial_wait_seconds=wait,
        )


@pytest.mark.parametrize("mismatch", ["method", "path", "authorization", "extra"])
def test_real_unexpected_requests_remain_observed_and_fail_closed(modules, mismatch):
    body_module, _ = modules
    fixture = body_module.BodyTimeoutHttpsFixture(
        expected_request(),
        {"status": 200, "body": []},
        chunk_offsets=[0, 0.03],
        late_disconnect_from_index=1,
    )
    fixture.__enter__()
    fixture.initial_ready.set()
    try:
        with closing(client_for(fixture)) as client:
            if mismatch == "method":
                response = send(client, method="POST")
                assert response.status == 501
                response.read()
            elif mismatch == "extra":
                assert json.loads(send(client).read()) == []
                with pytest.raises(RemoteDisconnected):
                    send(client)
            else:
                with pytest.raises(RemoteDisconnected):
                    send(
                        client,
                        **(
                            {"path": "/private-sentinel"}
                            if mismatch == "path"
                            else {"token": "private-sentinel"}
                        ),
                    )
        with pytest.raises(AssertionError) as caught:
            fixture.assert_requests()
        assert "private-sentinel" not in str(caught.value)
        assert len(fixture.requests) == (2 if mismatch == "extra" else 1)
        assert fixture.requests[0]["method"] == (
            "POST" if mismatch == "method" else "GET"
        )
    finally:
        fixture.close()


def test_untrusted_tls_is_not_accepted_as_an_expected_late_disconnect(modules):
    body_module, _ = modules
    with body_module.BodyTimeoutHttpsFixture(
        expected_request(),
        {"status": 200, "body": []},
        chunk_offsets=[0, 0.03],
        late_disconnect_from_index=1,
    ) as fixture:
        with closing(client_for(fixture, trusted=False)) as client:
            with pytest.raises(ssl.SSLCertVerificationError):
                send(client)
        assert fixture.requests == []
        assert not fixture.body_started.is_set()
        assert fixture.chunk_observations == []


@pytest.mark.parametrize(
    "body", [{"large": "x" * 65_536}, {"bad": float("nan")}, {"bad": object()}]
)
def test_invalid_or_oversized_body_rejected_without_private_diagnostics(modules, body):
    module, _ = modules
    with pytest.raises(AssertionError) as caught:
        module.BodyTimeoutHttpsFixture(
            expected_request(), {"status": 200, "body": body}, chunk_offsets=[0, 0.001]
        )
    assert len(str(caught.value)) < 120


class ControlledWriter:
    def __init__(self, error, slot, phase="write"):
        self.error, self.slot, self.phase = error, slot, phase
        self.index = -1

    def write(self, data):
        self.index += 1
        if self.index == self.slot and self.phase == "write":
            raise self.error
        return len(data) - (self.index == self.slot and self.phase == "short")

    def flush(self):
        if self.index == self.slot and self.phase == "flush":
            raise self.error


def exercise_writer(module, error, slot, *, allowed=1, phase="write"):
    fixture = module.BodyTimeoutHttpsFixture(
        expected_request(),
        {"status": 200, "body": []},
        chunk_offsets=[0, 0.001],
        late_disconnect_from_index=allowed,
    )
    fixture.body_started_at = time.monotonic()
    writer = ControlledWriter(error, slot, phase)
    return fixture, lambda: fixture.write_response_body(
        SimpleNamespace(wfile=writer),
        fixture.body_bytes,
        index=0,
        path="/owned",
        stage=fixture.stage,
    )


@pytest.mark.parametrize(
    "error_type,category",
    [
        (BrokenPipeError, "broken_pipe"),
        (ConnectionResetError, "connection_reset"),
        (ssl.SSLEOFError, "tls_eof"),
        (ssl.SSLZeroReturnError, "tls_closed"),
    ],
)
@pytest.mark.parametrize("phase", ["write", "flush"])
def test_only_explicit_final_peer_close_is_counted_not_claimed_as_flushed(
    modules, error_type, category, phase
):
    fixture, write = exercise_writer(
        modules[0], error_type("private-sentinel"), 1, phase=phase
    )
    write()
    observations = fixture.observations()
    assert [item["outcome"] for item in observations] == ["flushed", "peer_closed"]
    assert observations[-1]["disconnect_category"] == category
    assert observations[-1]["flushed_byte_count"] is None
    assert "private-sentinel" not in json.dumps(observations)
    assert fixture.schedule_completed.is_set() and fixture.handler_finished.is_set()
    observations.clear()
    assert len(fixture.observations()) == 2


@pytest.mark.parametrize(
    "error_type",
    [BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLZeroReturnError],
)
@pytest.mark.parametrize("slot,allowed", [(0, 1), (1, None)])
def test_peer_close_without_exact_final_slot_permission_propagates(
    modules, error_type, slot, allowed
):
    error = error_type("private-sentinel")
    fixture, write = exercise_writer(modules[0], error, slot, allowed=allowed)
    with pytest.raises(error_type) as caught:
        write()
    assert caught.value is error
    assert not fixture.schedule_completed.is_set() and fixture.handler_finished.is_set()
    assert not any(item["outcome"] == "peer_closed" for item in fixture.observations())


@pytest.mark.parametrize(
    "error_type", [ssl.SSLError, OSError, TimeoutError, RuntimeError]
)
@pytest.mark.parametrize("phase", ["write", "flush"])
def test_unexpected_final_send_failure_is_never_masked(modules, error_type, phase):
    error = error_type("private-sentinel")
    fixture, write = exercise_writer(modules[0], error, 1, phase=phase)
    with pytest.raises(error_type) as caught:
        write()
    assert caught.value is error
    assert not fixture.schedule_completed.is_set() and fixture.handler_finished.is_set()


def test_short_write_fails_instead_of_claiming_full_progress(modules):
    fixture, write = exercise_writer(modules[0], None, 1, phase="short")
    with pytest.raises(AssertionError, match="full chunk"):
        write()
    assert len(fixture.observations()) == 1
    assert not fixture.schedule_completed.is_set()


@pytest.mark.parametrize("during_body", [False, True])
def test_early_close_cancels_schedule_joins_handler_and_is_idempotent(
    modules, during_body
):
    fixture = modules[0].BodyTimeoutHttpsFixture(
        expected_request(),
        {"status": 200, "body": []},
        chunk_offsets=[0, 5],
        initial_wait_seconds=1,
    )
    fixture.__enter__()
    certificate_directory = fixture.cert.parent

    def read():
        with closing(client_for(fixture)) as client:
            try:
                return send(client).read()
            except (IncompleteRead, RemoteDisconnected):
                return None

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(read)
            assert fixture.request_started.wait(2)
            if during_body:
                fixture.initial_ready.set()
                assert fixture.chunk_events[0].wait(2)
            started = time.monotonic()
            fixture.close()
            fixture.close()
            assert time.monotonic() - started < 3
            pending.result(timeout=3)
        assert fixture.handler_finished.is_set()
        assert not fixture.schedule_completed.is_set()
        assert not fixture.thread.is_alive()
        assert not certificate_directory.exists()
    finally:
        fixture.close()


def test_incomplete_http_headers_have_bounded_handler_cleanup_after_tls(
    modules, monkeypatch
):
    fixture = modules[0].BodyTimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, chunk_offsets=[0, 0.01]
    )
    handler_ready = Event()
    configure = fixture.configure_request_connection

    def configured(handler):
        configure(handler)
        handler_ready.set()

    monkeypatch.setattr(fixture, "configure_request_connection", configured)
    fixture.__enter__()
    try:
        with closing(client_for(fixture)) as client:
            client.connect()
            client.sock.sendall(b"GET /owned HTTP/1.1\r\nX-Incomplete:")
            assert handler_ready.wait(2)
            started = time.monotonic()
            fixture.close()
            assert time.monotonic() - started < 3.5
            assert client.sock.recv(1) == b""
        assert fixture.requests == []
        assert not fixture.thread.is_alive()
        assert not fixture.cert.parent.exists()
    finally:
        fixture.close()


def test_base_connection_setup_hook_does_not_change_existing_socket_defaults(modules):
    calls = []
    handler = SimpleNamespace(connection=SimpleNamespace(settimeout=calls.append))
    modules[1].WorkerHttpsFixture().configure_request_connection(handler)
    assert calls == []
    fixture = modules[0].BodyTimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, chunk_offsets=[0, 0.001]
    )
    fixture.configure_request_connection(handler)
    assert calls == [2.0]


def test_actual_unexpected_tls_send_failure_reaches_static_owner_ledger(
    modules, monkeypatch
):
    fixture = modules[0].BodyTimeoutHttpsFixture(
        expected_request(),
        {"status": 200, "body": []},
        chunk_offsets=[0, 0.01],
        late_disconnect_from_index=1,
    )

    def fail_write(*args, **kwargs):
        raise ssl.SSLError("private-send-sentinel")

    monkeypatch.setattr(fixture, "write_response_body", fail_write)
    fixture.__enter__()
    fixture.initial_ready.set()
    try:
        with closing(client_for(fixture)) as client:
            with pytest.raises(IncompleteRead):
                send(client).read()
        fixture.close()
        assert fixture.failures == ["Owned HTTPS request handler failed"]
        with pytest.raises(
            AssertionError, match="Owned body transport failed"
        ) as caught:
            fixture.assert_requests()
        assert "private-send-sentinel" not in str(caught.value)
        assert fixture.observations() == []
        assert not fixture.schedule_completed.is_set()
    finally:
        fixture.close()


@pytest.mark.parametrize("after_close", [False, True])
def test_single_use_rejects_active_or_closed_reentry_without_replacing_owners(
    modules, monkeypatch, after_close
):
    module, base = modules
    fixture = module.BodyTimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, chunk_offsets=[0, 0.01]
    )
    entries = []
    original_enter = base.WorkerHttpsFixture.__enter__

    def enter(owner):
        entries.append(owner)
        return original_enter(owner)

    monkeypatch.setattr(base.WorkerHttpsFixture, "__enter__", enter)
    fixture.__enter__()
    server, thread, certificates = fixture.server, fixture.thread, fixture.certificates
    directory = fixture.cert.parent
    try:
        if after_close:
            fixture.close()
        with pytest.raises(AssertionError, match="single-use"):
            fixture.__enter__()
        assert entries == [fixture]
        assert fixture.server is server and fixture.thread is thread
        assert fixture.certificates is certificates
        assert thread.is_alive() is not after_close
    finally:
        fixture.close()
    assert not thread.is_alive() and not directory.exists()


def test_single_use_rejects_entry_after_close_before_any_allocation(
    modules, monkeypatch
):
    module, base = modules
    fixture = module.BodyTimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, chunk_offsets=[0, 0.01]
    )
    entries = []
    monkeypatch.setattr(
        base.WorkerHttpsFixture, "__enter__", lambda owner: entries.append(owner)
    )
    fixture.close()
    with pytest.raises(AssertionError, match="single-use"):
        fixture.__enter__()
    assert entries == []
    assert fixture.server is fixture.thread is fixture.certificates is None


def test_partial_entry_failure_cleans_up_and_cannot_retry_allocations(
    modules, monkeypatch
):
    module, base = modules
    fixture = module.BodyTimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, chunk_offsets=[0, 0.01]
    )
    directories = []
    original_error = RuntimeError("synthetic-certificate-allocation-failure")

    def fail_certificate(directory):
        directories.append(directory)
        assert directory.is_dir()
        raise original_error

    monkeypatch.setattr(base, "create_loopback_certificate", fail_certificate)
    with pytest.raises(RuntimeError) as caught:
        fixture.__enter__()
    assert caught.value is original_error
    assert len(directories) == 1 and not directories[0].exists()
    assert fixture.server is fixture.thread is None
    with pytest.raises(AssertionError, match="single-use"):
        fixture.__enter__()
    fixture.close()
    assert len(directories) == 1
