"""Real loopback TLS fixture controls, not DIDComm or PostgreSQL qualification."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http.client import HTTPSConnection
import importlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
JWE = '{"protected":"synthetic","ciphertext":"bounded"}'


@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("didcomm_wallet_fixture")


def connection(fixture, *, trusted=True):
    context = (
        ssl.create_default_context(cafile=str(fixture.cert))
        if trusted
        else ssl.create_default_context()
    )
    return HTTPSConnection(
        "127.0.0.1", fixture.server.server_port, context=context, timeout=3
    )


def request(fixture, *, method="POST", path="/inbox", body=JWE, headers=None):
    with closing(connection(fixture)) as client:
        client.request(
            method,
            path,
            body=body.encode() if isinstance(body, str) else body,
            headers=headers
            if headers is not None
            else {"Content-Type": "application/didcomm-encrypted+json"},
        )
        response = client.getresponse()
        return response.status, json.loads(response.read())


def captures(fixture):
    return request(fixture, method="GET", path="/captures", body=None, headers={})


@pytest.mark.parametrize("status", [200, 503])
def test_real_https_captures_exact_utf8_and_configured_response(
    module, tmp_path, status, capsys
):
    with module.WalletFixture(tmp_path, status=status) as fixture:
        assert fixture.origin.startswith("https://127.0.0.1:")
        assert fixture.cert == tmp_path / "ca.pem"
        assert request(fixture) == (status, {})
        unicode_jwe = JWE + " é"
        assert request(fixture, body=unicode_jwe) == (status, {})
        assert captures(fixture) == (
            200,
            {"messages": [JWE, unicode_jwe], "failures": 0},
        )
    fixture.close()
    assert not fixture.thread.is_alive()
    assert (tmp_path / "ca.pem").is_file() and (tmp_path / "server.key").is_file()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", fixture.server.server_port), timeout=1)
    assert capsys.readouterr() == ("", "")


def test_untrusted_ca_cannot_deliver_and_does_not_poison_server(module, tmp_path):
    with module.WalletFixture(tmp_path) as fixture:
        with closing(connection(fixture, trusted=False)) as client:
            with pytest.raises(ssl.SSLCertVerificationError):
                client.request("POST", "/inbox", body=JWE)
        assert request(fixture)[0] == 200
        status, state = captures(fixture)
        assert status == 200 and state["messages"] == [JWE] and state["failures"] == 1


@pytest.mark.parametrize(
    "method,path,body,headers",
    [
        (
            "POST",
            "/wrong-private-path",
            JWE,
            {"Content-Type": "application/didcomm-encrypted+json"},
        ),
        (
            "POST",
            "/inbox?private=query",
            JWE,
            {"Content-Type": "application/didcomm-encrypted+json"},
        ),
        ("POST", "/inbox", JWE, {"Content-Type": "application/json"}),
        (
            "POST",
            "/inbox",
            JWE,
            {"Content-Type": "application/didcomm-encrypted+json; charset=utf-8"},
        ),
        (
            "POST",
            "/inbox",
            b"\xffprivate",
            {"Content-Type": "application/didcomm-encrypted+json"},
        ),
        ("POST", "/inbox", b"", {"Content-Type": "application/didcomm-encrypted+json"}),
        ("GET", "/captures?private=query", None, {}),
        ("GET", "/captures", b"private", {}),
        ("DELETE", "/inbox", None, {}),
    ],
)
def test_invalid_requests_are_static_and_never_captured(
    module, tmp_path, method, path, body, headers, capsys
):
    with module.WalletFixture(tmp_path) as fixture:
        status, payload = request(
            fixture, method=method, path=path, body=body, headers=headers
        )
        assert status in (400, 501) and payload == {}
        assert captures(fixture) == (200, {"messages": [], "failures": 1})
    assert capsys.readouterr() == ("", "")


def raw_request(fixture, headers):
    context = ssl.create_default_context(cafile=str(fixture.cert))
    with closing(
        socket.create_connection(("127.0.0.1", fixture.server.server_port), timeout=3)
    ) as raw:
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as stream:
            stream.sendall(
                b"POST /inbox HTTP/1.1\r\nHost: 127.0.0.1\r\n" + headers + b"\r\n"
            )
            response = bytearray()
            while part := stream.recv(4096):
                response.extend(part)
            return bytes(response)


@pytest.mark.parametrize(
    "framing",
    [
        b"",
        b"Content-Length: -1\r\n",
        b"Content-Length: 01\r\n",
        b"Content-Length: 1048577\r\n",
        b"Content-Length: 9999999999999999999\r\n",
        b"Content-Length: 1\r\nContent-Length: 1\r\n",
        b"Content-Length: 1, 1\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        b"Content-Length: 1\r\nExpect: 100-continue\r\n",
        b"Content-Length: 1\r\nContent-Type: application/didcomm-encrypted+json\r\n",
    ],
)
def test_wrong_or_ambiguous_framing_rejected_before_body(module, tmp_path, framing):
    with module.WalletFixture(tmp_path) as fixture:
        response = raw_request(
            fixture, b"Content-Type: application/didcomm-encrypted+json\r\n" + framing
        )
        assert response.startswith(b"HTTP/1.0 400 ") and response.endswith(b"{}")
        assert captures(fixture) == (200, {"messages": [], "failures": 1})


def test_capture_count_is_bounded_without_eviction(module, tmp_path):
    with module.WalletFixture(tmp_path) as fixture:
        for index in range(module.MAX_MESSAGES):
            assert request(fixture, body=str(index))[0] == 200
        assert request(fixture, body="private-overflow")[0] == 413
        assert captures(fixture) == (
            200,
            {"messages": list(map(str, range(module.MAX_MESSAGES))), "failures": 1},
        )


def test_one_megabyte_boundary_and_total_capture_budget(module, tmp_path):
    body = "x" * module.MAX_BODY_BYTES
    with module.WalletFixture(tmp_path) as fixture:
        for _ in range(4):
            assert request(fixture, body=body)[0] == 200
        assert request(fixture, body="private-overflow")[0] == 413
        assert fixture.server.capture_bytes == module.MAX_CAPTURE_BYTES
        assert captures(fixture) == (200, {"messages": [body] * 4, "failures": 1})


@pytest.mark.parametrize("phase", ["tls", "headers", "body"])
def test_partial_connection_has_bounded_close(module, monkeypatch, tmp_path, phase):
    monkeypatch.setattr(module, "READ_TIMEOUT", 0.2)
    monkeypatch.setattr(module, "REQUEST_TIMEOUT", 0.4)
    fixture = module.WalletFixture(tmp_path)
    raw = socket.create_connection(("127.0.0.1", fixture.server.server_port), timeout=2)
    stream = raw
    try:
        if phase != "tls":
            stream = ssl.create_default_context(cafile=str(fixture.cert)).wrap_socket(
                raw, server_hostname="127.0.0.1"
            )
            if phase == "headers":
                stream.sendall(b"POST /inbox HTTP/1.1\r\nPrivate: incomplete")
            else:
                stream.sendall(
                    b"POST /inbox HTTP/1.1\r\nContent-Type: application/didcomm-encrypted+json\r\nContent-Length: 8\r\n\r\nx"
                )
        before = time.monotonic()
        fixture.close()
        assert time.monotonic() - before < 2
        assert not fixture.thread.is_alive() and fixture.server.messages == []
        assert fixture.server.failures == 1
    finally:
        stream.close()
        raw.close()
        fixture.close()


@pytest.mark.parametrize("status", [True, None, 201, "200", 200.0])
def test_invalid_fixture_input_cannot_overwrite_files(module, tmp_path, status):
    with pytest.raises(ValueError, match="invalid owned wallet fixture inputs"):
        module.WalletFixture(tmp_path, status=status)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_total_request_deadline_precedes_longer_socket_timeout(
    module, monkeypatch, tmp_path, phase
):
    monkeypatch.setattr(module, "READ_TIMEOUT", 2.0)
    monkeypatch.setattr(module, "REQUEST_TIMEOUT", 0.2)
    with module.WalletFixture(tmp_path) as fixture:
        context = ssl.create_default_context(cafile=str(fixture.cert))
        with closing(
            socket.create_connection(
                ("127.0.0.1", fixture.server.server_port), timeout=3
            )
        ) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as stream:
                before = time.monotonic()
                stream.sendall(
                    b"POST /inbox HTTP/1.1\r\nPrivate: incomplete"
                    if phase == "headers"
                    else b"POST /inbox HTTP/1.1\r\nContent-Type: application/didcomm-encrypted+json\r\nContent-Length: 8\r\n\r\nx"
                )
                response = bytearray()
                while part := stream.recv(4096):
                    response.extend(part)
                assert time.monotonic() - before < 1.5
                assert b"private" not in response.lower()
        assert captures(fixture) == (200, {"messages": [], "failures": 1})


def test_existing_parent_data_is_not_overwritten(module, tmp_path):
    marker = tmp_path / "parent-owned"
    marker.write_text("synthetic", encoding="utf-8")
    with pytest.raises(ValueError):
        module.WalletFixture(tmp_path)
    assert marker.read_text() == "synthetic"
    assert list(tmp_path.iterdir()) == [marker]


def test_cli_has_one_bounded_ready_line_and_no_request_logs(tmp_path):
    child = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts/didcomm_wallet_fixture.py"),
            str(tmp_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            try:
                line = executor.submit(child.stdout.readline, 4098).result(timeout=40)
            except BaseException:
                child.kill()
                child.wait(timeout=5)
                raise
        assert line.endswith(b"\n") and len(line) <= 4097
        ready = json.loads(line)
        assert set(ready) == {"origin", "ca_file"}
        assert ready["ca_file"] == str(tmp_path / "ca.pem")
        port = int(ready["origin"].rsplit(":", 1)[1])
        with closing(
            HTTPSConnection(
                "127.0.0.1",
                port,
                context=ssl.create_default_context(cafile=ready["ca_file"]),
                timeout=3,
            )
        ) as client:
            client.request("GET", "/captures")
            assert json.loads(client.getresponse().read()) == {
                "messages": [],
                "failures": 0,
            }
        child.terminate()
        stdout, stderr = child.communicate(timeout=8)
        assert stdout == stderr == b""
        if os.name != "nt":
            assert child.returncode == 0
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


def test_cli_rejects_private_arguments_without_echo_or_side_effect(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/didcomm_wallet_fixture.py"),
            str(tmp_path),
            "--unknown",
            "private-secret",
        ],
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 1 and result.stdout == result.stderr == b""
    assert list(tmp_path.iterdir()) == []
