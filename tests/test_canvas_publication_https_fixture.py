"""Owned peer/runner controls only; actual native TLS proof is the Linux gate."""

from http.client import HTTPSConnection, RemoteDisconnected
import importlib
import io
import json
from pathlib import Path
import ssl
import copy

import pytest
import yaml


@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("test_canvas_publication_https")


def client(fixture, *, trusted=True):
    return HTTPSConnection(
        "127.0.0.1",
        fixture.server.server_port,
        timeout=5,
        context=ssl.create_default_context(cafile=str(fixture.cert))
        if trusted
        else ssl.create_default_context(),
    )


def stage():
    return {
        "offset": 0,
        "expected": [
            {
                "method": "POST",
                "path": "/publish",
                "headers": {
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                "body": {"credential": "synthetic"},
            }
        ],
        "response": {
            "status": 201,
            "content_type": "application/json",
            "body": b'{"id":"synthetic"}',
        },
    }


def test_default_handler_identity_preserves_get_delete_and_no_post(module):
    class Original:
        pass

    fixture = module.WorkerHttpsFixture()
    assert fixture.request_handler_type(Original) is Original
    with fixture:
        handler = fixture.server.RequestHandlerClass
        assert handler.do_DELETE is handler.do_GET
        assert not hasattr(handler, "do_POST")


def test_independent_complete_post_observation_and_checked_cleanup(module):
    with module.PublicationHttpsFixture() as fixture:
        fixture.stage = stage()
        connection = client(fixture)
        try:
            expected = fixture.stage["expected"][0]
            connection.request(
                "POST", "/publish", json.dumps(expected["body"]), expected["headers"]
            )
            response = connection.getresponse()
            assert response.status == 201
            assert response.getheader("X-Request-Id") == "synthetic-request-1"
            assert response.read() == b'{"id":"synthetic"}'
            module.assert_peer_effects(fixture, 0, 0, [expected])
        finally:
            connection.close()
        directory = Path(fixture.certificates.name)
    assert not fixture.thread.is_alive()
    assert fixture.server.fileno() == -1
    assert not directory.exists()


@pytest.mark.parametrize("failure", ["body", "path", "oversized"])
def test_rejected_post_is_counted_but_not_accepted(module, failure):
    fixture = module.PublicationHttpsFixture()
    with pytest.raises(AssertionError, match="handler failed"):
        with fixture:
            fixture.stage = stage()
            connection = client(fixture)
            try:
                headers = dict(fixture.stage["expected"][0]["headers"])
                if failure == "oversized":
                    headers["Content-Length"] = str(module.BODY_CAP + 1)
                connection.request(
                    "POST",
                    "/other" if failure == "path" else "/publish",
                    b"{}" if failure == "body" else b'{"credential":"synthetic"}',
                    headers,
                )
                with pytest.raises(RemoteDisconnected):
                    connection.getresponse()
            finally:
                connection.close()
            assert len(fixture.requests) == 1
            assert not fixture.accepted
    assert not fixture.thread.is_alive()


def test_untrusted_peer_has_no_attempt_or_accepted_post(module):
    with module.PublicationHttpsFixture() as fixture:
        fixture.stage = stage()
        connection = client(fixture, trusted=False)
        try:
            with pytest.raises(ssl.SSLCertVerificationError):
                connection.request("POST", "/publish", b"{}")
        finally:
            connection.close()
        module.assert_peer_effects(fixture, 0, 0, [])


@pytest.mark.parametrize("field", ["requests", "accepted", "failures"])
def test_zero_effect_guard_rejects_each_independent_channel(module, field):
    fixture = module.PublicationHttpsFixture()
    getattr(fixture, field).append({})
    with pytest.raises(AssertionError):
        module.assert_peer_effects(fixture, 0, 0, [])


def test_environment_does_not_inherit_operator_proxy_or_trust(module, monkeypatch):
    for key in [
        "CANVAS_CREDENTIALS_API_TOKEN_FILE",
        "HTTPS_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ]:
        monkeypatch.setenv(key, "synthetic-unowned-selector")
    environment = module.child_environment("https://127.0.0.1:443", "bridge_base")
    assert "synthetic-unowned-selector" not in environment.values()
    assert "SSL_CERT_FILE" not in environment and "SSL_CERT_DIR" not in environment


def test_unowned_reference_origin_cannot_be_rebased(module):
    with pytest.raises(AssertionError, match="Unowned reference origin"):
        module.expected_requests(
            {"trace": [{"kind": "http", "url": "https://other.invalid/publish"}]}
        )


@pytest.mark.parametrize("stream", [0, 1])
def test_all_synthetic_secret_inputs_are_denied_in_both_streams(module, stream):
    scenarios = json.loads(
        (module.ROOT / "contracts/canvas-mirror-adapter-scenarios.json").read_text(
            encoding="utf-8"
        )
    )["adapter"]
    cases = json.loads(
        (module.ROOT / "contracts/canvas-mirror-adapter-reference.json").read_text(
            encoding="utf-8"
        )
    )["adapter"]
    denied = module.synthetic_secret_bytes(scenarios, cases)
    assert set(denied) >= {
        b"synthetic-provider-token",
        b"synthetic-selected-token",
        b"synthetic-later-token",
        b"never-outbound-inline",
        b"nested-never-outbound",
    }
    for secret in denied:
        outputs = [io.BytesIO(b"safe"), io.BytesIO(b"safe")]
        outputs[stream] = io.BytesIO(secret)
        with pytest.raises(AssertionError, match="(secret|authentication material)"):
            module.read_publication_output(*outputs, denied)
    assert module.read_publication_output(
        io.BytesIO(b"safe"), io.BytesIO(b""), denied
    ) == (b"safe", b"")


def test_all_51_peer_input_responses_preserve_bytes(module):
    scenarios = json.loads(
        (module.ROOT / "contracts/canvas-mirror-adapter-scenarios.json").read_text(
            encoding="utf-8"
        )
    )["adapter"]
    assert len(scenarios) == 51
    for scenario in scenarios:
        response = module.provider_response(scenario)
        assert response["status"] == scenario.get("provider_status", 201)
        if "provider_body" in scenario:
            assert (
                response["body"].decode(scenario.get("provider_encoding", "utf-8"))
                == scenario["provider_body"]
            )


def require_registered(workflow):
    matches = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("name") == "Test Canvas publication adapter over real HTTPS"
    ]
    assert len(matches) == 1
    step = matches[0]
    assert "if" not in step and "continue-on-error" not in step
    assert step["working-directory"] == "rust" and step["shell"] == "bash"
    script = step["run"]
    for required in [
        "set -euo pipefail",
        'select(.target.name == "issuance-behavior")',
        "canvas_publication_behavior::https_child: test",
        'python3 ../scripts/test_canvas_publication_https.py "$publication_executable"',
    ]:
        assert required in script


def test_actual_https_is_mandatory_in_required_ci(module):
    workflow = yaml.safe_load(
        (module.ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    require_registered(workflow)
    for mutation in ("if", "continue-on-error", "remove", "disconnect"):
        changed = copy.deepcopy(workflow)
        for job in changed["jobs"].values():
            for step in job.get("steps", []):
                if (
                    step.get("name")
                    == "Test Canvas publication adapter over real HTTPS"
                ):
                    if mutation == "remove":
                        job["steps"].remove(step)
                    elif mutation == "disconnect":
                        step["run"] = step["run"].replace(
                            "python3 ../scripts/test_canvas_publication_https.py",
                            "true #",
                        )
                    else:
                        step[mutation] = True
                    break
        with pytest.raises(AssertionError):
            require_registered(changed)
