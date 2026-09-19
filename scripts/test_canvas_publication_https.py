"""Run the frozen adapter graph against owned HTTPS, with child-only Linux trust.

Only configured/request origins and returned transport-origin metadata are
rebased. Credential/provenance content and provider response bytes stay frozen.
This is adapter/network proof, not a route, repository or automation-loop gate.
"""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit

from canvas_worker_https_fixture import WorkerHttpsFixture
from canvas_worker_output_capture import owned_log_streams, read_private_output
from canvas_worker_owned_process import OwnedProcess

ROOT = Path(__file__).resolve().parents[1]
TEST = "canvas_publication_behavior::https_child"
BODY_CAP = 1024 * 1024


def provider_response(scenario):
    # These are the controlled peer inputs, not manufactured result expectations.
    text = scenario.get(
        "provider_body",
        '{"result":[{"entityId":"external-1","issuer":"issuer-elevenid",'
        '"openBadgeId":"https://badges.example/assertion/external-1"}]}'
        if "provider" in scenario
        else '{"id":"external-1","issuer_id":"issuer-elevenid"}',
    )
    return {
        "status": scenario.get("provider_status", 201),
        "body": text.encode(scenario.get("provider_encoding", "utf-8")),
        "content_type": scenario.get("provider_content_type", "application/json"),
    }


def expected_requests(case):
    expected = []
    for request in case["trace"]:
        if request["kind"] != "http":
            continue
        url = urlsplit(request["url"])
        assert url.scheme == "https" and url.netloc in {
            "bridge.example",
            "api.badgr.io",
        }, "Unowned reference origin must not be rebased"
        assert not url.query and not url.fragment
        expected.append(
            {
                "method": request["method"],
                "path": url.path,
                "headers": request["headers"],
                "body": json.loads(request["body"]),
            }
        )
    return expected


class PublicationHttpsFixture(WorkerHttpsFixture):
    def __init__(self):
        super().__init__()
        self.accepted = []

    def configure_request_connection(self, handler):
        # Includes the request-body read: a partial POST cannot hold cleanup.
        handler.connection.settimeout(3)

    def request_handler_type(self, base):
        owner = self

        class Handler(base):
            def do_POST(self):
                stage = self.observed_stage
                length = int(self.headers["Content-Length"])
                assert 0 <= length <= BODY_CAP, "Owned POST exceeds body bound"
                assert self.headers.get("Transfer-Encoding") is None
                deadline = time.monotonic() + 3
                body = bytearray()
                while len(body) < length:
                    remaining = deadline - time.monotonic()
                    assert remaining > 0, "Owned POST body deadline"
                    self.connection.settimeout(remaining)
                    chunk = self.rfile.read1(min(65536, length - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                assert len(body) == length, "Owned POST is incomplete"
                headers = {
                    "accept": self.headers.get("Accept"),
                    "content-type": self.headers.get("Content-Type"),
                }
                token = self.headers.get("Authorization")
                if token is not None:
                    headers["authorization"] = token
                observed = {
                    "method": self.command,
                    "path": self.path,
                    "headers": headers,
                    "body": json.loads(body),
                }
                index = self.observed_request_index - stage["offset"]
                assert 0 <= index < len(stage["expected"]), "Unexpected POST attempt"
                assert observed == stage["expected"][index], "POST contract differs"
                owner.accepted.append(observed)
                response = stage["response"]
                self.send_response(response["status"])
                self.send_header("Content-Type", response["content_type"])
                self.send_header("X-Request-Id", "synthetic-request-1")
                self.send_header("Content-Length", str(len(response["body"])))
                self.end_headers()
                self.wfile.write(response["body"])

        return Handler


def child_environment(origin, case, *, cert=None, cert_directory=None, failure=None):
    # No inherited application/operator *_FILE, proxy, or trust selectors.
    environment = {
        name: os.environ[name]
        for name in ("PATH", "LANG", "LC_ALL", "TMPDIR", "LD_LIBRARY_PATH")
        if name in os.environ
    }
    environment.update(
        MARTY_CANVAS_PUBLICATION_HTTPS_ORIGIN=origin,
        MARTY_CANVAS_PUBLICATION_HTTPS_CASE=case,
    )
    if cert is not None:
        environment.update(SSL_CERT_FILE=str(cert), SSL_CERT_DIR=str(cert_directory))
    if failure is not None:
        environment["MARTY_CANVAS_PUBLICATION_HTTPS_FAILURE"] = failure
    return environment


def synthetic_secret_bytes(scenarios, cases):
    denied = {"synthetic-provider-token"}
    pending = list(scenarios)
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "secrets":
                    denied.update(
                        secret
                        for secret in item.values()
                        if isinstance(secret, str) and secret
                    )
                elif key.lower().endswith("token") and isinstance(item, str) and item:
                    denied.add(item)
                pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
    for case in cases:
        for call in case["trace"]:
            if call["kind"] == "http":
                token = call["headers"].get("authorization", "")
                if token:
                    assert token.startswith("Bearer ")
                    denied.add(token.removeprefix("Bearer "))
    return tuple(value.encode("utf-8") for value in sorted(denied) if value)


def read_publication_output(stdout, stderr, denied):
    streams = read_private_output(stdout, stderr, "synthetic-provider-token")
    if any(secret in stream for stream in streams for secret in denied):
        raise AssertionError("Synthetic publication secret appeared in owned output")
    return streams


def run_child(executable, environment, directory, denied):
    with ExitStack() as owner:
        out, out_reader = owned_log_streams(owner, directory)
        err, err_reader = owned_log_streams(owner, directory)
        child = OwnedProcess(
            [executable, TEST, "--exact", "--nocapture", "--test-threads=1"],
            stdin=-3,
            stdout=out,
            stderr=err,
            env=environment,
        )
        owner.callback(child.cleanup)
        deadline = time.monotonic() + 30
        while child.poll() is None:
            read_publication_output(out_reader, err_reader, denied)
            assert time.monotonic() < deadline, "Publication HTTPS child deadline"
            time.sleep(0.025)
        assert child.wait(timeout=5) == 0, "Publication HTTPS child failed"
        stdout, stderr = read_publication_output(out_reader, err_reader, denied)
        marker = (
            "PUBLICATION_HTTPS_CASE_OK="
            + environment["MARTY_CANVAS_PUBLICATION_HTTPS_CASE"]
        ).encode()
        assert stdout.splitlines().count(marker) == 1, "Missing exact child completion"
        assert b"1 passed; 0 failed" in stdout and not stderr


def assert_peer_effects(fixture, offset, accepted_offset, expected):
    attempts = fixture.requests[offset:]
    assert len(attempts) == len(expected), "Unexpected HTTP attempt count"
    assert fixture.accepted[accepted_offset:] == expected, (
        "Accepted HTTP requests differ"
    )
    assert not fixture.failures, "Owned HTTPS handler failed"


def run(executable):
    assert sys.platform == "linux", "Publication platform trust requires Linux"
    executable = str(Path(executable).resolve(strict=True))
    corpus = json.loads(
        (ROOT / "contracts/canvas-mirror-adapter-reference.json").read_text(
            encoding="utf-8"
        )
    )
    scenarios = json.loads(
        (ROOT / "contracts/canvas-mirror-adapter-scenarios.json").read_text(
            encoding="utf-8"
        )
    )["adapter"]
    cases = corpus["adapter"]
    assert len(cases) == len(scenarios) == 51
    assert [case["id"] for case in cases] == [case["id"] for case in scenarios]
    denied = synthetic_secret_bytes(scenarios, cases)
    with PublicationHttpsFixture() as fixture:
        directory = Path(fixture.certificates.name)
        empty_ca_directory = directory / "empty-ca-directory"
        empty_ca_directory.mkdir()
        try:
            # Denial controls use a valid bridge input and an owned server, but
            # neither DNS authorization nor certificate validation is bypassed.
            assert cases[0]["id"] == "bridge_base"
            for failure in ("trust", "origin"):
                fixture.stage = {"offset": len(fixture.requests), "expected": []}
                offset, accepted_offset = len(fixture.requests), len(fixture.accepted)
                environment = child_environment(
                    fixture.origin,
                    "bridge_base",
                    failure=failure,
                    cert=fixture.cert if failure == "origin" else None,
                    cert_directory=empty_ca_directory,
                )
                run_child(executable, environment, directory, denied)
                assert_peer_effects(fixture, offset, accepted_offset, [])
            for case, scenario in zip(cases, scenarios, strict=True):
                expected = expected_requests(case)
                offset, accepted_offset = len(fixture.requests), len(fixture.accepted)
                fixture.stage = {
                    "offset": offset,
                    "expected": expected,
                    "response": provider_response(scenario),
                }
                run_child(
                    executable,
                    child_environment(
                        fixture.origin,
                        case["id"],
                        cert=fixture.cert,
                        cert_directory=empty_ca_directory,
                    ),
                    directory,
                    denied,
                )
                assert_peer_effects(fixture, offset, accepted_offset, expected)
        finally:
            # The shared owner removes only its certificate files/directory;
            # this extra empty trust directory is exactly owned by this runner.
            empty_ca_directory.rmdir()
    print(
        "Publication HTTPS passed: 51 frozen adapter cases; origin/TLS denials; checked peer effects"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_canvas_publication_https.py TEST_EXECUTABLE")
    run(sys.argv[1])
