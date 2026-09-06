"""Supply frozen HTTPS responses to actual native worker processes on Linux."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
from email.utils import parsedate_to_datetime
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
from threading import Thread

from test_canvas_lti_https import create_loopback_certificate
from canvas_worker_https_fixture import response_headers


def run(executable, scenario="rest"):
    assert scenario in {"rest", "facts", "retry", "retry-after", "validation"}
    root = Path(__file__).resolve().parents[1]
    spec = json.loads(
        (root / f"contracts/canvas-worker-{scenario}-scenarios.json").read_text()
    )
    if "extends" in spec:
        base = json.loads((root / "contracts" / spec["extends"]).read_text())
        spec = {**base, **spec}
    reference = json.loads(
        (root / f"contracts/canvas-worker-{scenario}-oracle.json").read_text()
    )
    if scenario in {"retry-after", "validation"}:
        names = [case["name"] for case in spec["cases"]]
        assert len(set(names)) == len(names)
        assert set(names) == set(reference)
        for case in spec["cases"]:
            stage = {
                **case,
                "status": 429 if scenario == "retry-after" else 500,
                "body": {"error": "synthetic-rate-limit"}
                if scenario == "retry-after"
                else {},
            }
            run_scenario(
                executable, scenario, {"stages": [stage]}, reference[case["name"]], case
            )
    else:
        run_scenario(executable, scenario, spec, reference)


def assert_retry_timing(output, case, dates, expected):
    prefix = "CANVAS_WORKER_RETRY_TIMING="
    records = [
        line[len(prefix) :] for line in output.splitlines() if line.startswith(prefix)
    ]
    assert len(records) == 1, "Expected one actual durable retry timing observation"
    timing = json.loads(records[0])
    assert set(timing) == {"available_at", "updated_at"}
    available_at = datetime.fromisoformat(timing["available_at"])
    updated_at = datetime.fromisoformat(timing["updated_at"])
    assert available_at.utcoffset() is not None and updated_at.utcoffset() is not None
    if case["timing"] == "http_date":
        assert len(dates) == 1
        matches = (
            abs((available_at - parsedate_to_datetime(dates[0])).total_seconds()) <= 1.1
        )
    else:
        assert case["timing"] == "bounds"
        minimum, maximum = case["delay_bounds"]
        assert type(minimum) is int and type(maximum) is int
        assert 0 <= minimum <= maximum <= 86400
        delay = (available_at - updated_at).total_seconds()
        matches = minimum - 0.1 <= delay <= maximum + 0.1
    assert {"kind": case["timing"], "matches": matches} == expected, (
        f"Native persisted Retry-After timing differs: {case['name']}"
    )


def run_scenario(executable, scenario, spec, reference, matrix_case=None):
    responses = [
        response
        for stage in spec["stages"]
        for response in (
            stage["responses"].values() if "responses" in stage else [stage]
        )
    ]
    requests = []
    dates = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            index = len(requests)
            requests.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "accept": self.headers.get("Accept"),
                }
            )
            # Unexpected extra reads fail the request-count check, never wrap.
            stage = (
                responses[index]
                if index < len(responses)
                else {"status": 500, "body": {}}
            )
            body = json.dumps(stage["body"], separators=(",", ":")).encode()
            self.send_response(stage["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            headers = response_headers(stage)
            if "retry_after_offset_seconds" in stage:
                dates.append(headers["Retry-After"])
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

    with tempfile.TemporaryDirectory(prefix="canvas-worker-rest-native-") as directory:
        certificate_root = Path(directory)
        cert, key = create_loopback_certificate(certificate_root)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            empty_ca_directory = certificate_root / "empty-ca-directory"
            empty_ca_directory.mkdir()
            environment = dict(os.environ)
            environment.update(
                MARTY_CANVAS_WORKER_REST_NATIVE_ORIGIN=f"https://127.0.0.1:{server.server_port}",
                MARTY_CANVAS_WORKER_REST_SCENARIO=scenario,
                SSL_CERT_FILE=str(cert),
                SSL_CERT_DIR=str(empty_ca_directory),
            )
            if matrix_case is not None:
                flag = {
                    "retry-after": "MARTY_CANVAS_WORKER_RETRY_AFTER_CASE",
                    "validation": "MARTY_CANVAS_WORKER_VALIDATION_CASE",
                }[scenario]
                environment[flag] = matrix_case["name"]
            child = subprocess.run(
                [executable, "worker_rest_native_child", "--exact", "--nocapture"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=240,
            )
            assert child.returncode == 0, (
                f"Native worker replay failed: {child.stdout} {child.stderr}"
            )
            expected = [
                request
                for observation in reference["observations"]
                for request in observation["requests"]
            ]
            assert requests == expected, "Actual worker HTTPS requests differ"
            if scenario == "retry-after":
                assert matrix_case is not None
                assert_retry_timing(
                    child.stdout, matrix_case, dates, reference["retry_timing"]
                )
            label = (
                scenario if matrix_case is None else f"{scenario}/{matrix_case['name']}"
            )
            print(
                f"Native worker {label} replay passed all {len(spec['stages'])} frozen HTTPS stages ({len(requests)} requests)"
            )
        finally:
            if thread is not None:
                server.shutdown()
                thread.join(timeout=5)
                assert not thread.is_alive()
            server.server_close()


if __name__ == "__main__":
    if len(sys.argv) not in {2, 3}:
        raise SystemExit(
            "Expected the exact compiled published-schema executable [rest|facts|retry|retry-after|validation]"
        )
    run(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else "rest")
