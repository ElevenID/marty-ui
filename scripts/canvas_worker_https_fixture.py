"""Owned loopback HTTPS fixture shared by published worker observations."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from email.utils import formatdate
import json
from pathlib import Path
import ssl
import tempfile
from threading import Event, Thread
import time

from test_canvas_lti_https import create_loopback_certificate


def response_headers(response, now=None):
    headers = dict(response.get("headers", {}))
    if "retry_after_offset_seconds" in response:
        offset = response["retry_after_offset_seconds"]
        assert type(offset) is int and -86401 <= offset <= 86401
        assert not any(key.lower() == "retry-after" for key in headers)
        headers["Retry-After"] = formatdate(
            (time.time() if now is None else now) + offset, usegmt=True
        )
    return headers


class WorkerHttpsFixture:
    def __init__(self):
        self.stage = {}
        self.requests = []
        self.retry_after_dates = []
        self.failures = []
        self.received = Event()
        self.release = Event()
        self.server = None
        self.thread = None
        self.certificates = None

    def __enter__(self):
        owner = self

        class Server(ThreadingHTTPServer):
            def handle_error(self, *_):
                # Propagate handler failures to the owning test without logging
                # headers, response bodies or a background-thread traceback.
                owner.failures.append("Owned HTTPS request handler failed")

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                owner.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "accept": self.headers.get("Accept"),
                    }
                )
                stage = owner.stage
                owner.received.set()
                if stage.get("hold_response"):
                    assert owner.release.wait(30), "Owned response was never released"
                response = (
                    stage["responses"][self.path] if "responses" in stage else stage
                )
                body = (
                    b""
                    if response["status"] == 204
                    else json.dumps(response["body"], separators=(",", ":")).encode()
                )
                try:
                    self.send_response(response["status"])
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    headers = response_headers(response)
                    if "retry_after_offset_seconds" in response:
                        owner.retry_after_dates.append(headers["Retry-After"])
                    for key, value in headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    if not stage.get("hold_response"):
                        raise

            # Revocation uses DELETE; retain the same observation, response and
            # owned-handler lifecycle as GET without duplicating transport logic.
            do_DELETE = do_GET

        try:
            self.certificates = tempfile.TemporaryDirectory(
                prefix="canvas-worker-rest-"
            )
            self.cert, key = create_loopback_certificate(Path(self.certificates.name))
            self.server = Server(("127.0.0.1", 0), Handler)
            # server_close must join the owned request handlers after release.
            self.server.daemon_threads = False
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.cert, key)
            self.server.socket = context.wrap_socket(
                self.server.socket, server_side=True
            )
            self.thread = Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self.origin = f"https://127.0.0.1:{self.server.server_port}"
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        self.release.set()
        if self.thread is not None and self.thread.ident is not None:
            self.server.shutdown()
            self.thread.join(timeout=5)
            assert not self.thread.is_alive(), "Owned HTTPS server did not stop"
        if self.server is not None:
            self.server.server_close()
        if self.certificates is not None:
            self.certificates.cleanup()

    def __exit__(self, exception_type, *_):
        self.close()
        if exception_type is None:
            assert not self.failures, self.failures
