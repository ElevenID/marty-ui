"""Owned loopback HTTPS capture fixture; cryptographic validation belongs to Rust."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import signal
import socket
import ssl
import sys
import threading

from test_canvas_lti_https import create_loopback_certificate

MAX_BODY_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 4 * MAX_BODY_BYTES
MAX_MESSAGES = 8
READ_TIMEOUT = 2.0
REQUEST_TIMEOUT = 5.0
MEDIA_TYPE = "application/didcomm-encrypted+json"


class _Server(HTTPServer):
    def __init__(self, context, status):
        self.context = context
        self.response_status = status
        self.messages = []
        self.capture_bytes = 0
        self.failures = 0
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)

    def failed(self):
        with self.lock:
            self.failures = min(self.failures + 1, 1_000_000)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(READ_TIMEOUT)
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except (OSError, ValueError):
            connection.close()
            self.failed()
            raise OSError("wallet TLS handshake rejected") from None

    def handle_error(self, *_):
        self.failed()  # Never delegate the traceback/request logging default.


class _Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.failed_request = False
        self.failure_lock = threading.Lock()
        self.deadline = threading.Timer(REQUEST_TIMEOUT, self.expire)
        self.deadline.daemon = True
        self.deadline.start()

    def failed(self):
        with self.failure_lock:
            if not self.failed_request:
                self.failed_request = True
                self.server.failed()

    def expire(self):
        self.failed()
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def handle(self):
        try:
            super().handle()
        except OSError:
            # Deadline shutdown can interrupt header parsing outside do_POST.
            # Attribute it to this request once, without server-level logging.
            self.failed()

    def finish(self):
        self.deadline.cancel()
        self.deadline.join(timeout=1)
        try:
            super().finish()
        except OSError:
            self.failed()

    def log_message(self, *_):
        pass

    def log_error(self, *_):
        self.failed()

    def send_error(self, code, *_args, **_kwargs):
        self.failed()
        self.respond({}, code)

    def respond(self, value, status):
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            self.failed()

    def framing(self, *, post):
        if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect"):
            return None
        lengths = self.headers.get_all("Content-Length", [])
        if not post and not lengths:
            return 0
        if len(lengths) != 1:
            return None
        value = lengths[0]
        if not value.isascii() or not value.isdecimal() or len(value) > 7:
            return None
        size = int(value)
        if str(size) != value or not (
            1 <= size <= MAX_BODY_BYTES if post else size == 0
        ):
            return None
        return size

    def do_POST(self):
        size = self.framing(post=True)
        if (
            self.path != "/inbox"
            or self.headers.get_all("Content-Type") != [MEDIA_TYPE]
            or size is None
        ):
            self.send_error(400)
            return
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("incomplete body")
            message = raw.decode("utf-8")
        except (OSError, ValueError):
            self.send_error(400)
            return
        with self.server.lock:
            accepted = (
                len(self.server.messages) < MAX_MESSAGES
                and self.server.capture_bytes + size <= MAX_CAPTURE_BYTES
            )
            if accepted:
                self.server.messages.append(message)
                self.server.capture_bytes += size
        if not accepted:
            self.send_error(413)
            return
        self.respond({}, self.server.response_status)

    def do_GET(self):
        if self.path != "/captures" or self.framing(post=False) != 0:
            self.send_error(400)
            return
        with self.server.lock:
            value = {
                "messages": list(self.server.messages),
                "failures": self.server.failures,
            }
        self.respond(value, 200)


class WalletFixture:
    """Caller owns directory and certificate deletion; close owns only the server."""

    def __init__(self, root, *, status=200):
        root = Path(root)
        if (
            not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or any(root.iterdir())
            or type(status) is not int
            or status not in (200, 503)
        ):
            raise ValueError("invalid owned wallet fixture inputs")
        self.cert, key = create_loopback_certificate(root)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, key)
        self.server = _Server(context, status)
        self.origin = f"https://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}
        )
        self.closed = False
        try:
            self.thread.start()
        except BaseException:
            self.server.server_close()
            raise

    def close(self):
        if self.closed:
            return
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=REQUEST_TIMEOUT + READ_TIMEOUT + 1)
        if self.thread.is_alive():
            raise AssertionError("wallet fixture shutdown did not complete")
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 1:
        status = 200
    elif len(args) == 3 and args[1] == "--status" and args[2] in ("200", "503"):
        status = int(args[2])
    else:
        return 1
    stop = threading.Event()
    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: stop.set())
        with WalletFixture(args[0], status=status) as fixture:
            ready = json.dumps(
                {"origin": fixture.origin, "ca_file": str(fixture.cert)}
            ).encode()
            if len(ready) > 4096:
                return 1
            sys.stdout.buffer.write(ready + b"\n")
            sys.stdout.buffer.flush()
            stop.wait()
    except (Exception, KeyboardInterrupt):
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0


if __name__ == "__main__":
    sys.exit(main())
