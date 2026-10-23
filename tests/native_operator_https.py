"""One real private-loopback HTTPS boundary for native operator profile tests."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import subprocess
import threading
from types import SimpleNamespace


@contextmanager
def https_json_server(tmp_path, dispatch, errors):
    key, ca = tmp_path / "listener.key", tmp_path / "ca.crt"
    config = tmp_path / "listener.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n")
    result = subprocess.run(["openssl", "req", "-config", str(config), "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(ca), "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:FALSE"],
                            check=False, capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length)) if length else None
            try:
                code, response = dispatch(self.command, self.path.removeprefix("/v1/"), body,
                                          self.headers.get("X-Vault-Token"))
                if code == 0:
                    self.close_connection = True
                    return
                data = json.dumps(response).encode() if code != 204 else b""
            except Exception as error:
                errors.append(error)
                code, data = 500, b"{}"
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = do_LIST = handle_request

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ca, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(endpoint=f"https://127.0.0.1:{server.server_port}", ca=ca)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not errors
