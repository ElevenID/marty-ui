"""Qualify native outbound HTTP against frozen observations using owned loopback TLS."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import zlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        try:
            text_cases = {
                "/text_cp1252": (
                    "text/plain; charset=windows-1252",
                    bytes(range(256)).hex(),
                ),
                "/text_cp037": ("text/plain; charset=cp037", bytes(range(256)).hex()),
                "/text_koi8_r": ("text/plain; charset=koi8-r", bytes(range(256)).hex()),
                "/text_mac_roman": (
                    "text/plain; charset=mac-roman",
                    bytes(range(256)).hex(),
                ),
                "/text_ascii": ("text/plain; charset=ascii", "636166e92080"),
                "/text_ascii_alias": (
                    "text/plain; charset=ANSI_X3.4-1968",
                    "636166e92080",
                ),
                "/text_latin1": ("text/plain; charset=iso-8859-1", "636166e92080"),
                "/text_latin1_alias": ("text/plain; charset=cp819", "636166e92080"),
                "/text_latin1_spaces": (
                    "text/plain; charset=ISO 8859-1",
                    "636166e92080",
                ),
                "/text_quoted_charset": (
                    'text/plain; CHARSET="LATIN1"',
                    "636166e92080",
                ),
                "/text_quoted_semicolon": (
                    'text/plain; note="x; charset=ascii"; charset=latin1',
                    "636166e92080",
                ),
                "/text_first_charset": (
                    "text/plain; charset=latin1; charset=ascii",
                    "636166e92080",
                ),
                "/text_unknown_charset": (
                    "text/plain; charset=synthetic-unknown",
                    "636166c3a9",
                ),
                "/text_empty_charset": ("text/plain; charset=", "636166c3a9"),
                "/text_without_charset": ("text/plain", "636166c3a9"),
                "/text_without_type": (None, "636166c3a9"),
                "/text_invalid_media_type": ("synthetic; charset=latin1", "636166e9"),
                "/text_utf8_sig": ("text/plain; charset=utf-8-sig", "efbbbf636166c3a9"),
                "/text_ascii_bom": ("text/plain; charset=ascii", "efbbbf636166c3a9"),
                "/text_json_latin1": (
                    "application/json; charset=latin1",
                    "7b226d657373616765223a22636166e9227d",
                ),
                "/text_long_latin1": ("text/plain; charset=latin1", "e9" * 1001),
                "/text_gb18030": (
                    "text/plain; charset=gb18030",
                    "c4e3bac390308130e3329a35ff30ff3041803041",
                ),
                "/text_euc_kr": (
                    "text/plain; charset=euc-kr",
                    "c7d1b1db"
                    + "a4d4a4a1a4bfa4d4"
                    + "a4d4a4bea4d3a4be"
                    + "a4d441a1a4bfa4d4"
                    + "a4d441",
                ),
                "/text_iso2022_internal": (
                    "text/plain; charset=iso2022_jp_2",
                    "1b2e4a1b4e21",
                ),
                "/text_iso2022_pending": (
                    "text/plain; charset=iso2022_kr",
                    "1b2821212121212121",
                ),
                "/text_iso2022_label": (
                    "text/plain; charset*=iso2022_jp_2''%1B.J%1BN!",
                    "626164",
                ),
                "/text_iso2022_label_json": (
                    "text/plain; charset*=iso2022_jp_2''%1B.J%1BN!",
                    "7b226163636570746564223a747275657d",
                ),
            }
            for name in ISO2022_ENCODINGS:
                text_cases[f"/text_{name}"] = (
                    "text/plain; charset=" + name,
                    "1b2429430e21210f1b244221401b284241",
                )
            for name in MULTIBYTE_ENCODINGS:
                text_cases[f"/text_multibyte_{name}"] = (
                    "text/plain; charset=" + name,
                    (
                        b"~{VP~}" + bytes(range(256)) + b"\x81\x40\x88\x62\x8f\xa2\xaf"
                    ).hex(),
                )
            for kind, payload in (
                ("text", b"caf\xe9"),
                ("json", b'{"accepted":true}'),
                ("empty", b""),
            ):
                text_cases[f"/text_ordinal_{kind}"] = (
                    "text/plain; charset=latin1; other*" + "0" * 4301 + "=latin1",
                    payload.hex(),
                )
            text_cases.update(
                {
                    "/text_utf7_label_latin1": (
                        "text/plain; charset*=u7''%2BAGwAYQB0AGkAbgAx-",
                        "636166e9",
                    ),
                    "/text_utf7_label_surrogate": (
                        "text/plain; charset*=u7''%2B2AA-",
                        "636166e9",
                    ),
                    "/text_utf7_label_null": (
                        "text/plain; charset*=u7''%2BAAA-",
                        "636166e9",
                    ),
                    "/text_utf7_label_null_codec": (
                        "text/plain; charset*=%00''latin1",
                        "636166e9",
                    ),
                    "/text_utf7_label_null_codec_json": (
                        "text/plain; charset*=%00''latin1",
                        "7b226163636570746564223a747275657d",
                    ),
                }
            )
            if self.path in text_cases:
                content_type, hexadecimal = text_cases[self.path]
                body = bytes.fromhex(hexadecimal)
                self.send_response(403)
                if content_type is not None:
                    self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                return
            compressed_cases = {
                "/gzip_json": "gzip",
                "/deflate_json": "deflate",
                "/raw_deflate_json": "deflate",
                "/stacked_json": "gzip, deflate",
                "/double_gzip_json": "gzip, gzip",
                "/mixed_case_gzip": " GZip ",
                "/unknown_encoding": "synthetic-unknown",
                "/unsupported_br": "br",
                "/gzip_trailing_bytes": "gzip",
                "/gzip_without_trailer": "gzip",
                "/gzip_invalid": "gzip",
                "/deflate_invalid": "deflate",
                "/gzip_success_invalid": "gzip",
                "/stacked_headers": "gzip, deflate",
                "/gzip_progress": "gzip",
                "/gzip_stall": "gzip",
            }
            if self.path in compressed_cases:
                body = b'{"accepted":true}'
                if self.path == "/gzip_json":
                    body = json.dumps(
                        {
                            "accepted": True,
                            "accept_encoding": self.headers.get("accept-encoding"),
                        }
                    ).encode()
                encoding = compressed_cases[self.path]
                if "invalid" in self.path:
                    body = b"not a compressed stream"
                elif self.path == "/raw_deflate_json":
                    body = zlib.compress(body, wbits=-15)
                elif encoding not in {"synthetic-unknown", "br"}:
                    for coding in encoding.lower().split(","):
                        body = zlib.compress(
                            body, wbits=31 if coding.strip() == "gzip" else 15
                        )
                if self.path == "/gzip_trailing_bytes":
                    body += b"synthetic unused bytes"
                if self.path == "/gzip_without_trailer":
                    body = body[:-8]
                self.send_response(200 if self.path == "/gzip_success_invalid" else 403)
                for coding in (
                    encoding.split(",")
                    if self.path == "/stacked_headers"
                    else [encoding]
                ):
                    self.send_header("Content-Encoding", coding.strip())
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.path == "/gzip_progress":
                    for offset in range(0, len(body), 3):
                        time.sleep(0.1)
                        self.wfile.write(body[offset : offset + 3])
                        self.wfile.flush()
                elif self.path == "/gzip_stall":
                    self.wfile.write(body[:10])
                    self.wfile.flush()
                    time.sleep(0.6)
                    self.wfile.write(body[10:])
                else:
                    self.wfile.write(body)
                self.wfile.flush()
                return
            unicode_cases = {
                "/json_utf8_bom": ("utf-8-sig", b""),
                "/json_utf16_le": ("utf-16-le", b""),
                "/json_utf16_be": ("utf-16-be", b""),
                "/json_utf16_le_bom": ("utf-16-le", b"\xff\xfe"),
                "/json_utf16_be_bom": ("utf-16-be", b"\xfe\xff"),
                "/json_utf32_le": ("utf-32-le", b""),
                "/json_utf32_be": ("utf-32-be", b""),
                "/json_utf32_le_bom": ("utf-32-le", b"\xff\xfe\x00\x00"),
                "/json_utf32_be_bom": ("utf-32-be", b"\x00\x00\xfe\xff"),
                "/text_utf8_bom": ("utf-8-sig", b""),
            }
            if self.path in unicode_cases:
                encoding, prefix = unicode_cases[self.path]
                value = (
                    "not JSON"
                    if self.path == "/text_utf8_bom"
                    else '{"message":"caf\u00e9 \U0001f642","accepted":true}'
                )
                body = prefix + value.encode(encoding)
                self.send_response(403)
                # JSON decoding uses bytes, independently of text charset.
                self.send_header(
                    "Content-Type",
                    "text/plain; charset=utf-8"
                    if self.path == "/text_utf8_bom"
                    else "application/json; charset=ascii",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                return
            if self.path in {
                "/failure_json_exact",
                "/failure_json_large",
                "/failure_text_large",
                "/failure_stall",
            }:
                payload = b'{"late":true}'
                if self.path == "/failure_text_large":
                    body = b"x" * 65537
                else:
                    padding = (
                        65536 - len(payload)
                        if self.path == "/failure_json_exact"
                        else 65537
                    )
                    body = b" " * padding + payload
                self.send_response(403)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.path == "/failure_stall":
                    self.wfile.write(body[:65537])
                    self.wfile.flush()
                    time.sleep(0.6)
                    self.wfile.write(body[65537:])
                else:
                    self.wfile.write(body)
                self.wfile.flush()
                return
            if self.path not in {"/immediate", "/headers", "/body", "/progress"}:
                self.server.failures.append("unexpected path")
                return
            if self.path == "/headers":
                time.sleep(0.6)
            self.send_response(200)
            self.send_header("Content-Length", "6")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.flush()
            if self.path == "/body":
                time.sleep(0.6)
            for byte in b"result":
                if self.path == "/progress":
                    time.sleep(0.15)
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            # Expected when the client deadline expires before this owned reply.
            pass



@contextmanager
def loopback_tls():
    with tempfile.TemporaryDirectory(prefix="outbound-http-oracle-") as directory:
        root = Path(directory)
        cert, key = root / "synthetic.pem", root / "synthetic.key"
        # cryptography is already a dependency of the pinned issuance image;
        # do not require an extra system executable or an OpenSSL config file.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-outbound-http")]
        )
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(private_key, hashes.SHA256())
        )
        cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = False
        server.failures = []
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        trust = ssl.create_default_context(cafile=str(cert))
        try:
            yield f"https://127.0.0.1:{server.server_port}", trust, cert
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive()
            assert not server.failures



ROUTINE_NATIVE_CASES = frozenset({"body_timeout", "untrusted_certificate"})



FROZEN_NATIVE_CASE_COUNT = 104



def run_native(executable, qualification="1"):
    root = Path(__file__).resolve().parents[1] / "contracts"
    cases = json.loads(
        (root / "outbound-http-timeout-scenarios.json").read_text(encoding="utf-8")
    )["cases"]
    expected = json.loads(
        (root / "outbound-http-timeout-oracle.json").read_text(encoding="utf-8")
    )["cases"]
    assert qualification in {"0", "1"}, "unknown outbound HTTP qualification tier"
    assert len(cases) == len(expected) == FROZEN_NATIVE_CASE_COUNT, (
        "frozen socket corpus changed"
    )
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names)), "duplicate frozen socket case"
    assert ROUTINE_NATIVE_CASES <= set(names), "routine TLS proof is missing"
    if qualification == "0":
        selected = [
            (case, observation)
            for case, observation in zip(cases, expected, strict=True)
            if case["name"] in ROUTINE_NATIVE_CASES
        ]
        assert len(selected) == len(ROUTINE_NATIVE_CASES)
    else:
        selected = list(zip(cases, expected, strict=True))
    observations = []
    with loopback_tls() as (origin, _, cert):
        for case, _ in selected:
            environment = dict(os.environ)
            environment["MARTY_OUTBOUND_TIMEOUT_NATIVE_CASE"] = json.dumps(case)
            environment["MARTY_OUTBOUND_TIMEOUT_NATIVE_ORIGIN"] = origin
            environment["MARTY_OUTBOUND_TIMEOUT_NATIVE_CERT"] = str(cert)
            child = subprocess.run(
                [
                    str(executable),
                    "outbound_http::tests::native_socket_case",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ],
                env=environment,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=15,
            )
            assert child.returncode == 0, (
                f"Native fixture child failed: {child.stdout} {child.stderr}"
            )
            lines = [
                line.removeprefix("OUTBOUND_TIMEOUT_NATIVE=")
                # Unicode NEL/LS/PS are valid inside JSON strings, not records.
                for line in child.stdout.split("\n")
                if line.startswith("OUTBOUND_TIMEOUT_NATIVE=")
            ]
            assert len(lines) == 1, "native child must emit exactly one observation"
            observations.append(json.loads(lines[0]))
    selected_expected = [observation for _, observation in selected]
    assert observations == selected_expected, {
        "mismatches": [
            {"expected": left, "native": right}
            for left, right in zip(selected_expected, observations, strict=True)
            if left != right
        ]
    }
    print(
        json.dumps(
            {"native_timeout_cases": len(observations), "status": "passed"},
            sort_keys=True,
        )
    )



ISO2022_ENCODINGS = ('iso2022_kr', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext')



MULTIBYTE_ENCODINGS = ('big5', 'big5hkscs', 'cp932', 'cp949', 'cp950', 'gb2312', 'gbk', 'johab', 'shift_jis', 'shift_jis_2004', 'shift_jisx0213', 'euc_jp', 'euc_jis_2004', 'euc_jisx0213', 'hz')



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-executable", type=Path, required=True)
    parser.add_argument("--qualification", choices=("0", "1"), default="1")
    arguments = parser.parse_args()
    run_native(arguments.native_executable, arguments.qualification)
