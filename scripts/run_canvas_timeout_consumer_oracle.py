"""Synthetic loopback TLS qualification of the exact Canvas HTTP client owner.

No deployment URLs or credentials are accepted. Only the test connection pool's
CA trust is injected; the published pinning transport and HTTPX socket operations
run unchanged. Local mode loads immutable Git source, image mode installed source.
"""

import argparse
import ast
import asyncio
import codecs
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import cache
import hashlib
import encodings
import encodings.aliases
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.metadata
import importlib.util
import ipaddress
import json
import os
import pkgutil
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import zlib
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


SOURCE_REF = "51f0a758a076777cb18a30b1db3f89c74ac23e01:services/issuance/application/canvas_lti_services.py"
SOURCE_SHA256 = "ab5b5a6de0e1c3ed45838e6ca0c1df1c84f3eb311de41060a60754769d7ac6b3"
RESPONSE_SOURCE_REF = "51f0a758a076777cb18a30b1db3f89c74ac23e01:services/issuance/infrastructure/adapters/canvas_credentials_adapter.py"
RESPONSE_SOURCE_SHA256 = (
    "24f5c0f22c075af3a11abbb48be52bcc6535e0d4fc31e446f7fb218bfe40d679"
)
NAMES = {
    "CanvasLtiServiceError",
    "normalize_canvas_https_origin",
    "_is_private_canvas_hostname",
    "_normalized_private_canvas_origins",
    "_canvas_origin_is_private_allowlisted",
    "_resolved_canvas_addresses",
    "PinnedCanvasAsyncTransport",
    "canvas_http_client",
}


def client_owner(source, origin):
    assert hashlib.sha256(source.encode()).hexdigest() == SOURCE_SHA256
    tree = ast.parse(source)
    nodes = [node for node in tree.body if getattr(node, "name", None) in NAMES]
    assert {node.name for node in nodes} == NAMES
    future = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    code = compile(
        ast.fix_missing_locations(ast.Module(body=[future, *nodes], type_ignores=[])),
        "published-canvas-http-owner",
        "exec",
    )
    namespace = {
        "httpx": httpx,
        "ipaddress": ipaddress,
        "socket": socket,
        "urlparse": urlparse,
        "private_canvas_origin_allowlist": lambda: [origin],
    }
    exec(code, namespace)
    return namespace["canvas_http_client"]


def response_owner(source):
    assert hashlib.sha256(source.encode()).hexdigest() == RESPONSE_SOURCE_SHA256
    names = {"_response_json_or_excerpt", "_truncate_text"}
    nodes = [
        node for node in ast.parse(source).body if getattr(node, "name", None) in names
    ]
    assert {node.name for node in nodes} == names
    future = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    code = compile(
        ast.fix_missing_locations(ast.Module(body=[future, *nodes], type_ignores=[])),
        "published-canvas-response-owner",
        "exec",
    )
    namespace = {}
    exec(code, namespace)
    return namespace["_response_json_or_excerpt"]


def single_byte_codecs(response_source):
    """Observe stateless single-byte text codecs, not multibyte/escape codecs."""
    project = response_owner(response_source)
    payload = bytes(range(256))
    names = {"ascii", "latin_1", "charmap"}
    for entry in pkgutil.iter_modules(encodings.__path__):
        try:
            module = importlib.import_module("encodings." + entry.name)
        except ImportError:
            # Platform-only mbcs/oem codecs are absent in the published image.
            continue
        table = getattr(module, "decoding_table", None)
        if isinstance(table, str) and len(table) == 256:
            names.add(entry.name)
    tables = {}
    for name in sorted(names):
        response = httpx.Response(
            403,
            headers={"Content-Type": "text/plain; charset=" + name},
            content=payload,
        )
        value = project(response)["body_excerpt"]
        assert len(value) == 256, (name, "not a single-byte scalar mapping")
        tables[name] = value
    aliases = {name: name for name in tables}
    unregistered_aliases = []
    for alias, target in sorted(encodings.aliases.aliases.items()):
        if target in tables:
            # Exercise the original HTTPX codec selection for every alias too.
            response = httpx.Response(
                403,
                headers={"Content-Type": "text/plain; charset=" + alias},
                content=payload,
            )
            try:
                resolved = codecs.lookup(alias)
            except LookupError:
                # Some stdlib alias keys are not themselves registered after
                # Python's case normalization. Preserve the observed fallback.
                assert project(response)["body_excerpt"] == payload.decode(
                    "utf-8", errors="replace"
                ), alias
                unregistered_aliases.append(alias)
                continue
            assert project(response)["body_excerpt"] == tables[target], alias
            assert resolved.name == codecs.lookup(target).name
            aliases[alias] = target
    return {
        "schema": "marty.canvas-single-byte-codecs/v1",
        "codecs": tables,
        "aliases": dict(sorted(aliases.items())),
        "unregistered_aliases": sorted(unregistered_aliases),
    }


def unicode_text_codecs(response_source):
    """Freeze text decoding separately from byte-first JSON/excerpt projection."""
    project = response_owner(response_source)
    names = {"utf_16", "utf_16_le", "utf_16_be", "utf_32", "utf_32_le", "utf_32_be"}
    aliases = {name: name for name in names}
    aliases.update(
        (alias, target)
        for alias, target in encodings.aliases.aliases.items()
        if target in names
    )
    payloads = {"empty": b"", "json_first": b'{"accepted":true}'}
    for width in (2, 4):
        for endian in ("le", "be"):
            encoding = f"utf_{width * 8}_{endian}"
            bom = (0xFEFF).to_bytes(width, "little" if endian == "le" else "big")
            text = "caf\u00e9 \U0001f642".encode(encoding)
            payloads[encoding] = text
            payloads[encoding + "_bom"] = bom + text
            payloads[encoding + "_double_bom"] = bom + bom + text
            for length in range(1, width + 1):
                payloads[f"{encoding}_prefix_{length}"] = bom[:length]
            for suffix in (b"\xff", b"\xff\xfe", b"\xff\xfe\x00"):
                payloads[f"{encoding}_trailing_{len(suffix)}"] = bom + text + suffix
            invalid_units = (
                (
                    [0xD800],
                    [0xDC00],
                    [0xD800, 0x61],
                    [0xD800, 0xD800, 0xDC00],
                    [0xD800, 0xFFFD],
                    [0xDFFF, 0xDFFF],
                )
                if width == 2
                else ([0xD800], [0xDC00], [0x110000], [0xFFFFFFFF])
            )
            for index, units in enumerate(invalid_units):
                payloads[f"{encoding}_invalid_{index}"] = bom + b"".join(
                    unit.to_bytes(width, "little" if endian == "le" else "big")
                    for unit in units
                )
            if width == 2:
                for index in (0, 2):
                    payloads[f"{encoding}_invalid_{index}_partial"] = (
                        payloads[f"{encoding}_invalid_{index}"] + b"\xff"
                    )
    cases = []
    for alias, target in sorted(aliases.items()):
        assert codecs.lookup(alias).name == codecs.lookup(target).name
        for label in (alias, alias.upper().replace("_", "-")):
            response = httpx.Response(
                403,
                content="caf\u00e9 \U0001f642".encode(target),
                headers={"content-type": "text/plain; charset=" + label},
            )
            assert response.text == "caf\u00e9 \U0001f642", label
    for alias in sorted(names):
        for name, payload in sorted(payloads.items()):
            response = httpx.Response(
                403,
                content=payload,
                headers={"content-type": "text/plain; charset=" + alias},
            )
            observed = {}
            for projection, operation in (
                ("text", lambda: response.text),
                ("excerpt", lambda: project(response)),
            ):
                try:
                    observed[projection] = {"value": operation()}
                except UnicodeError as failure:
                    assert type(failure) is UnicodeError, "unexpected decoder exception"
                    observed[projection] = {
                        "error_class": type(failure).__name__,
                        "error": str(failure),
                    }
            cases.append(
                {
                    "name": alias + "/" + name,
                    "charset": alias,
                    "body_hex": payload.hex(),
                    **observed,
                }
            )
    return {
        "schema": "marty.canvas-unicode-text/v1",
        "aliases": dict(sorted(aliases.items())),
        "cases": cases,
    }


def observe_charset(header, payload, project):
    response = httpx.Response(
        403, content=payload, headers={} if header is None else {"content-type": header}
    )
    observed = {}
    for projection, operation in (
        ("charset", lambda: response.charset_encoding),
        ("text", lambda: response.text),
        ("excerpt", lambda: project(response)),
    ):
        try:
            observed[projection] = {"value": operation()}
        except (UnicodeError, TypeError, ValueError, RuntimeError) as failure:
            assert type(failure) in (
                UnicodeError,
                TypeError,
                ValueError,
                RuntimeError,
            ), "unexpected header error"
            observed[projection] = {
                "error_class": type(failure).__name__,
                "error": str(failure),
            }
    return observed


def charset_headers(response_source):
    """Observe the actual HTTPX/email parameter reader, not an RFC approximation."""
    project = response_owner(response_source)
    headers = [
        None,
        "",
        "text/plain",
        "charset=latin1",
        'charset="latin1"',
        "text/plain; charset",
        "text/plain; charset; charset=latin1",
        "text/plain; charset=; charset=latin1",
        "text/plain; charset=<latin1>",
        "text/plain; charset='latin1'",
        "text/plain; CHARSET=LATIN1",
        "text/plain; charset=latin1; charset=ascii",
        "text/plain; charset=ascii; charset=latin1",
        'text/plain; charset="latin1"',
        'text/plain; charset="latin1',
        'text/plain; charset=latin1"',
        'text/plain; charset="latin1; note=x"',
        'text/plain; note="x; charset=ascii"; charset=latin1',
        'text/plain; note="x\\"; charset=ascii"; charset=latin1',
        'text/plain; note="x\\\\"; charset=ascii"; charset=latin1',
        "text/plain; charset* = us-ascii''latin1",
        "text/plain; charset*=us-ascii''latin%31",
        "text/plain; charset*=utf-8'en'ISO-8859-1",
        "text/plain; charset*=unknown''latin1",
        "text/plain; charset*=latin1",
        "text/plain; charset*=utf-8'latin1",
        "text/plain; charset*=utf-8''%FF",
        "text/plain; charset*=utf-8''%C3%A9",
        "text/plain; charset*=unknown''%6catin1",
        "text/plain; charset*=utf-8''latin%Q1",
        "text/plain; charset*=utf-16le''l%00a%00t%00i%00n%001%00",
        "text/plain; charset*=utf-16''l%00a%00t%00i%00n%001%00",
        "text/plain; charset*=utf-32le''l%00%00%00a%00%00%00t%00%00%00i%00%00%00n%00%00%001%00%00%00",
        "text/plain; charset*=us-ascii''<latin1>",
        "text/plain; charset*=us-ascii''latin1; charset=ascii",
        "text/plain; charset=ascii; charset*=us-ascii''latin1",
        "text/plain; charset*0=latin; charset*1=1",
        "text/plain; charset*1=1; charset*0=latin",
        "text/plain; charset*1=latin; charset*5=1",
        "text/plain; charset*10=1; charset*2=latin",
        "text/plain; charset*0000000000000000000000000002=latin; charset*3=1",
        "text/plain; charset*0*=utf-8''lat; charset*1=in1",
        "text/plain; charset*0=utf-8''lat; charset*1*=in%31",
        "text/plain; charset*0=latin; charset*1*=1",
        "text/plain; charset*0=latin; charset*0=1",
        "text/plain; charset*=latin; charset*=1",
        "text/plain; charset*=latin; charset*0=1",
        "text/plain; charset*0=latin; charset*=1",
        "text/plain; charset=latin1; other*=x; other*0=y",
        "text/plain; charset=latin1; other*0=x; other*=y",
        "text/plain; charset*0*=utf-8''latin1; charset",
        "text/plain; charset**=latin1; charset=ascii",
        "text/plain; charset*0x=latin1; charset=ascii",
        "text/plain; charset=iso.8859.1",
        "text/plain; charset=latin.1",
        "text/plain; charset=utf.16.le",
        "text/plain; charset=utf.16le",
        "text/plain; charset=cp.1252",
        "text/plain; charset=windows.1252",
    ]
    cases = []
    for index, header in enumerate(headers):
        for payload_name, payload in (
            ("text", b"caf\xe9"),
            ("json", b'{"accepted":true}'),
            ("empty", b""),
        ):
            observed = observe_charset(header, payload, project)
            cases.append(
                {
                    "name": f"header_{index}_{payload_name}",
                    "content_type": header,
                    "body_hex": payload.hex(),
                    **observed,
                }
            )
    return {
        "schema": "marty.canvas-charset-headers/v1",
        "registry_aliases": dict(sorted(encodings.aliases.aliases.items())),
        "cases": cases,
    }


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
            for name in codec_owner("canvas_iso2022_codec_oracle").NAMES:
                text_cases[f"/text_{name}"] = (
                    "text/plain; charset=" + name,
                    "1b2429430e21210f1b244221401b284241",
                )
            for name in multibyte_owner().NAMES:
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
    with tempfile.TemporaryDirectory(prefix="canvas-timeout-oracle-") as directory:
        root = Path(directory)
        cert, key = root / "synthetic.pem", root / "synthetic.key"
        # cryptography is already a dependency of the pinned issuance image;
        # do not require an extra system executable or an OpenSSL config file.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-canvas-timeout")]
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


async def observe(source, response_source, cases, origin, trust):
    factory = client_owner(source, origin)
    excerpt = response_owner(response_source)
    observations = []
    for case in cases:
        client = factory(timeout=float(case["seconds"]))
        # Preserve the actual pinned transport. Trust only this fixture leaf in
        # its original-origin pool; no machine trust or process-wide SSL changes.
        if case.get("trusted", True):
            client._transport._origin_transports[origin] = httpx.AsyncHTTPTransport(
                verify=trust, trust_env=False, retries=0
            )
        async with client:
            try:
                async with asyncio.timeout(5):
                    response = await client.get(origin + "/" + case["response"])
                    result = {
                        "status": response.status_code,
                        "body": excerpt(response)
                        if case.get("projection") == "excerpt"
                        else response.text,
                    }
                    if case.get("projection") == "discard":
                        result["body"] = None
            except httpx.HTTPError as failure:
                result = {"error_class": type(failure).__name__}
            except (UnicodeError, RuntimeError, ValueError) as failure:
                result = {"error_class": type(failure).__name__}
            except TimeoutError:
                raise AssertionError("owned test watchdog expired") from None
        observations.append({"name": case["name"], **result})
    return observations


@cache
def codec_owner(name):
    spec = importlib.util.spec_from_file_location(
        name,
        Path(__file__).with_name(name + ".py"),
    )
    multibyte = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(multibyte)
    return multibyte


def multibyte_owner():
    return codec_owner("canvas_multibyte_codec_oracle")


def run(source=None, response_source=None):
    if source is None:
        spec = importlib.util.find_spec("issuance.application.canvas_lti_services")
        source = Path(spec.origin).read_text(encoding="utf-8")
    if response_source is None:
        spec = importlib.util.find_spec(
            "issuance.infrastructure.adapters.canvas_credentials_adapter"
        )
        response_source = Path(spec.origin).read_text(encoding="utf-8")
    cases = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "contracts/canvas-timeout-consumer-scenarios.json"
        ).read_text(encoding="utf-8")
    )["cases"]
    with loopback_tls() as (origin, trust, _):
        observations = asyncio.run(
            observe(source, response_source, cases, origin, trust)
        )
    return {
        "source_sha256": SOURCE_SHA256,
        "response_source_sha256": RESPONSE_SOURCE_SHA256,
        "single_byte_codecs": single_byte_codecs(response_source),
        "unicode_text_codecs": unicode_text_codecs(response_source),
        "charset_headers": charset_headers(response_source),
        "charset_ordinals": codec_owner("canvas_charset_ordinal_oracle").observe(
            response_source
        ),
        "utf7_codec": codec_owner("canvas_utf7_codec_oracle").observe(response_source),
        "multibyte_codecs": multibyte_owner().run(),
        "gb18030_codec": codec_owner("canvas_gb18030_codec_oracle").observe(),
        "euc_kr_codec": codec_owner("canvas_euc_kr_codec_oracle").observe(),
        "iso2022_codecs": codec_owner("canvas_iso2022_codec_oracle").run(),
        "boundary": "exact published Canvas HTTP factory, pinning transport and helpers; actual HTTPX loopback TLS; test-only exact origin allowlist and per-pool CA trust; no full adapter import",
        "runtime": {
            name: importlib.metadata.version(name)
            for name in ("httpx", "httpcore", "anyio")
        },
        "cases": observations,
    }


def run_native(executable):
    root = Path(__file__).resolve().parents[1] / "contracts"
    cases = json.loads(
        (root / "canvas-timeout-consumer-scenarios.json").read_text(encoding="utf-8")
    )["cases"]
    expected = json.loads(
        (root / "canvas-timeout-consumer-oracle.json").read_text(encoding="utf-8")
    )["cases"]
    observations = []
    with loopback_tls() as (origin, _, cert):
        for case in cases:
            environment = dict(os.environ)
            environment["MARTY_CANVAS_TIMEOUT_NATIVE_CASE"] = json.dumps(case)
            environment["MARTY_CANVAS_TIMEOUT_NATIVE_ORIGIN"] = origin
            environment["MARTY_CANVAS_TIMEOUT_NATIVE_CERT"] = str(cert)
            child = subprocess.run(
                [
                    str(executable),
                    "canvas_operation_http::tests::native_socket_case",
                    "--exact",
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
                line.removeprefix("CANVAS_TIMEOUT_NATIVE=")
                # Unicode NEL/LS/PS are valid inside JSON strings, not records.
                for line in child.stdout.split("\n")
                if line.startswith("CANVAS_TIMEOUT_NATIVE=")
            ]
            assert len(lines) == 1, "native child must emit exactly one observation"
            observations.append(json.loads(lines[0]))
    assert observations == expected, {
        "mismatches": [
            {"expected": left, "native": right}
            for left, right in zip(expected, observations, strict=True)
            if left != right
        ]
    }
    print(
        json.dumps(
            {"native_timeout_cases": len(observations), "status": "passed"},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source-repository")
    mode.add_argument("--native-executable", type=Path)
    arguments = parser.parse_args()
    if arguments.native_executable:
        run_native(arguments.native_executable)
        raise SystemExit(0)
    source = (
        subprocess.run(
            ["git", "show", SOURCE_REF],
            cwd=arguments.source_repository,
            capture_output=True,
            check=True,
        )
        .stdout.decode("utf-8")
        .replace("\r\n", "\n")
    )
    response_source = (
        subprocess.run(
            ["git", "show", RESPONSE_SOURCE_REF],
            cwd=arguments.source_repository,
            capture_output=True,
            check=True,
        )
        .stdout.decode("utf-8")
        .replace("\r\n", "\n")
    )
    print(json.dumps(run(source, response_source), sort_keys=True))
