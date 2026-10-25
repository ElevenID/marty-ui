"""Guest-local, read-only HTTPS and OIDC discovery observation.

The controller executes this exact signed-harness source via SSH. It accepts only
the authenticated public installer CA and localhost origin; it never changes
trust, sends credentials, follows redirects, or claims browser login.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import signal
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit


MAX_BODY = 65536
ISSUER_PATH = "/realms/11id"
DISCOVERY_PATH = ISSUER_PATH + "/.well-known/openid-configuration"


def require(value):
    if not value:
        raise ValueError("installed TLS observation refused")


def exact_endpoint(value, origin, path):
    require(isinstance(value, str) and value == origin + path)
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname == "localhost"
            and not parsed.username and not parsed.password and not parsed.query
            and not parsed.fragment)


def fetch(context, port, path):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as plain:
        with context.wrap_socket(plain, server_hostname="localhost") as secured:
            require(secured.version() in ("TLSv1.2", "TLSv1.3"))
            peer = secured.getpeercert(binary_form=True)
            require(isinstance(peer, bytes) and 0 < len(peer) <= 16384)
            secured.settimeout(10)
            request = (f"GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n"
                       "Accept: application/json\r\nConnection: close\r\n\r\n")
            secured.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(secured, method="GET")
            response.begin()
            require(response.version == 11 and response.status == 200)
            require(response.getheader("Location") is None)
            length = response.getheader("Content-Length")
            if length is not None:
                require(re.fullmatch(r"[0-9]{1,6}", length) is not None and int(length) <= MAX_BODY)
            body = response.read(MAX_BODY + 1)
            require(0 < len(body) <= MAX_BODY)
            return hashlib.sha256(peer).hexdigest(), secured.version(), response.status, body


def probe(origin, ca_pem, installation_id, engine_id, *, now=time.time, fetcher=fetch):
    require(isinstance(origin, str) and re.fullmatch(r"https://localhost:[1-9][0-9]{3,4}", origin))
    port = int(origin.rsplit(":", 1)[1])
    require(1024 <= port <= 65535)
    require(isinstance(ca_pem, str) and 0 < len(ca_pem) <= 16384
            and "PRIVATE KEY" not in ca_pem)
    require(isinstance(installation_id, str) and re.fullmatch(r"[0-9a-f-]{36}", installation_id))
    require(isinstance(engine_id, str) and re.fullmatch(r"[A-Za-z0-9:._-]{1,128}", engine_id))
    encoded = "".join(ca_pem.splitlines()[1:-1])
    der = base64.b64decode(encoded, validate=True)
    require(0 < len(der) <= 12288)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=ca_pem)
    first = fetcher(context, port, "/")
    second = fetcher(context, port, DISCOVERY_PATH)
    require(first[0] == second[0] and first[1] == second[1]
            and first[2] == second[2] == 200)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    discovery = json.loads(second[3], object_pairs_hook=pairs)
    require(isinstance(discovery, dict))
    issuer = origin + ISSUER_PATH
    exact_endpoint(discovery.get("issuer"), origin, ISSUER_PATH)
    exact_endpoint(discovery.get("authorization_endpoint"), origin,
                   ISSUER_PATH + "/protocol/openid-connect/auth")
    exact_endpoint(discovery.get("token_endpoint"), origin,
                   ISSUER_PATH + "/protocol/openid-connect/token")
    exact_endpoint(discovery.get("jwks_uri"), origin,
                   ISSUER_PATH + "/protocol/openid-connect/certs")
    return dict(schema="elevenid.installer-live-tls-observation/v1",
                installation_id=installation_id, engine_id=engine_id, origin=origin,
                ca_der_sha256=hashlib.sha256(der).hexdigest(), peer_der_sha256=first[0],
                tls_version=first[1], root_status=first[2], discovery_status=second[2],
                discovery_sha256=hashlib.sha256(second[3]).hexdigest(), issuer=issuer,
                observed_at=int(now()), browser_login_observed=False,
                host_trust_modified=False)


def main():
    try:
        require(len(sys.argv) == 5)
        signal.alarm(30)
        ca = base64.b64decode(sys.argv[2], validate=True).decode("ascii")
        result = probe(sys.argv[1], ca, sys.argv[3], sys.argv[4])
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (ValueError, OSError, ssl.SSLError, TimeoutError, UnicodeError,
            json.JSONDecodeError, http.client.HTTPException):
        raise SystemExit("Installed TLS observation refused") from None
    finally:
        # main() is also exercised in-process by the release contracts. Never
        # leave its process-wide deadline armed after a refused observation.
        signal.alarm(0)


if __name__ == "__main__":
    main()
