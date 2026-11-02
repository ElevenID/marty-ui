"""Guest-local, read-only HTTPS and OIDC discovery observation.

The controller executes this exact signed-harness source via SSH. The native
trust export binds the configured HTTPS authority and the separate local socket.
The probe verifies that authority over that socket; it never changes trust,
sends credentials, follows redirects, or claims public reachability/browser login.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import stat
import sys
import time
from urllib.parse import urlsplit


MAX_BODY = 65536
ISSUER_PATH = "/realms/11id"
DISCOVERY_PATH = ISSUER_PATH + "/.well-known/openid-configuration"
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"


def require(value):
    if not value:
        raise ValueError("installed TLS observation refused")


def public_origin(value):
    """Validate the canonical authority without DNS resolution or normalization."""
    require(isinstance(value, str) and value.isascii() and len(value) <= 320
            and value.startswith("https://")
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
            and not any(c in value for c in "\\%\"'"))
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.netloc and not parsed.path
            and not parsed.query and not parsed.fragment
            and not parsed.username and not parsed.password
            and value == "https://" + parsed.netloc)
    host = parsed.hostname
    require(host and host == host.lower())
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
        labels = host.split(".")
        require(len(host) <= 253 and all(re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            and not labels[-1].isdigit()
            and re.fullmatch(r"0x[0-9a-f]*", labels[-1]) is None)
    if address is not None:
        require(str(address) == host and not address.is_unspecified
                and not address.is_multicast and host != "255.255.255.255"
                and getattr(address, "ipv4_mapped", None) is None)
    authority = "[" + host + "]" if address is not None and address.version == 6 else host
    if parsed.port is not None:
        require(0 < parsed.port <= 65535 and parsed.port != 443)
        authority += ":" + str(parsed.port)
    require(parsed.netloc == authority)
    return parsed


def local_address(value):
    """Parse only the exact numeric SocketAddr supplied by the native owner."""
    require(isinstance(value, str) and value.isascii() and len(value) <= 64)
    parsed = urlsplit("https://" + value)
    require(not parsed.path and not parsed.query and not parsed.fragment
            and not parsed.username and not parsed.password)
    address = ipaddress.ip_address(parsed.hostname)
    require(not address.is_unspecified and not address.is_multicast
            and str(address) != "255.255.255.255"
            and getattr(address, "ipv4_mapped", None) is None
            and parsed.port is not None and 1024 <= parsed.port <= 65535)
    host = "[" + str(address) + "]" if address.version == 6 else str(address)
    require(value == host + ":" + str(parsed.port))
    return str(address), parsed.port


def certificate_hashes(pem):
    require(isinstance(pem, str) and 0 < len(pem) <= 65536)
    pattern = r"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----"
    require(re.fullmatch(r"\s*(?:" + pattern + r"\s*)+", pem) is not None)
    matches = re.findall(pattern, pem)
    require(1 <= len(matches) <= 16)
    result = []
    for encoded in matches:
        encoded = "".join(encoded.splitlines())
        der = base64.b64decode(encoded, validate=True)
        require(0 < len(der) <= 12288 and base64.b64encode(der).decode() == encoded)
        result.append(hashlib.sha256(der).hexdigest())
    return result


def exact_endpoint(value, origin, path):
    require(isinstance(value, str) and value == origin + path)
    public_origin(origin)


def fetch(context, address, origin, path):
    identity = public_origin(origin)
    with socket.create_connection(local_address(address), timeout=10) as plain:
        with context.wrap_socket(plain, server_hostname=identity.hostname) as secured:
            require(secured.version() in ("TLSv1.2", "TLSv1.3"))
            peer = secured.getpeercert(binary_form=True)
            require(isinstance(peer, bytes) and 0 < len(peer) <= 16384)
            secured.settimeout(10)
            request = (f"GET {path} HTTP/1.1\r\nHost: {identity.netloc}\r\n"
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


def system_public_roots():
    """Read the supported Ubuntu root bundle explicitly, ignoring SSL_* overrides.

    This probe records its own store digest. It does not claim that the host
    bundle is the native operator's compiled Mozilla store or a browser store.
    """
    fd=os.open(SYSTEM_CA_BUNDLE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==0
                and before.st_mode & 0o022==0 and 0<before.st_size<=2*1024*1024)
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(2*1024*1024+1)
        after=os.fstat(fd)
        require(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns))
        return raw.decode('ascii'),hashlib.sha256(raw).hexdigest()
    finally:os.close(fd)


def probe(origin, local_probe_address, certificate_scope, ca_pem, installation_id,
          engine_id, *, now=time.time, fetcher=fetch, public_roots=False, expected_leaf=None):
    public_origin(origin)
    local_address(local_probe_address)
    require(certificate_scope in ("public-ingress", "backend"))
    require(isinstance(installation_id, str) and re.fullmatch(r"[0-9a-f-]{36}", installation_id))
    require(isinstance(engine_id, str) and re.fullmatch(r"[A-Za-z0-9:._-]{1,128}", engine_id))
    if public_roots:
        require(ca_pem=='' and certificate_scope=='public-ingress'
                and isinstance(expected_leaf,str) and re.fullmatch(r'[0-9a-f]{64}',expected_leaf))
        ca_pem,bundle_sha256=system_public_roots()
        hashes=None
    else:
        require(expected_leaf is None)
        hashes = certificate_hashes(ca_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=ca_pem)
    first = fetcher(context, local_probe_address, origin, "/")
    second = fetcher(context, local_probe_address, origin, DISCOVERY_PATH)
    require(first[0] == second[0] and first[1] == second[1]
            and first[2] == second[2] == 200)
    require(not public_roots or first[0]==expected_leaf)
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
    result = dict(schema="elevenid.installer-live-tls-observation/v2",
                installation_id=installation_id, engine_id=engine_id, origin=origin,
                local_probe_address=local_probe_address, certificate_scope=certificate_scope,
                public_endpoint_observed=False,
                peer_der_sha256=first[0],
                tls_version=first[1], root_status=first[2], discovery_status=second[2],
                discovery_sha256=hashlib.sha256(second[3]).hexdigest(), issuer=issuer,
                observed_at=int(now()), browser_login_observed=False,
                host_trust_modified=False)
    if public_roots:
        result.update(schema="elevenid.installer-live-tls-observation/v3",
                      probe_trust_source="ubuntu-system-ca-bundle",
                      probe_trust_bundle_sha256=bundle_sha256)
    else:result['ca_der_sha256']=hashes[0]
    return result


def main():
    try:
        require(len(sys.argv) in (7,9))
        signal.alarm(30)
        ca = base64.b64decode(sys.argv[4], validate=True).decode("ascii")
        if len(sys.argv)==9:
            require(sys.argv[7]=='--public-roots')
            result = probe(sys.argv[1],sys.argv[2],sys.argv[3],ca,sys.argv[5],sys.argv[6],
                           public_roots=True,expected_leaf=sys.argv[8])
        else:result = probe(sys.argv[1], sys.argv[2], sys.argv[3], ca, sys.argv[5], sys.argv[6])
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
