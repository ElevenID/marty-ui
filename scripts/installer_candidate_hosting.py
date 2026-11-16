"""Closed public-hosting binding for version-two signed candidate grants.

The binding is derived from exact customer input bytes. It never agrees to
terms, resolves DNS, opens a listener or grants publication/installation rights.
The native installer independently applies its ordinary hosting validator.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit, urlunsplit

NAME = "hosting-input.json"
ROOTS_NAME = "acme-staging-roots.pem"
MAX_BYTES = 8192
MAX_ROOTS_BYTES = 65536
FIELDS = {"input_sha256", "input_size_bytes", "public_origin", "public_entry_origin",
          "certificate_source", "acme_environment", "acme_terms_url", "staging_trust"}
DIRECTORIES = {
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "production": "https://acme-v02.api.letsencrypt.org/directory",
}


def require(value: bool, message="candidate hosting binding differs") -> None:
    if not value:
        raise ValueError(message)


def exact(value, required, optional=frozenset()):
    require(type(value) is dict and required <= set(value) <= required | optional)
    return value


def decode(raw: bytes) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate candidate hosting field")
            result[key] = value
        return result
    def invalid_number(_):
        raise ValueError("invalid candidate hosting number")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_number)
    require(type(value) is dict)
    return value


def origin(value: str, *, address: bool) -> str:
    require(type(value) is str and value.isascii() and len(value) <= 320
            and value.startswith("https://") and not re.search(r"[\s/?#@%\\'\"]", value[8:]))
    authority = value[8:]
    if authority.startswith("["):
        match = re.fullmatch(r"\[([^]]+)\](?::([0-9]+))?", authority)
        require(match is not None)
        host, port = match.groups()
        ip = ipaddress.IPv6Address(host)
        require(str(ip) == host and ip.ipv4_mapped is None)
    else:
        match = re.fullmatch(r"([^:]+)(?::([0-9]+))?", authority)
        require(match is not None)
        host, port = match.groups()
        try:
            ip = ipaddress.IPv4Address(host)
        except ValueError:
            ip = None
    if port is not None:
        number = int(port)
        require(0 < number <= 65535 and number != 443 and str(number) == port)
    if address:
        require(ip is not None and not ip.is_loopback and not ip.is_unspecified
                and not ip.is_multicast and str(ip) != "255.255.255.255")
    else:
        require(ip is None and host == host.lower() and len(host) <= 253 and "." in host
                and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                        for label in host.split(".")))
        last = host.rsplit(".", 1)[-1]
        require(not last.isdecimal() and re.fullmatch(r"0x[0-9a-f]+", last) is None)
        # Reject malformed A-labels rather than treating their ASCII shape as
        # proof that downstream URL clients will preserve the same authority.
        for label in host.split("."):
            if label.startswith("xn--"):
                require(label.encode("ascii").decode("idna").encode("idna").decode("ascii") == label)
    return value


def terms(value: str) -> str:
    require(type(value) is str and value.isascii() and 0 < len(value) <= 2048
            and not re.search(r"[\s\\]", value))
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.netloc == "letsencrypt.org"
            and not parsed.query and not parsed.fragment
            and parsed.path.startswith("/documents/") and parsed.path.endswith(".pdf")
            and urlunsplit(parsed) == value
            and not any(part.lower() in (".", "..", "%2e", "%2e%2e", ".%2e", "%2e.")
                        for part in parsed.path.split("/")))
    return value


def validate(binding: dict) -> None:
    exact(binding, FIELDS)
    require(type(binding["input_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", binding["input_sha256"]) is not None
            and type(binding["input_size_bytes"]) is int
            and 0 < binding["input_size_bytes"] <= MAX_BYTES)
    origin(binding["public_origin"], address=False)
    if binding["public_entry_origin"] is not None:
        origin(binding["public_entry_origin"], address=True)
    require(binding["certificate_source"] in ("managed-ca", "acme"))
    if binding["certificate_source"] == "acme":
        require(type(binding["acme_environment"]) is str and binding["acme_environment"] in DIRECTORIES)
        terms(binding["acme_terms_url"])
    else:
        require(binding["acme_environment"] is None and binding["acme_terms_url"] is None)
    staging = binding["certificate_source"] == "acme" and binding["acme_environment"] == "staging"
    require(staging == (binding["staging_trust"] is not None))
    if staging:
        trust = exact(binding["staging_trust"], {"sha256", "size_bytes"})
        require(type(trust["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", trust["sha256"]) is not None
                and type(trust["size_bytes"]) is int and 0 < trust["size_bytes"] <= MAX_ROOTS_BYTES)


def from_bytes(raw: bytes, *, staging_roots: bytes | None = None) -> dict:
    value = exact(decode(raw), {"schema", "mode", "public_origin", "listener", "tls"},
                  {"public_entry_origin", "connector", "web"})
    require(value["schema"] == "elevenid.installation-hosting/v1" and value["mode"] == "direct"
            and value.get("connector") is None)
    if value.get("web") is not None:
        web = exact(value["web"], {"enabled_sections"})
        sections = web["enabled_sections"]
        require(type(sections) is list and len(sections) <= 2
                and all(type(section) is str and section in ("public", "console") for section in sections)
                and len(set(sections)) == len(sections))
    canonical = origin(value["public_origin"], address=False)
    alias = value.get("public_entry_origin")
    if alias is not None:
        origin(alias, address=True)
    listener = exact(value["listener"], {"bind_address", "port"})
    require(type(listener["bind_address"]) is str and type(listener["port"]) is int
            and 1024 <= listener["port"] <= 65535)
    address = ipaddress.ip_address(listener["bind_address"])
    require(not address.is_loopback and not address.is_multicast
            and str(address) != "255.255.255.255"
            and not (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None))
    tls = exact(value["tls"], {"termination", "certificate_source"}, {"acme", "http01_host_port"})
    require(tls["termination"] == "marty-keyless" and tls["certificate_source"] in ("managed-ca", "acme"))
    environment = agreed_terms = None
    if tls["certificate_source"] == "acme":
        acme = exact(tls.get("acme"), {"environment", "directory_url", "profile", "terms_url", "terms_agreed"}, {"contact"})
        environment = acme["environment"]
        require(type(environment) is str and environment in DIRECTORIES
                and acme["directory_url"] == DIRECTORIES[environment]
                and acme["profile"] == "shortlived" and acme["terms_agreed"] is True)
        agreed_terms = terms(acme["terms_url"])
        contact = acme.get("contact")
        if contact is not None:
            require(type(contact) is str and contact.isascii() and len(contact) <= 261
                    and contact.startswith("mailto:") and "@" in contact[7:])
            local, domain = contact[7:].rsplit("@", 1)
            require(0 < len(local) <= 64 and not local.startswith(".") and not local.endswith(".")
                    and ".." not in local and re.fullmatch(r"[A-Za-z0-9._+-]+", local) is not None)
            origin("https://" + domain, address=False)
            require(":" not in domain)
        port = tls.get("http01_host_port")
        require(type(port) is int and 1024 <= port <= 65535 and port != listener["port"])
    else:
        require(tls.get("acme") is None and tls.get("http01_host_port") is None)
    binding = dict(input_sha256=hashlib.sha256(raw).hexdigest(), input_size_bytes=len(raw),
                   public_origin=canonical, public_entry_origin=alias,
                   certificate_source=tls["certificate_source"], acme_environment=environment,
                   acme_terms_url=agreed_terms, staging_trust=None)
    if staging_roots is not None:
        require(type(staging_roots) is bytes and 0 < len(staging_roots) <= MAX_ROOTS_BYTES)
        binding["staging_trust"] = dict(sha256=hashlib.sha256(staging_roots).hexdigest(), size_bytes=len(staging_roots))
    validate(binding)
    return binding


def require_bytes(binding: dict, raw: bytes, *, staging_roots: bytes | None = None) -> None:
    validate(binding)
    require(from_bytes(raw, staging_roots=staging_roots) == binding, "authenticated candidate hosting bytes changed")


def private_directory(path: Path) -> int:
    require(path.is_absolute() and ".." not in path.parts)
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            require(info.st_uid in (0, os.geteuid()) and
                    (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX))
        info = os.fstat(parent)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        result, parent = parent, None
        return result
    finally:
        if parent is not None:
            os.close(parent)


class HeldInput:
    """Retain the exact private input inode across signature/transport work."""
    def __init__(self, path: Path, maximum=MAX_BYTES):
        require(type(maximum) is int and 0 < maximum <= MAX_ROOTS_BYTES)
        self.maximum = maximum
        self.path, self.parent, self.fd = Path(path), None, None
        try:
            self.parent = private_directory(self.path.parent)
            self.fd = self._open()
            self.identity = self._identity(self.fd)
            self.raw = self._read(self.fd)
            self.check()
        except BaseException:
            self.close()
            raise

    def _identity(self, fd):
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and 0 < info.st_size <= self.maximum)
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _open(self):
        return os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                       dir_fd=self.parent)

    def _read(self, fd):
        raw = os.pread(fd, self.maximum + 1, 0)
        require(0 < len(raw) <= self.maximum)
        return raw

    def check(self):
        parent = private_directory(self.path.parent)
        current = None
        try:
            held, named = os.fstat(self.parent), os.fstat(parent)
            require((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
                    "candidate hosting directory changed")
            current = self._open()
            require(self._identity(current) == self.identity == self._identity(self.fd)
                    and self._read(current) == self.raw == self._read(self.fd),
                    "candidate hosting file changed")
        finally:
            if current is not None:
                os.close(current)
            os.close(parent)
        return self.raw

    def close(self):
        for name in ("fd", "parent"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def file_names(record: dict) -> set[str]:
    if "hosting" not in record:
        return set()
    validate(record["hosting"])
    return {NAME} | ({ROOTS_NAME} if record["hosting"]["staging_trust"] is not None else set())


def check_file(record: dict, directory: Path) -> dict[str, bytes]:
    """Fixed-file transport closure; v1 may never acquire configuration scope."""
    from contextlib import ExitStack
    expected = file_names(record)
    for name in {NAME, ROOTS_NAME} - expected:
        require(not os.path.lexists(directory / name), "grant cannot carry unbound hosting or staging trust input")
    with ExitStack() as stack:
        held = {name: stack.enter_context(HeldInput(directory / name,
                MAX_ROOTS_BYTES if name == ROOTS_NAME else MAX_BYTES)) for name in expected}
        raw = {name: item.check() for name, item in held.items()}
        if expected:
            require_bytes(record["hosting"], raw[NAME], staging_roots=raw.get(ROOTS_NAME))
        return raw
