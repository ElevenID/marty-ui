#!/usr/bin/env python3
"""Assemble one complete self-host secret generation without changing the live one.

The Keycloak and workload TLS producers must have qualified their remote keys,
certificates, and scoped tokens first. This step only assembles immutable file
inputs for a later controlled Compose recreation; it never activates them.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys

# Keep a receipt-verified extracted bundle immutable while importing siblings.
sys.dont_write_bytecode = True
from passport_remote_tls import SELFHOST_CERT_FILES, SELFHOST_TLS_FILES  # noqa: E402
from provision_selfhost_disposable_tls import KEY_METADATA_FILE, verified_key_metadata  # noqa: E402
from provision_selfhost_keycloak_kms import OUTPUTS as KEYCLOAK_OUTPUTS  # noqa: E402


MAX_SECRET_BYTES = 64 * 1024
RENEWED_FILES = SELFHOST_TLS_FILES | KEYCLOAK_OUTPUTS
CA_FILE = "workload_identity_ca_cert"
PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----\n?\Z")
RENEWED_CERT_FILES = SELFHOST_CERT_FILES | {
    "keycloak_master_rs256_cert", "keycloak_11id_rs256_cert",
}
RENEWED_TOKEN_FILES = RENEWED_FILES - RENEWED_CERT_FILES


def private_empty_or_source(path: Path, *, empty: bool) -> Path:
    if os.name != "posix" or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ValueError("secret generation requires an existing POSIX private directory")
    info = path.stat()
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("secret generation directory must be owner-private")
    if empty and any(path.iterdir()):
        raise ValueError("new secret generation directory must be empty")
    return path.resolve()


def bounded_file(path: Path, *, allow_empty: bool = False) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if path.is_symlink():
        raise ValueError("secret generation contains a symlink")
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SECRET_BYTES:
            raise ValueError("secret generation contains an invalid file")
        value = os.read(fd, MAX_SECRET_BYTES + 1)
        if (len(value) != info.st_size or len(value) > MAX_SECRET_BYTES
                or (not value and not allow_empty)
                or b"PRIVATE KEY" in value or b"\0" in value):
            raise ValueError("secret generation contains private or invalid material")
        return value
    finally:
        os.close(fd)


def entries(root: Path) -> dict[str, Path]:
    found = {entry.name: entry for entry in root.iterdir()}
    if any(not name or name in (".", "..") or not path.is_file() or path.is_symlink()
           for name, path in found.items()):
        raise ValueError("secret generation contains a non-regular entry")
    return found


def public_trust_overlap(old_ca: bytes, new_ca: bytes) -> bytes:
    """Make the sole supported two-issuer trust bundle from public certificates."""
    if (PEM_CERT.fullmatch(old_ca) is None or PEM_CERT.fullmatch(new_ca) is None
            or old_ca.rstrip(b"\n") == new_ca.rstrip(b"\n")):
        raise ValueError("CA overlap requires two distinct single public certificates")
    return old_ca.rstrip(b"\n") + b"\n" + new_ca.rstrip(b"\n") + b"\n"


def retired_public_trust(bundle: bytes) -> bytes:
    """Return only the replacement issuer from an exact two-cert bundle."""
    marker = b"-----BEGIN CERTIFICATE-----\n"
    split = bundle.find(marker, len(marker))
    if split < 0:
        raise ValueError("CA retirement requires an exact two-issuer public bundle")
    old_ca, new_ca = bundle[:split], bundle[split:]
    try:
        canonical = public_trust_overlap(old_ca, new_ca)
    except ValueError as error:
        raise ValueError("CA retirement requires an exact two-issuer public bundle") from error
    if bundle != canonical:
        raise ValueError("CA retirement requires an exact two-issuer public bundle")
    return new_ca


def verify_generations(current: Path, candidate: Path, *, ca_overlap: bool = False,
                       ca_retire: bool = False) -> tuple[int, int]:
    """Require a complete KMS-only successor with identical static inputs."""
    if ca_overlap and ca_retire:
        raise ValueError("CA overlap and trust retirement are separate ceremonies")
    current = private_empty_or_source(current, empty=False)
    candidate = private_empty_or_source(candidate, empty=False)
    if current == candidate:
        raise ValueError("secret generations must be distinct")
    old, new = entries(current), entries(candidate)
    if old.keys() != new.keys() or not RENEWED_FILES <= old.keys():
        raise ValueError("secret generation file inventory changed")
    changed = 0
    token_values = []
    for name in sorted(old):
        before = bounded_file(old[name], allow_empty=name not in RENEWED_FILES)
        after = bounded_file(new[name], allow_empty=name not in RENEWED_FILES)
        if stat.S_IMODE(old[name].stat().st_mode) != stat.S_IMODE(new[name].stat().st_mode):
            raise ValueError("secret generation file mode changed")
        should_change = (name == CA_FILE if ca_retire else
                         name in RENEWED_FILES and (name != CA_FILE or ca_overlap))
        if (before != after) != should_change:
            raise ValueError("secret generation changed the wrong input")
        if name == CA_FILE and ca_overlap:
            prefix = before.rstrip(b"\n") + b"\n"
            if (PEM_CERT.fullmatch(before) is None or not after.startswith(prefix)
                    or after != public_trust_overlap(before, after[len(prefix):])):
                raise ValueError("CA overlap bundle is not the exact old and new public issuers")
        if name == CA_FILE and ca_retire and after != retired_public_trust(before):
            raise ValueError("CA retirement did not remove only the old public issuer")
        changed += should_change
        if name in RENEWED_TOKEN_FILES:
            token_values.append(after)
    if len(set(token_values)) != len(token_values):
        raise ValueError("renewed scopes share a token")
    return len(old), changed


def write_generation(active: dict[str, Path], payloads: dict[str, bytes],
                     current: Path, output: Path, *, ca_overlap: bool = False,
                     ca_retire: bool = False) -> int:
    created: list[Path] = []
    try:
        for name, value in sorted(payloads.items()):
            old_mode = stat.S_IMODE(active[name].stat().st_mode)
            if old_mode not in (0o400, 0o440, 0o444, 0o600, 0o640, 0o644):
                raise ValueError("active secret file has unsupported mode")
            destination = output / name
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            created.append(destination)
            with os.fdopen(fd, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fchmod(stream.fileno(), old_mode)
                os.fsync(stream.fileno())
        verify_generations(current, output, ca_overlap=ca_overlap, ca_retire=ca_retire)
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return len(payloads)


def stage(current: Path, tls: Path, keycloak: Path, output: Path, *, ca_overlap: bool = False) -> int:
    roots = [private_empty_or_source(path, empty=(path == output))
             for path in (current, tls, keycloak, output)]
    if len(set(roots)) != 4:
        raise ValueError("secret generation directories must be distinct")
    current, tls, keycloak, output = roots
    active_owner = current.stat().st_uid
    if (output.stat().st_uid != os.getuid()
            or any(path.stat().st_uid not in (active_owner, os.getuid())
                   for path in (tls, keycloak))):
        raise ValueError("secret generation directory has an unexpected owner")
    active = entries(current)
    tls_files = entries(tls)
    keycloak_files = entries(keycloak)
    if not RENEWED_FILES <= active.keys():
        raise ValueError("active generation lacks a renewable input")
    if tls_files.keys() != SELFHOST_TLS_FILES | {KEY_METADATA_FILE}:
        raise ValueError("workload TLS candidate is incomplete")
    if keycloak_files.keys() != KEYCLOAK_OUTPUTS:
        raise ValueError("Keycloak candidate is incomplete")
    verified_key_metadata(tls)

    payloads = {name: bounded_file(path, allow_empty=name not in RENEWED_FILES)
                for name, path in active.items()}
    for source in (tls_files, keycloak_files):
        for name, path in source.items():
            if name != KEY_METADATA_FILE:
                candidate = bounded_file(path)
                if name == CA_FILE:
                    if ca_overlap:
                        candidate = public_trust_overlap(payloads[name], candidate)
                    elif candidate != payloads[name]:
                        raise ValueError("CA rollover needs a separate trust-overlap ceremony")
                elif candidate == payloads[name]:
                    raise ValueError("renewed input did not change")
                payloads[name] = candidate

    tokens = [payloads[name] for name in RENEWED_FILES
              if name not in SELFHOST_CERT_FILES and not name.endswith("_cert")]
    if len(set(tokens)) != len(tokens):
        raise ValueError("renewed scopes share a token")

    return write_generation(active, payloads, current, output, ca_overlap=ca_overlap)


def stage_retired_trust(current: Path, output: Path) -> int:
    current = private_empty_or_source(current, empty=False)
    output = private_empty_or_source(output, empty=True)
    if current == output or output.stat().st_uid != os.getuid():
        raise ValueError("CA retirement generation directories are invalid")
    active = entries(current)
    if not RENEWED_FILES <= active.keys():
        raise ValueError("active generation lacks a renewable input")
    payloads = {name: bounded_file(path, allow_empty=name not in RENEWED_FILES)
                for name, path in active.items()}
    payloads[CA_FILE] = retired_public_trust(payloads[CA_FILE])
    return write_generation(active, payloads, current, output, ca_retire=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("current", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    for name in ("tls", "keycloak"):
        parser.add_argument(f"--{name}", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--ca-overlap", action="store_true")
    mode.add_argument("--ca-retire", action="store_true")
    args = parser.parse_args()
    try:
        if args.ca_retire:
            if args.tls is not None or args.keycloak is not None:
                raise ValueError("CA retirement does not replace leaves or scoped tokens")
            count = stage_retired_trust(args.current, args.output)
        else:
            if args.tls is None or args.keycloak is None:
                raise ValueError("leaf renewal requires both scoped producer outputs")
            count = stage(args.current, args.tls, args.keycloak, args.output,
                          ca_overlap=args.ca_overlap)
    except (OSError, ValueError) as error:
        print(f"self-host secret generation failed: {error}", file=sys.stderr)
        return 2
    print(f"Staged {count} secret inputs for controlled recreation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
