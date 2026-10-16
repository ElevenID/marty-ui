#!/usr/bin/env python3
"""Generate only local, disposable self-host text credentials.

Managed OpenBao keys/tokens, workload certificates, and external integration
credentials are deliberately outside this generator's contract.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Callable


GENERATED = frozenset({
    "device_registration_gateway_key",
    "device_registration_signing_keys_key",
    "flow_application_event_hmac_key",
    "flow_webhook_secret",
    "grpc_service_token",
    "issuance_api_key",
    "keycloak_admin_password",
    "keycloak_db_password",
    "marty_api_client_secret",
    "marty_db_password",
    "notification_applicant_event_token",
    "notification_webhook_secret",
    "postgres_password",
    "signing_keys_integration_secret_key",
    "signing_keys_issuer_sign_key",
    "signing_keys_service_sign_gateway_key",
    "token_hmac_key",
})
HEX_32_BYTES = re.compile(r"[0-9a-f]{64}\Z")
REPO = Path(__file__).resolve().parents[1]


def require_private_root(root: Path) -> None:
    if os.name != "posix":
        raise ValueError("disposable credentials require a POSIX host with private file modes")
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("disposable secret root must be an existing private directory")
    if root.resolve().is_relative_to(REPO):
        raise ValueError("disposable secret root must be outside the source checkout")
    status = root.stat()
    if status.st_uid != os.getuid() or status.st_mode & 0o077:
        raise ValueError("disposable secret root must be owner-private")


def generate(root: Path, random_hex: Callable[[int], str] = secrets.token_hex) -> None:
    require_private_root(root)
    if any((root / name).exists() or (root / name).is_symlink() for name in GENERATED):
        raise ValueError("disposable credential output would overwrite a file")
    values = {name: random_hex(32) for name in sorted(GENERATED)}
    if (set(values) != GENERATED or len(set(values.values())) != len(GENERATED)
            or any(not isinstance(value, str) or not HEX_32_BYTES.fullmatch(value)
                   for value in values.values())):
        raise ValueError("disposable credential generator returned invalid or reused material")
    created: list[Path] = []
    try:
        for name, value in values.items():
            path = root / name
            descriptor = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            created.append(path)
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(value)
    except (OSError, UnicodeError):
        for path in created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass  # A partial disposable root must be discarded by its operator.
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        generate(args.secret_root)
    except (OSError, ValueError) as error:
        print(f"disposable credential setup failed: {error}", file=sys.stderr)
        return 2
    print(f"Created {len(GENERATED)} disposable credential files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
