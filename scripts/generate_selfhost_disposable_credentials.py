#!/usr/bin/env python3
"""Generate only local, disposable self-host text credentials.

Managed OpenBao keys/tokens, workload certificates, and external integration
credentials are deliberately outside this generator's contract.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import string
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
MDOC_OPERATORS = frozenset({
    "mdoc_iaca_issue_gateway_key",
    "mdoc_dsc_issue_gateway_key",
})
HEX_32_BYTES = re.compile(r"[0-9a-f]{64}\Z")
REPO = Path(__file__).resolve().parents[1]
OPERATOR_PASSWORD_POLICY = "length(8) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1)"


def validate_operator_password(value: str, realm_file: Path | None = None) -> None:
    """Validate a conservative character subset of the shipped 11id policy.

    This is for the synthetic operator, not service credentials or master-realm
    administration. A changed realm policy requires an explicit validator review.
    Never include the password or failed character class in the exception.
    """
    realm_file = realm_file or REPO / "config/keycloak/11id-realm.json"
    try:
        realm = json.loads(realm_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("shipped operator password policy is unavailable") from None
    if not isinstance(realm, dict) or realm.get("passwordPolicy") != OPERATOR_PASSWORD_POLICY:
        raise ValueError("shipped operator password policy needs review")
    if (not isinstance(value, str) or len(value) < 8
            or not any(char in string.ascii_uppercase for char in value)
            or not any(char in string.ascii_lowercase for char in value)
            or not any(char in string.digits for char in value)
            or not any(char in string.punctuation for char in value)):
        raise ValueError("synthetic operator password does not satisfy the shipped realm policy")


def generate_operator_password(random_hex: Callable[[int], str] = secrets.token_hex,
                               *, realm_file: Path | None = None) -> str:
    """Keep 256 random bits while guaranteeing all reviewed character classes."""
    material = random_hex(32)
    if not isinstance(material, str) or not HEX_32_BYTES.fullmatch(material):
        raise ValueError("operator password generator returned invalid material")
    value = "Aa1!" + material
    validate_operator_password(value, realm_file)
    return value


def write_operator_password(path: Path,
                            random_hex: Callable[[int], str] = secrets.token_hex,
                            *, realm_file: Path | None = None) -> None:
    require_private_root(path.parent)
    value = generate_operator_password(random_hex, realm_file=realm_file)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(value + "\n")
    except (OSError, UnicodeError):
        path.unlink(missing_ok=True)
        raise


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


def generate(root: Path, random_hex: Callable[[int], str] = secrets.token_hex,
             *, mdoc_operators_only: bool = False) -> None:
    names = MDOC_OPERATORS if mdoc_operators_only else GENERATED
    require_private_root(root)
    if any((root / name).exists() or (root / name).is_symlink() for name in names):
        raise ValueError("disposable credential output would overwrite a file")
    values = {name: random_hex(32) for name in sorted(names)}
    if (set(values) != names or len(set(values.values())) != len(names)
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
                stream.flush()
                # Compose bind-mounts the file into containers with distinct
                # non-root UIDs. The 0700 host directory protects the files;
                # their final mode must permit those containers to read them.
                os.fchmod(stream.fileno(), 0o444)
    except (OSError, UnicodeError):
        for path in created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass  # A partial disposable root must be discarded by its operator.
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--secret-root", type=Path)
    target.add_argument("--operator-password-file", type=Path,
                        help="fresh operator-only file in an existing private directory")
    parser.add_argument("--mdoc-operators-only", action="store_true",
                        help="with --secret-root, generate only the two distinct MDOC operator credentials")
    args = parser.parse_args()
    if args.mdoc_operators_only and args.secret_root is None:
        parser.error("--mdoc-operators-only requires --secret-root")
    try:
        if args.operator_password_file is not None:
            write_operator_password(args.operator_password_file)
        else:
            generate(args.secret_root, mdoc_operators_only=args.mdoc_operators_only)
    except (OSError, ValueError) as error:
        print(f"disposable credential setup failed: {error}", file=sys.stderr)
        return 2
    print("Created disposable operator password file" if args.operator_password_file is not None
          else f"Created {len(MDOC_OPERATORS if args.mdoc_operators_only else GENERATED)} disposable credential files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
