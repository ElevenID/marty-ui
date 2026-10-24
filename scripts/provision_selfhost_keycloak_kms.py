#!/usr/bin/env python3
"""Create or stage Keycloak remote-key inputs in an operator-owned secret root.

Run against the same HTTPS OpenBao used by the self-host workload bootstrap.
The DIDComm plugin must already be mounted. This script never exports a private
key and refuses to overwrite any existing Keycloak input. Ordinary renewal
reuses the current PKI issuer; explicit CA-rotation staging uses a separately
scoped authority and issuer while retaining the same remote key versions.
Neither path activates the staged credentials.
"""

from __future__ import annotations

from http.client import HTTPException
from pathlib import Path
import os
import secrets
import sys
from urllib.error import HTTPError, URLError
from selfhost_native_operator import (keycloak_policy, keycloak_provision,
                                      OperatorCleanupError)

from selfhost_openbao_client import Bao


REALMS = ("master", "11id")
PURPOSES = ("cookie", "ciba")
OUTPUTS = frozenset({
    "keycloak_signing_kms_token", "keycloak_master_rs256_cert",
    "keycloak_11id_rs256_cert",
    *(f"keycloak_{realm}_{purpose}_token" for realm in REALMS for purpose in PURPOSES),
})
def selected_pki_mount(*, renew: bool, requested: str | None) -> str:
    if not renew:
        if requested is not None:
            raise ValueError("Keycloak CA selection is renewal-only")
        return "keycloak-pki"
    if requested is None or requested == "keycloak-pki":
        return "keycloak-pki"
    version = requested.removeprefix("keycloak-pki-v")
    if (not requested.startswith("keycloak-pki-v") or not version.isdecimal()
            or int(version) not in range(2, 9) or version != str(int(version))):
        raise ValueError("replacement Keycloak PKI mount is invalid")
    return requested


# Compatibility name retained for callers of the Python entrypoint.
KeycloakBao = Bao


def signing_policy() -> str:
    return keycloak_policy("signing")


def jwe_policy(realm: str, purpose: str, version: str) -> str:
    try:
        return keycloak_policy("jwe", realm=realm, purpose=purpose, version=version)
    except RuntimeError as error:
        raise ValueError("Keycloak JWE policy reference is invalid") from error


def provision(bao: Bao, *, renew: bool = False,
              pki_mount: str = "keycloak-pki") -> dict[str, str]:
    """Use the native KMS-only producer; retain the privileged file handoff."""
    pki_mount = selected_pki_mount(
        renew=renew, requested=pki_mount if renew or pki_mount != "keycloak-pki" else None,
    )
    return keycloak_provision(bao, renew=renew, pki_mount=pki_mount,
                             nonce=secrets.token_hex(6))


def require_available_private_root(root: Path) -> None:
    if os.name != "posix":
        raise RuntimeError("disposable Keycloak provisioning requires a POSIX filesystem")
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RuntimeError("disposable Keycloak output root must be an existing private directory")
    owner = root.stat()
    if owner.st_uid != os.getuid() or owner.st_mode & 0o077:
        raise RuntimeError("disposable Keycloak output root is not owner-private")
    if any((root / name).exists() or (root / name).is_symlink() for name in OUTPUTS):
        raise RuntimeError("disposable Keycloak output would overwrite an existing secret")


def write_outputs(root: Path, outputs: dict[str, str], *, staged: bool = False) -> None:
    require_available_private_root(root)
    if set(outputs) != OUTPUTS:
        raise RuntimeError("disposable Keycloak output would overwrite or omit a secret")
    if any(not isinstance(content, str) or not content or "PRIVATE KEY" in content
           for content in outputs.values()):
        raise RuntimeError("disposable Keycloak output contains private or empty material")
    created: list[Path] = []
    try:
        for name, content in outputs.items():
            path = root / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(content)
                stream.flush()
                # Initial Compose bind mounts need public-read mode inside an
                # owner-private host root. Renewal stays owner-only until a
                # separate activation flow validates and installs it.
                os.fchmod(stream.fileno(), 0o600 if staged else 0o444)
    except (OSError, UnicodeError):
        for path in created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass  # The operator must discard a partial disposable root.
        raise


def main() -> int:
    try:
        endpoint = os.environ["BAO_ADDR"]
        ca = Path(os.environ["BAO_CACERT"])
        mode = os.environ.get("SELFHOST_KEYCLOAK_MODE", "initial")
        if mode not in ("initial", "renew"):
            raise RuntimeError("Keycloak provisioning mode is invalid")
        selected_mount = selected_pki_mount(
            renew=mode == "renew", requested=os.environ.get("SELFHOST_KEYCLOAK_PKI_MOUNT"),
        )
        token_variable = ("BAO_CA_ROTATION_TOKEN_FILE" if selected_mount != "keycloak-pki"
                          else "BAO_RENEWAL_TOKEN_FILE" if mode == "renew"
                          else "BAO_ROOT_TOKEN_FILE")
        token_file = Path(os.environ[token_variable])
        root = Path(os.environ["SELFHOST_KEYCLOAK_OUTPUT_DIR"])
        if (not endpoint.startswith("https://") or not ca.is_absolute()
                or not ca.is_file() or ca.is_symlink() or not token_file.is_absolute()
                or not token_file.is_file() or token_file.is_symlink()):
            raise RuntimeError("disposable Keycloak OpenBao inputs are invalid")
        token = token_file.read_text(encoding="ascii").strip()
        if len(token) < 20:
            raise RuntimeError("Keycloak OpenBao authority token is absent")
        require_available_private_root(root)
        renewing = mode == "renew"
        outputs = provision(KeycloakBao(endpoint, ca, token), renew=renewing,
                            pki_mount=selected_mount)
        try:
            write_outputs(root, outputs, staged=renewing)
        except Exception as error:
            raise OperatorCleanupError("Keycloak provisioning requires operator recovery") from error
    except OperatorCleanupError as error:
        print(str(error), file=sys.stderr)
        return 3
    except (KeyError, OSError, ValueError, RuntimeError, HTTPError, URLError,
            HTTPException) as error:
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"disposable Keycloak provisioning failed: {detail}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
