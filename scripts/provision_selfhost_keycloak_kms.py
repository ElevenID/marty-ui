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
import re
import secrets
import sys
from urllib.error import HTTPError, URLError
from selfhost_native_operator import (certificate_expiry, keycloak_policy, keycloak_token,
                                      OperatorCleanupError)

from selfhost_openbao_client import (Bao,
                                    certificate_public_key_der, public_key_der,
                                    require_ca_rotation_authority,
                                    require_renewal_authority)


REALMS = ("master", "11id")
PURPOSES = ("cookie", "ciba")
VERSION = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
OUTPUTS = frozenset({
    "keycloak_signing_kms_token", "keycloak_master_rs256_cert",
    "keycloak_11id_rs256_cert",
    *(f"keycloak_{realm}_{purpose}_token" for realm in REALMS for purpose in PURPOSES),
})
SESSION_TTL = "8h"
MIN_VALIDITY_SECONDS = 7 * 60 * 60
ROLE_CONFIG = {
    "allow_any_name": True, "key_type": "rsa", "key_bits": 2048,
    "max_ttl": SESSION_TTL, "use_csr_common_name": False, "use_csr_sans": False,
}


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


class KeycloakBao(Bao):
    def request(
        self, method: str, path: str, body: dict | None = None, *, token: str | None = None,
        authenticate: bool = True,
    ) -> dict:
        try:
            return super().request(method, path, body, token=token,
                                   authenticate=authenticate)
        except HTTPError as error:
            if token is not None:
                raise
            raise RuntimeError(
                f"disposable Keycloak OpenBao rejected {method} {path}: HTTP {error.code}"
            ) from error


def require_data(response: dict, field: str) -> dict:
    data = response.get("data")
    if not isinstance(data, dict) or field not in data:
        raise RuntimeError("disposable Keycloak OpenBao response is incomplete")
    return data


def signing_policy() -> str:
    return keycloak_policy("signing")


def jwe_policy(realm: str, purpose: str, version: str) -> str:
    try:
        return keycloak_policy("jwe", realm=realm, purpose=purpose, version=version)
    except RuntimeError as error:
        raise ValueError("Keycloak JWE policy reference is invalid") from error


def require_cert_lifetime(certificate: str) -> None:
    if not certificate_expiry(certificate, MIN_VALIDITY_SECONDS):
        raise RuntimeError("disposable Keycloak certificate expires before tester session")


def require_mounts(bao: Bao, *, renew: bool = False,
                   pki_mount: str = "keycloak-pki") -> None:
    mounts = require_data(bao.request("GET", "sys/mounts"), "transit/")
    if (mounts["transit/"].get("type") != "transit"
            or mounts.get("didcomm/", {}).get("type") != "openbao-didcomm-authcrypt"
            or (not renew and "keycloak-pki/" in mounts)
            or (renew and mounts.get("keycloak-pki/", {}).get("type") != "pki")
            or (renew and mounts.get(f"{pki_mount}/", {}).get("type") != "pki")):
        raise RuntimeError("disposable OpenBao lacks the reviewed Keycloak mounts")


def provision(bao: Bao, *, renew: bool = False,
              pki_mount: str = "keycloak-pki") -> dict[str, str]:
    created: list[str] = []
    try:
        return _provision(bao, created, renew=renew, pki_mount=pki_mount)
    except OperatorCleanupError:
        raise
    except Exception as error:
        if created:
            raise OperatorCleanupError("Keycloak provisioning requires operator recovery") from error
        raise


def _provision(bao: Bao, created: list[str], *, renew: bool = False,
               pki_mount: str = "keycloak-pki") -> dict[str, str]:
    """Return exactly seven public certificates/scoped tokens, not private keys."""
    pki_mount = selected_pki_mount(
        renew=renew, requested=pki_mount if renew or pki_mount != "keycloak-pki" else None,
    )
    if renew:
        if pki_mount == "keycloak-pki":
            require_renewal_authority(bao)
        else:
            require_ca_rotation_authority(bao)
    require_mounts(bao, renew=renew, pki_mount=pki_mount)
    if renew:
        if pki_mount != "keycloak-pki":
            bao.request("POST", f"{pki_mount}/roles/rs256", ROLE_CONFIG)
        role = require_data(bao.request("GET", f"{pki_mount}/roles/rs256"), "key_type")
        if (role["key_type"] != "rsa" or role.get("key_bits") != 2048
                or role.get("allow_any_name") is not True
                or role.get("max_ttl") != 8 * 60 * 60):
            raise RuntimeError("Keycloak renewal PKI role changed")
        ca = require_data(bao.request("GET", f"{pki_mount}/cert/ca"), "certificate")
        require_cert_lifetime(ca["certificate"])
    else:
        bao.request("POST", "sys/mounts/keycloak-pki", {
            "type": "pki", "config": {"max_lease_ttl": "8760h"},
        })
        ca = require_data(bao.request("POST", "keycloak-pki/root/generate/internal", {
            "common_name": "Marty disposable Keycloak CA", "ttl": "8760h",
            "key_type": "ec", "key_bits": 256,
        }), "certificate")
        if "private_key" in ca:
            raise RuntimeError("disposable Keycloak PKI exported its CA key")
        bao.request("POST", "keycloak-pki/roles/rs256", ROLE_CONFIG)
    outputs: dict[str, str] = {}
    for realm in REALMS:
        rsa_key = f"keycloak-{realm}-rs256"
        hmac_key = f"keycloak-{realm}-hs512"
        for name, kind, extra in ((rsa_key, "rsa-2048", {}),
                                  (hmac_key, "hmac", {"key_size": 64})):
            if not renew:
                bao.request("POST", f"transit/keys/{name}", {
                    "type": kind, "exportable": False,
                    "allow_plaintext_backup": False, **extra,
                })
            metadata = require_data(bao.request("GET", f"transit/keys/{name}"), "type")
            if (metadata["type"] != kind or metadata.get("exportable") is not False
                    or metadata.get("allow_plaintext_backup") is not False
                    or metadata.get("latest_version") != 1):
                raise RuntimeError("disposable Keycloak key lacks version-1 custody")
        csr = require_data(bao.request("POST", f"transit/keys/{rsa_key}/csr",
                                       {"version": 1}), "csr")["csr"]
        signed = require_data(bao.request("POST", f"{pki_mount}/sign/rs256", {
            "csr": csr, "common_name": f"{realm}.keycloak.internal", "ttl": SESSION_TTL,
        }), "certificate")
        if "private_key" in signed:
            raise RuntimeError("disposable Keycloak leaf exported a private key")
        certificate = signed["certificate"]
        metadata = require_data(bao.request("GET", f"transit/keys/{rsa_key}"), "keys")
        public_key = metadata["keys"].get("1", {}).get("public_key")
        if not isinstance(public_key, str) or not isinstance(certificate, str):
            raise RuntimeError("disposable Keycloak RS256 public key is absent")
        require_cert_lifetime(certificate)
        # Rust only receives public data. Verify the mounted certificate is
        # bound to the non-exportable Transit version that Keycloak will sign.
        if certificate_public_key_der(certificate) != public_key_der(public_key):
            raise RuntimeError("disposable Keycloak RS256 certificate key differs")
        outputs[f"keycloak_{realm}_rs256_cert"] = certificate
    nonce = secrets.token_hex(6)
    if not renew:
        bao.request("POST", "transit/keys/foreign-keycloak-selfhost", {
            "type": "rsa-2048", "exportable": False, "allow_plaintext_backup": False,
        })
    signing_token = keycloak_token(bao, "signing", renew=renew, nonce=nonce)
    created.append(signing_token)
    outputs["keycloak_signing_kms_token"] = signing_token
    for realm in REALMS:
        for purpose in PURPOSES:
            key_path = f"didcomm/keycloak/keys/{realm}/{purpose}"
            if not renew:
                bao.request("POST", key_path, {})
            current = require_data(bao.request("GET", key_path), "version")
            version = current["version"]
            if not isinstance(version, str) or not VERSION.fullmatch(version):
                raise RuntimeError("disposable Keycloak JWE version is invalid")
            token = keycloak_token(bao, "jwe", renew=renew, nonce=nonce,
                                   realm=realm, purpose=purpose, version=version)
            created.append(token)
            outputs[f"keycloak_{realm}_{purpose}_token"] = token
    if set(outputs) != OUTPUTS or len(set(outputs[name] for name in outputs if name.endswith("_token"))) != 5:
        raise RuntimeError("disposable Keycloak output contract is incomplete")
    return outputs


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
