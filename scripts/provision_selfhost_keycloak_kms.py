#!/usr/bin/env python3
"""Create or stage Keycloak remote-key inputs in an operator-owned secret root.

Run against the same HTTPS OpenBao used by the self-host workload bootstrap.
The DIDComm plugin must already be mounted. This script never exports a private
key and refuses to overwrite any existing Keycloak input. Renewal reuses the
same remote key versions, PKI issuer, and exact scoped policies; it does not
activate the staged credentials or roll the short-lived CA.
"""

from __future__ import annotations

import base64
from http.client import HTTPException
from pathlib import Path
import os
import re
import secrets
import subprocess
import sys
from urllib.error import HTTPError, URLError

from selfhost_openbao_client import (Bao, RENEWAL_LEAF_ROLE,
                                    certificate_public_key_der, public_key_der,
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


def scoped_token(bao: Bao, policy: str, name: str) -> str:
    bao.request("PUT", f"sys/policies/acl/{name}", {"policy": policy})
    return mint_token(bao, name)


def mint_token(bao: Bao, name: str, *, renew: bool = False) -> str:
    endpoint = f"auth/token/create/{RENEWAL_LEAF_ROLE}" if renew else "auth/token/create"
    result = bao.request("POST", endpoint, {
        "policies": [name], "no_default_policy": True, "ttl": SESSION_TTL,
    }).get("auth", {})
    token = result.get("client_token") if isinstance(result, dict) else None
    if not isinstance(token, str) or len(token) < 20 or token == bao.token:
        raise RuntimeError("disposable Keycloak signer token is unscoped")
    if (type(result.get("lease_duration")) is not int
            or result["lease_duration"] < MIN_VALIDITY_SECONDS):
        raise RuntimeError("disposable Keycloak token expires before tester session")
    return token


def renewed_token(bao: Bao, policy: str, prefix: str) -> str:
    """Reuse an exactly scoped existing policy; never widen it during renewal."""
    names = require_data(bao.request("LIST", "sys/policies/acl"), "keys")["keys"]
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise RuntimeError("Keycloak renewal policy inventory is invalid")
    matching = []
    for name in names:
        if name.startswith(prefix) and VERSION.fullmatch(name):
            current = require_data(bao.request("GET", f"sys/policies/acl/{name}"), "policy")
            if current["policy"] == policy:
                matching.append(name)
    if len(matching) != 1:
        raise RuntimeError("Keycloak renewal requires one exact existing scoped policy")
    token = mint_token(bao, matching[0], renew=True)
    lookup = require_data(bao.request("POST", "auth/token/lookup", {"token": token}), "policies")
    if (lookup["policies"] != [matching[0]] or type(lookup.get("ttl")) is not int
            or not MIN_VALIDITY_SECONDS <= lookup["ttl"] <= 8 * 60 * 60):
        raise RuntimeError("Keycloak renewed token has unexpected scope or lifetime")
    return token


def signing_policy() -> str:
    return "".join(
        f'path "transit/keys/keycloak-{realm}-rs256" {{ capabilities = ["read"] }}\n'
        f'path "transit/sign/keycloak-{realm}-rs256" {{ capabilities = ["update"] }}\n'
        f'path "transit/keys/keycloak-{realm}-hs512" {{ capabilities = ["read"] }}\n'
        f'path "transit/hmac/keycloak-{realm}-hs512/sha2-512" {{ capabilities = ["update"] }}\n'
        f'path "transit/verify/keycloak-{realm}-hs512/sha2-512" {{ capabilities = ["update"] }}\n'
        for realm in REALMS
    )


def jwe_policy(realm: str, purpose: str, version: str) -> str:
    if realm not in REALMS or purpose not in PURPOSES or not VERSION.fullmatch(version):
        raise ValueError("Keycloak JWE policy reference is invalid")
    key_path = f"didcomm/keycloak/keys/{realm}/{purpose}"
    return (f'path "{key_path}" {{ capabilities = ["read"] }}\n'
            f'path "didcomm/keycloak/jwe/encode/{realm}/{purpose}/{version}" '
            '{ capabilities = ["update"] }\n'
            f'path "didcomm/keycloak/jwe/decode/{realm}/{purpose}/{version}" '
            '{ capabilities = ["update"] }\n')


def require_cert_lifetime(certificate: str) -> None:
    lifetime = subprocess.run(
        ["openssl", "x509", "-checkend", str(MIN_VALIDITY_SECONDS), "-noout"],
        input=certificate.encode("ascii"), capture_output=True, timeout=10,
        check=False,
    )
    if lifetime.returncode:
        raise RuntimeError("disposable Keycloak certificate expires before tester session")


def require_mounts(bao: Bao, *, renew: bool = False) -> None:
    mounts = require_data(bao.request("GET", "sys/mounts"), "transit/")
    if (mounts["transit/"].get("type") != "transit"
            or mounts.get("didcomm/", {}).get("type") != "openbao-didcomm-authcrypt"
            or ("keycloak-pki/" in mounts) == (not renew)
            or (renew and mounts.get("keycloak-pki/", {}).get("type") != "pki")):
        raise RuntimeError("disposable OpenBao lacks the reviewed Keycloak mounts")


def provision(bao: Bao, *, renew: bool = False) -> dict[str, str]:
    """Return exactly seven public certificates/scoped tokens, not private keys."""
    if renew:
        require_renewal_authority(bao)
    require_mounts(bao, renew=renew)
    if renew:
        role = require_data(bao.request("GET", "keycloak-pki/roles/rs256"), "key_type")
        if (role["key_type"] != "rsa" or role.get("key_bits") != 2048
                or role.get("allow_any_name") is not True
                or role.get("max_ttl") != 8 * 60 * 60):
            raise RuntimeError("Keycloak renewal PKI role changed")
        ca = require_data(bao.request("GET", "keycloak-pki/cert/ca"), "certificate")
        require_cert_lifetime(ca["certificate"])
    else:
        bao.request("POST", "sys/mounts/keycloak-pki", {"type": "pki"})
        ca = require_data(bao.request("POST", "keycloak-pki/root/generate/internal", {
            "common_name": "Marty disposable Keycloak CA", "ttl": "24h",
            "key_type": "ec", "key_bits": 256,
        }), "certificate")
        if "private_key" in ca:
            raise RuntimeError("disposable Keycloak PKI exported its CA key")
        bao.request("POST", "keycloak-pki/roles/rs256", {
            "allow_any_name": True, "key_type": "rsa", "key_bits": 2048,
            "max_ttl": SESSION_TTL, "use_csr_common_name": False, "use_csr_sans": False,
        })
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
        signed = require_data(bao.request("POST", "keycloak-pki/sign/rs256", {
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
        # OpenSSL only receives public data. Verify the mounted certificate is
        # bound to the non-exportable Transit version that Keycloak will sign.
        if certificate_public_key_der(certificate) != public_key_der(public_key):
            raise RuntimeError("disposable Keycloak RS256 certificate key differs")
        outputs[f"keycloak_{realm}_rs256_cert"] = certificate
    nonce = secrets.token_hex(6)
    signing_token = (renewed_token(bao, signing_policy(), "selfhost-keycloak-sign-") if renew
                     else scoped_token(bao, signing_policy(), f"selfhost-keycloak-sign-{nonce}"))
    for realm in REALMS:
        signed = bao.request("POST", f"transit/sign/keycloak-{realm}-rs256", {
            "input": base64.b64encode(b"selfhost-keycloak-probe").decode("ascii"),
            "hash_algorithm": "sha2-256", "signature_algorithm": "pkcs1v15",
        }, token=signing_token)
        if not require_data(signed, "signature").get("signature"):
            raise RuntimeError("disposable Keycloak RS256 token cannot sign")
    outputs["keycloak_signing_kms_token"] = signing_token
    if not renew:
        bao.request("POST", "transit/keys/foreign-keycloak-selfhost", {
            "type": "rsa-2048", "exportable": False, "allow_plaintext_backup": False,
        })
    for realm in REALMS:
        for purpose in PURPOSES:
            key_path = f"didcomm/keycloak/keys/{realm}/{purpose}"
            if not renew:
                bao.request("POST", key_path, {})
            current = require_data(bao.request("GET", key_path), "version")
            version = current["version"]
            if not isinstance(version, str) or not VERSION.fullmatch(version):
                raise RuntimeError("disposable Keycloak JWE version is invalid")
            policy = jwe_policy(realm, purpose, version)
            prefix = f"selfhost-keycloak-{realm}-{purpose}-"
            token = (renewed_token(bao, policy, prefix) if renew
                     else scoped_token(bao, policy, f"{prefix}{nonce}"))
            if require_data(bao.request("GET", key_path, token=token), "version")["version"] != version:
                raise RuntimeError("disposable Keycloak JWE token cannot read its key")
            outputs[f"keycloak_{realm}_{purpose}_token"] = token
    if set(outputs) != OUTPUTS or len(set(outputs[name] for name in outputs if name.endswith("_token"))) != 5:
        raise RuntimeError("disposable Keycloak output contract is incomplete")
    for token_name in sorted(name for name in outputs if name.endswith("_token")):
        token = outputs[token_name]
        for forbidden in ("transit/keys/foreign-keycloak-selfhost",):
            try:
                bao.request("GET", forbidden, token=token)
            except HTTPError as error:
                if error.code != 403:
                    raise RuntimeError("disposable Keycloak foreign-key denial changed") from error
            else:
                raise RuntimeError("disposable Keycloak token crossed its scope")
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
        token_file = Path(os.environ[
            "BAO_RENEWAL_TOKEN_FILE" if mode == "renew" else "BAO_ROOT_TOKEN_FILE"
        ])
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
        write_outputs(root, provision(KeycloakBao(endpoint, ca, token), renew=renewing),
                      staged=renewing)
    except (KeyError, OSError, ValueError, RuntimeError, HTTPError, URLError,
            HTTPException) as error:
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"disposable Keycloak provisioning failed: {detail}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
