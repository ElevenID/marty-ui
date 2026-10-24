"""Guard the reviewed CA authority against mount and key-custody drift."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_ca_rotation_identity as rotation  # noqa: E402


def test_ca_policy_uses_exact_versioned_mounts_and_denies_other_authority() -> None:
    names = [f"selfhost-test-policy-{index}" for index in range(21)]
    acl = rotation.rotation_acl(names)
    for version in rotation.VERSIONS:
        for prefix in ("workload-pki", "keycloak-pki"):
            mount = f"{prefix}-v{version}"
            assert (f'path "sys/mounts/{mount}" '
                    '{ capabilities = ["create", "read", "update"] }') in acl
            assert (f'path "{mount}/root/generate/internal" '
                    '{ capabilities = ["create", "update"] }') in acl
    assert 'path "workload-pki-v2/sign/organization-server"' in acl
    assert 'path "keycloak-pki-v2/sign/rs256"' in acl
    assert ('path "sys/policies/acl/selfhost-kms-ca-rotation" '
            '{ capabilities = ["read"] }') in acl
    assert 'path "sys/mounts/workload-pki-v9"' not in acl
    assert 'path "sys/mounts/keycloak-pki-v9"' not in acl
    assert 'workload-pki-v*' not in acl
    assert 'keycloak-pki-v*' not in acl
    assert 'transit/export/' not in acl
    assert 'path "sys/mounts/*"' not in acl
    assert 'auth/selfhost-renew/role/kms-renewer/secret-id' not in acl
    bundle = json.loads((Path(__file__).resolve().parents[1] /
                         "deploy-config/bundles/selfhost.json").read_text(encoding="utf-8"))
    assert "scripts/provision_selfhost_ca_rotation_identity.py" in bundle["assets"]


def test_public_ca_certificate_verification_rejects_wrong_or_tampered_issuer() -> None:
    certificate = (Path(__file__).parent / "fixtures" /
                   "selfhost_ca_issuer_public.pem").read_text(encoding="ascii")
    rotation.checked_issuer_certificate(certificate, "workload", 2)
    with pytest.raises(RuntimeError, match="native validation"):
        rotation.checked_issuer_certificate(certificate, "keycloak", 2)
    with pytest.raises(RuntimeError, match="native validation"):
        rotation.checked_issuer_certificate(certificate + certificate, "workload", 2)

    header, encoded = certificate.split("\n", 1)
    payload, footer = encoded.split("-----END CERTIFICATE-----", 1)
    der = bytearray(base64.b64decode(payload))
    der[-1] ^= 1  # Keep the certificate parseable while invalidating its signature.
    tampered = (header + "\n" + base64.encodebytes(der).decode("ascii") +
                "-----END CERTIFICATE-----" + footer)
    with pytest.raises(RuntimeError, match="native validation"):
        rotation.checked_issuer_certificate(tampered, "workload", 2)
