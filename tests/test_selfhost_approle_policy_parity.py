"""Pin the six reviewed AppRole ACLs while their implementation moves to Rust."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from provision_selfhost_disposable_tls import ENV_PREFIX_ROLE, KEY_NAMES  # noqa: E402
from scripts.selfhost_native_operator import approle_policy  # noqa: E402


# SHA-256 of the exact ACL strings produced by the Python owners at
# de059147ea520b792a953ef5896981445e565e1c. The fixed 21-name input is
# sorted as the renewal and CA-rotation policy receipts are on disk. These
# values are independent of the native implementation and need no Git history
# or external service when the installed bundle runs this test.
NAMES = sorted(f"selfhost-test-policy-{index}" for index in range(21))
GOLDEN = {
    "audit": (466, "93202de9c1569b254da3f18f7b0966081c0b3b911e3026f48d9f4d0cdae8953c"),
    "evidence": (569, "7c0d3c84f46bb2464ab58c7af02fa61a851da58fccb210347c4fc112db9d6c7f"),
    "renewal": (8248, "cc52f9a05c1ddcba281998bca63c69fb963296de322861787f44d8fc0a566b1c"),
    "ca-rotation": (31592, "eda90e6376b58d79a37bf7bcbb7dcd9c4c47229abaae152703fd724decebc2f7"),
    "snapshot": (60, "bf00f28128327440706c81402b5abdf44a9ae69964b18cbf28f6a6116b873af6"),
    "snapshot-rotator": (636, "678578cc57677f7bb74ee989ad5c75be5d678a4c8d2425057cbb3de5fbc0d45a"),
}


@pytest.mark.parametrize("role", GOLDEN)
def test_native_approle_policy_matches_reviewed_python_bytes(role: str) -> None:
    context = {"names": NAMES} if role in {"renewal", "ca-rotation"} else {}
    acl = approle_policy(role, **context)
    expected_length, expected_sha256 = GOLDEN[role]
    encoded = acl.encode("utf-8")
    assert len(encoded) == expected_length
    assert hashlib.sha256(encoded).hexdigest() == expected_sha256
    assert "*" not in acl
    assert "transit/export/" not in acl


def test_renewal_and_ca_rotation_keep_distinct_secret_id_authority() -> None:
    renewal = approle_policy("renewal", names=NAMES)
    ca_rotation = approle_policy("ca-rotation", names=NAMES)
    secret_id = 'path "auth/selfhost-renew/role/kms-renewer/secret-id"'
    assert secret_id in renewal
    assert secret_id not in ca_rotation
    assert 'path "sys/mounts/workload-pki-v8"' in ca_rotation
    assert 'path "sys/mounts/workload-pki-v9"' not in ca_rotation
    assert len(KEY_NAMES) == 16
    assert set(ENV_PREFIX_ROLE.values()) == set(KEY_NAMES)
    for role, key_name in KEY_NAMES.items():
        for acl in (renewal, ca_rotation):
            assert f'path "transit/keys/{key_name}"' in acl, role
            assert f'path "workload-pki/sign/{role}"' in acl, role
    for name in NAMES:
        assert f'path "sys/policies/acl/{name}"' in renewal
        assert f'path "sys/policies/acl/{name}"' in ca_rotation


def test_snapshot_reader_and_rotator_keep_disjoint_authority() -> None:
    reader = approle_policy("snapshot")
    rotator = approle_policy("snapshot-rotator")
    assert reader == 'path "sys/storage/raft/snapshot" { capabilities = ["read"] }'
    assert 'path "sys/storage/raft/snapshot"' not in rotator
    assert 'path "auth/selfhost-snapshot/role/raft-exporter/secret-id"' in rotator
    assert 'path "auth/selfhost-snapshot/role/raft-exporter-rotator/secret-id"' in rotator


@pytest.mark.parametrize("role", ["renewal", "ca-rotation"])
def test_policy_receipt_rejects_missing_or_repeated_names(role: str) -> None:
    for names in (NAMES[:-1], [*NAMES[:-1], NAMES[0]]):
        with pytest.raises(RuntimeError, match="Rust operator validation failed"):
            approle_policy(role, names=names)
