"""Complete secret generations preserve static inputs and reject unsafe overlays."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from passport_remote_tls import SELFHOST_TLS_FILES  # noqa: E402
from provision_selfhost_disposable_tls import KEY_METADATA_FILE, KEY_NAMES  # noqa: E402
from provision_selfhost_keycloak_kms import OUTPUTS as KEYCLOAK_OUTPUTS  # noqa: E402
from stage_selfhost_renewed_secrets import public_trust_overlap, stage, verify_generations  # noqa: E402


OLD_CA = b"-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----\n"
NEW_CA = b"-----BEGIN CERTIFICATE-----\nTkVX\n-----END CERTIFICATE-----\n"


def test_public_trust_overlap_accepts_exactly_two_distinct_public_certs() -> None:
    assert public_trust_overlap(OLD_CA, NEW_CA) == OLD_CA + NEW_CA
    for invalid in (OLD_CA, OLD_CA + NEW_CA, b"-----BEGIN PRIVATE KEY-----\nYWJj\n"):
        with pytest.raises(ValueError, match="two distinct single public certificates"):
            public_trust_overlap(OLD_CA, invalid)


def test_assembly_ships_with_its_shared_producers() -> None:
    root = Path(__file__).resolve().parents[1]
    assets = set(json.loads((root / "deploy-config/bundles/selfhost.json").read_text())
                 ["assets"])
    assert {
        "scripts/stage_selfhost_renewed_secrets.py",
        "scripts/activate_selfhost_renewed_secrets.py",
        "scripts/passport_remote_tls.py",
        "scripts/provision_selfhost_disposable_tls.py",
        "scripts/provision_selfhost_keycloak_kms.py",
    } <= assets


@pytest.fixture
def generation(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    roots = tuple(tmp_path / name for name in ("current", "tls", "keycloak", "output"))
    for root in roots:
        root.mkdir(mode=0o700)
    current, tls, keycloak, _ = roots
    for name in sorted(SELFHOST_TLS_FILES | KEYCLOAK_OUTPUTS):
        current.joinpath(name).write_text(f"old-{name}-scoped-value", encoding="ascii")
        current.joinpath(name).chmod(0o644)
    current.joinpath("optional_empty_secret").touch(mode=0o644)
    for name in SELFHOST_TLS_FILES:
        value = (f"old-{name}-scoped-value" if name == "workload_identity_ca_cert"
                 else f"new-{name}-scoped-value")
        tls.joinpath(name).write_text(value, encoding="ascii")
    for name in KEYCLOAK_OUTPUTS:
        keycloak.joinpath(name).write_text(f"new-{name}-scoped-value", encoding="ascii")
    tls.joinpath(KEY_METADATA_FILE).write_text(json.dumps({
        "schema": "marty.selfhost-disposable-tls-keys/v1",
        "roles": [{"role": role, "key_name": key, "version": 1}
                  for role, key in KEY_NAMES.items()],
    }), encoding="ascii")
    return roots


@pytest.mark.skipif(os.name != "posix", reason="POSIX secret generation contract")
def test_stage_preserves_static_inputs_and_overlays_all_renewed_files(generation) -> None:
    current, tls, keycloak, output = generation
    expected = len(SELFHOST_TLS_FILES | KEYCLOAK_OUTPUTS) + 1
    assert stage(current, tls, keycloak, output) == expected
    assert verify_generations(current, output) == (expected, len(SELFHOST_TLS_FILES | KEYCLOAK_OUTPUTS) - 1)
    assert len(list(output.iterdir())) == expected
    assert output.joinpath("optional_empty_secret").read_bytes() == b""
    assert output.joinpath("workload_identity_ca_cert").read_bytes() == (
        current / "workload_identity_ca_cert").read_bytes()
    for name in SELFHOST_TLS_FILES - {"workload_identity_ca_cert"}:
        assert output.joinpath(name).read_bytes() == tls.joinpath(name).read_bytes()
    for name in KEYCLOAK_OUTPUTS:
        assert output.joinpath(name).read_bytes() == keycloak.joinpath(name).read_bytes()
    assert {p.stat().st_mode & 0o777 for p in output.iterdir()} == {0o644}


@pytest.mark.skipif(os.name != "posix", reason="POSIX secret generation contract")
def test_stage_rejects_ca_change_without_partial_output(generation) -> None:
    current, tls, keycloak, output = generation
    tls.joinpath("workload_identity_ca_cert").write_text("different-ca", encoding="ascii")
    with pytest.raises(ValueError, match="trust-overlap"):
        stage(current, tls, keycloak, output)
    assert list(output.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX secret generation contract")
def test_stage_ca_overlap_keeps_old_trust_and_adds_exact_new_issuer(generation) -> None:
    current, tls, keycloak, output = generation
    (current / "workload_identity_ca_cert").write_bytes(OLD_CA)
    (tls / "workload_identity_ca_cert").write_bytes(NEW_CA)
    count = stage(current, tls, keycloak, output, ca_overlap=True)
    assert (output / "workload_identity_ca_cert").read_bytes() == OLD_CA + NEW_CA
    assert verify_generations(current, output, ca_overlap=True) == (
        count, len(SELFHOST_TLS_FILES | KEYCLOAK_OUTPUTS))
    with pytest.raises(ValueError, match="wrong input"):
        verify_generations(current, output)
    (output / "workload_identity_ca_cert").write_bytes(NEW_CA + OLD_CA)
    with pytest.raises(ValueError, match="old and new public issuers"):
        verify_generations(current, output, ca_overlap=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX secret generation contract")
def test_stage_rejects_symlink_and_reused_token(generation) -> None:
    current, tls, keycloak, output = generation
    token = tls / "org_tls_kms_token"
    token.unlink()
    token.symlink_to(current / "org_tls_kms_token")
    with pytest.raises(ValueError, match="non-regular"):
        stage(current, tls, keycloak, output)
    token.unlink()
    token.write_text((current / "org_tls_kms_token").read_text(), encoding="ascii")
    with pytest.raises(ValueError, match="did not change"):
        stage(current, tls, keycloak, output)
    assert list(output.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX secret generation contract")
def test_activation_pair_rejects_static_value_and_mode_changes(generation) -> None:
    current, tls, keycloak, output = generation
    stage(current, tls, keycloak, output)
    static = output / "optional_empty_secret"
    static.write_text("unexpected", encoding="ascii")
    with pytest.raises(ValueError, match="wrong input"):
        verify_generations(current, output)
    static.write_bytes(b"")
    static.chmod(0o600)
    with pytest.raises(ValueError, match="file mode"):
        verify_generations(current, output)
