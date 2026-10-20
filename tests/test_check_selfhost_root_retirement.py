"""The retirement audit must reject a root-dependent rollback before any cutover."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_selfhost_root_retirement as retirement  # noqa: E402
from stage_selfhost_renewed_secrets import RENEWED_TOKEN_FILES  # noqa: E402


def test_retirement_token_inventory_covers_default_compose_services() -> None:
    root = Path(__file__).resolve().parents[1]
    model = yaml.safe_load((root / "docker-compose.selfhost.prod.yml").read_text())
    mounted = set()
    for name, service in model["services"].items():
        if name == "kms-initialize":
            continue
        mounted.update(secret if isinstance(secret, str) else secret["source"]
                       for secret in service.get("secrets", []))
    kms_tokens = {
        name for name in mounted
        if name.endswith("_token") and (
            "openbao" in name or name.startswith("haip_")
            or name.startswith("sign_grant_") or name in RENEWED_TOKEN_FILES
        )
    }
    assert kms_tokens == set(retirement.STATIC_KMS_TOKENS) | RENEWED_TOKEN_FILES


@pytest.mark.skipif(os.name != "posix", reason="POSIX operator preflight")
def test_rollback_root_child_stops_retirement_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    compose = tmp_path / "compose.yml"
    ca = tmp_path / "ca.crt"
    compose.write_text("services: {}", encoding="ascii")
    ca.write_text("public CA", encoding="ascii")
    args = argparse.Namespace(
        project_name="marty-selfhost-retirement-probe", minimum_token_ttl=3600,
        compose_file=compose, compose_override=None,
        bao_ca=ca, bao_addr="https://127.0.0.1:8200",
        rollback_secrets=tmp_path / "rollback", active_secrets=tmp_path / "active",
        rollback_env=tmp_path / "rollback.env", active_env=tmp_path / "active.env",
        renewal_identity=tmp_path / "renewal",
        ca_rotation_identity=tmp_path / "ca-rotation",
        snapshot_identity=tmp_path / "snapshot",
        evidence_identity=tmp_path / "evidence", audit_identity=tmp_path / "audit",
        snapshot_rotator_identity=tmp_path / "snapshot-rotator",
        audit_org_id="00000000-0000-0000-0000-000000000001",
        audit_org_slug="marty", audit_did="did:web:localhost:orgs:marty",
        openbao_state_dir=tmp_path / "state", snapshot_export_dir=tmp_path / "exports",
        openbao_config=tmp_path / "openbao.hcl",
    )
    monkeypatch.setattr(retirement, "verify_generations", lambda *_args: (81, 39))
    monkeypatch.setattr(retirement, "checked_env", lambda *_args: ["KEY=value"])
    monkeypatch.setattr(retirement, "Bao", lambda *_args: object())
    monkeypatch.setattr(retirement, "renewal_login",
                        lambda *_args: ("role", "secret", [], "scoped-token"))
    monkeypatch.setattr(retirement, "ca_rotation_login", lambda *_args: "ca-token")
    monkeypatch.setattr(retirement, "require_renewal_authority", lambda *_args: None)

    def reject_child(_bao, old, new, ttl, *, require_orphan_old, require_orphan_new):
        assert (old, new, ttl) == (args.rollback_secrets, args.active_secrets, 3600)
        assert require_orphan_old is True and require_orphan_new is True
        raise ValueError("renewed OpenBao token still depends on bootstrap root")

    monkeypatch.setattr(retirement, "checked_tokens", reject_child)
    with pytest.raises(ValueError, match="depends on bootstrap root"):
        retirement.audit(args)


def test_static_service_token_must_be_orphaned(tmp_path: Path) -> None:
    name, policies = next(iter(retirement.STATIC_KMS_TOKENS.items()))
    (tmp_path / name).write_text("synthetic-root-child-token-value", encoding="ascii")

    class RootChildBao:
        def request(self, method, path, body=None, *, token=None):
            assert (method, path) == ("POST", "auth/token/lookup")
            return {"data": {"policies": sorted(policies), "ttl": 7200,
                             "orphan": False}}

    with pytest.raises(ValueError, match="still depends on root"):
        retirement.checked_static_tokens(RootChildBao(), tmp_path, 3600)


def test_static_service_token_cannot_gain_root_or_private_key_authority(
    tmp_path: Path,
) -> None:
    for name in retirement.STATIC_KMS_TOKENS:
        (tmp_path / name).write_text(f"synthetic-{name}-token-value", encoding="ascii")

    class PrivilegedBao:
        def request(self, method, path, body=None, *, token=None):
            if path == "auth/token/lookup":
                name = next(name for name in retirement.STATIC_KMS_TOKENS
                            if body["token"] == f"synthetic-{name}-token-value")
                return {"data": {"policies": sorted(retirement.STATIC_KMS_TOKENS[name]),
                                 "ttl": 7200, "orphan": True}}
            assert (method, path) == ("POST", "sys/capabilities")
            assert body["token"] == f"synthetic-{next(iter(retirement.STATIC_KMS_TOKENS))}-token-value"
            return {"data": {name: (["update"] if name == "auth/token/create"
                                    else ["deny"]) for name in body["paths"]}}

    with pytest.raises(ValueError, match="privileged or private-key authority"):
        retirement.checked_static_tokens(PrivilegedBao(), tmp_path, 3600)


@pytest.mark.parametrize("include_recovery", [False, True])
def test_snapshot_preflight_accepts_only_secret_free_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, include_recovery: bool,
) -> None:
    args = argparse.Namespace(
        snapshot_export_dir=tmp_path, openbao_state_dir=tmp_path / "state",
        openbao_config=tmp_path / "openbao.hcl",
        bao_addr="https://127.0.0.1:8200", snapshot_identity=tmp_path / "identity",
    )
    snapshot = b"synthetic encrypted snapshot"

    def fake_export(*_args, **_kwargs):
        archive = tmp_path / "openbao-raft-synthetic.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("raft.snap", snapshot)
            bundle.writestr("openbao-selfhost.hcl", 'storage "raft" {}')
            bundle.writestr("manifest.json", json.dumps({
                "format": "marty-openbao-raft-snapshot-v2",
                "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
            }))
            if include_recovery:
                bundle.writestr("recovery/root.token", "forbidden")
        return argparse.Namespace(returncode=0)

    monkeypatch.setattr(retirement.subprocess, "run", fake_export)
    if include_recovery:
        with pytest.raises(ValueError, match="unexpected files"):
            retirement.export_current_snapshot(args)
    else:
        assert retirement.export_current_snapshot(args).name == "openbao-raft-synthetic.zip"
