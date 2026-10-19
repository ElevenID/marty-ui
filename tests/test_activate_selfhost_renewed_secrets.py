"""Activation changes only an owned KMS-only project and restores it on failure."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import activate_selfhost_renewed_secrets as activation  # noqa: E402


def test_health_requires_all_expected_roles_and_zero_exit_jobs() -> None:
    states = [
        {"Service": "keycloak", "State": "running", "Health": "healthy"},
        {"Service": "db-migrate", "State": "exited", "ExitCode": 0},
    ]
    assert activation.healthy(states, {"keycloak", "db-migrate"})
    assert not activation.healthy(states, {"keycloak"})
    states[1]["ExitCode"] = 1
    assert not activation.healthy(states, {"keycloak", "db-migrate"})
    states[1]["ExitCode"] = 0
    states[0] = {"Service": "keycloak", "State": "exited", "ExitCode": 0}
    assert not activation.healthy(states, {"keycloak", "db-migrate"})


def test_owned_service_closure_only_omits_named_optional_edge_roles() -> None:
    running = {"keycloak", "gateway", "postgres"}
    declared = running | {"cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"}
    assert activation.owned_service_closure(declared, running)
    assert not activation.owned_service_closure(declared | {"signing-keys"}, running)
    assert not activation.owned_service_closure(declared, running | {"foreign-service"})


def test_certificate_overlap_rejects_invalid_public_certificate() -> None:
    fixture = json.loads((Path(__file__).parent / "fixtures/passport_beta_chain_public.json")
                         .read_text(encoding="utf-8"))
    activation.checked_certificate_lifetime(fixture["csca"], 3600)
    with pytest.raises(ValueError, match="outside the required validity overlap"):
        activation.checked_certificate_lifetime(fixture["csca"], 11 * 365 * 24 * 3600)
    with pytest.raises(ValueError, match="validity is invalid"):
        activation.checked_certificate_lifetime("not a certificate", 3600)


def test_activation_rejects_leaf_tokens_still_dependent_on_bootstrap_root(
    tmp_path: Path,
) -> None:
    token_name = sorted(activation.RENEWED_TOKEN_FILES)[0]
    (tmp_path / token_name).write_text("scoped-token")

    class RootChildBao:
        def request(self, method, path, body=None, *, token=None):
            assert (method, path) == ("POST", "auth/token/lookup")
            return {"data": {"policies": ["selfhost-exact-policy"],
                             "ttl": 7200, "orphan": False,
                             "path": "auth/token/create/selfhost-renew-leaf"}}

    with pytest.raises(ValueError, match="depends on bootstrap root"):
        activation.checked_tokens(RootChildBao(), tmp_path, tmp_path, 3600,
                                  require_orphan_new=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX activation contract")
def test_env_pair_changes_only_generation_path(tmp_path: Path) -> None:
    old, new = tmp_path / "old", tmp_path / "new"
    for root in (old, new):
        root.mkdir()
    old_env, new_env = tmp_path / "old.env", tmp_path / "new.env"
    old_env.write_text(f"SELFHOST_SECRET_DIR={old}\nKEY_NAME=version-one\n")
    new_env.write_text(f"SELFHOST_SECRET_DIR={new}\nKEY_NAME=version-one\n")
    old_env.chmod(0o600)
    new_env.chmod(0o600)
    assert activation.checked_env(old_env, old) == activation.checked_env(new_env, new)
    new_env.write_text(f"SELFHOST_SECRET_DIR={new}\nKEY_NAME=version-two\n")
    assert activation.checked_env(old_env, old) != activation.checked_env(new_env, new)


@pytest.mark.skipif(os.name != "posix", reason="POSIX activation contract")
def test_failed_activation_recreates_prior_kms_only_generation(tmp_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    project = "marty-selfhost-qual-0badcafedeadbeef"
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    new.mkdir()
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services: {}\n")
    ca = tmp_path / "ca.crt"
    ca.write_text("public CA")
    log_dir = tmp_path / "logs"
    log_dir.mkdir(mode=0o700)
    args = argparse.Namespace(
        project_name=project, compose_file=compose,
        current_env=tmp_path / "old.env", renewed_env=tmp_path / "new.env",
        current_secrets=old, renewed_secrets=new, bao_addr="https://127.0.0.1:8200",
        bao_ca=ca, bao_token_file=tmp_path / "operator.token",
        minimum_token_ttl=3600, log_dir=log_dir, report=log_dir / "result.json",
    )
    monkeypatch.setattr(activation, "verify_generations", lambda *_: (81, 39))
    monkeypatch.setattr(activation, "checked_env", lambda *_: ["KEY_NAME=version-one"])
    monkeypatch.setattr(activation, "private_file", lambda *_: "operator-token-long-enough")
    monkeypatch.setattr(activation, "Bao", lambda *_: object())
    monkeypatch.setattr(activation, "require_renewal_authority", lambda *_: None)
    monkeypatch.setattr(activation, "checked_tokens", lambda *_, **__: None)
    monkeypatch.setattr(activation, "checked_certificates", lambda *_: None)
    old_model = {"services": {name: {} for name in
                            ("keycloak", "gateway", "signing-keys", "postgres")},
                 "secrets": {"sample": {"file": str(old / "sample")}}}
    new_model = json.loads(json.dumps(old_model))
    new_model["secrets"]["sample"]["file"] = str(new / "sample")
    monkeypatch.setattr(activation, "run_json", lambda cmd, **_: (
        new_model if str(args.renewed_env) in cmd else old_model))
    states = [{"Service": name, "State": "running", "Health": "healthy"}
              for name in old_model["services"]]
    monkeypatch.setattr(activation, "statuses", lambda *_cmd, **_kw: states)
    monkeypatch.setattr(activation, "secret_mounts", lambda *_: 184)
    calls = []

    def recreate(command, services, **_):
        calls.append(command)
        if str(args.renewed_env) in command:
            raise RuntimeError("controlled new-generation failure")
        return states

    monkeypatch.setattr(activation, "recreate", recreate)
    with pytest.raises(RuntimeError, match="prior KMS-only generation restored"):
        activation.activate(args)
    assert len(calls) == 2
    assert str(args.renewed_env) in calls[0]
    assert str(args.current_env) in calls[1]
    assert json.loads(args.report.read_text())["result"] == "rolled_back"
