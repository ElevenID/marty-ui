"""Activation changes only an owned KMS-only project and restores it on failure."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import activate_selfhost_renewed_secrets as activation  # noqa: E402


def test_compose_override_is_part_of_both_generation_commands(tmp_path: Path) -> None:
    compose = tmp_path / "compose.yml"
    override = tmp_path / "network.yml"
    env = tmp_path / "generation.env"
    command = activation.compose_args("owned-project", env, compose, override)
    assert command[-4:] == ["-f", str(compose), "-f", str(override)]
    assert activation.compose_args("owned-project", env, compose) == command[:-2]


def test_health_requires_all_expected_roles_and_zero_exit_jobs() -> None:
    model = {"services": {"keycloak": {"healthcheck": {"test": ["CMD", "true"]}},
                          "db-migrate": {}}}
    states = [
        {"Service": "keycloak", "State": "running", "Health": "healthy"},
        {"Service": "db-migrate", "State": "exited", "ExitCode": 0},
    ]
    assert activation.healthy(states, {"keycloak", "db-migrate"}, model)
    assert not activation.healthy(states, {"keycloak"}, model)
    states[1]["ExitCode"] = 1
    assert not activation.healthy(states, {"keycloak", "db-migrate"}, model)
    states[1]["ExitCode"] = 0
    states[0] = {"Service": "keycloak", "State": "exited", "ExitCode": 0}
    assert not activation.healthy(states, {"keycloak", "db-migrate"}, model)


def test_health_rejects_missing_declared_check_and_accepts_disabled_check() -> None:
    model = {"services": {"gateway": {"healthcheck": {"test": ["CMD", "true"]}},
                          "canvas-sync-worker": {"healthcheck": {"disable": True}}}}
    states = [{"Service": "gateway", "State": "running", "Health": ""},
              {"Service": "canvas-sync-worker", "State": "running", "Health": ""}]
    services = {"gateway", "canvas-sync-worker"}
    assert not activation.healthy(states, services, model)
    states[0]["Health"] = "healthy"
    assert activation.healthy(states, services, model)
    states[1]["Health"] = "healthy"
    assert not activation.healthy(states, services, model)


def test_owned_service_closure_only_omits_named_optional_edge_roles() -> None:
    running = {"keycloak", "gateway", "postgres"}
    declared = running | {"cloudflared", "cloudflared-beta", "tunnel-nginx-proxy",
                          "kms-initialize"}
    assert activation.owned_service_closure(declared, running)
    assert not activation.owned_service_closure(declared | {"signing-keys"}, running)
    assert not activation.owned_service_closure(declared, running | {"foreign-service"})


def test_activation_requires_rootless_db_migration_model() -> None:
    model = {"services": {"db-migrate": {
        "environment": {"MARTY_KMS_BOOTSTRAP_ENABLED": "false"}, "secrets": []},
        "kms-initialize": {"profiles": ["kms-init"]}}}
    activation.require_rootless_migration(model)
    model["services"]["db-migrate"]["secrets"] = ["openbao_bootstrap_token"]
    with pytest.raises(ValueError, match="must not mount bootstrap token"):
        activation.require_rootless_migration(model)
    model["services"]["db-migrate"]["secrets"] = []
    model["services"]["db-migrate"]["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"] = "true"
    with pytest.raises(ValueError, match="must not rerun KMS bootstrap"):
        activation.require_rootless_migration(model)
    with pytest.raises(ValueError, match="must not rerun KMS bootstrap"):
        activation.require_rootless_migration({"services": {}})


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


def test_root_retirement_rejects_root_child_in_rollback_generation(
    tmp_path: Path,
) -> None:
    token_name = sorted(activation.RENEWED_TOKEN_FILES)[0]
    rollback, active = tmp_path / "rollback", tmp_path / "active"
    rollback.mkdir()
    active.mkdir()
    (rollback / token_name).write_text("root-child-token", encoding="ascii")

    class RootChildBao:
        def request(self, method, path, body=None, *, token=None):
            assert (method, path, body) == (
                "POST", "auth/token/lookup", {"token": "root-child-token"},
            )
            return {"data": {"policies": ["selfhost-exact-policy"],
                             "ttl": 7200, "orphan": False,
                             "path": "auth/token/create/selfhost-renew-leaf"}}

    with pytest.raises(ValueError, match="depends on bootstrap root"):
        activation.checked_tokens(RootChildBao(), rollback, active, 3600,
                                  require_orphan_new=True, require_orphan_old=True)


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


def test_secret_mounts_require_exact_read_only_generation_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "generation"
    names = sorted(activation.RENEWED_TOKEN_FILES)
    mounts = [{"Destination": f"/run/secrets/{name}", "Type": "bind",
               "Source": str(root / name), "RW": False}
              for name in names]
    alias = {"Destination": "/run/secrets/renamed.token", "Type": "bind",
             "Source": str(root / names[0]), "RW": False}
    project = "marty-selfhost-probe"
    model = {"secrets": {name: {"file": str(root / name)} for name in names},
             "services": {
                 "gateway": {"secrets": [{"source": name,
                                          "target": f"/run/secrets/{name}"}
                                         for name in names]},
                 "auth": {"secrets": [{"source": names[0],
                                      "target": alias["Destination"]}]}}}
    inspected = [
        {"Config": {"Labels": {"com.docker.compose.project": project,
                               "com.docker.compose.service": service}},
         "Mounts": service_mounts}
        for service, service_mounts in (("gateway", mounts), ("auth", [alias]))
    ]
    monkeypatch.setattr(activation.subprocess, "run", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, "a" * 12 + "\n" + "b" * 12, ""))
    monkeypatch.setattr(activation, "run_json", lambda *_args, **_kwargs: inspected)
    assert activation.secret_mounts(project, root, {"gateway", "auth"}, model) == len(names) + 1

    for changed in (
        lambda entries: entries[0]["Mounts"][0].update(
            Source=str(root / names[1])),
        lambda entries: entries[0]["Mounts"][0].update(RW=True),
        lambda entries: entries[0]["Mounts"].pop(),
        lambda entries: entries[1]["Mounts"][0].update(
            Source=str(root / names[1])),
    ):
        broken = deepcopy(inspected)
        changed(broken)
        monkeypatch.setattr(activation, "run_json", lambda *_args, **_kwargs: broken)
        with pytest.raises(RuntimeError, match="secret mount|token mounts"):
            activation.secret_mounts(project, root, {"gateway", "auth"}, model)

    monkeypatch.setattr(activation, "run_json", lambda *_args, **_kwargs:
                        [{**inspected[0], "Mounts": "invalid"}, inspected[1]])
    with pytest.raises(RuntimeError, match="project mounts are invalid"):
        activation.secret_mounts(project, root, {"gateway", "auth"}, model)


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
        project_name=project, compose_file=compose, compose_override=None,
        current_env=tmp_path / "old.env", renewed_env=tmp_path / "new.env",
        current_secrets=old, renewed_secrets=new, bao_addr="https://127.0.0.1:8200",
        bao_ca=ca, bao_token_file=tmp_path / "operator.token",
        minimum_token_ttl=3600, log_dir=log_dir, report=log_dir / "result.json",
    )
    monkeypatch.setattr(activation, "verify_generations", lambda *_, **__: (81, 39))
    monkeypatch.setattr(activation, "checked_env", lambda *_: ["KEY_NAME=version-one"])
    monkeypatch.setattr(activation, "checked_compose_secret_files", lambda *_: None)
    monkeypatch.setattr(activation, "private_file", lambda *_: "operator-token-long-enough")
    monkeypatch.setattr(activation, "Bao", lambda *_: object())
    monkeypatch.setattr(activation, "require_renewal_authority", lambda *_: None)
    monkeypatch.setattr(activation, "checked_tokens", lambda *_, **__: None)
    monkeypatch.setattr(activation, "checked_certificates", lambda *_: None)
    old_model = {"services": {name: {"healthcheck": {"test": ["CMD", "true"]}} for name in
                            ("keycloak", "gateway", "signing-keys", "postgres")},
                 "secrets": {"sample": {"file": str(old / "sample")}}}
    old_model["services"]["db-migrate"] = {
        "environment": {"MARTY_KMS_BOOTSTRAP_ENABLED": "false"}, "secrets": []}
    old_model["services"]["kms-initialize"] = {"profiles": ["kms-init"]}
    new_model = json.loads(json.dumps(old_model))
    new_model["secrets"]["sample"]["file"] = str(new / "sample")
    monkeypatch.setattr(activation, "run_json", lambda cmd, **_: (
        new_model if str(args.renewed_env) in cmd else old_model))
    states = [{"Service": name, "State": "running", "Health": "healthy"}
              for name in old_model["services"] if name not in {"db-migrate", "kms-initialize"}]
    states.append({"Service": "db-migrate", "State": "exited", "ExitCode": 0})
    monkeypatch.setattr(activation, "statuses", lambda *_cmd, **_kw: states)
    monkeypatch.setattr(activation, "secret_mounts", lambda *_: 184)
    calls = []

    def recreate(command, services, model, **_):
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


def test_ca_overlap_certificate_preflight_binds_each_generation_to_its_issuer(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    new.mkdir()
    old_workload = "-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----\n"
    new_workload = "-----BEGIN CERTIFICATE-----\nTkVX\n-----END CERTIFICATE-----\n"
    old_keycloak, new_keycloak = "old-keycloak-issuer", "new-keycloak-issuer"
    (old / "workload_identity_ca_cert").write_text(old_workload)
    (new / "workload_identity_ca_cert").write_text(old_workload + new_workload)
    for root in (old, new):
        for cert_name in activation.TLS_CERT_BY_ROLE.values():
            (root / cert_name).write_text(f"{root.name}-{cert_name}")
        for realm in activation.REALMS:
            (root / f"keycloak_{realm}_rs256_cert").write_text(f"{root.name}-{realm}")

    class FakeBao:
        def __init__(self, *, replacement: bool = False):
            self.replacement = replacement

        def request(self, method, path):
            assert method == "GET"
            if path.endswith("/cert/ca"):
                assert path in ({"workload-pki-v5/cert/ca", "keycloak-pki-v5/cert/ca"}
                                if self.replacement else
                                {"workload-pki/cert/ca", "keycloak-pki/cert/ca"})
                return {"data": {"certificate": (
                    new_workload if "workload" in path else new_keycloak)
                    if self.replacement else (
                    old_workload if "workload" in path else old_keycloak)}}
            assert not self.replacement and path.startswith("transit/keys/")
            return {"data": {"type": "rsa-2048" if "keycloak-" in path else "ecdsa-p256",
                             "exportable": False, "allow_plaintext_backup": False,
                             "latest_version": 1, "keys": {"1": {"public_key": "public"}}}}

    chains = []
    monkeypatch.setattr(activation, "checked_certificate_lifetime", lambda *_: None)
    monkeypatch.setattr(activation, "checked_certificate_chain",
                        lambda path, issuer: chains.append((path.parent.name, issuer)))
    monkeypatch.setattr(activation, "certificate_public_key_der", lambda *_: b"public")
    monkeypatch.setattr(activation, "public_key_der", lambda *_: b"public")
    primary, ca = FakeBao(), FakeBao(replacement=True)
    activation.checked_certificates(primary, old, new, 3600,
                                    replacement=(ca, "workload-pki-v5", "keycloak-pki-v5"))
    assert chains.count(("old", old_workload)) == len(activation.TLS_CERT_BY_ROLE)
    assert chains.count(("new", new_workload)) == len(activation.TLS_CERT_BY_ROLE)
    assert chains.count(("old", old_keycloak)) == len(activation.REALMS)
    assert chains.count(("new", new_keycloak)) == len(activation.REALMS)
    (new / "workload_identity_ca_cert").write_text(new_workload + old_workload)
    with pytest.raises(ValueError, match="mounted trust anchor"):
        activation.checked_certificates(primary, old, new, 3600,
                                        replacement=(ca, "workload-pki-v5", "keycloak-pki-v5"))

    class ReusedKeycloakIssuer(FakeBao):
        def request(self, method, path):
            if path == "keycloak-pki-v5/cert/ca":
                return {"data": {"certificate": old_keycloak}}
            return super().request(method, path)

    with pytest.raises(ValueError, match="Keycloak issuer did not change"):
        activation.checked_certificates(primary, old, new, 3600,
                                        replacement=(ReusedKeycloakIssuer(replacement=True),
                                                     "workload-pki-v5", "keycloak-pki-v5"))


def test_compose_secret_preflight_requires_all_rendered_files(tmp_path: Path) -> None:
    root = tmp_path / "generation"
    root.mkdir()
    (root / "workload_identity_ca_cert").write_text("public certificate")
    model = {"secrets": {
        "workload_identity_ca_cert": {"file": str(root / "workload_identity_ca_cert")},
        "cloudflare_tunnel_token": {"file": str(root / "cloudflare_tunnel_token")},
    }}
    with pytest.raises(ValueError, match="missing from the generation"):
        activation.checked_compose_secret_files(model, root)
    (root / "cloudflare_tunnel_token").write_text("disposable test value")
    activation.checked_compose_secret_files(model, root)
    model["secrets"]["cloudflare_tunnel_token"]["file"] = str(tmp_path / "elsewhere")
    with pytest.raises(ValueError, match="binding is invalid"):
        activation.checked_compose_secret_files(model, root)


@pytest.mark.parametrize("workload,keycloak", [
    ("workload-pki-v1", "keycloak-pki-v2"),
    ("workload-pki-v02", "keycloak-pki-v2"),
    ("workload-pki-v9", "keycloak-pki-v2"),
    ("workload-pki-v2/roles/admin", "keycloak-pki-v2"),
    ("workload-pki-v2", "keycloak-pki-v9"),
])
def test_overlap_mounts_reject_out_of_scope_paths(workload: str, keycloak: str) -> None:
    with pytest.raises(ValueError, match="outside reviewed versions"):
        activation.checked_overlap_mounts(True, workload, keycloak)
