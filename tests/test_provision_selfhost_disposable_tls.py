"""Disposable installed TLS staging uses reviewed digests and keyless outputs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import provision_selfhost_disposable_tls as stage  # noqa: E402
from with_disposable_event_stream_kms import (  # noqa: E402
    validate_selfhost_tls_output_inventory,
)
from generate_selfhost_disposable_credentials import GENERATED  # noqa: E402
from passport_remote_tls import (  # noqa: E402
    PUBLIC_TLS_FILES, SELFHOST_CERT_FILES, SELFHOST_TLS_FILES, accept_remote_tls,
)
from provision_selfhost_keycloak_kms import OUTPUTS as KEYCLOAK_OUTPUTS  # noqa: E402

SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
OPENBAO = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "b" * 64


@pytest.mark.parametrize("uid,mode,allowed", [
    (0, 0o400, True), (1000, 0o400, False),
    (0, 0o444, False), (0, 0o600, False),
])
def test_root_token_metadata_contract(uid: int, mode: int, allowed: bool) -> None:
    assert stage.protected_root_token_metadata(uid, mode) is allowed


def test_live_tls_contract_admits_only_verified_manifest_beside_secrets(
    tmp_path: Path,
) -> None:
    (tmp_path / "workload_identity_ca_cert").write_text("public", encoding="ascii")
    metadata = tmp_path / stage.KEY_METADATA_FILE
    metadata.write_text(json.dumps({
        "schema": "marty.selfhost-disposable-tls-keys/v1",
        "roles": [
            {"role": role, "key_name": name, "version": 1}
            for role, name in stage.KEY_NAMES.items()
        ],
    }), encoding="ascii")
    validate_selfhost_tls_output_inventory(tmp_path, {"workload_identity_ca_cert"})
    (tmp_path / "unlisted-secret").write_text("unexpected", encoding="ascii")
    with pytest.raises(RuntimeError, match="differs from the secret catalog"):
        validate_selfhost_tls_output_inventory(tmp_path, {"workload_identity_ca_cert"})
    (tmp_path / "unlisted-secret").unlink()
    metadata.write_text('{"schema":"wrong","roles":[]}', encoding="ascii")
    with pytest.raises(ValueError, match="disposable TLS key metadata"):
        validate_selfhost_tls_output_inventory(tmp_path, {"workload_identity_ca_cert"})


def test_selfhost_tls_acceptor_matches_catalog_not_passport_files() -> None:
    catalog = json.loads((ROOT / "deploy-config/catalog/secrets.json").read_text(
        encoding="utf-8"))["secrets"]
    expected = {name for name in catalog if (
        name == "workload_identity_ca_cert"
        or name.endswith("_tls_kms_token")
        or "_workload_" in name and name.endswith("_cert")
    )}
    assert SELFHOST_TLS_FILES == expected
    assert len(SELFHOST_CERT_FILES) == 17
    assert len(SELFHOST_TLS_FILES) == 33
    assert "passport_edge_tls_cert" not in SELFHOST_TLS_FILES


def test_disposable_producers_close_exact_local_secret_roster() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text(
        encoding="utf-8"))
    local_secrets = {
        entry if isinstance(entry, str) else entry["source"]
        for service, definition in compose["services"].items()
        if service not in {"cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"}
        for entry in definition.get("secrets", [])
    }
    catalog = json.loads((ROOT / "deploy-config/catalog/secrets.json").read_text(
        encoding="utf-8"))["secrets"]
    optional = {entry["compose_secret"] for entry in catalog.values()
                if entry.get("allow_empty") and entry.get("compose_secret") in local_secrets}
    openbao = {
        "openbao_tls_ca_cert", "openbao_service_token", "openbao_bootstrap_token",
        "signing_keys_openbao_token", "didcomm_issuance_openbao_token",
        "notification_openbao_token", "haip_kms_token", "sign_grant_verify_token",
    } | {
        f"sign_grant_mint_{role}_token" for role in (
            "gateway_service", "gateway_issuer_did", "flow_wallet",
            "issuance_credential", "issuance_canvas", "issuance_readiness",
            "issuance_passport",
        )
    }
    assert len(local_secrets) == 78
    assert len(optional) == 6
    assert local_secrets == GENERATED | KEYCLOAK_OUTPUTS | SELFHOST_TLS_FILES | openbao | optional


def bundle(tmp_path: Path) -> Path:
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    (bundle_root / ".marty-selfhost-images.json").write_text(json.dumps({
        "schema": "marty.selfhost-image-lock/v1",
        "services": {"gateway": SERVICES, "signing-keys": SERVICES},
        "openbao_didcomm_image": OPENBAO,
    }), encoding="utf-8")
    (bundle_root / ".env.selfhost.production.example").write_bytes(
        (ROOT / ".env.selfhost.production.example").read_bytes())
    (bundle_root / "docker-compose.yml").write_bytes(
        (ROOT / "docker-compose.selfhost.prod.yml").read_bytes())
    return bundle_root


def key_metadata() -> dict[str, object]:
    return {
        "schema": "marty.selfhost-disposable-tls-keys/v1",
        "roles": [
            {"role": role, "key_name": name, "version": 1}
            for role, name in stage.KEY_NAMES.items()
        ],
    }


def test_tls_env_fragment_is_exact_and_drift_fails_closed(tmp_path: Path) -> None:
    root = bundle(tmp_path)
    fragment = stage.render_tls_env_fragment(root, key_metadata())
    lines = fragment.splitlines()
    assert len(lines) == 32
    assert len(set(lines)) == 32
    assert "GATEWAY_TLS_KMS_KEY_NAME=workload-tls-gateway-auth-client" in lines
    assert "GATEWAY_TLS_KMS_KEY_VERSION=1" in lines
    assert all("_TLS_KMS_KEY_NAME=" in line or "_TLS_KMS_KEY_VERSION=" in line
               for line in lines)
    assert not any(token in fragment for token in ("_ADDR=", "DOMAIN=", "DID=", "TOKEN="))

    example = root / ".env.selfhost.production.example"
    compose = root / "docker-compose.yml"
    original_example = example.read_text(encoding="ascii")
    original_compose = compose.read_text(encoding="ascii")
    compose.write_text(original_compose.replace(
        "GATEWAY_TLS_KMS_KEY_NAME:-}", "GATEWAY_TLS_KMS_KEY_NAME:?required}"
    ), encoding="ascii")
    assert stage.render_tls_env_fragment(root, key_metadata()) == fragment
    compose.write_text(original_compose, encoding="ascii")
    mutations = (
        (example, original_example + "\nGATEWAY_TLS_KMS_KEY_NAME=duplicate\n"),
        (example, original_example.replace("GATEWAY_TLS_KMS_KEY_VERSION=1",
                                           "GATEWAY_TLS_KMS_KEY_VERSION=2")),
        (example, original_example.replace("GATEWAY_TLS_KMS_KEY_VERSION=1\n", "")),
        (example, original_example.replace("GATEWAY_TLS_KMS_KEY_NAME=workload-tls-gateway-auth-client",
                                           "GATEWAY_TLS_KMS_KEY_NAME=workload-tls-other")),
        (example, original_example.replace(
            "GATEWAY_TLS_KMS_KEY_NAME=workload-tls-gateway-auth-client",
            "GATEWAY_TLS_KMS_KEY_NAME=workload-tls-auth-client",
        ).replace(
            "AUTH_TLS_KMS_KEY_NAME=workload-tls-auth-client",
            "AUTH_TLS_KMS_KEY_NAME=workload-tls-gateway-auth-client",
        )),
        (compose, original_compose.replace("${GATEWAY_TLS_KMS_KEY_NAME:-}",
                                            "${UNLISTED_TLS_KMS_KEY_NAME:-}", 1)),
        (compose, original_compose.replace("${GATEWAY_TLS_KMS_KEY_NAME:-}",
                                            "${GATEWAY_TLS_KMS_KEY_VERSION:-}", 1)),
        (compose, original_compose.replace("${GATEWAY_TLS_KMS_KEY_NAME:-}",
                                            "${GATEWAY_TLS_KMS_KEY_NAME}", 1)),
        (compose, original_compose.replace("${GATEWAY_TLS_KMS_KEY_NAME:-}",
                                            "${GATEWAY_TLS_KMS_KEY_NAME:-other}", 1)),
        (compose, original_compose + "\nx-drift: ${EXTRA_TLS_KMS_KEY_NAME:-other}\n"),
    )
    for path, changed in mutations:
        path.write_text(changed, encoding="ascii")
        with pytest.raises(ValueError, match="shipped TLS KMS"):
            stage.render_tls_env_fragment(root, key_metadata())
        path.write_text(original_example if path == example else original_compose,
                        encoding="ascii")
    (root / "docker-compose.yml").unlink()
    with pytest.raises(ValueError, match="configuration input"):
        stage.render_tls_env_fragment(root, key_metadata())
    if os.name == "posix":
        compose.symlink_to(ROOT / "docker-compose.selfhost.prod.yml")
        with pytest.raises(ValueError, match="configuration input"):
            stage.render_tls_env_fragment(root, key_metadata())


def test_disposable_key_metadata_is_exact_and_nonsecret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = tmp_path / stage.KEY_METADATA_FILE
    valid = key_metadata()
    metadata.write_text(json.dumps(valid), encoding="ascii")
    assert stage.verified_key_metadata(tmp_path) == valid
    original_read = stage.os.read
    with monkeypatch.context() as patch:
        patch.setattr(stage.os, "read", lambda fd, size: original_read(fd, min(size, 13)))
        assert stage.verified_key_metadata(tmp_path) == valid
    assert len(stage.KEY_NAMES) == 16
    example = (ROOT / ".env.selfhost.production.example").read_text(encoding="ascii")
    expected = {value for line in example.splitlines()
                if "_TLS_KMS_KEY_NAME=" in line
                for value in [line.split("=", 1)[1]]}
    assert set(stage.KEY_NAMES.values()) == expected
    for mutation in (
        lambda doc: doc["roles"][0].update(version=2),
        lambda doc: doc["roles"][0].update(version=True),
        lambda doc: doc["roles"][0].update(key_name="workload-tls-other"),
        lambda doc: doc["roles"][0].update(role=doc["roles"][1]["role"]),
        lambda doc: doc.update(secret="not-allowed"),
    ):
        changed = key_metadata()
        mutation(changed)
        metadata.write_text(json.dumps(changed), encoding="ascii")
        with pytest.raises(ValueError, match="disposable TLS key metadata"):
            stage.verified_key_metadata(tmp_path)
    metadata.write_text('{"schema":"x","schema":"y"}', encoding="ascii")
    with pytest.raises(ValueError, match="duplicate fields"):
        stage.verified_key_metadata(tmp_path)
    metadata.unlink()
    with pytest.raises(ValueError, match="bootstrap input"):
        stage.verified_key_metadata(tmp_path)
    if os.name == "posix":
        metadata.symlink_to(ROOT / ".env.selfhost.production.example")
        with pytest.raises(ValueError, match="bootstrap input"):
            stage.verified_key_metadata(tmp_path)
        metadata.unlink()
    metadata.write_text("x" * 8193, encoding="ascii")
    with pytest.raises(ValueError, match="oversized"):
        stage.verified_key_metadata(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO open semantics")
def test_key_metadata_rejects_fifo_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fifo = tmp_path / stage.KEY_METADATA_FILE
    os.mkfifo(fifo)
    original_open = stage.os.open

    def bounded_open(path: Path, flags: int, *args: object) -> int:
        assert flags & os.O_NONBLOCK
        assert flags & os.O_NOFOLLOW
        return original_open(path, flags, *args)

    monkeypatch.setattr(stage.os, "open", bounded_open)
    with pytest.raises(ValueError, match="bootstrap input"):
        stage.verified_key_metadata(tmp_path)


def test_locked_images_and_bundle_assets(tmp_path: Path) -> None:
    root = bundle(tmp_path)
    assert stage.exact_images(root) == (SERVICES, OPENBAO)
    assets = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text(
        encoding="utf-8"))["assets"]
    assert {"scripts/provision_selfhost_disposable_tls.py",
            "scripts/start_selfhost_disposable_openbao.py",
            "scripts/stage_selfhost_keycloak_inputs.py",
            "scripts/passport_remote_tls.py",
            "docs/selfhost-disposable-qualification-runbook.md"} <= set(assets)
    lock = root / ".marty-selfhost-images.json"
    data = json.loads(lock.read_text(encoding="utf-8"))
    data["services"]["signing-keys"] = SERVICES.replace("a" * 64, "c" * 64)
    lock.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="reviewed installer image"):
        stage.exact_images(root)


def test_openbao_network_requires_exact_running_project_and_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    details = [{
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "HostConfig": {"PortBindings": {"8200/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "18200"}]}},
        "Config": {"Image": OPENBAO, "Labels": {
            "com.docker.compose.project": "marty-selfhost-openbao",
            "com.docker.compose.service": "openbao",
        }},
        "Mounts": [{"Destination": "/bao/data", "Type": "bind", "Source": str(state)}],
        "NetworkSettings": {
            "Networks": {"private": {"Aliases": ["openbao"]}},
            "Ports": {"8200/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18200"}]},
        },
    }]
    monkeypatch.setattr(stage.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0, "123456789abc\n", ""))
    monkeypatch.setattr(stage, "docker_json", lambda args: details)
    assert stage.openbao_network("marty-selfhost-openbao", state, OPENBAO) == "private"
    assert stage.openbao_network("marty-selfhost-openbao", state, OPENBAO,
                                 expected_host_port=18200) == "private"
    with pytest.raises(RuntimeError, match="loopback HTTPS port"):
        stage.openbao_network("marty-selfhost-openbao", state, OPENBAO,
                              expected_host_port=18201)
    details[0]["NetworkSettings"]["Ports"]["8200/tcp"][0]["HostIp"] = "0.0.0.0"
    with pytest.raises(RuntimeError, match="loopback HTTPS port"):
        stage.openbao_network("marty-selfhost-openbao", state, OPENBAO,
                              expected_host_port=18200)
    details[0]["NetworkSettings"]["Ports"]["8200/tcp"][0]["HostIp"] = "127.0.0.1"
    details[0]["HostConfig"]["PortBindings"]["8200/tcp"][0]["HostPort"] = "18201"
    with pytest.raises(RuntimeError, match="loopback HTTPS port"):
        stage.openbao_network("marty-selfhost-openbao", state, OPENBAO,
                              expected_host_port=18200)
    details[0]["HostConfig"]["PortBindings"]["8200/tcp"][0]["HostPort"] = "18200"
    details[0]["State"]["Health"]["Status"] = "unhealthy"
    with pytest.raises(RuntimeError, match="loopback HTTPS port"):
        stage.openbao_network("marty-selfhost-openbao", state, OPENBAO,
                              expected_host_port=18200)
    details[0]["State"]["Health"]["Status"] = "healthy"
    details[0]["Config"]["Image"] = SERVICES
    with pytest.raises(RuntimeError, match="locked bundle image"):
        stage.openbao_network("marty-selfhost-openbao", state, OPENBAO)
    details[0]["Config"]["Image"] = OPENBAO
    details[0]["Config"]["Labels"]["com.docker.compose.project"] = "other"
    with pytest.raises(RuntimeError, match="locked bundle image"):
        stage.openbao_network("marty-selfhost-openbao", state, OPENBAO)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Linux root-only disposable staging")
def test_stages_only_public_tls_outputs_into_existing_private_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    existing = secret_root / "existing-credential"
    existing.write_text("leave-alone", encoding="ascii")
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    (state / "tls" / "ca.crt").write_text("public-ca", encoding="ascii")
    (state / "root.token").write_text("root-token-only-in-state-123456", encoding="ascii")
    root = bundle(tmp_path)
    monkeypatch.setattr(stage, "openbao_network", lambda *_: "private")
    certificate = (ROOT / "rust/services/signing-keys/tests/fixtures"
                   / "public_certificates/root-ca.pem").read_text(encoding="ascii")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        assert command[0:3] == ["docker", "run", "--rm"]
        assert "--network" in command and command[command.index("--network") + 1] == "private"
        assert command[-1] == SERVICES
        mount = next(part for part in command if part.startswith("type=bind,")
                     and part.endswith(",dst=/output"))
        output = Path(mount.split(",src=", 1)[1].split(",dst=", 1)[0])
        for name in SELFHOST_TLS_FILES:
            value = certificate if name.endswith("_cert") else f"hvs.synthetic-{name}-distinct"
            (output / name).write_text(value, encoding="ascii")
        (output / stage.KEY_METADATA_FILE).write_text(
            json.dumps(key_metadata()), encoding="ascii",
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(stage.subprocess, "run", fake_run)
    original_fchown = stage.os.fchown
    ownership: list[tuple[int, int]] = []

    def record_fchown(fd: int, uid: int, gid: int) -> None:
        ownership.append((uid, gid))
        original_fchown(fd, uid, gid)

    monkeypatch.setattr(stage.os, "fchown", record_fchown)
    stage.provision(root, secret_root, state, "marty-selfhost-openbao")
    assert {path.name for path in secret_root.iterdir()} == SELFHOST_TLS_FILES | {existing.name}
    assert existing.read_text(encoding="ascii") == "leave-alone"
    assert not (secret_root / "root.token").exists()
    assert all(stat.S_IMODE((secret_root / name).stat().st_mode) == 0o644
               for name in SELFHOST_TLS_FILES)
    manifest = tmp_path / stage.KEY_METADATA_FILE
    assert json.loads(manifest.read_text(encoding="ascii")) == key_metadata()
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600
    fragment = tmp_path / stage.KEY_ENV_FRAGMENT_FILE
    assert fragment.read_text(encoding="ascii") == stage.render_tls_env_fragment(
        root, key_metadata())
    assert stat.S_IMODE(fragment.stat().st_mode) == 0o600
    assert fragment.stat().st_uid == secret_root.stat().st_uid
    assert ownership == [(secret_root.stat().st_uid, secret_root.stat().st_gid)] * 2
    assert manifest.stat().st_uid == secret_root.stat().st_uid


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode rollback")
def test_public_tls_move_rolls_back_after_chmod_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "tls-output"
    output.mkdir(mode=0o700)
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(mode=0o700)
    certificate = (ROOT / "rust/services/signing-keys/tests/fixtures"
                   / "public_certificates/root-ca.pem").read_text(encoding="ascii")
    for name in PUBLIC_TLS_FILES:
        (output / name).write_text(
            certificate if name.endswith("_cert") else f"hvs.synthetic-{name}-distinct-token",
            encoding="ascii",
        )
    original_chmod = os.chmod
    called = 0

    def fail_third_chmod(path: Path, mode: int) -> None:
        nonlocal called
        called += 1
        if called == 3:
            raise OSError("injected chmod failure")
        original_chmod(path, mode)

    monkeypatch.setattr(os, "chmod", fail_third_chmod)
    with pytest.raises(OSError, match="injected chmod failure"):
        accept_remote_tls(output, secrets_dir, "root-token-must-not-be-reused")
    assert {path.name for path in output.iterdir()} == PUBLIC_TLS_FILES
    assert list(secrets_dir.iterdir()) == []


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Linux root-only disposable staging")
def test_ownership_failure_removes_all_staged_tls_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    (state / "tls" / "ca.crt").write_text("public-ca", encoding="ascii")
    (state / "root.token").write_text("root-token-only-in-state-123456", encoding="ascii")
    root = bundle(tmp_path)
    monkeypatch.setattr(stage, "openbao_network", lambda *_: "private")
    certificate = (ROOT / "rust/services/signing-keys/tests/fixtures"
                   / "public_certificates/root-ca.pem").read_text(encoding="ascii")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        mount = next(part for part in command if part.startswith("type=bind,")
                     and part.endswith(",dst=/output"))
        output = Path(mount.split(",src=", 1)[1].split(",dst=", 1)[0])
        for name in SELFHOST_TLS_FILES:
            (output / name).write_text(
                certificate if name.endswith("_cert") else f"hvs.synthetic-{name}-distinct",
                encoding="ascii",
            )
        (output / stage.KEY_METADATA_FILE).write_text(
            json.dumps(key_metadata()), encoding="ascii",
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(stage.subprocess, "run", fake_run)
    called = 0

    def fail_third_chown(_path: Path, _uid: int, _gid: int) -> None:
        nonlocal called
        called += 1
        if called == 3:
            raise OSError("injected chown failure")

    monkeypatch.setattr(stage.os, "chown", fail_third_chown)
    with pytest.raises(OSError, match="injected chown failure"):
        stage.provision(root, secret_root, state, "marty-selfhost-openbao")
    assert list(secret_root.iterdir()) == []
    assert not (tmp_path / stage.KEY_METADATA_FILE).exists()
    assert not (tmp_path / stage.KEY_ENV_FRAGMENT_FILE).exists()


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Linux root-only disposable staging")
@pytest.mark.parametrize("failed_diagnostic", ["metadata", "fragment"])
def test_metadata_cleanup_failure_still_rolls_back_all_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_diagnostic: str,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    (state / "tls" / "ca.crt").write_text("public-ca", encoding="ascii")
    (state / "root.token").write_text("root-token-only-in-state-123456", encoding="ascii")
    root = bundle(tmp_path)
    monkeypatch.setattr(stage, "openbao_network", lambda *_: "private")
    certificate = (ROOT / "rust/services/signing-keys/tests/fixtures"
                   / "public_certificates/root-ca.pem").read_text(encoding="ascii")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        mount = next(part for part in command if part.startswith("type=bind,")
                     and part.endswith(",dst=/output"))
        output = Path(mount.split(",src=", 1)[1].split(",dst=", 1)[0])
        for name in SELFHOST_TLS_FILES:
            (output / name).write_text(
                certificate if name.endswith("_cert") else f"hvs.synthetic-{name}-distinct",
                encoding="ascii",
            )
        (output / stage.KEY_METADATA_FILE).write_text(
            json.dumps(key_metadata()), encoding="ascii",
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(stage.subprocess, "run", fake_run)

    original_fchown = stage.os.fchown
    fchown_calls = 0

    def fail_fchown(fd: int, uid: int, gid: int) -> None:
        nonlocal fchown_calls
        fchown_calls += 1
        if fchown_calls == (1 if failed_diagnostic == "metadata" else 2):
            raise OSError("injected owner failure")
        original_fchown(fd, uid, gid)

    monkeypatch.setattr(stage.os, "fchown", fail_fchown)
    original_unlink = Path.unlink
    failed_path = tmp_path / (stage.KEY_METADATA_FILE if failed_diagnostic == "metadata"
                              else stage.KEY_ENV_FRAGMENT_FILE)

    def fail_manifest_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path == failed_path:
            raise OSError("injected metadata cleanup failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_manifest_unlink)
    with pytest.raises(RuntimeError, match="ownership rollback is incomplete"):
        stage.provision(root, secret_root, state, "marty-selfhost-openbao")
    assert list(secret_root.iterdir()) == []
    assert failed_path.exists()
    other = tmp_path / (stage.KEY_ENV_FRAGMENT_FILE if failed_diagnostic == "metadata"
                        else stage.KEY_METADATA_FILE)
    assert not other.exists()


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Linux root-only disposable staging")
@pytest.mark.parametrize("remove_status", [0, 1])
def test_timeout_cleanup_retains_id_only_if_removal_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, remove_status: int,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    (state / "tls" / "ca.crt").write_text("public-ca", encoding="ascii")
    (state / "root.token").write_text("root-token-only-in-state-123456", encoding="ascii")
    root = bundle(tmp_path)
    monkeypatch.setattr(stage, "openbao_network", lambda *_: "private")
    container_id = "d" * 64

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        if command[0:2] == ["docker", "run"]:
            Path(command[command.index("--cidfile") + 1]).write_text(
                container_id, encoding="ascii",
            )
            raise subprocess.TimeoutExpired(command, 180)
        assert command == ["docker", "rm", "--force", container_id]
        return subprocess.CompletedProcess(command, remove_status)

    monkeypatch.setattr(stage.subprocess, "run", fake_run)
    expected = stage.BootstrapCleanupError if remove_status else subprocess.TimeoutExpired
    with pytest.raises(expected):
        stage.provision(root, secret_root, state, "marty-selfhost-openbao")
    cidfiles = list(tmp_path.glob("marty-selfhost-tls-*.cid"))
    assert len(cidfiles) == remove_status
    if remove_status:
        assert cidfiles[0].read_text(encoding="ascii") == container_id
    assert list(secret_root.iterdir()) == []
