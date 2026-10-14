#!/usr/bin/env python3
"""Opt-in, unqualified extracted-bundle OpenBao bootstrap handoff probe."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import sys
import tempfile
import time
from pathlib import Path

if __package__:
    from . import probe_selfhost_installed_migrations as migrations
    from .check_selfhost_locked_image_platform import accepted_repo_digests
else:
    import probe_selfhost_installed_migrations as migrations
    from check_selfhost_locked_image_platform import accepted_repo_digests

HELPER_IMAGE = (
    "quay.io/openbao/openbao@sha256:"
    "6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"
)
PLUGIN_URI = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm"
OWNED = "marty.selfhost.bootstrap-handoff"
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_NAMES = (
    "openbao_service_token",
    "openbao_bootstrap_token",
    "notification_openbao_token",
    "passport_callback_signer_bao_token",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise migrations.QualificationError(message)


def checked(
    args: list[str], env: dict[str, str], reason: str, timeout: int = 90
) -> str:
    # The underlying wrapper never includes captured Docker output in errors.
    return migrations._checked(migrations.command(args, env, timeout), reason)


def named_container(name: str, env: dict[str, str]) -> str:
    found = checked(
        ["docker", "ps", "-aq", "--no-trunc", "--filter", f"name=^/{name}$"],
        env,
        "Disposable OpenBao ownership query failed",
    ).strip()
    require(
        not found or CONTAINER_ID.fullmatch(found) is not None,
        "Disposable OpenBao name has ambiguous ownership",
    )
    return found


def inspect_owned(
    container_id: str,
    env: dict[str, str],
    name: str,
    *,
    require_address: bool = True,
    expected_mounts: dict[str, tuple[str, bool]] | None = None,
    expected_tmpfs: set[str] | None = None,
    expected_user: str | None = None,
    expected_image: str = HELPER_IMAGE,
) -> str:
    raw = checked(
        ["docker", "inspect", "--format", "{{json .}}", container_id],
        env,
        "Disposable OpenBao container cannot be inspected",
    )
    try:
        item = json.loads(raw)
        bridge = item["NetworkSettings"]["Networks"]["bridge"]
        address = bridge["IPAddress"]
        network = item["HostConfig"]["NetworkMode"]
        labels = item["Config"]["Labels"]
        image = item["Config"]["Image"]
        user = item["Config"]["User"]
        ports = item["HostConfig"]["PortBindings"]
        tmpfs = item["HostConfig"].get("Tmpfs") or {}
        assert item["Id"] == container_id
        assert item["Name"] == "/" + name
        assert isinstance(labels, dict)
        assert (
            network
            in ({"bridge"} if expected_mounts is None else {"bridge", "default"})
            and labels.get(OWNED) == name
        )
        assert image == expected_image
        if expected_user is not None:
            assert user == expected_user
        assert not ports
        assert tmpfs == {path: "" for path in (expected_tmpfs or set())}
        mounts = item["Mounts"]
        assert isinstance(mounts, list)
        actual_mounts = {
            mount["Destination"]: (mount["Source"], mount["RW"])
            for mount in mounts
            if mount["Type"] == "bind"
        }
        assert len(actual_mounts) == len(mounts)
        assert actual_mounts == (expected_mounts or {})
        if require_address:
            assert ipaddress.ip_address(address).is_private
            assert ipaddress.ip_address(address).version == 4
    except (AssertionError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise migrations.QualificationError(
            "Disposable OpenBao identity, network, or no-host-port boundary changed"
        ) from exc
    return address


def verify_reviewed_image(env: dict[str, str], image: str) -> None:
    checked(
        ["docker", "pull", "--platform", "linux/amd64", image],
        env,
        "Reviewed OpenBao image cannot be pulled",
        240,
    )
    raw = checked(
        ["docker", "image", "inspect", image, "--format", "{{json .}}"],
        env,
        "Reviewed OpenBao image cannot be inspected",
    )
    try:
        metadata = json.loads(raw)
    except ValueError as exc:
        raise migrations.QualificationError(
            "Reviewed OpenBao image is invalid"
        ) from exc
    digests = metadata.get("RepoDigests") if isinstance(metadata, dict) else None
    require(
        isinstance(metadata, dict)
        and metadata.get("Os") == "linux"
        and metadata.get("Architecture") == "amd64"
        and isinstance(digests, list)
        and any(
            isinstance(item, str) and item in accepted_repo_digests(image)
            for item in digests
        ),
        "Reviewed OpenBao image is not the exact linux/amd64 digest",
    )


def verify_helper_image(env: dict[str, str], helper: Path) -> None:
    source = helper.read_text(encoding="utf-8")
    require(
        source.count(HELPER_IMAGE) == 1
        and re.findall(r"quay\.io/openbao/openbao\S*", source) == [HELPER_IMAGE],
        "Extracted bootstrap helper image differs from reviewed digest",
    )
    verify_reviewed_image(env, HELPER_IMAGE)


def qualified_plugin_image(transaction_path: Path) -> str:
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    role = transaction.get("images", {}).get("openbao_didcomm", {})
    require(
        transaction.get("schema") == "elevenid.stack-release-transaction/v1"
        and transaction.get("state") == "qualified"
        and isinstance(role, dict)
        and role.get("uri") == PLUGIN_URI
        and isinstance(role.get("digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", role["digest"]) is not None,
        "Qualified transaction lacks an exact DIDComm plugin image",
    )
    return f"{PLUGIN_URI}@{role['digest']}"


def mount_disposable_plugin(
    container_id: str, env: dict[str, str], root_token: str
) -> None:
    plugin_sha = checked(
        ["docker", "exec", container_id, "sha256sum", "/plugins/openbao-didcomm-authcrypt"],
        env,
        "Qualified DIDComm plugin binary is missing",
    ).split()[0]
    require(
        re.fullmatch(r"[0-9a-f]{64}", plugin_sha) is not None,
        "Qualified DIDComm plugin binary hash is invalid",
    )
    client_env = {**env, "BAO_TOKEN": root_token}
    cli = [
        "docker", "exec", "--env", "BAO_TOKEN",
        "--env", "BAO_ADDR=http://127.0.0.1:8200", container_id, "bao",
    ]
    checked(
        cli + ["plugin", "register", f"-sha256={plugin_sha}", "secret", "openbao-didcomm-authcrypt"],
        client_env,
        "Qualified DIDComm plugin cannot be registered",
    )
    checked(
        cli + ["secrets", "enable", "-path=didcomm", "openbao-didcomm-authcrypt"],
        client_env,
        "Qualified DIDComm plugin cannot be mounted",
    )


def probe(install_root: Path, receipt: dict, plugin_image: str) -> dict:
    require(
        not install_root.resolve().is_relative_to(migrations.ROOT.resolve()),
        "Extracted install root must be outside the source checkout",
    )
    helper = install_root / "scripts/bootstrap-selfhost-vault.sh"
    require(
        helper.is_file() and not helper.is_symlink(),
        "Extracted bootstrap helper is missing",
    )
    name = "marty-selfhost-bootstrap-" + secrets.token_hex(8)
    helper_name = name + "-helper"
    root_token = secrets.token_hex(32)
    env = os.environ.copy()
    env["BAO_DEV_ROOT_TOKEN_ID"] = root_token
    verify_helper_image(env, helper)
    verify_reviewed_image(env, plugin_image)
    require(
        not named_container(name, env), "Disposable OpenBao name was already occupied"
    )
    require(
        not named_container(helper_name, env),
        "Disposable bootstrap helper name was already occupied",
    )
    with tempfile.TemporaryDirectory(prefix="marty-selfhost-bootstrap-") as temporary:
        secret_dir = Path(temporary) / "secrets"
        secret_dir.mkdir(mode=0o700)
        plugin_config = Path(temporary) / "plugin.hcl"
        plugin_config.write_text('plugin_directory = "/plugins"\n', encoding="ascii")
        plugin_config.chmod(0o644)
        if os.name == "posix":
            secret_dir.chmod(0o700)
        token_file = secret_dir / "root.token"
        token_file.write_text(root_token, encoding="ascii")
        if os.name == "posix":
            token_file.chmod(0o600)
        server_mount = {
            "/openbao/config/plugin.hcl": (str(plugin_config.resolve()), False),
        }
        server_tmpfs = {"/openbao/file", "/openbao/logs"}
        container_id = ""
        try:
            container_id = checked(
                [
                    "docker",
                    "create",
                    "--name",
                    name,
                    "--network",
                    "bridge",
                    "--label",
                    f"{OWNED}={name}",
                    "-v",
                    f"{plugin_config}:/openbao/config/plugin.hcl:ro",
                    "--tmpfs",
                    "/openbao/file",
                    "--tmpfs",
                    "/openbao/logs",
                    "-e",
                    "BAO_DEV_ROOT_TOKEN_ID",
                    plugin_image,
                    "server",
                    "-dev",
                    "-dev-listen-address=0.0.0.0:8200",
                    "-config=/openbao/config/plugin.hcl",
                ],
                env,
                "Disposable OpenBao container cannot be created",
            ).strip()
            require(
                CONTAINER_ID.fullmatch(container_id) is not None,
                "Disposable OpenBao returned an invalid container ID",
            )
            require(
                named_container(name, env) == container_id,
                "Disposable OpenBao ID differs from owned name",
            )
            inspect_owned(
                container_id, env, name, require_address=False,
                expected_mounts=server_mount, expected_tmpfs=server_tmpfs,
                expected_image=plugin_image,
            )
            checked(
                ["docker", "start", container_id],
                env,
                "Disposable OpenBao cannot start",
            )
            address = inspect_owned(
                container_id, env, name, expected_mounts=server_mount,
                expected_tmpfs=server_tmpfs, expected_image=plugin_image,
            )
            for _ in range(30):
                result = migrations.command(
                    [
                        "docker",
                        "exec",
                        container_id,
                        "bao",
                        "status",
                        "-address=http://127.0.0.1:8200",
                    ],
                    env,
                    10,
                )
                if result.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise migrations.QualificationError(
                    "Disposable OpenBao did not become ready"
                )
            mount_disposable_plugin(container_id, env, root_token)
            helper_env = {
                **{
                    key: value
                    for key, value in env.items()
                    if key != "BAO_DEV_ROOT_TOKEN_ID"
                },
                "BAO_ADDR": f"http://{address}:8200",
                "BAO_TOKEN_FILE": str(token_file),
                "SELFHOST_SECRET_DIR": str(secret_dir),
                "SELFHOST_BOOTSTRAP_CONTAINER_NAME": helper_name,
            }
            result = migrations.command(["/bin/sh", str(helper)], helper_env, 180)
            require(result.returncode == 0, "Extracted OpenBao bootstrap helper failed")
            for value in (
                root_token,
                *(
                    path.read_text(encoding="ascii")
                    for path in (secret_dir / name for name in TOKEN_NAMES)
                    if path.is_file()
                ),
            ):
                require(
                    value not in result.stdout + result.stderr,
                    "Bootstrap helper printed a token",
                )
            scoped_values = []
            for token_name in TOKEN_NAMES:
                path = secret_dir / token_name
                require(
                    path.is_file()
                    and not path.is_symlink()
                    and path.stat().st_size >= 16
                    and path.read_text(encoding="ascii") != root_token,
                    "Extracted bootstrap did not mint distinct scoped tokens",
                )
                scoped_values.append(path.read_text(encoding="ascii"))
            require(
                len(set(scoped_values)) == len(TOKEN_NAMES),
                "Extracted bootstrap reused a scoped token",
            )
            return {
                "schema": "marty.selfhost-bootstrap-handoff-probe/v1",
                "qualification": "unqualified",
                "archive_sha256": receipt["archive_sha256"],
                "image_lock_sha256": receipt["image_lock_sha256"],
                "openbao_image": HELPER_IMAGE,
                "scoped_tokens": list(TOKEN_NAMES),
            }
        finally:
            try:
                helper_id = named_container(helper_name, env)
                if helper_id:
                    source = str((install_root / "docker/openbao-init.sh").resolve())
                    directory = str(secret_dir.resolve())
                    inspect_owned(
                        helper_id,
                        env,
                        helper_name,
                        require_address=False,
                        expected_mounts={
                            "/scripts/openbao-init.sh": (source, False),
                            "/work-service": (directory, True),
                            "/work-bootstrap": (directory, True),
                            "/work-notification": (directory, True),
                            "/work-callback": (directory, True),
                        },
                        expected_user=(
                            f"{os.getuid()}:{os.getgid()}"
                            if os.name == "posix"
                            else "1000:1000"
                        ),
                    )
                    checked(
                        ["docker", "rm", "--force", "--volumes", helper_id],
                        env,
                        "Disposable bootstrap helper cleanup failed",
                    )
                    require(
                        not named_container(helper_name, env),
                        "Disposable bootstrap helper remains after cleanup",
                    )
            finally:
                owned_id = named_container(name, env)
                if owned_id:
                    require(
                        CONTAINER_ID.fullmatch(container_id) is None
                        or container_id == owned_id,
                        "Disposable OpenBao identity changed before cleanup",
                    )
                    inspect_owned(
                        owned_id, env, name, require_address=False,
                        expected_mounts=server_mount, expected_tmpfs=server_tmpfs,
                        expected_image=plugin_image,
                    )
                    checked(
                        ["docker", "rm", "--force", "--volumes", owned_id],
                        env,
                        "Disposable OpenBao cleanup failed",
                    )
                    require(
                        not named_container(name, env),
                        "Disposable OpenBao remains after cleanup",
                    )


def main() -> None:
    require(sys.platform == "linux", "Bootstrap handoff requires a Linux Docker host")
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "archive",
        "image-lock",
        "transaction",
        "receipt",
        "descriptor",
        "install-root",
        "source-sha",
        "run-id",
    ):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    _, receipt = migrations.bundle_images(
        Path(args.archive),
        Path(args.image_lock),
        Path(args.transaction),
        Path(args.receipt),
        Path(args.descriptor),
        Path(args.install_root),
        args.source_sha,
        args.run_id,
    )
    plugin_image = qualified_plugin_image(Path(args.transaction))
    print(json.dumps(probe(Path(args.install_root), receipt, plugin_image), sort_keys=True))


if __name__ == "__main__":
    main()
