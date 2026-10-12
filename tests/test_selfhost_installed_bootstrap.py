"""Bounded opt-in bootstrap handoff controls; no product installation claim."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_selfhost_installed_bootstrap as bootstrap  # noqa: E402


def result(
    args: list[str], stdout: str = "", status: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, status, stdout, "")


def owned_model(
    container_id: str,
    name: str,
    address: str = "172.17.0.2",
    *,
    mounts: list[dict] | None = None,
) -> str:
    return json.dumps(
        {
            "Id": container_id,
            "Name": "/" + name,
            "Config": {
                "Labels": {bootstrap.OWNED: name},
                "Image": bootstrap.HELPER_IMAGE,
                "User": (
                    f"{os.getuid()}:{os.getgid()}"
                    if os.name == "posix"
                    else "1000:1000"
                )
                if mounts
                else "openbao",
            },
            "HostConfig": {
                "NetworkMode": "default" if mounts else "bridge",
                "PortBindings": {},
            },
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": address}}},
            "Mounts": mounts or [],
        }
    )


@pytest.mark.parametrize(
    "change", ["name", "label", "null_labels", "network", "port", "address"]
)
def test_owned_container_rejects_boundary_change(monkeypatch, change: str) -> None:
    container_id = "a" * 64
    name = "marty-selfhost-bootstrap-1234567890abcdef"
    model = json.loads(owned_model(container_id, name))
    if change == "name":
        model["Name"] = "/foreign"
    elif change == "label":
        model["Config"]["Labels"][bootstrap.OWNED] = "foreign"
    elif change == "null_labels":
        model["Config"]["Labels"] = None
    elif change == "network":
        model["HostConfig"]["NetworkMode"] = "host"
    elif change == "port":
        model["HostConfig"]["PortBindings"] = {"8200/tcp": [{"HostPort": "8200"}]}
    else:
        model["NetworkSettings"]["Networks"]["bridge"]["IPAddress"] = "8.8.8.8"
    monkeypatch.setattr(
        bootstrap, "checked", lambda *_args, **_kwargs: json.dumps(model)
    )
    with pytest.raises(bootstrap.migrations.QualificationError):
        bootstrap.inspect_owned(container_id, {}, name)


def test_helper_cleanup_rejects_foreign_mount_before_forced_remove(monkeypatch) -> None:
    container_id = "d" * 64
    name = "marty-selfhost-bootstrap-1234567890abcdef-helper"
    model = owned_model(
        container_id,
        name,
        mounts=[
            {
                "Type": "bind",
                "Source": "/foreign",
                "Destination": "/work-service",
                "RW": True,
            }
        ],
    )
    monkeypatch.setattr(bootstrap, "checked", lambda *_args, **_kwargs: model)
    with pytest.raises(bootstrap.migrations.QualificationError):
        bootstrap.inspect_owned(
            container_id,
            {},
            name,
            require_address=False,
            expected_mounts={"/work-service": ("/owned", True)},
        )


def test_helper_cleanup_rejects_wrong_runtime_user(monkeypatch) -> None:
    container_id = "e" * 64
    name = "marty-selfhost-bootstrap-1234567890abcdef-helper"
    model = json.loads(
        owned_model(
            container_id,
            name,
            mounts=[
                {
                    "Type": "bind",
                    "Source": "/owned",
                    "Destination": "/work-service",
                    "RW": True,
                }
            ],
        )
    )
    model["Config"]["User"] = "foreign:foreign"
    monkeypatch.setattr(
        bootstrap, "checked", lambda *_args, **_kwargs: json.dumps(model)
    )
    with pytest.raises(bootstrap.migrations.QualificationError):
        bootstrap.inspect_owned(
            container_id,
            {},
            name,
            require_address=False,
            expected_mounts={"/work-service": ("/owned", True)},
            expected_user=(
                f"{os.getuid()}:{os.getgid()}" if os.name == "posix" else "1000:1000"
            ),
        )


def test_shipped_helper_does_not_put_bootstrap_token_in_docker_argv() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "scripts/bootstrap-selfhost-vault.sh"
    ).read_text(encoding="utf-8")
    assert "export BAO_TOKEN\n" in source
    assert "-e BAO_TOKEN \\" in source
    assert "-e BAO_TOKEN=" not in source
    assert "BAO_TOKEN_FILE" in source
    assert source.startswith("#!/bin/sh\nset -e\numask 077\n")
    assert "/bin/sh -ec '\numask 077\n" in source
    assert 'private_tmp="$(mktemp "$output_dir/.openbao-token.XXXXXX")"' in source
    assert 'mv -f "$private_tmp" "$output_file"' in source
    for output in (
        "SERVICE_TOKEN_OUTPUT_FILE",
        "SIGNING_KEYS_TOKEN_OUTPUT_FILE",
        "DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE",
        "NOTIFICATION_TOKEN_OUTPUT_FILE",
        "PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE",
    ):
        assert f'write_private_token "${output}"' in source
    assert 'write_private_token "$grant_file" "$grant_token"' in source


@pytest.mark.skipif(os.name != "posix", reason="POSIX atomic file replacement")
def test_scoped_tokens_replace_public_placeholders_without_exposing_old_fd(
    tmp_path: Path,
) -> None:
    source = (
        Path(__file__).resolve().parents[1] / "scripts/bootstrap-selfhost-vault.sh"
    ).read_text(encoding="utf-8")
    inner = source.split("/bin/sh -ec '\n", 1)[1].rsplit("\n'\n", 1)[0]
    # Only stub the external OpenBao init and token minting. The shipped
    # private-file writer and rename are executed unchanged.
    inner = inner.replace("/bin/sh /scripts/openbao-init.sh", ":", 1)
    fake_bao = (
        'bao() { case "$*" in\n'
        '  *signing-keys-managed*) command printf \'{"auth":{"client_token":"signing-new"}}\\n\' ;;\n'
        '  *didcomm-issuance*) command printf \'{"auth":{"client_token":"didcomm-new"}}\\n\' ;;\n'
        '  *sign-grant-mint-*) command printf \'{"auth":{"client_token":"grant-new"}}\\n\' ;;\n'
        '  *sign-grant-verify*) command printf \'{"auth":{"client_token":"verify-new"}}\\n\' ;;\n'
        '  *credential-service*) command printf \'{"auth":{"client_token":"service-new"}}\\n\' ;;\n'
        '  *notification-webhook-service*) command printf \'{"auth":{"client_token":"notification-new"}}\\n\' ;;\n'
        '  *passport-provider-callback-service*) command printf \'{"auth":{"client_token":"callback-new"}}\\n\' ;;\n'
        "esac; }\n"
        'mv() { [ "$1" = -f ] && shift; '
        '[ "$(stat -c %a "$1")" = 600 ] || exit 98; '
        'command mv -f "$@"; }\n'
    )
    paths = [tmp_path / name for name in bootstrap.TOKEN_NAMES]
    signing_path = tmp_path / "signing_keys_openbao_token"
    didcomm_path = tmp_path / "didcomm_issuance_openbao_token"
    paths.extend((signing_path, didcomm_path))
    for path in paths:
        path.write_text("shipped-public-placeholder", encoding="ascii")
        path.chmod(0o644)
    environment = {
        **os.environ,
        "BAO_ADDR": "http://127.0.0.1:8200",
        "BAO_TOKEN": "synthetic-bootstrap-token",
        "SERVICE_TOKEN_OUTPUT_FILE": str(paths[0]),
        "NOTIFICATION_TOKEN_OUTPUT_FILE": str(paths[1]),
        "PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE": str(paths[2]),
        "SIGNING_KEYS_TOKEN_OUTPUT_FILE": str(signing_path),
        "DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE": str(didcomm_path),
        "GRANT_TOKEN_OUTPUT_DIR": str(tmp_path),
    }
    with paths[0].open("rb") as old_handle:
        completed = subprocess.run(
            ["/bin/sh", "-ec", fake_bao + inner],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert old_handle.read() == b"shipped-public-placeholder"
    assert [path.read_text(encoding="ascii") for path in paths] == [
        "service-new",
        "notification-new",
        "callback-new",
        "signing-new",
        "didcomm-new",
    ]
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)
    grant_paths = list(tmp_path.glob("sign_grant_*_token"))
    assert len(grant_paths) == 8
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in grant_paths)
    assert not list(tmp_path.glob(".openbao-token.*"))

    paths[0].unlink()
    paths[0].symlink_to(paths[1])
    rejected = subprocess.run(
        ["/bin/sh", "-ec", fake_bao + inner],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert rejected.returncode != 0
    assert "Scoped token output path is unsafe." in rejected.stderr
    assert paths[1].read_text(encoding="ascii") == "notification-new"


def test_source_checkout_cannot_be_used_as_install_root() -> None:
    with pytest.raises(
        bootstrap.migrations.QualificationError, match="outside the source checkout"
    ):
        bootstrap.probe(bootstrap.migrations.ROOT, {})


@pytest.mark.skipif(os.name != "posix", reason="POSIX helper execution")
@pytest.mark.parametrize("named", [False, True])
def test_shipped_helper_inherits_token_without_argv_value(
    tmp_path: Path,
    named: bool,
) -> None:
    helper = Path(__file__).resolve().parents[1] / "scripts/bootstrap-selfhost-vault.sh"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$@" > "$FAKE_DOCKER_ARGV"\n'
        'printf "%s" "$BAO_TOKEN" > "$FAKE_DOCKER_ENV"\n'
        "for name in openbao_service_token notification_openbao_token passport_callback_signer_bao_token; do\n"
        '  printf "%s" synthetic-scoped-token > "$SELFHOST_SECRET_DIR/$name"\n'
        "done\n",
        encoding="ascii",
    )
    docker.chmod(0o700)
    synthetic_token = "synthetic-bootstrap-token-not-a-secret"
    argv_file = tmp_path / "argv"
    env_file = tmp_path / "env"
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir(mode=0o700)
    environment = {
        **os.environ,
        "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
        "BAO_ADDR": "http://127.0.0.1:8200",
        "BAO_TOKEN": synthetic_token,
        "SELFHOST_SECRET_DIR": str(secret_dir),
        "FAKE_DOCKER_ARGV": str(argv_file),
        "FAKE_DOCKER_ENV": str(env_file),
    }
    disposable_name = "marty-selfhost-bootstrap-1234567890abcdef-helper"
    if named:
        environment["SELFHOST_BOOTSTRAP_CONTAINER_NAME"] = disposable_name
    completed = subprocess.run(
        ["/bin/sh", str(helper)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0
    assert env_file.read_text(encoding="ascii") == synthetic_token
    assert synthetic_token not in argv_file.read_text(encoding="ascii")
    assert synthetic_token not in completed.stdout + completed.stderr
    args = argv_file.read_text(encoding="ascii").splitlines()
    assert args[args.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert ("--name" in args) is named
    if named:
        assert args[args.index("--name") + 1] == disposable_name
        assert ("marty.selfhost.bootstrap-handoff=" + disposable_name) in args
    assert stat.S_IMODE(secret_dir.stat().st_mode) == 0o700
    for token_name in bootstrap.TOKEN_NAMES:
        assert stat.S_IMODE((secret_dir / token_name).stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "failure", [None, "helper", "token", "leak", "bad_create", "timeout"]
)
def test_handoff_owns_cleanup_and_never_prints_tokens(
    monkeypatch,
    tmp_path: Path,
    failure: str | None,
) -> None:
    helper = tmp_path / "scripts/bootstrap-selfhost-vault.sh"
    helper.parent.mkdir()
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(bootstrap, "verify_helper_image", lambda *_args: None)
    container_id = "b" * 64
    helper_id = "c" * 64
    calls: list[list[str]] = []
    helper_env: dict[str, str] = {}

    def fake_command(args: list[str], env: dict[str, str], timeout: int = 90):
        calls.append(args)
        if args[:2] == ["docker", "ps"]:
            if args[-1].endswith("-helper$"):
                removed = ["docker", "rm", "--force", "--volumes", helper_id] in calls
                return result(
                    args,
                    helper_id
                    if helper_env and failure == "timeout" and not removed
                    else "",
                )
            created = any(call[:2] == ["docker", "create"] for call in calls)
            removed = ["docker", "rm", "--force", "--volumes", container_id] in calls
            return result(args, container_id if created and not removed else "")
        if args[:2] == ["docker", "create"]:
            assert "BAO_DEV_ROOT_TOKEN_ID" in args and not any(
                env["BAO_DEV_ROOT_TOKEN_ID"] in part for part in args
            )
            return result(
                args, "malformed" if failure == "bad_create" else container_id
            )
        if args[:2] == ["docker", "inspect"]:
            if args[-1] == helper_id:
                directory = str(Path(helper_env["SELFHOST_SECRET_DIR"]).resolve())
                source = str((tmp_path / "docker/openbao-init.sh").resolve())
                mounts = [
                    {
                        "Type": "bind",
                        "Source": source,
                        "Destination": "/scripts/openbao-init.sh",
                        "RW": False,
                    },
                    *(
                        {
                            "Type": "bind",
                            "Source": directory,
                            "Destination": destination,
                            "RW": True,
                        }
                        for destination in (
                            "/work-service",
                            "/work-notification",
                            "/work-callback",
                        )
                    ),
                ]
                return result(
                    args, owned_model(helper_id, name[0] + "-helper", mounts=mounts)
                )
            return result(args, owned_model(container_id, name[0]))
        if args[:3] == ["docker", "exec", container_id]:
            return result(args)
        if args[:2] == ["/bin/sh", str(helper)]:
            helper_env.update(env)
            assert "BAO_TOKEN_FILE" in env and env["BAO_TOKEN_FILE"] not in args
            assert "BAO_DEV_ROOT_TOKEN_ID" not in env
            assert env["SELFHOST_BOOTSTRAP_CONTAINER_NAME"] == name[0] + "-helper"
            if failure == "timeout":
                raise bootstrap.migrations.QualificationError("synthetic timeout")
            if failure != "helper":
                for index, token_name in enumerate(bootstrap.TOKEN_NAMES):
                    path = Path(env["SELFHOST_SECRET_DIR"]) / token_name
                    if failure != "token" or token_name != bootstrap.TOKEN_NAMES[-1]:
                        path.write_text(str(index + 1) * 64, encoding="ascii")
            return result(
                args,
                Path(env["BAO_TOKEN_FILE"]).read_text(encoding="ascii")
                if failure == "leak"
                else "",
                status=int(failure == "helper"),
            )
        return result(args)

    name = [""]

    def inspected(args, env, reason, timeout=90):
        if args[:2] == ["docker", "create"]:
            name[0] = args[args.index("--name") + 1]
        raw = fake_command(args, env, timeout)
        return bootstrap.migrations._checked(raw, reason)

    monkeypatch.setattr(bootstrap, "checked", inspected)
    monkeypatch.setattr(bootstrap.migrations, "command", fake_command)
    receipt = {"archive_sha256": "1" * 64, "image_lock_sha256": "2" * 64}
    if failure is None:
        report = bootstrap.probe(tmp_path, receipt)
        assert report["qualification"] == "unqualified"
        assert report["scoped_tokens"] == list(bootstrap.TOKEN_NAMES)
    else:
        with pytest.raises(bootstrap.migrations.QualificationError):
            bootstrap.probe(tmp_path, receipt)
    assert ["docker", "rm", "--force", "--volumes", container_id] in calls
    if failure == "timeout":
        assert ["docker", "rm", "--force", "--volumes", helper_id] in calls
    assert any(call[:2] == ["docker", "ps"] for call in calls)
