#!/usr/bin/env python3
"""Bridge root-only OpenBao provisioning to an operator-owned private install."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from provision_selfhost_disposable_tls import preview_openbao_owner
from provision_selfhost_keycloak_kms import OUTPUTS


def owned_dir(path: Path, uid: int) -> Path:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or path.stat().st_uid != uid
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError("disposable Keycloak path is not operator-owned and private")
    return path.resolve()


def openbao_state_dir(path: Path) -> Path:
    # The TLS init container chowns its bind-mounted state to the OpenBao UID.
    # The locked container and exact state bind mount are verified below.
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError("disposable OpenBao state is not a private directory")
    return path.resolve()


def input_file(path: Path) -> Path:
    if (path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 65536):
        raise ValueError("disposable OpenBao input is missing or invalid")
    return path


def stage(private_root: Path, operator_uid: int) -> int:
    if (os.name != "posix" or os.geteuid() != 0 or operator_uid <= 0
            or operator_uid == os.geteuid()):
        raise ValueError("Keycloak input transfer requires sudo from a non-root operator")
    root = owned_dir(private_root, operator_uid)
    secrets = owned_dir(root / "secrets", operator_uid)
    state = openbao_state_dir(root / "openbao-state")
    install = root / "install" / "selfhost-prepared"
    if install.is_symlink() or not install.is_dir():
        raise ValueError("staged preview install is missing")
    _, port = preview_openbao_owner(root, state, install)
    ca = input_file(state / "tls" / "ca.crt")
    public_ca = input_file(secrets / "openbao_tls_ca_cert")
    if public_ca.read_bytes() != ca.read_bytes():
        raise ValueError("OpenBao public CA does not match the server")
    token = input_file(state / "root.token")
    if (stat.S_IMODE(token.stat().st_mode) != 0o400
            or token.stat().st_uid != 0):
        raise ValueError("OpenBao root token has unsafe ownership or mode")
    if any((secrets / name).exists() or (secrets / name).is_symlink()
           for name in OUTPUTS):
        raise ValueError("Keycloak output already exists")
    # The root token is never copied to the install or to the operator-owned
    # secret root. The existing provisioner runs in a root-owned staging dir.
    # Ignore inherited TMPDIR: the operator owns the private install root and
    # must not be able to swap root-owned staging while it contains secrets.
    temporary_parent = Path("/tmp")
    parent = temporary_parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or not parent.st_mode & stat.S_ISVTX):
        raise ValueError("root-owned sticky temporary parent is unavailable")
    with tempfile.TemporaryDirectory(prefix="marty-keycloak-inputs-",
                                     dir=temporary_parent) as temporary:
        output = Path(temporary)
        output.chmod(0o700)
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "BAO_ADDR": f"https://127.0.0.1:{port}",
            "BAO_CACERT": str(ca),
            "BAO_ROOT_TOKEN_FILE": str(token),
            "SELFHOST_KEYCLOAK_OUTPUT_DIR": str(output),
        }
        helper = Path(__file__).resolve().with_name("provision_selfhost_keycloak_kms.py")
        result = subprocess.run([sys.executable, str(helper)], env=env,
                                capture_output=True, text=True, timeout=240,
                                check=False)
        if result.returncode:
            raise RuntimeError("disposable Keycloak provisioning failed")
        if {path.name for path in output.iterdir()} != OUTPUTS:
            raise RuntimeError("disposable Keycloak outputs are incomplete")
        for name in OUTPUTS:
            produced = input_file(output / name)
            if (produced.stat().st_uid != 0
                    or produced.stat().st_nlink != 1
                    or stat.S_IMODE(produced.stat().st_mode) != 0o444):
                raise RuntimeError("disposable Keycloak output mode is invalid")
        directory = os.open(secrets, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            owner = os.fstat(directory)
            if (owner.st_uid != operator_uid
                    or stat.S_IMODE(owner.st_mode) != 0o700):
                raise ValueError("Keycloak output directory changed")
            created: list[str] = []
            try:
                for name in sorted(OUTPUTS):
                    produced = output / name
                    content = produced.read_bytes()
                    # O_EXCL prevents replacement; the directory fd prevents
                    # a renamed parent redirecting a privileged write.
                    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                         os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    created.append(name)
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fchown(stream.fileno(), operator_uid, owner.st_gid)
                        os.fchmod(stream.fileno(), 0o444)
                current = secrets.lstat()
                if (current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino):
                    raise RuntimeError("Keycloak output directory was replaced")
                return len(created)
            except BaseException:
                for name in created:
                    os.unlink(name, dir_fd=directory)
                raise
        finally:
            os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        uid = int(os.environ["SUDO_UID"])
        count = stage(args.private_root, uid)
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        print(f"disposable Keycloak staging failed: {type(error).__name__}",
              file=sys.stderr)
        return 2
    print(f"Staged {count} scoped Keycloak inputs without exporting private keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
