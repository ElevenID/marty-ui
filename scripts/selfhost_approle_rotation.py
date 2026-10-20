"""Shared fail-closed SecretID rotation for scoped self-host OpenBao AppRoles."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.error import HTTPError


@dataclass(frozen=True)
class RotationSpec:
    mount: str
    role: str
    role_id_file: str
    secret_id_file: str
    directory_prefix: str
    label: str

    @property
    def secret_id_path(self) -> str:
        return f"auth/{self.mount}/role/{self.role}/secret-id"


def require_revoked(bao, role_id: str, secret_id: str,
                    spec: RotationSpec) -> None:
    try:
        bao.request("POST", f"auth/{spec.mount}/login", {
            "role_id": role_id, "secret_id": secret_id,
        }, authenticate=False)
    except HTTPError as error:
        if error.code in (400, 403):
            return
        raise
    raise ValueError(f"retired {spec.label} AppRole credential remains usable")


def _identity_name(path: Path, prefix: str) -> bool:
    return re.fullmatch(re.escape(prefix) + r"(?:-[a-z0-9-]{1,80})?",
                        path.name) is not None


def rotate(
    bao, identity: Path, output: Path, spec: RotationSpec,
    login: Callable[[object, Path], str],
    validate: Callable[..., Path], read: Callable[[Path], str],
    write: Callable[[Path, str], None],
    manager_login: Callable[[object], str] | None = None,
) -> None:
    identity = validate(identity, empty=False)
    output = validate(output, empty=True)
    if (identity == output or identity.parent != output.parent
            or not _identity_name(identity, spec.directory_prefix)
            or not _identity_name(output, spec.directory_prefix)):
        raise ValueError(f"replacement {spec.label} identity must be separate")
    old_token = login(bao, identity)
    create_token = manager_login(bao) if manager_login is not None else old_token
    role_id = read(identity / spec.role_id_file).strip()
    old_secret = read(identity / spec.secret_id_file).strip()
    new_secret = bao.request("POST", spec.secret_id_path, {}, token=create_token) \
        .get("data", {}).get("secret_id")
    if not isinstance(new_secret, str) or len(new_secret) < 20 or new_secret == old_secret:
        raise ValueError(f"replacement {spec.label} SecretID is invalid")
    staged = False
    try:
        write(output / spec.role_id_file, role_id)
        write(output / spec.secret_id_file, new_secret)
        new_token = login(bao, output)
        staged = True
    finally:
        if not staged:
            for name in (spec.role_id_file, spec.secret_id_file):
                (output / name).unlink(missing_ok=True)
            bao.request("POST", spec.secret_id_path + "/destroy",
                        {"secret_id": new_secret}, token=create_token)
    destroy_token = manager_login(bao) if manager_login is not None else new_token
    bao.request("POST", spec.secret_id_path + "/destroy",
                {"secret_id": old_secret}, token=destroy_token)
    require_revoked(bao, role_id, old_secret, spec)


def retire(
    bao, identity: Path, retired: Path, spec: RotationSpec,
    login: Callable[[object, Path], str],
    validate: Callable[..., Path], read: Callable[[Path], str],
    manager_login: Callable[[object], str] | None = None,
) -> None:
    identity = validate(identity, empty=False)
    retired = validate(retired, empty=False)
    if identity == retired:
        raise ValueError(f"retired {spec.label} identity must be separate")
    token = login(bao, identity)
    role_id = read(identity / spec.role_id_file).strip()
    secret_id = read(identity / spec.secret_id_file).strip()
    old_role = read(retired / spec.role_id_file).strip()
    old_secret = read(retired / spec.secret_id_file).strip()
    if old_role != role_id or old_secret == secret_id:
        raise ValueError(f"retired {spec.label} identity differs from active AppRole")
    destroy_token = manager_login(bao) if manager_login is not None else token
    bao.request("POST", spec.secret_id_path + "/destroy",
                {"secret_id": old_secret}, token=destroy_token)
    require_revoked(bao, old_role, old_secret, spec)
