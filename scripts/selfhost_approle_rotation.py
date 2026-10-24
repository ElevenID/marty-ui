"""Independent AppRole rotation descriptions and retired-credential proof."""

from __future__ import annotations

from dataclasses import dataclass
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
