"""Backup-scope contract for the rendered self-host Compose model."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest


GATE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts/check_selfhost_recovery_scope.py")
)["recovery_scope"]


def model(root: Path) -> dict:
    services = {}
    for service, target, subdir in (
        ("postgres", "/var/lib/postgresql/data", "postgres"),
        ("redis", "/data", "redis"),
        ("applicant", "/app/data", "applicant"),
    ):
        services[service] = {
            "volumes": [
                {"type": "bind", "source": str(root / subdir), "target": target}
            ]
        }
    services["gateway"] = {
        "volumes": [
            {"type": "bind", "source": str(root / "config"),
             "target": "/app/config", "read_only": True}
        ]
    }
    return {"services": services}


def test_records_complete_writable_state_scope_without_secret_values(tmp_path: Path) -> None:
    result = GATE(model(tmp_path), tmp_path, "a" * 64)
    assert result["qualification"] == "unqualified"
    assert result["compose_model_sha256"] == "a" * 64
    assert result["writable_bind_mounts"] == [
        {"service": "applicant", "target": "/app/data", "state_subdir": "applicant"},
        {"service": "postgres", "target": "/var/lib/postgresql/data", "state_subdir": "postgres"},
        {"service": "redis", "target": "/data", "state_subdir": "redis"},
    ]
    assert "OpenBao state/export" in result["separate_recovery_inputs"]


@pytest.mark.parametrize("keep_local_postgres", [False, True])
def test_external_database_cannot_be_claimed_by_a_local_state_inventory(
    tmp_path: Path, keep_local_postgres: bool,
) -> None:
    value = model(tmp_path)
    if not keep_local_postgres:
        del value["services"]["postgres"]
    value["secrets"] = {
        "marty_db_password": {"file": str(tmp_path / "secrets/external_postgres_password")}
    }
    with pytest.raises(ValueError, match="external databases need a separate"):
        GATE(value, tmp_path, "a" * 64)


@pytest.mark.parametrize("variable,value", [
    ("DATABASE_URL_TEMPLATE", "postgresql://marty:$${MARTY_DB_PASSWORD}@pooler.example.test:5432/postgres?sslmode=verify-full"),
    ("DATABASE_URL", "postgresql://user:sensitive-password@pooler.example.test/postgres"),
    ("DATABASE_URL", "postgresql://marty:private@postgres:5432/marty?host=pooler.example.test"),
    ("DATABASE_URL_FILE", "/run/secrets/uninspected_database_url"),
])
def test_local_placeholder_postgres_does_not_cover_external_application_data(
    tmp_path: Path, variable: str, value: str,
) -> None:
    rendered = model(tmp_path)
    rendered["services"]["gateway"]["environment"] = {variable: value}
    with pytest.raises(ValueError, match="external databases need a separate") as error:
        GATE(rendered, tmp_path, "a" * 64)
    assert value not in str(error.value)
    assert "sensitive-password" not in str(error.value)


def test_local_database_templates_remain_accepted(tmp_path: Path) -> None:
    rendered = model(tmp_path)
    rendered["services"]["gateway"]["environment"] = {
        "DATABASE_URL_TEMPLATE": "postgresql+asyncpg://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty"
    }
    assert GATE(rendered, tmp_path, "a" * 64)["qualification"] == "unqualified"


@pytest.mark.parametrize("environment", [
    ["DATABASE_URL=postgresql://user:private@pooler.example.test/postgres"],
    "DATABASE_URL=postgresql://user:private@pooler.example.test/postgres",
    None,
])
def test_uninspectable_environment_cannot_hide_external_database(
    tmp_path: Path, environment: object,
) -> None:
    rendered = model(tmp_path)
    rendered["services"]["gateway"]["environment"] = environment
    with pytest.raises(ValueError, match="external databases need a separate") as error:
        GATE(rendered, tmp_path, "a" * 64)
    assert "private" not in str(error.value)


def test_project_scoped_redis_socket_is_ephemeral_and_not_backed_up(tmp_path: Path) -> None:
    value = model(tmp_path)
    value["name"] = "marty-qualification"
    value["volumes"] = {
        "redis-socket": {"name": "marty-qualification_redis-socket"}
    }
    value["services"]["redis"]["volumes"].append(
        {"type": "volume", "source": "redis-socket", "target": "/data/run"}
    )
    result = GATE(value, tmp_path, "a" * 64)
    assert result["ephemeral_project_volume_mounts"] == [
        {"service": "redis", "target": "/data/run", "source": "redis-socket"}
    ]
    value["volumes"]["redis-socket"]["name"] = "shared-redis-socket"
    with pytest.raises(ValueError, match="external or fixed name"):
        GATE(value, tmp_path, "a" * 64)


@pytest.mark.parametrize(
    "change",
    ["new-writable", "moved-state", "missing-state", "named-volume", "bad-mode"],
)
def test_rejects_incomplete_or_expanded_backup_scope(tmp_path: Path, change: str) -> None:
    value = deepcopy(model(tmp_path))
    if change == "new-writable":
        value["services"]["gateway"]["volumes"].append(
            {"type": "bind", "source": str(tmp_path / "new"), "target": "/app/new"}
        )
    elif change == "moved-state":
        value["services"]["postgres"]["volumes"][0]["source"] = str(
            tmp_path.parent / "outside-postgres"
        )
    elif change == "missing-state":
        value["services"]["applicant"]["volumes"] = []
    elif change == "named-volume":
        value["services"]["redis"]["volumes"][0].update(
            type="volume", source="unreviewed-redis"
        )
    else:
        value["services"]["postgres"]["volumes"][0]["read_only"] = "false"
    with pytest.raises(ValueError):
        GATE(value, tmp_path, "a" * 64)


def test_rejects_relative_or_filesystem_root_as_backup_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute non-root"):
        GATE(model(tmp_path), Path("relative"), "a" * 64)
    root = Path(tmp_path.anchor)
    with pytest.raises(ValueError, match="absolute non-root"):
        GATE(model(tmp_path), root, "a" * 64)


def test_rejects_symlinked_state_roots_and_subdirectories(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    with pytest.raises(ValueError, match="state root must not be a symlink"):
        GATE(model(alias), alias, "a" * 64)
    nested = alias / "nested"
    with pytest.raises(ValueError, match="state root must not be a symlink"):
        GATE(model(nested), nested, "a" * 64)

    (tmp_path / "outside").mkdir()
    (actual / "postgres").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="escaped backup root"):
        GATE(model(actual), actual, "a" * 64)


def test_rejects_outside_alias_even_when_it_resolves_to_the_expected_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    (root / "postgres").mkdir()
    alias = tmp_path / "postgres-alias"
    try:
        alias.symlink_to(root / "postgres", target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    value = model(root)
    value["services"]["postgres"]["volumes"][0]["source"] = str(alias)
    with pytest.raises(ValueError, match="escaped backup root"):
        GATE(value, root, "a" * 64)


@pytest.mark.parametrize("component", ["ancestor", "state-child"])
def test_symlink_boundary_is_enforced_on_hosts_without_symlink_creation(
    tmp_path: Path, monkeypatch, component: str
) -> None:
    root = tmp_path / "state"
    flagged = tmp_path if component == "ancestor" else root / "postgres"
    original = Path.is_symlink
    monkeypatch.setattr(
        Path, "is_symlink", lambda path: path == flagged or original(path)
    )
    with pytest.raises(
        ValueError,
        match="state root must not be a symlink|escaped backup root",
    ):
        GATE(model(root), root, "a" * 64)


def test_windows_junction_component_is_rejected(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "state"
    flagged = root / "postgres"
    original = getattr(Path, "is_junction", lambda _path: False)
    monkeypatch.setattr(
        Path, "is_junction", lambda path: path == flagged or original(path), raising=False
    )
    with pytest.raises(ValueError, match="escaped backup root"):
        GATE(model(root), root, "a" * 64)


def test_cli_emits_only_a_bound_unqualified_report_after_scope_passes(
    tmp_path: Path,
) -> None:
    checker = Path(__file__).resolve().parents[1] / "scripts/check_selfhost_recovery_scope.py"
    rendered = tmp_path / "compose.json"
    raw = json.dumps(model(tmp_path)).encode()
    rendered.write_bytes(raw)
    command = [sys.executable, str(checker), "--compose-model", str(rendered),
               "--state-root", str(tmp_path)]
    accepted = subprocess.run(command, capture_output=True, text=True, check=True)
    assert json.loads(accepted.stdout)["compose_model_sha256"] == hashlib.sha256(raw).hexdigest()
    value = model(tmp_path)
    value["services"]["gateway"]["volumes"][0]["read_only"] = False
    rendered.write_text(json.dumps(value), encoding="utf-8")
    rejected = subprocess.run(command, capture_output=True, text=True, check=False)
    assert rejected.returncode != 0
    assert rejected.stdout == ""
