#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def build_parser(repo_root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export the standalone self-host OpenBao state for backup or migration.")
    parser.add_argument("--env-file", default=str(repo_root / ".env.selfhost.production.local"))
    parser.add_argument("--state-dir", default="")
    parser.add_argument("--export-dir", default="")
    parser.add_argument("--config-file", default=str(repo_root / "docker" / "openbao-selfhost.hcl"))
    return parser


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    parser = build_parser(repo_root)
    args = parser.parse_args()

    env_file = Path(args.env_file).expanduser().resolve()
    env_values = load_env_file(env_file)

    state_dir_value = args.state_dir or env_values.get("SELFHOST_OPENBAO_STATE_DIR", "")
    export_dir_value = args.export_dir or env_values.get("SELFHOST_OPENBAO_EXPORT_DIR", "")
    config_file = Path(args.config_file).expanduser().resolve()

    if not state_dir_value:
        raise SystemExit("SELFHOST_OPENBAO_STATE_DIR is required via --state-dir or the env file.")
    if not export_dir_value:
        raise SystemExit("SELFHOST_OPENBAO_EXPORT_DIR is required via --export-dir or the env file.")

    state_dir = Path(state_dir_value).expanduser()
    export_dir = Path(export_dir_value).expanduser()

    state_dir = state_dir.resolve()
    export_dir = export_dir.resolve()

    if not state_dir.exists():
        raise SystemExit(f"OpenBao state directory does not exist: {state_dir}")
    if not config_file.exists():
        raise SystemExit(f"OpenBao config file does not exist: {config_file}")

    export_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    archive_base = export_dir / f"openbao-export-{timestamp}"

    with tempfile.TemporaryDirectory() as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        staged_root = temp_dir / archive_base.name
        staged_root.mkdir(parents=True, exist_ok=True)

        shutil.copy2(config_file, staged_root / "openbao-selfhost.hcl")
        shutil.copytree(state_dir, staged_root / "state")
        (staged_root / "manifest.json").write_text(
            json.dumps(
                {
                    "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "source_state_dir": str(state_dir),
                    "config_file": str(config_file),
                    "warning": "This archive contains OpenBao recovery material, including root token and unseal key data. Handle it like a top-tier secret.",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        archive_path = shutil.make_archive(str(archive_base), "zip", root_dir=temp_dir, base_dir=staged_root.name)

    print(f"Exported OpenBao state archive: {archive_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())