#!/usr/bin/env python3
"""Export a live self-host OpenBao Raft snapshot with snapshot-only authority."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from selfhost_native_operator import operator_bytes  # noqa: E402


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
    parser = argparse.ArgumentParser(
        description="Export a live self-host OpenBao Raft snapshot for recovery."
    )
    parser.add_argument(
        "--env-file", default=str(repo_root / ".env.selfhost.production.local")
    )
    parser.add_argument("--state-dir", default="")
    parser.add_argument("--export-dir", default="")
    parser.add_argument(
        "--config-file", default=str(repo_root / "docker/openbao-selfhost.hcl")
    )
    parser.add_argument("--bao-url", default="")
    parser.add_argument("--snapshot-identity-dir", default="")
    return parser


def export(state_dir: Path, export_dir: Path, config_file: Path, bao_url: str,
           snapshot_identity_dir: Path) -> Path:
    result = operator_bytes(
        Path(__file__).resolve().parents[1], "operator", "export-snapshot",
        str(state_dir.expanduser().absolute()), str(export_dir.expanduser().absolute()),
        str(config_file.expanduser().absolute()), bao_url,
        str(snapshot_identity_dir.expanduser().absolute()),
    )
    return Path(result.decode("utf-8").strip())


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    args = build_parser(repo_root).parse_args()
    env_values = load_env_file(Path(args.env_file).expanduser().resolve())
    state_dir = args.state_dir or env_values.get("SELFHOST_OPENBAO_STATE_DIR", "")
    export_dir = args.export_dir or env_values.get("SELFHOST_OPENBAO_EXPORT_DIR", "")
    identity_dir = (args.snapshot_identity_dir
                    or env_values.get("SELFHOST_OPENBAO_SNAPSHOT_IDENTITY_DIR", ""))
    if not state_dir or not export_dir or not identity_dir:
        raise SystemExit(
            "OpenBao state, export and snapshot identity directories are required"
        )
    port = env_values.get("SELFHOST_OPENBAO_HOST_PORT", "18200")
    bao_url = args.bao_url or f"https://127.0.0.1:{port}"
    try:
        archive = export(
            Path(state_dir), Path(export_dir), Path(args.config_file), bao_url,
            Path(identity_dir),
        )
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from error
    print(f"Exported OpenBao Raft snapshot archive: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
