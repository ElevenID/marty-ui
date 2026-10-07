#!/usr/bin/env python3
"""Export a live self-host OpenBao Raft snapshot and its recovery material."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

RECOVERY_FILES = ("selfhost-init.json", "root.token", "unseal.key")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise RuntimeError("OpenBao snapshot request redirected unexpectedly")


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
    return parser


def snapshot_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname not in (
        "127.0.0.1",
        "localhost",
        "::1",
    ):
        raise ValueError("self-host OpenBao snapshot URL must use local loopback HTTP")
    if (
        not parsed.port
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "self-host OpenBao snapshot URL must be a local origin with a port"
        )
    return value.rstrip("/") + "/v1/sys/storage/raft/snapshot"


def stream_snapshot(url: str, token: str, output: Path) -> str:
    request = urllib.request.Request(url, headers={"X-Vault-Token": token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    digest = hashlib.sha256()
    size = 0
    try:
        with opener.open(request, timeout=300) as response, output.open("wb") as sink:
            if response.status != 200:
                raise RuntimeError("OpenBao Raft snapshot request did not succeed")
            while chunk := response.read(1024 * 1024):
                sink.write(chunk)
                digest.update(chunk)
                size += len(chunk)
    except (OSError, urllib.error.HTTPError) as error:
        raise RuntimeError("OpenBao Raft snapshot request failed") from error
    if size == 0:
        raise RuntimeError("OpenBao returned an empty Raft snapshot")
    return digest.hexdigest()


def export(state_dir: Path, export_dir: Path, config_file: Path, bao_url: str) -> Path:
    state_dir = state_dir.expanduser().resolve()
    export_dir = export_dir.expanduser().resolve()
    config_file = config_file.expanduser().resolve()
    if not state_dir.is_dir():
        raise ValueError(f"OpenBao state directory does not exist: {state_dir}")
    if not config_file.is_file():
        raise ValueError(f"OpenBao config file does not exist: {config_file}")
    if 'storage "raft"' not in config_file.read_text(encoding="utf-8"):
        raise ValueError("self-host OpenBao export requires Raft storage")
    if export_dir == state_dir or state_dir in export_dir.parents:
        raise ValueError("OpenBao export directory must be outside the state directory")
    recovery = {}
    for name in RECOVERY_FILES:
        path = state_dir / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"OpenBao recovery file is missing or not regular: {name}")
        recovery[name] = path.read_bytes()
        if not recovery[name]:
            raise ValueError(f"OpenBao recovery file is empty: {name}")
    token = recovery["root.token"].decode("utf-8").strip()
    if not token:
        raise ValueError("OpenBao root token file is empty")
    url = snapshot_url(bao_url)
    export_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archive = export_dir / f"openbao-raft-{timestamp}-{uuid.uuid4().hex[:8]}.zip"
    partial = export_dir / (archive.name + ".partial")
    try:
        with tempfile.TemporaryDirectory() as temp:
            snapshot = Path(temp) / "raft.snap"
            snapshot_sha256 = stream_snapshot(url, token, snapshot)
            manifest = {
                "created_at": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "format": "marty-openbao-raft-snapshot-v1",
                "snapshot_sha256": snapshot_sha256,
                "warning": "Contains OpenBao root and unseal recovery material; protect as a top-tier secret.",
            }
            descriptor = os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with (
                os.fdopen(descriptor, "wb") as output,
                zipfile.ZipFile(output, "w") as bundle,
            ):
                bundle.write(snapshot, "raft.snap", compress_type=zipfile.ZIP_STORED)
                bundle.write(
                    config_file,
                    "openbao-selfhost.hcl",
                    compress_type=zipfile.ZIP_DEFLATED,
                )
                for name, value in recovery.items():
                    bundle.writestr(
                        f"recovery/{name}", value, compress_type=zipfile.ZIP_DEFLATED
                    )
                bundle.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
            os.replace(partial, archive)
    finally:
        partial.unlink(missing_ok=True)
    return archive


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    args = build_parser(repo_root).parse_args()
    env_values = load_env_file(Path(args.env_file).expanduser().resolve())
    state_dir = args.state_dir or env_values.get("SELFHOST_OPENBAO_STATE_DIR", "")
    export_dir = args.export_dir or env_values.get("SELFHOST_OPENBAO_EXPORT_DIR", "")
    if not state_dir or not export_dir:
        raise SystemExit(
            "SELFHOST_OPENBAO_STATE_DIR and SELFHOST_OPENBAO_EXPORT_DIR are required"
        )
    port = env_values.get("SELFHOST_OPENBAO_HOST_PORT", "18200")
    bao_url = args.bao_url or f"http://127.0.0.1:{port}"
    try:
        archive = export(
            Path(state_dir), Path(export_dir), Path(args.config_file), bao_url
        )
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from error
    print(f"Exported OpenBao Raft snapshot archive: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
