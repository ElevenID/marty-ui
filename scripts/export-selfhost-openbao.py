#!/usr/bin/env python3
"""Export a live self-host OpenBao Raft snapshot with snapshot-only authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
from provision_selfhost_snapshot_identity import checked_login, snapshot_origin  # noqa: E402
from selfhost_openbao_client import Bao  # noqa: E402


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
    parser.add_argument("--snapshot-identity-dir", default="")
    return parser


def snapshot_url(value: str) -> str:
    return snapshot_origin(value) + "/v1/sys/storage/raft/snapshot"


def stream_snapshot(url: str, token: str, output: Path, ca_file: Path) -> str:
    request = urllib.request.Request(url, headers={"X-Vault-Token": token})
    tls_context = ssl.create_default_context(cafile=str(ca_file))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=tls_context),
        NoRedirect(),
    )
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as sink, opener.open(request, timeout=300) as response:
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


def export(state_dir: Path, export_dir: Path, config_file: Path, bao_url: str,
           snapshot_identity_dir: Path) -> Path:
    state_dir = state_dir.expanduser().resolve()
    export_dir = export_dir.expanduser().absolute()
    config_file = config_file.expanduser().resolve()
    if not state_dir.is_dir():
        raise ValueError(f"OpenBao state directory does not exist: {state_dir}")
    if not config_file.is_file():
        raise ValueError(f"OpenBao config file does not exist: {config_file}")
    if 'storage "raft"' not in config_file.read_text(encoding="utf-8"):
        raise ValueError("self-host OpenBao export requires Raft storage")
    url = snapshot_url(bao_url)
    ca_file = state_dir / "tls" / "ca.crt"
    if not ca_file.is_file() or ca_file.is_symlink():
        raise ValueError("OpenBao public TLS CA is missing from KMS state")
    if (export_dir.is_symlink() or not export_dir.is_dir()
            or (os.name == "posix" and stat.S_IMODE(export_dir.stat().st_mode) != 0o700)):
        raise ValueError("OpenBao export directory must already be owner-private")
    export_dir = export_dir.resolve()
    if export_dir == state_dir or state_dir in export_dir.parents:
        raise ValueError("OpenBao export directory must be outside the state directory")
    token = checked_login(Bao(bao_url, ca_file, ""), snapshot_identity_dir.expanduser().absolute())
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archive = export_dir / f"openbao-raft-{timestamp}-{uuid.uuid4().hex[:8]}.zip"
    partial = export_dir / (archive.name + ".partial")
    try:
        with tempfile.TemporaryDirectory() as temp:
            snapshot = Path(temp) / "raft.snap"
            snapshot_sha256 = stream_snapshot(url, token, snapshot, ca_file)
            manifest = {
                "created_at": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "format": "marty-openbao-raft-snapshot-v2",
                "snapshot_sha256": snapshot_sha256,
                "warning": "Contains all OpenBao Raft key custody state; hold unseal material separately.",
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
