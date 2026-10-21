"""Bind beta upgrades to the active private connector input; never emit a token."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


class TunnelInputError(RuntimeError):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise TunnelInputError("Beta tunnel credential/configuration binding failed")


def private_input(path: Path) -> tuple[Path, bytes]:
    absolute = path.absolute()
    require(absolute.resolve(strict=True) == absolute)
    for part in (absolute, *absolute.parents):
        require(not part.name.lower().startswith("onedrive"))
        metadata = part.lstat()
        require(not stat.S_ISLNK(metadata.st_mode))
        require(not (getattr(metadata, "st_file_attributes", 0) & 0x400))
    before = absolute.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 16384)
    if os.name == "nt":
        script = """$ErrorActionPreference='Stop'
$acl=Get-Acl -LiteralPath $env:BETA_TUNNEL_PRIVATE_INPUT
$allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if($owner -notin $allowed){throw 'Private credential owner refused'}
foreach($rule in $acl.Access){
  if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Private credential access refused'}
}
"""
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env={**os.environ, "BETA_TUNNEL_PRIVATE_INPUT": str(absolute)},
            capture_output=True,
            timeout=30,
        )
        require(result.returncode == 0)
    else:
        require(before.st_uid == os.getuid() and before.st_mode & 0o077 == 0)
    with absolute.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        content = stream.read(16385)
    after = absolute.stat()
    # Reading may update atime; identity, custody mode and content timestamps
    # must remain stable across the actual opened file and final pathname.
    for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns"):
        require(
            getattr(opened, field) == getattr(before, field) == getattr(after, field)
        )
    # Windows Python versions differ on fstat creation/change-time semantics.
    # Compare pathname ctime to the same pathname API, not to the descriptor API.
    require(before.st_ctime_ns == after.st_ctime_ns)
    require(len(content) == before.st_size)
    return absolute, content


def token_from_input(content: bytes) -> str:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeError:
        raise TunnelInputError(
            "Beta tunnel credential/configuration binding failed"
        ) from None
    match = re.fullmatch(r"TUNNEL_TOKEN=([A-Za-z0-9_+/=-]{32,16000})\r?\n?", text)
    require(match is not None)
    return match.group(1)


def bind_active(token: str, container: dict, *, prepare_legacy_migration: bool = False) -> str:
    require(container["State"]["Running"] is True)
    labels = container["Config"]["Labels"]
    require(labels.get("com.docker.compose.project") == "elevenid-beta")
    require(labels.get("com.docker.compose.service") == "cloudflared")
    values = [
        item.split("=", 1)[1]
        for item in container["Config"]["Env"]
        if item.startswith("TUNNEL_TOKEN=")
    ]
    require(values == [token] or (prepare_legacy_migration and values == []))
    command = container["Config"]["Cmd"]
    require(isinstance(command, list) and all(isinstance(arg, str) for arg in command))
    entrypoint = container["Config"].get("Entrypoint") or []
    require(
        isinstance(entrypoint, list) and all(isinstance(arg, str) for arg in entrypoint)
    )
    if prepare_legacy_migration:
        # Only the exact former repository command is migratable. This mode
        # prepares configuration; ordinary deployment still rejects argv tokens.
        require(command == ["tunnel", "--no-autoupdate", "run", "--token", token])
        require(not any(token in arg or "--token" in arg for arg in entrypoint))
    else:
        require(not any(
            token in arg or arg == "--token" or arg.startswith("--token=")
            for arg in [*entrypoint, *command]
        ))
    identity = container["Id"]
    require(re.fullmatch(r"[a-f0-9]{64}", identity) is not None)
    return identity


def inspect_active() -> dict:
    result = subprocess.run(
        [
            "docker",
            "ps",
            "--no-trunc",
            "--quiet",
            "--filter",
            "label=com.docker.compose.project=elevenid-beta",
            "--filter",
            "label=com.docker.compose.service=cloudflared",
        ],
        capture_output=True,
        timeout=30,
    )
    require(result.returncode == 0)
    ids = result.stdout.decode().split()
    require(len(ids) == 1 and re.fullmatch(r"[a-f0-9]{64}", ids[0]) is not None)
    result = subprocess.run(
        ["docker", "inspect", ids[0]], capture_output=True, timeout=30
    )
    require(result.returncode == 0 and len(result.stdout) <= 262144)
    containers = json.loads(result.stdout)
    require(isinstance(containers, list) and len(containers) == 1)
    return containers[0]


def override_text(path: Path) -> str:
    # Reset only the legacy inline value. Other connector settings survive.
    # Compose then resolves the protected env_file, without credential argv.
    return (
        "services:\n  cloudflared:\n    command: [tunnel, --no-autoupdate, run]\n"
        "    environment:\n      TUNNEL_TOKEN: !reset null\n    env_file:\n      - "
        + json.dumps(str(path))
        + "\n"
    )


def validate(
    path: Path,
    expected_fingerprint: str | None = None,
    expected_container: str | None = None,
    *,
    prepare_legacy_migration: bool = False,
) -> dict:
    require(bool(expected_fingerprint) == bool(expected_container))
    path, content = private_input(path)
    fingerprint = hashlib.sha256(content).hexdigest()
    if expected_fingerprint:
        require(fingerprint == expected_fingerprint)
    identity = bind_active(token_from_input(content), inspect_active(),
                           prepare_legacy_migration=prepare_legacy_migration)
    if expected_container:
        require(identity == expected_container)
    return {
        "credential_file": str(path),
        "credential_sha256": fingerprint,
        "connector_id": identity,
        "scope": "BETA_TUNNEL_INPUT_ONLY",
        "productionDemoReady": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credential-env-file", type=Path, required=True)
    parser.add_argument("--expected-fingerprint")
    parser.add_argument("--expected-container")
    parser.add_argument("--override-output", type=Path)
    parser.add_argument("--prepare-legacy-migration", action="store_true")
    args = parser.parse_args()
    try:
        require(not args.prepare_legacy_migration or args.override_output is not None)
        binding = validate(
            args.credential_env_file, args.expected_fingerprint, args.expected_container,
            prepare_legacy_migration=args.prepare_legacy_migration,
        )
        if args.override_output:
            path = args.override_output.absolute()
            require(
                path.parent.resolve(strict=True) == path.parent
                and not path.is_symlink()
            )
            text = override_text(Path(binding["credential_file"]))
            if path.exists():
                require(path.is_file() and path.read_text(encoding="utf8") == text)
            else:
                with path.open("x", encoding="utf8") as stream:
                    stream.write(text)
            # Recheck custody and binding after writing only public configuration.
            validate(
                args.credential_env_file,
                binding["credential_sha256"],
                binding["connector_id"],
                prepare_legacy_migration=args.prepare_legacy_migration,
            )
        if args.prepare_legacy_migration:
            binding["connector_migration_required"] = True
        print(json.dumps(binding))
        return 0
    except Exception:
        # No content, native stderr, process environment or raw exception in output.
        print("Beta tunnel private input validation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
