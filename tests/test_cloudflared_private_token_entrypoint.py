"""Execute the real shell entrypoint with a controlled child; never contact Cloudflare."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "CONTROLLED_FILE_TOKEN_ONLY"


@pytest.mark.parametrize("case", ["valid", "empty", "missing"])
def test_file_token_never_enters_child_arguments_or_logs(tmp_path, case):
    shell = (
        str(Path("C:/Program Files/Git/bin/bash.exe"))
        if os.name == "nt"
        else shutil.which("sh")
    )
    if not shell or not Path(shell).is_file():
        pytest.skip("requires POSIX shell for the controlled entrypoint check")
    entrypoint = tmp_path / "entrypoint.sh"
    entrypoint.write_text(
        (ROOT / "scripts/cloudflared-selfhost.sh").read_text(encoding="utf8"),
        encoding="utf8",
        newline="\n",
    )
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    child = binary_dir / "cloudflared"
    child.write_text(
        """#!/bin/sh
set -eu
test "$#" -eq 3
test "$1" = tunnel
test "$2" = --no-autoupdate
test "$3" = run
test "$TUNNEL_TOKEN" = CONTROLLED_FILE_TOKEN_ONLY
test -z "${CLOUDFLARE_TUNNEL_TOKEN_FILE+x}"
printf '{"scope":"CONTROLLED_ENTRYPOINT_CHILD_ONLY","pass":true}\\n'
""",
        encoding="utf8",
        newline="\n",
    )
    child.chmod(0o700)
    if case != "missing":
        (tmp_path / "credential.txt").write_bytes(
            (TOKEN + "\r\n").encode() if case == "valid" else b"\r\n"
        )
    env = {
        **os.environ,
        "CLOUDFLARE_TUNNEL_TOKEN_FILE": "credential.txt",
        "TUNNEL_TOKEN": "CONTROLLED_OLD_ENV_VALUE",
        "PATH": str(binary_dir) + os.pathsep + os.environ["PATH"],
    }
    result = subprocess.run(
        [shell, "entrypoint.sh"], cwd=tmp_path, env=env, capture_output=True, timeout=10
    )
    assert TOKEN.encode() not in result.stdout + result.stderr
    if case == "valid":
        assert result.returncode == 0 and result.stderr == b""
        assert json.loads(result.stdout) == {
            "scope": "CONTROLLED_ENTRYPOINT_CHILD_ONLY",
            "pass": True,
        }
    else:
        assert result.returncode == 1 and result.stdout == b""
        assert b"token file" in result.stderr
