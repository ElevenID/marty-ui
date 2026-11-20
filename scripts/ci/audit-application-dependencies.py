"""Require a clean npm audit of the committed application dependency profile.

This adds the same npm scanner scope used for the full frontend lock. It does
not replace the existing Bun/full-lock audit or introduce a disposition.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = Path("ui/profiles/application")
INPUTS = ("package.json", "package-lock.json")
COMMAND = ("npm", "audit", "--json", "--omit=optional", "--package-lock-only", "--audit-level=low")
MAX_INPUT_BYTES = 8 * 1024 * 1024

_spec = importlib.util.spec_from_file_location("ui_dependency_audit_policy", Path(__file__).with_name("audit-ui-dependencies.py"))
assert _spec is not None and _spec.loader is not None
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)


def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    """Read only the two fixed, regular profile inputs, without following links."""
    directory = root.resolve()
    for part in PROFILE.parts:
        directory /= part
        policy.require(stat.S_ISDIR(directory.lstat().st_mode), "Application profile directory is not ordinary")
    for name in (".npmrc", ".npm-extension.mjs", ".npm-extension.cjs", "npm-shrinkwrap.json"):
        policy.require(not os.path.lexists(directory / name), "Unreviewed application audit configuration")
    result = {}
    for name in INPUTS:
        descriptor = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(descriptor)
            policy.require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_INPUT_BYTES,
                           "Application audit input must be a bounded regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                content = source.read(MAX_INPUT_BYTES + 1)
            policy.require(len(content) == metadata.st_size, "Application audit input changed while reading")
            policy.document(content.decode("utf-8"))
            result[name] = (content, stat.S_IMODE(metadata.st_mode))
        finally:
            os.close(descriptor)
    return result


def audit(root: Path) -> None:
    before = snapshot(root)
    executable = shutil.which(COMMAND[0])
    policy.require(executable is not None, "Missing dependency scanner")
    try:
        with tempfile.TemporaryDirectory(prefix="marty-application-audit-") as temporary:
            state = Path(temporary)
            for name in ("user-config", "global-config"):
                (state / name).write_text("", encoding="utf-8")
            environment = {key: value for key, value in os.environ.items() if key in {
                "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SystemRoot", "ComSpec", "USERPROFILE", "LOCALAPPDATA",
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
                "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
            }}
            environment.update({
                "npm_config_userconfig": str(state / "user-config"),
                "npm_config_globalconfig": str(state / "global-config"),
                "npm_config_cache": str(state / "cache"),
                "npm_config_registry": "https://registry.npmjs.org",
                "npm_config_ignore_scripts": "true",
            })
            result = subprocess.run([executable, *COMMAND[1:]], cwd=root / PROFILE, env=environment,
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8",
                                    timeout=120, check=False)
            policy.require(result.returncode in (0, 1), "Dependency scanner failed")
            present = policy.npm_findings(policy.document(result.stdout))
            policy.require(present == (result.returncode == 1), "Inconsistent npm audit result")
    finally:
        policy.require(snapshot(root) == before, "Application audit changed a committed profile input")
    print("Application dependency profile audit passed without findings")


def main() -> int:
    if len(sys.argv) != 1:
        print("Application dependency audit accepts no arguments", file=sys.stderr)
        return 1
    try:
        audit(ROOT)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        # Neither scanner documents nor scanner stderr are trusted output.
        print("Application dependency audit refused; inspect scanner findings", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
