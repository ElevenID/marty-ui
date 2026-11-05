"""Explicit read credentials for private web OCI proofs and fixed Actions intake.

Public installer/file verification keeps its independent anonymous runner. These
transports never inherit Docker helpers, token stores, proxy or TLS overrides.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

import ui_release as ui
import verify_installer_provenance as verifier
import website_release as web

CONFIG_LIMIT = 64 * 1024
ERROR_LIMIT = 64 * 1024
ARCHIVE_LIMIT = 32 * 1024 * 1024


def opaque_credential(value: object, maximum: int) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and all(0x21 <= ord(character) <= 0x7e for character in value))


def environment(directory: str) -> dict[str, str]:
    result = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    result.update(HOME=directory, USERPROFILE=directory, GH_CONFIG_DIR=directory,
                  XDG_CONFIG_HOME=directory, XDG_CACHE_HOME=directory,
                  GH_PROMPT_DISABLED="1", GH_HOST="github.com")
    return result


def error_category(stderr: bytes) -> str:
    # Report a fixed category, never remote text, credential values or URLs.
    text = stderr.lower()
    if any(value in text for value in (b"unauthorized", b"authentication required", b"http 401")):
        return "authentication"
    if any(value in text for value in (b"denied", b"forbidden", b"http 403")):
        return "access denied"
    if any(value in text for value in (b"creating sigstore verifier", b"no valid sigstore", b"trusted root")):
        return "trust initialization"
    if any(value in text for value in (b"certificate", b"signature", b"identity", b"attestation")):
        return "proof verification"
    return "remote command"


def command(args: list[str], *, env: dict[str, str], directory: str,
            maximum: int, label: str, timeout: int = 120) -> bytes:
    """Bound both subprocess streams while reading; kill on overflow or timeout."""
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=directory, env=env)
    except OSError:
        raise ValueError(label + " failed (process start)") from None

    def read(stream, limit):
        data = bytearray()
        try:
            while chunk := stream.read(min(64 * 1024, limit + 1 - len(data))):
                data.extend(chunk)
                if len(data) > limit:
                    process.kill()
                    return bytes(data[:limit]), True
            return bytes(data), False
        finally:
            stream.close()

    with ThreadPoolExecutor(max_workers=2) as workers:
        output = workers.submit(read, process.stdout, maximum)
        errors = workers.submit(read, process.stderr, ERROR_LIMIT)
        timed_out = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            code = process.wait()
        stdout, output_overflow = output.result()
        stderr, error_overflow = errors.result()
    if timed_out:
        raise ValueError(label + " failed (timeout)")
    if output_overflow or error_overflow:
        raise ValueError(label + " failed (output limit)")
    if code != 0:
        raise ValueError(label + " failed (" + error_category(stderr) + ")")
    return stdout


def json_object(raw: bytes) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            ui.require(key not in result, "registry config has duplicate fields")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("registry config is not valid JSON") from None
    ui.require(isinstance(value, dict), "registry config must be an object")
    return value


def registry_auth(path: Path) -> bytes:
    """Return only static ghcr.io basic auth; never execute credential helpers."""
    verifier.local_file(path, maximum=CONFIG_LIMIT, private=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            ui.require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= CONFIG_LIMIT,
                       "registry config must be a bounded regular file")
            if os.name == "posix":
                ui.require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
                           "registry config must be owned and readable only by the operator")
            raw = stream.read(CONFIG_LIMIT + 1)
    except OSError:
        raise ValueError("registry config is unavailable") from None
    ui.require(0 < len(raw) <= CONFIG_LIMIT, "registry config exceeds its limit")
    value = json_object(raw)
    entries = value.get("auths")
    ui.require(isinstance(entries, dict), "registry config requires static ghcr.io auth")
    entry = entries.get("ghcr.io")
    ui.require(isinstance(entry, dict) and set(entry) == {"auth"},
               "registry config requires exactly one static ghcr.io auth value")
    encoded = entry["auth"]
    ui.require(isinstance(encoded, str) and 0 < len(encoded) <= 8192, "invalid ghcr.io auth encoding")
    try:
        decoded = base64.b64decode(encoded, validate=True)
        username, separator, token = decoded.decode("ascii").partition(":")
    except (ValueError, UnicodeError):
        raise ValueError("invalid ghcr.io auth encoding") from None
    ui.require(base64.b64encode(decoded).decode("ascii") == encoded and separator == ":"
               and opaque_credential(username, 128) and ":" not in username
               and opaque_credential(token, 4096),
               "invalid ghcr.io static username/token")
    # All other registries, helpers, headers, contexts and proxy settings from
    # the explicitly selected source file are deliberately absent in this copy.
    return ui.canonical({"auths": {"ghcr.io": {"auth": encoded}}})


def registry_command(args: list[str], *, config: Path) -> str:
    held = registry_auth(config)
    with tempfile.TemporaryDirectory(prefix="marty-web-registry-") as temporary:
        path = Path(temporary) / "config.json"
        with path.open("xb") as stream:
            stream.write(held)
        path.chmod(0o600)
        env = environment(temporary)
        env["DOCKER_CONFIG"] = temporary
        raw = command(args, env=env, directory=temporary, maximum=verifier.MAX_OUTPUT,
                      label="private web OCI verification")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("private web OCI verifier returned invalid text") from None


class GitHubReader:
    """One selected token snapshot; GH_TOKEN is the fixed default, with no fallback."""

    def __init__(self, *, gh: Path, repository: str, run_id: str, attempt: str,
                 kind: str, token_env: str | None = "GH_TOKEN"):
        ui.require(repository in web.REPOSITORIES and kind in {"website", "application"}
                   and all(isinstance(value, str) and ui.RUN.fullmatch(value) for value in (run_id, attempt)),
                   "invalid authenticated Actions intake selection")
        verifier.local_file(gh)
        ui.require(token_env in {"GH_TOKEN", "GITHUB_TOKEN"},
                   "Actions intake requires --github-token-env GH_TOKEN or GITHUB_TOKEN")
        token = os.environ.get(token_env, "")
        ui.require(opaque_credential(token, 4096),
                   "explicit GitHub API token is missing or malformed")
        self.gh, self._token = gh, token
        self.prefix = f"repos/{repository}/actions"
        self.attempt_endpoint = f"{self.prefix}/runs/{run_id}/attempts/{attempt}"
        name = f"web-{kind}-{run_id}-{attempt}"
        self.artifacts_endpoint = f"{self.prefix}/runs/{run_id}/artifacts?name={name}&per_page=100"

    def _read(self, endpoint: str, *, maximum: int) -> bytes:
        metadata = endpoint in {self.attempt_endpoint, self.artifacts_endpoint}
        archive = re.fullmatch(re.escape(self.prefix) + r"/artifacts/[1-9][0-9]*/zip", endpoint) is not None
        ui.require((metadata and maximum == verifier.MAX_OUTPUT)
                   or (archive and type(maximum) is int and 0 < maximum <= ARCHIVE_LIMIT),
                   "GitHub intake endpoint or output bound is not allowed")
        with tempfile.TemporaryDirectory(prefix="marty-web-api-") as temporary:
            env = environment(temporary)
            env["GH_TOKEN"] = self._token
            return command([str(self.gh), "api", "--hostname", "github.com", "--method", "GET",
                            "-H", "X-GitHub-Api-Version: 2022-11-28", endpoint],
                           env=env, directory=temporary, maximum=maximum,
                           label="web Actions intake", timeout=180)

    def attempt(self) -> str:
        return self._read(self.attempt_endpoint, maximum=verifier.MAX_OUTPUT).decode("utf-8")

    def artifacts(self) -> str:
        return self._read(self.artifacts_endpoint, maximum=verifier.MAX_OUTPUT).decode("utf-8")

    def archive(self, artifact_id: int, *, maximum: int) -> bytes:
        ui.require(type(artifact_id) is int and artifact_id > 0, "invalid Actions artifact ID")
        return self._read(f"{self.prefix}/artifacts/{artifact_id}/zip", maximum=maximum)
