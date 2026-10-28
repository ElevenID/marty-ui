"""Authenticate a closed Ubuntu package bundle for an installer-only VM trial.

This module neither installs packages nor authorizes a rootless daemon.  The
caller must independently bind the bundle, dpkg status, and this code to the
current VM before treating a returned observation as current evidence.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request


ARCHIVE_FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
BASE = "https://archive.ubuntu.com/ubuntu/"
SECURITY = "https://security.ubuntu.com/ubuntu/"
POCKETS = {
    "noble": BASE,
    "noble-updates": BASE,
    "noble-security": SECURITY,
}
COMPONENTS = ("main", "universe")
REQUIRED = ("uidmap", "rootlesskit")
OPTIONAL = ("slirp4netns", "fuse-overlayfs")
DEPENDENCIES = ("libsubid4",)
TARGETS = REQUIRED + OPTIONAL + DEPENDENCIES
MAX_INRELEASE = 2 * 1024 * 1024
MAX_INDEX = 32 * 1024 * 1024
MAX_PLAIN_INDEX = 256 * 1024 * 1024
MAX_DEB = 64 * 1024 * 1024
MAX_STATUS = 16 * 1024 * 1024
EXPECTED_VERSIONS = {
    "uidmap": "1:4.13+dfsg1-4ubuntu3.2",
    "libsubid4": "1:4.13+dfsg1-4ubuntu3.2",
    "rootlesskit": "1.1.1-1ubuntu0.24.04.3",
    "slirp4netns": "1.2.1-1build2",
    "fuse-overlayfs": "1.13-1",
}
FIELD = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*\Z")
VERSION = re.compile(r"[A-Za-z0-9.+:~_-]{1,96}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")


class Refused(ValueError):
    """A fixed, nonsensitive admission refusal."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Refused(reason)


def private_file(path: Path, maximum: int, uid: int | None = None) -> bytes:
    """Read bounded ordinary single-link bytes from a held inode, then rebind."""
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 <= before.st_size <= maximum
                and (uid is None or before.st_uid == uid), "bundle file custody invalid")
        read_fd = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_CLOEXEC)
        try:
            require(os.fstat(read_fd).st_ino == before.st_ino,
                    "bundle file reopen changed")
            chunks = []
            remaining = before.st_size
            while remaining:
                part = os.read(read_fd, min(65536, remaining))
                require(bool(part), "bundle file truncated")
                chunks.append(part)
                remaining -= len(part)
            require(os.read(read_fd, 1) == b"", "bundle file grew")
            after = os.fstat(read_fd)
        finally:
            os.close(read_fd)
        named = path.stat(follow_symlinks=False)
        attrs = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                 "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) == getattr(named, key)
                    for key in attrs), "bundle file identity changed")
        return b"".join(chunks)
    finally:
        os.close(fd)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise Refused("Ubuntu archive redirect refused")


def fixed_url(pocket: str, relative: str) -> str:
    require(pocket in POCKETS and _safe_relative(relative),
            "Ubuntu archive URL invalid")
    if relative.startswith("pool/"):
        require(relative.endswith(".deb") and re.fullmatch(r"pool/[A-Za-z0-9._/+~-]+", relative)
                is not None, "Ubuntu package URL invalid")
        return POCKETS[pocket] + relative
    allowed = {f"dists/{pocket}/InRelease"} | {
        f"dists/{pocket}/{component}/binary-amd64/Packages.xz"
        for component in COMPONENTS
    }
    require(relative in allowed,
            "Ubuntu archive URL path invalid")
    return POCKETS[pocket] + relative


def fetch_fixed(pocket: str, relative: str, maximum: int) -> bytes:
    """Fetch only a closed Ubuntu path, without proxy, redirects, or ambient auth."""
    require(maximum in (MAX_INRELEASE, MAX_INDEX, MAX_DEB),
            "Ubuntu archive byte limit invalid")
    url = fixed_url(pocket, relative)
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in
            ("archive.ubuntu.com", "security.ubuntu.com") and not parsed.username
            and not parsed.password and parsed.port is None and not parsed.query
            and not parsed.fragment, "Ubuntu archive host invalid")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/octet-stream"})
    try:
        with opener.open(request, timeout=25) as response:
            require(response.status == 200 and response.geturl() == url,
                    "Ubuntu archive response invalid")
            chunks = []
            remaining = maximum + 1
            while remaining:
                part = response.read(min(65536, remaining))
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            raw = b"".join(chunks)
    except (OSError, urllib.error.URLError) as exc:
        raise Refused("Ubuntu archive fetch failed") from exc
    require(len(raw) <= maximum, "Ubuntu archive response oversized")
    return raw


def _paragraphs(raw: bytes, maximum: int) -> list[dict[str, str]]:
    require(len(raw) <= maximum, "package metadata oversized")
    try:
        value = raw.decode("utf-8")
    except UnicodeError as exc:
        raise Refused("package metadata encoding invalid") from exc
    out = []
    for paragraph in value.strip().split("\n\n"):
        if not paragraph:
            continue
        row: dict[str, str] = {}
        previous = None
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                require(previous is not None, "package continuation invalid")
                row[previous] += "\n" + line[1:]
                continue
            key, sep, field = line.partition(":")
            require(bool(sep) and bool(FIELD.fullmatch(key)) and key not in row,
                    "package field invalid")
            row[key] = field.lstrip(" ")
            previous = key
        out.append(row)
    require(bool(out), "package metadata empty")
    return out


def _release_payload(raw: bytes) -> bytes:
    require(raw.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\n"),
            "archive signature envelope invalid")
    head, marker, tail = raw.partition(b"\n\n")
    require(bool(marker) and (b"Hash: SHA256" in head or b"Hash: SHA512" in head) and
            b"\n-----BEGIN PGP SIGNATURE-----" in tail,
            "archive signature envelope invalid")
    return tail.split(b"\n-----BEGIN PGP SIGNATURE-----", 1)[0]


def _release_fields(payload: bytes) -> tuple[dict[str, str], dict[str, tuple[int, str]]]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise Refused("archive metadata encoding invalid") from exc
    fields: dict[str, str] = {}
    hashes: dict[str, tuple[int, str]] = {}
    in_hashes = False
    for line in lines:
        if line == "SHA256:":
            require(not in_hashes, "archive SHA256 section duplicated")
            in_hashes = True
            continue
        if line.startswith(" "):
            if in_hashes:
                match = re.fullmatch(r" ([0-9a-f]{64}) +([0-9]{1,12}) +([^ ]+)", line)
                require(match is not None, "archive SHA256 row invalid")
                digest, size, path = match.groups()
                require(path not in hashes and _safe_relative(path),
                        "archive SHA256 path invalid")
                hashes[path] = (int(size), digest)
            continue
        if in_hashes:
            in_hashes = False
        key, sep, value = line.partition(":")
        if sep:
            require(key not in fields, "archive field duplicated")
            fields[key] = value.strip()
    require(bool(hashes), "archive SHA256 unavailable")
    return fields, hashes


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return (bool(value) and not value.startswith("/") and "\\" not in value
            and "//" not in value and all(part not in ("", ".", "..") for part in path.parts)
            and str(path) == value)


def _utc(value: str) -> dt.datetime:
    from email.utils import parsedate_to_datetime
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError) as exc:
        raise Refused("archive time invalid") from exc
    require(parsed is not None and parsed.tzinfo is not None,
            "archive time invalid")
    return parsed.astimezone(dt.timezone.utc)


def verify_inrelease(path: Path, keyring: Path, pocket: str,
                     now: dt.datetime) -> tuple[dict, dict]:
    require(os.geteuid() != 0, "archive parser must run unprivileged")
    require(pocket in POCKETS, "archive pocket invalid")
    raw = private_file(path, MAX_INRELEASE)
    key = private_file(keyring, 1024 * 1024, uid=0)
    require(bool(key), "archive keyring empty")
    command = ("/usr/bin/gpgv", "--status-fd", "1", "--keyring", str(keyring), str(path))
    try:
        done = subprocess.run(command, env={"PATH": "/usr/bin", "LC_ALL": "C"},
                              cwd="/", stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("archive signature verification unavailable") from exc
    require(done.returncode == 0 and len(done.stdout) <= 16384 and len(done.stderr) <= 16384,
            "archive signature invalid")
    valid = [line.split() for line in done.stdout.decode("ascii", "replace").splitlines()
             if line.startswith("[GNUPG:] VALIDSIG ")]
    require(len(valid) == 1 and len(valid[0]) >= 3 and valid[0][2] == ARCHIVE_FINGERPRINT,
            "archive signer not admitted")
    require(private_file(path, MAX_INRELEASE) == raw
            and private_file(keyring, 1024 * 1024, uid=0) == key,
            "archive signature inputs changed")
    fields, hashes = _release_fields(_release_payload(raw))
    require(fields.get("Origin") == "Ubuntu" and fields.get("Label") == "Ubuntu"
            and fields.get("Suite") == pocket and fields.get("Codename") == "noble"
            and fields.get("Architectures", "").split().count("amd64") == 1
            and all(component in fields.get("Components", "").split() for component in COMPONENTS),
            "archive release policy invalid")
    date = _utc(fields.get("Date", ""))
    valid_until = _utc(fields["Valid-Until"]) if "Valid-Until" in fields else None
    require(now.tzinfo is not None and date <= now + dt.timedelta(minutes=10),
            "archive release time invalid")
    if pocket == "noble":
        require(date >= dt.datetime(2024, 4, 25, tzinfo=dt.timezone.utc),
                "archive base release invalid")
    else:
        require(now - date <= dt.timedelta(hours=48), "archive release stale")
    if valid_until is not None:
        require(now <= valid_until + dt.timedelta(minutes=10),
                "archive release expired")
    return ({"pocket": pocket, "base_url": POCKETS[pocket],
             "inrelease_sha256": sha(raw), "keyring_sha256": sha(key),
             "signer_fingerprint": ARCHIVE_FINGERPRINT, "date": date.isoformat(),
             "valid_until": valid_until.isoformat() if valid_until else None}, hashes)


def verify_index(path: Path, release_hashes: dict, component: str) -> list[dict[str, str]]:
    require(component in COMPONENTS, "archive component invalid")
    suffix = f"{component}/binary-amd64/Packages.xz"
    require(suffix in release_hashes, "archive index not signed")
    compressed = private_file(path, MAX_INDEX)
    size, digest = release_hashes[suffix]
    require(len(compressed) == size and sha(compressed) == digest,
            "archive index digest invalid")
    try:
        decompressor = lzma.LZMADecompressor()
        plain = decompressor.decompress(compressed, max_length=MAX_PLAIN_INDEX + 1)
    except lzma.LZMAError as exc:
        raise Refused("archive index compression invalid") from exc
    require(decompressor.eof and not decompressor.unused_data
            and len(plain) <= MAX_PLAIN_INDEX,
            "archive index size invalid")
    rows = _paragraphs(plain, MAX_PLAIN_INDEX)
    return rows


def select_package(rows: list[dict[str, str]], package: str, version: str) -> dict:
    require(package in TARGETS and VERSION.fullmatch(version) is not None,
            "package selection invalid")
    selected = [row for row in rows if row.get("Package") == package
                and row.get("Version") == version and row.get("Architecture") == "amd64"]
    require(len(selected) == 1, "package entry missing or ambiguous")
    row = selected[0]
    filename = row.get("Filename", "")
    require(_safe_relative(filename) and filename.startswith("pool/")
            and filename.endswith(".deb") and HEX.fullmatch(row.get("SHA256", "")) is not None
            and row.get("Size", "").isdecimal() and 0 < int(row["Size"]) <= MAX_DEB,
            "package archive reference invalid")
    return {"package": package, "version": version, "filename": filename,
            "sha256": row["SHA256"], "size": int(row["Size"]),
            "depends": row.get("Depends", "")}


def verify_deb(path: Path, selected: dict) -> dict:
    raw = private_file(path, MAX_DEB)
    require(len(raw) == selected["size"] and sha(raw) == selected["sha256"],
            "package archive digest invalid")
    return {key: selected[key] for key in ("package", "version", "sha256", "size")}


def _private_directory(path: Path) -> None:
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_mode & 0o777 == 0o700,
            "archive bundle custody invalid")


def _publish_file(directory: Path, name: str, data: bytes) -> Path:
    require(bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,95}", name))
            and len(data) <= MAX_PLAIN_INDEX,
            "archive bundle record invalid")
    _private_directory(directory)
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    require(private_file(path, max(len(data), 1), uid=os.geteuid()) == data,
            "archive bundle record changed")
    return path


def acquire_verified_bundle(directory: Path, keyring: Path,
                            now: dt.datetime) -> dict:
    """Download and verify only fixed Noble metadata and five exact candidates.

    The private directory must be newly created by the caller. Any interrupted
    run leaves O_EXCL records; this function never resumes or adopts them.
    No package transaction is simulated here, so its result is not install
    admission and must never be treated as such.
    """
    require(os.geteuid() != 0, "archive acquisition must run unprivileged")
    _private_directory(directory)
    require(not any(directory.iterdir()), "archive bundle is not fresh")
    releases = []
    candidates: dict[str, list[dict]] = {name: [] for name in TARGETS}
    for pocket in POCKETS:
        release_name = f"{pocket}.inrelease"
        release_path = _publish_file(directory, release_name,
                                     fetch_fixed(pocket, f"dists/{pocket}/InRelease",
                                                 MAX_INRELEASE))
        release, hashes = verify_inrelease(release_path, keyring, pocket, now)
        releases.append(release)
        for component in COMPONENTS:
            relative = f"dists/{pocket}/{component}/binary-amd64/Packages.xz"
            index_path = _publish_file(directory, f"{pocket}.{component}.packages.xz",
                                       fetch_fixed(pocket, relative, MAX_INDEX))
            rows = verify_index(index_path, hashes, component)
            for package in TARGETS:
                for row in rows:
                    if (row.get("Package") == package
                            and row.get("Version") == EXPECTED_VERSIONS[package]
                            and row.get("Architecture") == "amd64"):
                        selected = select_package(rows, package, EXPECTED_VERSIONS[package])
                        candidates[package].append({**selected, "pocket": pocket,
                                                    "component": component})
    selected_packages = []
    for package in TARGETS:
        rows = candidates[package]
        require(bool(rows), "fixed package candidate unavailable")
        identities = {(row["sha256"], row["size"], row["filename"]) for row in rows}
        require(len(identities) == 1, "mixed archive package identity")
        selected = rows[-1]
        deb_path = _publish_file(directory, f"{package}.deb",
                                 fetch_fixed(selected["pocket"], selected["filename"],
                                             MAX_DEB))
        verified = verify_deb(deb_path, selected)
        selected_packages.append({**verified, "pocket": selected["pocket"],
                                  "component": selected["component"]})
    _private_directory(directory)
    return {"archive_releases": releases, "packages": selected_packages,
            "transaction_simulated": False, "package_actions_authorized": False}


def inspect_simulation(raw: bytes, initially_installed: dict[str, str],
                       admitted: dict[str, str]) -> list[dict]:
    """Accept only exact new Inst actions; reject every other dpkg operation."""
    require(len(raw) <= 65536, "package simulation oversized")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise Refused("package simulation encoding invalid") from exc
    actions = []
    configured = []
    for line in lines:
        if line.startswith(("Reading package lists", "Building dependency tree",
                            "Reading state information", "The following NEW packages",
                            "The following additional packages", "Suggested packages:",
                            "Recommended packages:", "0 upgraded, ")):
            continue
        if line.startswith(" ") or not line.strip():
            continue
        match = re.fullmatch(r"(Inst|Conf) ([a-z0-9][a-z0-9+.-]*) \(([A-Za-z0-9.+:~_-]+) [^)]+\)", line)
        require(match is not None, "package simulation action invalid")
        action, package, version = match.groups()
        require(package not in initially_installed and admitted.get(package) == version,
                "package simulation changes installed or unadmitted package")
        (actions if action == "Inst" else configured).append(
            {"package": package, "version": version})
    require({action["package"] for action in actions} >= set(REQUIRED)
            and len(actions) == len({action["package"] for action in actions})
            and len(configured) == len(actions)
            and {(item["package"], item["version"]) for item in configured}
                == {(item["package"], item["version"]) for item in actions},
            "package simulation incomplete")
    return actions
