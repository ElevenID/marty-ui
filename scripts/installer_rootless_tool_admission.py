#!/usr/bin/env python3
"""Admit Docker CE rootless extras into private test-controller storage only.

Never installs a package, runs a maintainer script, alters a system keyring, or
invokes an extracted tool. The caller must review this code before live use.
"""

import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import installer_rootless_host_custody_fixture as fixture


BASE = "https://download.docker.com/linux/ubuntu/"
FINGERPRINT = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
MEMBERS = {
    "./usr/bin/dockerd-rootless.sh": "dockerd-rootless.sh",
    "./usr/bin/rootlesskit": "rootlesskit",
    "./usr/bin/rootlesskit-docker-proxy": "rootlesskit-docker-proxy",
    "./usr/bin/vpnkit": "vpnkit",
}


def trusted_system_binary(path):
    metadata = Path(path).lstat()
    fixture.require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and metadata.st_mode & 0o6022 == 0
                    and metadata.st_mode & 0o111 != 0,
                    "trusted system verifier unavailable")
    try:
        capability = os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError as error:
        fixture.require(error.errno == errno.ENODATA,
                        "system verifier capability metadata unavailable")
    else:
        fixture.require(not capability, "system verifier has file capabilities")


def bounded_get(relative, limit):
    fixture.require(re.fullmatch(r"[A-Za-z0-9/._+~%-]+", relative) is not None
                    and ".." not in relative.split("/"), "invalid repository path")
    trusted_system_binary("/usr/bin/curl")
    footer = b"\nMARTY_HTTP_STATUS:200"
    data = fixture.run(["/usr/bin/curl", "-q", "--fail", "--silent", "--show-error",
                        "--proto", "=https", "--max-redirs", "0", "--proxy", "",
                        "--connect-timeout", "10", "--max-time", "60",
                        "--max-filesize", str(limit), "--write-out",
                        "\nMARTY_HTTP_STATUS:%{http_code}", BASE + relative],
                       {"PATH": "/usr/bin:/bin", "HOME": "/"}, timeout=65,
                       output_limit=limit + len(footer), binary=True)
    fixture.require(data.endswith(footer), "repository response was not exact HTTP 200")
    data = data[:-len(footer)]
    fixture.require(0 < len(data) <= limit, "repository object exceeds bound")
    return data


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def signed_index(inside):
    key = bounded_get("gpg", 65536)
    inrelease = bounded_get("dists/noble/InRelease", 1024 * 1024)
    key_path, index_path = inside / "docker.gpg", inside / "InRelease"
    save(key_path, key)
    save(index_path, inrelease)
    home = inside / "gnupg"
    home.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(inside), "GNUPGHOME": str(home)}
    gpg = "/usr/bin/gpg"
    gpgv = "/usr/bin/gpgv"
    for binary in (gpg, gpgv):
        trusted_system_binary(binary)
    observed = fixture.run([gpg, "--batch", "--no-options", "--with-colons", "--fingerprint",
                            "--show-keys", str(key_path)], env)
    fixture.require(sum(line.startswith("pub:") for line in observed.splitlines()) == 1,
                    "Docker repository keyring has another primary key")
    fingerprints = [line.split(":")[9] for line in observed.splitlines() if line.startswith("fpr:")]
    fixture.require(1 <= len(fingerprints) <= 4 and fingerprints[0] == FINGERPRINT
                    and len(fingerprints) == len(set(fingerprints)),
                    "Docker repository primary-key fingerprint differs")
    keyring = inside / "trusted.gpg"
    fixture.run([gpg, "--batch", "--no-options", "--dearmor", "--output", str(keyring),
                 str(key_path)], env)
    verified = fixture.run([gpgv, "--status-fd", "1", "--keyring", str(keyring),
                            str(index_path)], env)
    signatures = [line.split() for line in verified.splitlines()
                  if line.startswith("[GNUPG:] VALIDSIG ")]
    fixture.require(len(signatures) == 1 and signatures[0][-1] == FINGERPRINT,
                    "signed repository identity differs")
    text = inrelease.decode("utf-8", "strict")
    lines = text.splitlines()
    for field in ("Label: Docker CE", "Origin: Docker", "Suite: noble"):
        fixture.require(lines.count(field) == 1, "signed Docker repository identity differs")
    architecture = [line for line in lines if line.startswith("Architectures: ")]
    component = [line for line in lines if line.startswith("Components: ")]
    fixture.require(len(architecture) == 1 and "amd64" in architecture[0].split()
                    and len(component) == 1 and "stable" in component[0].split(),
                    "signed Docker repository target differs")
    date = [line.removeprefix("Date: ") for line in lines if line.startswith("Date: ")]
    fixture.require(len(date) == 1, "signed repository date missing")
    issued = parsedate_to_datetime(date[0]).astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    fixture.require(issued <= now + timedelta(hours=1)
                    and now - issued <= timedelta(days=7),
                    "signed repository index is stale or future dated")
    marker = "stable/binary-amd64/Packages"
    fixture.require("SHA256:" in lines, "signed index SHA256 section missing")
    section = lines[lines.index("SHA256:") + 1:]
    rows = []
    for line in section:
        if not line.startswith(" "):
            break
        fields = line.split()
        if len(fields) == 3 and fields[2] == marker:
            rows.append(fields)
    fixture.require(len(rows) == 1 and re.fullmatch(r"[0-9a-f]{64}", rows[0][0])
                    and rows[0][1].isdecimal(), "signed package index digest ambiguous")
    size = int(rows[0][1])
    fixture.require(0 < size <= 32 * 1024 * 1024, "package index size exceeds bound")
    packages = bounded_get("dists/noble/" + marker, size)
    fixture.require(len(packages) == size and hashlib.sha256(packages).hexdigest() == rows[0][0],
                    "package index bytes differ from signed digest")
    return packages.decode("utf-8", "strict"), hashlib.sha256(inrelease).hexdigest()


def package_record(packages, docker_version):
    matches = []
    for block in packages.split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if line.startswith(" ") or ": " not in line:
                continue
            key, value = line.split(": ", 1)
            fixture.require(key not in fields, "duplicate package field")
            fields[key] = value
        version = fields.get("Version", "")
        if (fields.get("Package") == "docker-ce-rootless-extras"
                and re.fullmatch(r"(?:5:)?" + re.escape(docker_version)
                                 + r"-\d+~ubuntu\.24\.04~noble", version)):
            matches.append(fields)
    fixture.require(len(matches) == 1, "no unique rootless extras matching installed dockerd")
    item = matches[0]
    filename = item.get("Filename", "")
    fixture.require(re.fullmatch(
        r"dists/noble/pool/stable/amd64/docker-ce-rootless-extras_[A-Za-z0-9.+~%-]+_amd64\.deb",
        filename) is not None and re.fullmatch(r"[0-9a-f]{64}", item.get("SHA256", ""))
        and item.get("Size", "").isdecimal() and item.get("Architecture") == "amd64",
        "rootless package metadata differs")
    fixture.require(0 < int(item["Size"]) <= 32 * 1024 * 1024,
                    "rootless package exceeds size bound")
    fixture.require(Path(filename).name ==
                    "docker-ce-rootless-extras_" + item["Version"].removeprefix("5:") + "_amd64.deb",
                    "rootless package filename/version differs")
    return item


def extract_closed(package, output, package_sha):
    trusted_system_binary("/usr/bin/dpkg-deb")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(output)}
    archive_bytes = fixture.run(["/usr/bin/dpkg-deb", "--fsys-tarfile", str(package)],
                                env, timeout=60, output_limit=64 * 1024 * 1024, binary=True)
    found = {}
    count = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive:
            count += 1
            fixture.require(count <= 4096, "rootless package has too many members")
            name = member.name.rstrip("/") if member.isdir() else member.name
            if name == ".":
                fixture.require(member.isdir(), "package root is not a directory")
                continue
            parts = name.split("/")
            fixture.require(len(name) <= 512 and not name.startswith("/")
                            and not any(part in ("..", "") for part in parts)
                            and not any(ord(char) < 32 or char == "\\" for char in name)
                            and member.size <= 16 * 1024 * 1024
                            and member.mode & 0o6000 == 0
                            and not member.pax_headers,
                            "unsafe rootless package member")
            fixture.require(member.isdir() or member.isfile(), "linked/special rootless package member")
            if not member.isfile():
                continue
            total += member.size
            fixture.require(total <= 64 * 1024 * 1024, "rootless package unpacked size exceeds bound")
            if name not in MEMBERS:
                continue
            fixture.require(name not in found and member.size > 0,
                            "required rootless tool duplicate or empty")
            source = archive.extractfile(member)
            fixture.require(source is not None, "required rootless tool unavailable")
            data = source.read(member.size + 1)
            fixture.require(len(data) == member.size, "required rootless tool size differs")
            target = output / MEMBERS[name]
            save(target, data)
            os.chmod(target, 0o500)
            try:
                capability = os.getxattr(target, "security.capability", follow_symlinks=False)
            except OSError as error:
                fixture.require(error.errno == errno.ENODATA,
                                "extracted tool capability metadata unavailable")
            else:
                fixture.require(not capability, "extracted tool has file capabilities")
            found[name] = hashlib.sha256(data).hexdigest()
    fixture.require("./usr/bin/dockerd-rootless.sh" in found
                    and "./usr/bin/rootlesskit" in found,
                    "required rootless tools absent from exact package")
    return {"package_sha256": package_sha, "member_sha256": found,
            "archive_members": count, "unpacked_regular_bytes": total}


def main():
    fixture.require(len(sys.argv) == 3, "fixed admission arguments only")
    preflight = Path(sys.argv[1])
    output = Path(sys.argv[2])
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    fixture.require(preflight == runner_temp / "marty-rootless-preflight.json"
                    and output == runner_temp / "marty-rootless-tools"
                    and preflight.is_file() and not output.exists(),
                    "admission paths differ")
    metadata = preflight.lstat()
    fixture.require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 4096,
                    "preflight custody differs")
    observed = json.loads(preflight.read_bytes())
    fixture.require(observed["schema"] == "marty.rootless-fixture-preflight/v1"
                    and observed["uid"] == os.geteuid()
                    and observed["subordinate_ranges_present"] is True
                    and observed["daemon_started"] is False,
                    "preflight identity differs")
    version_text = observed["dockerd_version"]
    match = re.fullmatch(r"Docker version (\d+\.\d+\.\d+), build [A-Za-z0-9._+-]+", version_text)
    fixture.require(match is not None, "installed dockerd version ambiguous")
    output.mkdir(mode=0o700)
    packages, inrelease_sha = signed_index(output)
    item = package_record(packages, match.group(1))
    package = bounded_get(item["Filename"], int(item["Size"]))
    fixture.require(len(package) == int(item["Size"])
                    and hashlib.sha256(package).hexdigest() == item["SHA256"],
                    "rootless .deb differs from signed index")
    package_path = output / "rootless-extras.deb"
    save(package_path, package)
    report = extract_closed(package_path, output, item["SHA256"])
    report.update({"schema": "marty.rootless-tool-admission/v1",
                   "uid": os.geteuid(), "docker_version": version_text,
                   "package_version": item["Version"],
                   "inrelease_sha256": inrelease_sha, "repo_key_fingerprint": FINGERPRINT,
                   "system_install": False, "extracted_tools_executed": False})
    fixture.write_record(Path(os.environ["RUNNER_TEMP"]) / "marty-rootless-admission.json", report)
    print("SIGNED_ROOTLESS_EXTRAS_EXTRACTED")


if __name__ == "__main__":
    main()
