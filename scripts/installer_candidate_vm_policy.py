"""Exact disposable Ubuntu guest bootstrap policy shared by seed and probe."""

from pathlib import Path
import os
import stat

import installer_release as release

GUEST_USER = "installer"
# Engineering bootstrap policy; installed acceptance records actual package
# identities and source before it may qualify a release.
PACKAGES = {
    "openssh-server": "1:9.6p1-3ubuntu13.20",
    "docker.io": "29.1.3-0ubuntu3~24.04.2",
    "docker-compose-v2": "2.40.3+ds1-0ubuntu1~24.04.1",
    "containerd": "2.2.1-0ubuntu1~24.04.4",
    "runc": "1.3.4-0ubuntu1~24.04.1",
}

# An explicit v2 selection is required; the historical v1 engineering seed
# remains rootful and its package policy and emitted bytes do not change.
ROOTLESS_UID = 1001
ROOTLESS_DOCKER_HOST = f"unix:///run/user/{ROOTLESS_UID}/docker.sock"
ROOTLESS_STARTUP_PROFILE = "rootless-startup-8gib"
ROOTLESS_FUNCTIONAL_PROFILE = "rootless-functional-recovery-8gib"
ROOTLESS_PROFILES = frozenset({ROOTLESS_STARTUP_PROFILE, ROOTLESS_FUNCTIONAL_PROFILE})
ROOTLESS_PACKAGES = dict(PACKAGES, **{
    "rootlesskit": "1.1.1-1ubuntu0.24.04.3",
    "uidmap": "1:4.13+dfsg1-4ubuntu3.2",
    "slirp4netns": "1.2.1-1build2",
    "fuse-overlayfs": "1.13-1",
    "dbus-user-session": "1.14.10-4ubuntu4.1",
    "apparmor": "4.0.1really4.0.1-0ubuntu0.24.04.9",
})
ROOTLESS_ASSET_DIRECTORY = Path(__file__).resolve().parent / "installer_candidate_vm_assets" / "moby-docker-v29.1.3"
ROOTLESS_GUEST_DIRECTORY = "/usr/local/lib/marty-rootless/docker-v29.1.3"
ROOTLESS_ASSETS_SHA256 = {
    "dockerd-rootless.sh": "8eb00d61b5e78ffc0dcd628f056389b5859cc61d6fe3ce17b4a3a4b08143c8a5",
    "dockerd-rootless-setuptool.sh": "e68ef6550fea1b5c01b5cc7a400a6b44ee28159d7714758c3845759e03e079dc",
    "LICENSE": "7c87873291f289713ac5df48b1f2010eb6963752bbd6b530416ab99fc37914a8",
    "NOTICE": "b40ec5b16182103ef1cd69d42a21c98369e35bd483b3973902da4807c0755446",
}
ROOTLESS_SEED_FIELDS = {"resource_profile", "guest_uid", "docker_host", "rootless_assets_sha256"}


def require_rootless_profile(value: str) -> str:
    release.require(type(value) is str and value in ROOTLESS_PROFILES,
                    "VM rootless resource profile unsupported")
    return value


def memory_mib(resource_profile: str | None) -> int:
    if resource_profile is None:
        return 4096
    require_rootless_profile(resource_profile)
    return 8192


def rootless_seed_fields(resource_profile: str) -> dict:
    return dict(resource_profile=require_rootless_profile(resource_profile),
                guest_uid=ROOTLESS_UID, docker_host=ROOTLESS_DOCKER_HOST,
                rootless_assets_sha256=dict(ROOTLESS_ASSETS_SHA256))


def seed_profile(record: dict) -> str | None:
    """Validate the closed, explicit seed policy without changing v1 meaning."""
    if record.get("schema") == "elevenid.installer-vm-seed/v1":
        release.require(not (set(record) & ROOTLESS_SEED_FIELDS),
                        "legacy VM seed contains rootless selection")
        return None
    release.require(record.get("schema") == "elevenid.installer-vm-seed/v2",
                    "VM seed version unsupported")
    profile = require_rootless_profile(record.get("resource_profile"))
    expected = rootless_seed_fields(profile)
    release.require(record.get("guest_user") == GUEST_USER
                    and record.get("packages") == ROOTLESS_PACKAGES
                    and all(type(record.get(key)) is type(value)
                            and record.get(key) == value
                            for key, value in expected.items()),
                    "VM rootless seed policy differs")
    return profile


def rootless_assets() -> dict[str, bytes]:
    """Read only the exact retained upstream sources; never fetch or execute."""
    result = {}
    for name, expected in ROOTLESS_ASSETS_SHA256.items():
        path = ROOTLESS_ASSET_DIRECTORY / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            held = os.fstat(fd)
            release.require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1
                            and 0 < held.st_size <= 32768,
                            "VM rootless source asset unavailable")
            raw = bytearray()
            while len(raw) < held.st_size:
                block = os.read(fd, held.st_size - len(raw))
                release.require(bool(block), "VM rootless source asset truncated")
                raw.extend(block)
            after = path.lstat()
            release.require((held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                            and release.digest(bytes(raw)) == expected,
                            "VM rootless source asset differs")
            result[name] = bytes(raw)
        finally:
            os.close(fd)
    return result
