"""Run the exact source-bound host probe over a pinned VM loopback SSH identity.

This read-only producer returns raw guest bytes. Its caller must hold the VM
lease, bind the target to live v2 evidence, preserve the raw bytes, run host
admission, and reobserve the VM before any nonce consumption or dispatch.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import shlex
import tempfile

from installer_candidate_controller import _directory
from installer_candidate_vm_create import _bytes
from installer_candidate_vm_guest_readiness import GUEST_USER
from installer_candidate_vm_runtime import _same_path
import installer_candidate_dispatch as dispatch
from installer_host_probe import command
import installer_release as release

SSH = Path("/usr/bin/ssh")


def probe(binding: dict, harness_source_sha: str, *, run=command) -> bytes:
    """Execute only the exact signed harness probe; return bounded raw stdout."""
    release.require(os.geteuid() == 0 and type(binding) is dict
                    and binding.get("qualified") is False
                    and binding.get("dispatch_authorized") is False,
                    "root diagnostic VM binding required")
    selected_binding = release.encode(binding)
    ssh = binding.get("ssh")
    release.exact(ssh, {"host", "port", "user", "control_dir",
                        "controller_key_sha256", "known_hosts_sha256"},
                  "VM pinned SSH identity")
    release.require(ssh["host"] == "127.0.0.1"
                    and ssh["user"] == GUEST_USER
                    and type(ssh["port"]) is int
                    and 1024 <= ssh["port"] <= 65535,
                    "VM host probe SSH target differs")
    for field in ("controller_key_sha256", "known_hosts_sha256"):
        release.sha(ssh[field], 64)
    control_dir = Path(ssh["control_dir"])
    held = _directory(control_dir)
    try:
        def unchanged() -> None:
            release.require(release.encode(binding) == selected_binding,
                            "VM host probe target binding changed")
            _same_path(control_dir, held, _directory)
            release.require(
                release.digest(_bytes(control_dir / "controller_ed25519", 8192))
                == ssh["controller_key_sha256"]
                and release.digest(_bytes(control_dir / "known_hosts", 4096))
                == ssh["known_hosts_sha256"],
                "VM host probe SSH material changed",
            )
        unchanged()
        dispatch.executable(SSH)
        source = dispatch.verified_harness_script(
            harness_source_sha, "installer_host_probe.py")
        release.require(type(source) is str and 0 < len(source.encode()) <= 65536,
                        "signed host probe source unavailable")
        encoded = base64.b64encode(source.encode()).decode("ascii")
        code = ("import base64;exec(compile(base64.b64decode(" + repr(encoded)
                + "),'installer-host-probe','exec'))")
        remote = ("exec env -i HOME=/home/" + GUEST_USER
                  + " PATH=/usr/bin:/bin /usr/bin/python3 -I -c "
                  + shlex.quote(code))
        options = dispatch.ssh_options(control_dir / "controller_ed25519",
                                       control_dir / "known_hosts", ssh["port"])
        options.extend(["-o", "HostKeyAlgorithms=ssh-ed25519"])
        unchanged()
        with tempfile.TemporaryDirectory(prefix="installer-vm-host-probe-") as home:
            raw = run([str(SSH), *options, "-T", GUEST_USER + "@127.0.0.1",
                       remote], env={"HOME": home, "PATH": "/usr/bin:/bin",
                                     "LANG": "C", "LC_ALL": "C"},
                      timeout=120, limit=65536)
        unchanged()
        release.require(type(raw) is bytes and 0 < len(raw) <= 65536,
                        "VM host observation output invalid")
        return raw
    finally:
        os.close(held)
