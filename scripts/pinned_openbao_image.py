"""Acquire only reviewed immutable public OpenBao images; never retry a running operation."""
from __future__ import annotations

import re
import subprocess
import time

_REFERENCE = re.compile(
    r"(?:quay\.io/openbao/openbao|ghcr\.io/elevenid/marty-ui-oss/openbao-didcomm)@sha256:[0-9a-f]{64}\Z"
)


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=120, check=False)


def require_pinned_openbao(image: str, *, runner=None, pause=None) -> None:
    """Reuse an exact local digest, or try its public pull three times with fixed safe facts."""
    if not isinstance(image, str) or not _REFERENCE.fullmatch(image):
        raise ValueError("OpenBao image must be an approved digest-pinned reference")
    runner, pause = runner or docker, pause or time.sleep
    try:
        if runner("image", "inspect", image).returncode == 0:
            return
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        raise RuntimeError("Docker is unavailable for pinned OpenBao acquisition") from None
    reason = "failed"
    for attempt in range(3):
        try:
            result = runner("pull", image)
            if result.returncode == 0:
                return
            stderr = (result.stderr or "").lower()
            # Never publish provider output: only allowlisted, credential-free failure facts.
            reason = "exit " + str(result.returncode)
            for phrase, category in (("unauthorized", "authorization"), ("denied", "authorization"),
                                     ("too many requests", "rate-limit"), ("toomanyrequests", "rate-limit"),
                                     ("manifest unknown", "missing-manifest"), ("not found", "missing-manifest"),
                                     ("timeout", "network"), ("bad gateway", "network"),
                                     ("connection", "network"), ("tls handshake", "network")):
                if phrase in stderr:
                    reason = category + "; " + reason
                    break
        except subprocess.TimeoutExpired:
            reason = "timeout"
        except OSError:
            raise RuntimeError("Docker is unavailable for pinned OpenBao acquisition") from None
        if attempt < 2:
            pause(2 ** attempt)
    raise RuntimeError("Pinned disposable OpenBao image is unavailable after three attempts (" + reason + ")")
