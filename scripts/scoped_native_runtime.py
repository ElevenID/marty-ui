"""Shared contracts for an explicitly reviewed local passport binary rollout.

No image publication, database reset, authority expansion or release qualification.
Historical audit operators remain immutable. Their generic bounded resource and
Compose helpers may be supplied by a hash-bound private wrapper at execution.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from datetime import datetime

UI_REVISION = "0aae5d6c03df0ccb2aa757d61fb022a24a962d14"
CORE_REVISION = "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac"
ROLE_BINARIES = {"flow": "marty-flow", "gateway": "marty-gateway", "issuance-native": "marty-issuance-service"}
MARTY_CLIENTS = frozenset("auth organization credential-template trust-profile applicant notification compliance-profile presentation-policy deployment-profile flow verification revocation-profile device-registration issuance issuance-native canvas-sync-worker passport-beta-bureau".split())
MIGRATIONS = ("flow/0003_physical_start_intents", "issuance/0010_passport_start_idempotency", "issuance/0011_passport_administrative_cancellation")

def require(value, code):
    if not value:
        raise ValueError(code)

def sha(file):
    with Path(file).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def ref(file):
    file = Path(file)
    return {"path": str(file), "sha256": sha(file), "bytes": file.stat().st_size}

def read_ref(bound, maximum=16 * 1024 * 1024):
    file = Path(bound["path"])
    require(file.is_file() and not file.is_symlink() and not getattr(file, "is_junction", lambda: False)(), "REGULAR_BOUND_FILE_REQUIRED")
    require(file.stat().st_size <= maximum and re.fullmatch(r"[a-f0-9]{64}", bound.get("sha256", "")), "BOUNDED_EXACT_REF_REQUIRED")
    require(sha(file) == bound["sha256"], "BOUND_FILE_CHANGED")
    return file

def save_exclusive(file, value):
    with Path(file).open("xb") as stream:
        stream.write((json.dumps(value, indent=2) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())

def save_state(file, value):
    # A stranded temp cannot block recording a later unknown outcome.
    file = Path(file)
    temp = file.with_name(file.name + "." + str(uuid.uuid4()) + ".tmp")
    save_exclusive(temp, value)
    os.replace(temp, file)

def selected_sources(plan):
    require(plan.get("uiRevision") == UI_REVISION and plan.get("coreRevision") == CORE_REVISION, "REVIEWED_UI_AND_LOCKED_CORE_REQUIRED")
    require(plan.get("roleBinaries") == ROLE_BINARIES, "EXACT_THREE_ROLE_SCOPE_REQUIRED")
    require(plan.get("releaseQualified") is False and plan.get("recordingQualified") is False, "FUNCTIONAL_SCOPE_ONLY")

def daemon_source(value):
    # Daemon bind sources, never arbitrary command/env/container-path rewriting.
    text = str(value)
    require(not re.search(r"[\x00-\x1f\x7f,]", text), "INVALID_BIND_SOURCE")
    if re.match(r"^[cCdD]:[\\/]", text):
        drive, tail = text[0].lower(), text[3:].replace("\\", "/")
        require(all(part not in ("", ".", "..") for part in tail.split("/")), "INVALID_BIND_SOURCE")
        return "/run/desktop/mnt/host/" + drive + "/" + tail
    require(not text.startswith(("/mnt/host/", "/host_mnt/")), "CLIENT_PATH_IS_NOT_DAEMON_BIND_SOURCE")
    require(text.startswith("/") and all(part not in (".", "..") for part in text.split("/")), "ABSOLUTE_BIND_SOURCE_REQUIRED")
    return text


def started_later(actual, prior):
    try:
        new = datetime.fromisoformat(actual.replace("Z", "+00:00"))
        old = datetime.fromisoformat(prior.replace("Z", "+00:00"))
        return new.tzinfo is not None and old.tzinfo is not None and new > old
    except (ValueError, AttributeError, TypeError):
        return False
