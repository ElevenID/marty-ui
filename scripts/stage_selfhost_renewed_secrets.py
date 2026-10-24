#!/usr/bin/env python3
"""Assemble one complete self-host secret generation without changing the live one.

The Keycloak and workload TLS producers must have qualified their remote keys,
certificates, and scoped tokens first. This step only assembles immutable file
inputs for a later controlled Compose recreation; it never activates them.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import sys

# Keep a receipt-verified extracted bundle immutable while importing siblings.
sys.dont_write_bytecode = True
from selfhost_operator_inputs import private_empty_or_source as private_empty_or_source  # noqa: E402
from passport_remote_tls import SELFHOST_CERT_FILES, SELFHOST_TLS_FILES  # noqa: E402
from selfhost_native_operator import generation_operation  # noqa: E402
from provision_selfhost_keycloak_kms import OUTPUTS as KEYCLOAK_OUTPUTS  # noqa: E402


MAX_SECRET_BYTES = 64 * 1024
RENEWED_FILES = SELFHOST_TLS_FILES | KEYCLOAK_OUTPUTS
CA_FILE = "workload_identity_ca_cert"
RENEWED_CERT_FILES = SELFHOST_CERT_FILES | {
    "keycloak_master_rs256_cert", "keycloak_11id_rs256_cert",
}
RENEWED_TOKEN_FILES = RENEWED_FILES - RENEWED_CERT_FILES


def bounded_file(path: Path, *, allow_empty: bool = False) -> bytes:
    return base64.b64decode(generation_operation("read", path=str(path), allow_empty=allow_empty), validate=True)


def entries(root: Path) -> dict[str, Path]:
    return {name: root / name for name in generation_operation("entries", root=str(root))}


def public_trust_overlap(old_ca: bytes, new_ca: bytes) -> bytes:
    return base64.b64decode(generation_operation(
        "overlap", old=base64.b64encode(old_ca).decode(), new=base64.b64encode(new_ca).decode(),
    ), validate=True)


def retired_public_trust(bundle: bytes) -> bytes:
    return base64.b64decode(generation_operation(
        "retired-trust", bundle=base64.b64encode(bundle).decode(),
    ), validate=True)


def verify_generations(current: Path, candidate: Path, *, ca_overlap: bool = False,
                       ca_retire: bool = False) -> tuple[int, int]:
    return tuple(generation_operation("verify", current=str(current), candidate=str(candidate),
                                      ca_overlap=ca_overlap, ca_retire=ca_retire))


def stage(current: Path, tls: Path, keycloak: Path, output: Path, *, ca_overlap: bool = False) -> int:
    return generation_operation("stage", current=str(current), tls=str(tls), keycloak=str(keycloak),
                                output=str(output), ca_overlap=ca_overlap)


def stage_retired_trust(current: Path, output: Path) -> int:
    return generation_operation("retire", current=str(current), output=str(output))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("current", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    for name in ("tls", "keycloak"):
        parser.add_argument(f"--{name}", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--ca-overlap", action="store_true")
    mode.add_argument("--ca-retire", action="store_true")
    args = parser.parse_args()
    try:
        if args.ca_retire:
            if args.tls is not None or args.keycloak is not None:
                raise ValueError("CA retirement does not replace leaves or scoped tokens")
            count = stage_retired_trust(args.current, args.output)
        else:
            if args.tls is None or args.keycloak is None:
                raise ValueError("leaf renewal requires both scoped producer outputs")
            count = stage(args.current, args.tls, args.keycloak, args.output,
                          ca_overlap=args.ca_overlap)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"self-host secret generation failed: {error}", file=sys.stderr)
        return 2
    print(f"Staged {count} secret inputs for controlled recreation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
