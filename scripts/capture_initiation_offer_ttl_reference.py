"""Observe unchanged Python entity configuration and expiry with a fixed clock."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch


SOURCE = "services/issuance/domain/entities.py"
BLOB = "1b5e2eba90c1ec13c1a38135f4da92813f1d1073"
NOW = datetime(2026, 8, 30, 12, tzinfo=timezone.utc)
MAX_MINUTES = (
    int((datetime(9999, 12, 31, 23, 59, tzinfo=timezone.utc) - NOW).total_seconds())
    // 60
)
MIN_MINUTES = int((datetime(1, 1, 1, tzinfo=timezone.utc) - NOW).total_seconds()) // 60
CASES = [
    ("unset-default", None),
    ("custom", "45"),
    ("zero", "0"),
    ("negative", "-5"),
    ("signed-whitespace", "  +90  "),
    ("digit-separators", "1_080"),
    ("unicode-decimal", "٠١٥"),
    ("empty", ""),
    ("whitespace-only", "  "),
    ("fraction", "1.5"),
    ("invalid", "invalid"),
    ("invalid-separators", "1__0"),
    ("maximum-calendar", str(MAX_MINUTES)),
    ("above-calendar", str(MAX_MINUTES + 1)),
    ("minimum-calendar", str(MIN_MINUTES)),
    ("below-calendar", str(MIN_MINUTES - 1)),
    ("above-i64", "9223372036854775808"),
    ("below-i64", "-9223372036854775809"),
]


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.replace(tzinfo=None) if tz is None else NOW.astimezone(tz)


def capture(root: Path) -> dict:
    source = root.resolve(strict=True) / SOURCE
    data = source.read_bytes().replace(b"\r\n", b"\n")
    actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if actual != BLOB:
        raise ValueError("Reference entity source blob differs")
    observations = []
    for index, (name, raw) in enumerate(CASES):
        module_name = f"_captured_issuance_entities_{index}"
        spec = importlib.util.spec_from_file_location(module_name, source)
        module = importlib.util.module_from_spec(spec)
        entry = {"case": name, "raw": raw}
        with patch.dict(os.environ), patch.dict(sys.modules, {module_name: module}):
            for variable in (
                "ISSUANCE_OFFER_TTL_MINUTES",
                "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
                "CANVAS_LTI_STATE_TTL_MINUTES",
            ):
                os.environ.pop(variable, None)
            if raw is not None:
                os.environ["ISSUANCE_OFFER_TTL_MINUTES"] = raw
            try:
                spec.loader.exec_module(module)
            except ValueError as error:
                entry.update(phase="module-import", error_type=type(error).__name__)
            else:
                entry["parsed_minutes"] = str(module._OFFER_TTL_MINUTES)
                module.datetime = FrozenDatetime
                try:
                    transaction = module.IssuanceTransaction(
                        id="synthetic-tx",
                        organization_id="synthetic-org",
                        credential_template_id="synthetic-template",
                        claims={},
                    )
                except OverflowError as error:
                    entry.update(
                        phase="transaction-construction",
                        error_type=type(error).__name__,
                    )
                else:
                    entry.update(
                        phase="accepted",
                        created_at=transaction.created_at.isoformat(),
                        expires_at=transaction.expires_at.isoformat(),
                    )
        observations.append(entry)
    return {
        "schema": "marty.initiation-offer-ttl-python-reference/v1",
        "reference": {
            "repository": "ElevenID/marty-credentials",
            "source_commit": "87eae30788924921a42848425d315e2f33f7ae41",
            "source_path": SOURCE,
            "source_blob": BLOB,
            "clock": NOW.isoformat(),
            "scope": "Executed unchanged entity module and dataclass factories with controlled environment and fixed datetime.now; no HTTP/gRPC admission, database, gateway or delivery qualification.",
        },
        "cases": observations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("credentials_checkout", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = capture(args.credentials_checkout)
    if args.check:
        path = (
            Path(__file__).resolve().parents[1]
            / "contracts/initiation-offer-ttl-python-reference.json"
        )
        if result != json.loads(path.read_text(encoding="utf-8")):
            raise ValueError("Exact offer expiry reference differs")
        print(f"Exact Python offer expiry replay matched: {len(result['cases'])} cases")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
