"""Repository-only expiry corpus guards; explicit --check runs the old entity."""

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture_initiation_offer_ttl_reference.py"
SPEC = importlib.util.spec_from_file_location("offer_ttl_capture", SCRIPT)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def corpus():
    return json.loads(
        (ROOT / "contracts/initiation-offer-ttl-python-reference.json").read_text(
            encoding="utf-8"
        )
    )


def test_expiry_reference_provenance_and_cases_are_closed():
    frozen = corpus()
    assert frozen["reference"]["source_blob"] == capture.BLOB
    assert frozen["reference"]["source_path"] == capture.SOURCE
    assert frozen["reference"]["clock"] == capture.NOW.isoformat()
    assert [(row["case"], row["raw"]) for row in frozen["cases"]] == capture.CASES
    assert len(frozen["cases"]) == 18
    assert [row["phase"] for row in frozen["cases"]].count("accepted") == 9
    assert [row["phase"] for row in frozen["cases"]].count("module-import") == 5
    assert [row["phase"] for row in frozen["cases"]].count(
        "transaction-construction"
    ) == 4


@pytest.mark.parametrize(
    "case,expected",
    [
        ("unset-default", "2026-09-06T12:00:00+00:00"),
        ("custom", "2026-08-30T12:45:00+00:00"),
        ("zero", "2026-08-30T12:00:00+00:00"),
        ("negative", "2026-08-30T11:55:00+00:00"),
        ("maximum-calendar", "9999-12-31T23:59:00+00:00"),
        ("minimum-calendar", "0001-01-01T00:00:00+00:00"),
    ],
)
def test_expiry_observations_do_not_clamp_or_extend_python_calendar(case, expected):
    observed = next(row for row in corpus()["cases"] if row["case"] == case)
    assert observed["phase"] == "accepted"
    assert observed["expires_at"] == expected


def test_large_integers_remain_valid_until_transaction_creation():
    for name in ("above-i64", "below-i64", "above-calendar", "below-calendar"):
        row = next(row for row in corpus()["cases"] if row["case"] == name)
        assert row["parsed_minutes"] == row["raw"]
        assert row["phase"] == "transaction-construction"
        assert row["error_type"] == "OverflowError"


def test_capture_rejects_modified_source_before_import(tmp_path):
    source = tmp_path / capture.SOURCE
    source.parent.mkdir(parents=True)
    source.write_text("raise AssertionError('must not execute')\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source blob differs"):
        capture.capture(tmp_path)


def test_production_construction_configures_shared_owner_before_http_and_grpc():
    source = (ROOT / "rust/services/issuance/src/main.rs").read_text(encoding="utf-8")
    configured = source.index(
        ".with_offer_ttl_minutes(config.issuance_offer_ttl_minutes.clone())"
    )
    http = source.index("let initiation_http = InitiationHttpService::new(")
    grpc = source.index("let grpc_platform = IssuanceGrpcPlatform::new(")
    assert configured < http < grpc
    assert "initiation.clone()," in source[http:grpc]
    assert source[grpc:].split(");", 1)[0].count("initiation,") == 1
