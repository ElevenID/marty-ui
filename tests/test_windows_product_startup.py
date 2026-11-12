"""Receipt and SQL boundaries for native system-catalog timestamps."""

from copy import deepcopy
import json
from pathlib import Path
import re
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import selfhost_windows_product_startup as startup  # noqa: E402

ORG = "00000000-0000-0000-0000-000000000001"
ISSUER = "did:web:startup-qa.invalid:orgs:marty"


def before():
    value = {
        "schema": startup.SCHEMA,
        "side": "before",
        "database_clock": "2026-11-12T00:00:00+00:00",
        "scope_sha256": startup._scope(ORG, ISSUER)[2],
    }
    for name, count in startup.COUNTS.items():
        value[name] = {
            "row_count": count + 1,
            "eligible_id_sha256": [format(i, "064x") for i in range(1, count + 1)],
            "observed_sha256": "b" * 64,
            "expected_after_sha256": "c" * 64,
        }
    return value


def after():
    prior = before()
    value = {
        "schema": startup.SCHEMA,
        "side": "after",
        "database_clock": "2026-11-12T00:00:01+00:00",
        "scope_sha256": prior["scope_sha256"],
    }
    for name, count in startup.COUNTS.items():
        value[name] = {
            "row_count": count + 1,
            "masked_rows": count,
            "updated_at_in_window": True,
            "observed_sha256": "c" * 64,
        }
    return value


def test_fixed_selects_scope_only_builtin_rows_and_the_configured_tenant_issuer():
    sql = startup.before_sql(ORG, "did:web:quote'host")
    assert "candidate.organization_id::text='" + ORG + "'" in sql
    assert "candidate.issuer_id='did:web:quote''host'" in sql
    assert all(name in sql for name in (*startup.WALLETS, *startup.DESTINATIONS))
    assert sql.count("to_jsonb(candidate) AS _cohort_row") == 5
    assert "candidate.is_system IS TRUE" in sql
    assert startup.DEPLOYMENT_ID in sql
    assert all(str(uuid.uuid5(uuid.UUID(ORG), name)) in sql for name in startup.ROLE_NAMES)
    assert not re.search(r"\b(UPDATE|DELETE|INSERT|CREATE|ALTER|DROP)\b", sql, re.I)
    final = startup.after_sql(before())
    assert "_cohort_row-'updated_at'" in final
    assert "updated_at >= '2026-11-12T00:00:00+00:00'::timestamptz" in final


def test_role_cohort_is_derived_for_the_exact_configured_organization():
    other = "00000000-0000-0000-0000-000000000002"
    sql = startup.before_sql(other, ISSUER)
    assert all(str(uuid.uuid5(uuid.UUID(other), name)) in sql for name in startup.ROLE_NAMES)
    assert all(str(uuid.uuid5(uuid.UUID(ORG), name)) not in sql for name in startup.ROLE_NAMES)
    assert "candidate.organization_id::text='" + other + "'" in sql


def test_older_three_cohort_receipt_does_not_silently_admit_new_scope():
    value = before()
    value["schema"] = "marty.windows-system-startup-timestamps/v1"
    value.pop("roles")
    value.pop("deployment")
    with pytest.raises(ValueError):
        startup.after_sql(value)


@pytest.mark.parametrize(
    "organization,issuer",
    [
        (None, ISSUER),
        ("bad", ISSUER),
        (ORG, None),
        (ORG, "https://wrong.invalid"),
        (ORG, "did:web:line\nbreak"),
        (ORG, "did:web:" + "x" * 2049),
    ],
)
def test_bad_scope_never_produces_sql(organization, issuer):
    with pytest.raises((ValueError, TypeError)):
        startup.before_sql(organization, issuer)


def test_timestamp_agreement_grants_no_native_or_transition_authority():
    result = startup.validate_delta(before(), after())
    assert (
        result["native_admission"] is False
        and result["product_transition_admission"] is False
    )


@pytest.mark.parametrize("name", list(startup.TABLES))
@pytest.mark.parametrize(
    "fault",
    [
        "row-count",
        "mask-count",
        "boolean-mask",
        "old-time",
        "unknown-row-payload",
        "extra-field",
    ],
)
def test_row_loss_overmasking_and_unrelated_payload_changes_refuse(name, fault):
    value = after()
    row = value[name]
    if fault == "row-count":
        row["row_count"] += 1
    elif fault == "mask-count":
        row["masked_rows"] += 1
    elif fault == "boolean-mask":
        row["masked_rows"] = True
    elif fault == "old-time":
        row["updated_at_in_window"] = False
    elif fault == "unknown-row-payload":
        row["observed_sha256"] = "d" * 64
    else:
        row["extra"] = "untrusted"
    with pytest.raises(ValueError):
        startup.validate_delta(before(), value)


@pytest.mark.parametrize("fault", ["scope", "clock", "naive-clock", "extra-table"])
def test_cross_scope_or_unbounded_clock_receipts_refuse(fault):
    value = after()
    if fault == "scope":
        value["scope_sha256"] = "f" * 64
    elif fault == "clock":
        value["database_clock"] = "2026-11-11T00:00:00+00:00"
    elif fault == "naive-clock":
        value["database_clock"] = "2026-11-12T00:00:01"
    else:
        value["extra"] = {}
    with pytest.raises(ValueError):
        startup.validate_delta(before(), value)


@pytest.mark.parametrize(
    "fault", ["missing-key", "duplicate-key", "sql-key", "too-many-rows"]
)
def test_missing_or_injectable_baseline_keys_refuse_before_after_sql(fault):
    value = before()
    row = value["wallets"]
    if fault == "missing-key":
        row["eligible_id_sha256"].pop()
    elif fault == "duplicate-key":
        row["eligible_id_sha256"][1] = row["eligible_id_sha256"][0]
    elif fault == "sql-key":
        row["eligible_id_sha256"][0] = "';SELECT 1;--"
    else:
        row["row_count"] = startup.membership.MAX_ROWS + 1
    with pytest.raises(ValueError):
        startup.after_sql(value)


def test_capture_rejects_changed_tenant_before_any_database_command(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("database command reached")

    monkeypatch.setattr(startup.probe, "_postgres_base", unexpected)
    with pytest.raises(ValueError):
        startup.capture(
            object(),
            [],
            "synthetic",
            organization_id="00000000-0000-0000-0000-000000000002",
            issuer_did=ISSUER,
            before=before(),
        )


def test_capture_uses_existing_read_only_postgres_transport(monkeypatch):
    calls = []
    item = {
        "Id": "a" * 64,
        "Config": {
            "Env": ["POSTGRES_USER=fixture"],
            "Labels": {
                "com.docker.compose.project": "marty-production-synthetic",
                "com.docker.compose.service": "postgres",
            },
        },
    }

    def text(docker, args, *, stdin_bytes):
        calls.append(args)
        assert args[:4] == ["exec", "--interactive", "--user", "postgres"]
        assert (
            startup.probe.PG_OPTIONS in args
            and "default_transaction_read_only=on" in startup.probe.PG_OPTIONS
        )
        assert args[-1] == "--file=-" and b"to_jsonb(candidate)" in stdin_bytes
        return json.dumps(before())

    monkeypatch.setattr(startup.probe, "_text", text)
    result = startup.capture(
        object(),
        [item],
        "marty-production-synthetic",
        organization_id=ORG,
        issuer_did=ISSUER,
    )
    assert result == before() and len(calls) == 1
    tampered = deepcopy(result)
    tampered["issuer"]["observed_sha256"] = "ordinary row content"
    with pytest.raises(ValueError):
        startup.validate_before(tampered)
