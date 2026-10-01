"""The Rust owner proof must bind the exact post-transition database and SQL."""

from __future__ import annotations

import json

import pytest

from scripts import verify_passport_beta_rust_owner as owner


def plan():
    return {
        "schema": "marty.passport-beta-aggregate-compose-plan/v1",
        "beta_origin": "https://beta.elevenidllc.com",
        "source_commit": "a" * 40,
        "postgres_container_id": "b" * 64,
        "postgres_system_identifier": "100",
        "database_oid": "200",
        "fence_epoch": "7",
        "migration_set_sha256": "c" * 64,
        "cutover_report_file_sha256": "d" * 64,
        "cutover_report_run_id": 42,
        **{field: owner.file_sha256(owner.ROOT / "scripts/sql" / filename)
           for field, filename in owner.TRANSITION_SQL_FILES.items()},
    }


def test_verifies_committed_rust_owner_with_exact_source(monkeypatch):
    recorded = plan()
    marker = f"100|200|rust_owner|7|9|7|{'a' * 40}|{'c' * 64}|true|false"
    monkeypatch.setattr(owner, "beta_psql", lambda *_: marker)
    calls = []

    def run(command):
        calls.append(command)
        return json.dumps({
            "schema": "marty.passport-beta-rust-owner-verification/v1",
            "phase": "rust_owner", "fence_epoch": 7, "transition_txid": 9,
            "transitioned_at": "2026-09-30T00:00:00Z",
            "functions_md5": {"guard_job": "e" * 32},
        })

    proof = owner.verify(recorded, runner=run,
                         render_verifier=lambda _: {"verified": True})
    assert proof["transition_txid"] == "9"
    assert proof["cutover_report_file_sha256"] == "d" * 64
    assert len(calls) == 1
    assert "marty.passport_beta_expected_transition_txid = '9'" in calls[0][-1]


@pytest.mark.parametrize("changed", [
    "100|200|fully_fenced|7|9|7|" + "a" * 40 + "|" + "c" * 64 + "|true|false",
    "100|200|rust_owner|7|9|7|" + "b" * 40 + "|" + "c" * 64 + "|true|false",
    "100|200|rust_owner|7|9|7|" + "a" * 40 + "|" + "c" * 64 + "|false|false",
])
def test_rejects_wrong_phase_source_or_closed_app_login(monkeypatch, changed):
    monkeypatch.setattr(owner, "beta_psql", lambda *_: changed)
    with pytest.raises(owner.HostProbeError, match="marker differs"):
        owner.verify(plan(), runner=lambda _: "",
                     render_verifier=lambda _: {"verified": True})


def test_rejects_changed_transition_sql_before_database_read(monkeypatch):
    recorded = plan()
    recorded["transition_sql_sha256"] = "0" * 64
    monkeypatch.setattr(owner, "beta_psql", lambda *_: pytest.fail("database was read"))
    with pytest.raises(owner.HostProbeError, match="protected SQL changed"):
        owner.verify(recorded, runner=lambda _: "",
                     render_verifier=lambda _: {"verified": True})
