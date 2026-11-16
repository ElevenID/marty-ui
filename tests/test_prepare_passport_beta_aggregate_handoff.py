"""The historical beta handoff must fail before reading operator state."""

from pathlib import Path

import pytest

from scripts import prepare_passport_beta_aggregate_handoff as handoff


def test_retired_handoff_rejects_before_touching_protected_source(monkeypatch):
    monkeypatch.setattr(
        handoff, "protected_source", lambda *_: pytest.fail("legacy source read")
    )
    with pytest.raises(handoff.HostProbeError, match="retired"):
        handoff.prepare(
            *(Path("unused") for _ in range(4)),
            runner=lambda _: pytest.fail("legacy operator command"),
        )


def test_existing_fence_caller_sends_authenticated_plain_sql():
    import json
    import re
    intent = {"verify_sql_sha256": handoff.file_sha256(handoff.VERIFY),
        "postgres_container_id": "b" * 64, "postgres_system_identifier": "100", "database_oid": "200", "fence_epoch": "7"}
    calls = []
    def runner(command):
        calls.append(command)
        assert command[-2] == "-c"
        assert not re.search(r"(?m)^\\[a-z]", command[-1], re.I)
        assert "trg_administratively_cancelled_passport_job" in command[-1]
        assert "FULL JOIN actual" in command[-1]
        return json.dumps({"schema": "marty.passport-beta-fence-verification/v1", "phase": "fully_fenced", "epoch": 7})
    handoff.verify_fence(intent, runner)
    assert len(calls) == 1
    intent["verify_sql_sha256"] = "0" * 64
    with pytest.raises(handoff.HostProbeError, match="verifier changed"):
        handoff.verify_fence(intent, lambda _: pytest.fail("Unauthenticated SQL reached database"))
