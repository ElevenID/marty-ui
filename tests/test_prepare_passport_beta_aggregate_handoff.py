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
