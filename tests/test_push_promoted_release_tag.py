from __future__ import annotations

import json

import pytest

from scripts import push_promoted_release_tag as handoff


def test_promotion_artifact_requires_one_immutable_checkpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    name = "stack-release-promotion-complete-123"
    record = {"name": name, "id": 456, "expired": False,
              "digest": "sha256:" + "a" * 64}
    monkeypatch.setattr(handoff, "output", lambda *args: json.dumps({"artifacts": [record]}))
    assert handoff.promotion_artifact("123", name) == (456, record["digest"])

    monkeypatch.setattr(handoff, "output", lambda *args: json.dumps({"artifacts": [record, record]}))
    with pytest.raises(ValueError, match="exactly one"):
        handoff.promotion_artifact("123", name)

    invalid = {**record, "digest": ""}
    monkeypatch.setattr(handoff, "output", lambda *args: json.dumps({"artifacts": [invalid]}))
    with pytest.raises(ValueError, match="immutable digest"):
        handoff.promotion_artifact("123", name)
