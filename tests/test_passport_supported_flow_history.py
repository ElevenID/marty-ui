"""Durable Flow history comes only from the owned disposable Postgres."""

import json

import pytest

from scripts.passport_supported_flow_history import (
    FlowHistoryError, read_owned_flow_history,
)


INSTANCE = "d0000000-0000-4000-8000-000000000001"
DEFINITION = "d0000000-0000-4000-8000-000000000002"
ORG = "00000000-0000-0000-0000-000000000001"
POSTGRES = "a" * 64


def test_history_queries_exact_owned_row_without_context():
    calls = []
    payload = {"organization_id": ORG, "flow_definition_id": DEFINITION,
               "status": "completed", "step_history": [], "steps": []}

    def inspector(args):
        calls.append(args)
        return json.dumps(payload) + "\n"

    record = {"containers": {"postgres": POSTGRES}}
    result = read_owned_flow_history(
        record, "base", INSTANCE, DEFINITION, inspector=inspector,
        ownership=lambda *args: {"live_ownership_verified": True})
    assert result == payload
    assert calls[0][:4] == ["exec", "--user", "postgres", POSTGRES]
    query = calls[0][-1]
    assert "FROM flow_service.flow_instances i" in query
    assert "JOIN flow_service.flow_definitions d" in query
    assert f"i.id='{INSTANCE}'" in query
    assert f"d.id='{DEFINITION}'" in query
    assert query.count(ORG) == 2
    assert "i.context" not in query


def test_history_rejects_unowned_storage_before_query():
    calls = []
    with pytest.raises(FlowHistoryError, match="ownership"):
        read_owned_flow_history(
            {"containers": {"postgres": POSTGRES}}, "base", INSTANCE, DEFINITION,
            inspector=lambda args: calls.append(args) or "",
            ownership=lambda *args: {"live_ownership_verified": False})
    assert calls == []


def test_history_rejects_extra_rows():
    output = json.dumps({"organization_id": ORG, "flow_definition_id": DEFINITION,
                         "status": "completed", "step_history": [], "steps": []})
    with pytest.raises(FlowHistoryError, match="row is missing"):
        read_owned_flow_history(
            {"containers": {"postgres": POSTGRES}}, "base", INSTANCE, DEFINITION,
            inspector=lambda args: output + "\n" + output + "\n",
            ownership=lambda *args: {"live_ownership_verified": True})
