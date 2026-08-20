from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_proto.v1 import event_stream_service_pb2

from gateway.routes.notifications import notification_router


CONTRACT = json.loads(
    (Path(__file__).parents[3] / "contracts" / "gateway-sse-behavior.json").read_text(
        encoding="utf-8"
    )
)


def _client() -> TestClient:
    app = FastAPI()
    app.state.es_grpc_channel = object()
    app.include_router(notification_router)

    @app.middleware("http")
    async def authorize(request, call_next):
        request.state.organization_id = CONTRACT["authorized_organization_id"]
        request.state.user_id = CONTRACT["authenticated_user_id"]
        return await call_next(request)

    return TestClient(app)


def test_legacy_gateway_executes_shared_sse_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class Stub:
        def __init__(self, channel) -> None:
            pass

        async def Subscribe(self, request):
            captured["request"] = request
            for event in CONTRACT["events"]:
                yield event_stream_service_pb2.DomainEvent(**event)

    monkeypatch.setattr(
        "marty_proto.v1.event_stream_service_pb2_grpc.EventStreamServiceStub", Stub
    )
    response = _client().get(
        f"/v1/notifications/events/push?{CONTRACT['valid_query']}"
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.text == "".join(CONTRACT["expected_frames"])
    assert captured["request"].organization_id == CONTRACT["authorized_organization_id"]
    assert list(captured["request"].event_types) == CONTRACT["expected_event_types"]

    class ErrorStub:
        def __init__(self, channel) -> None:
            pass

        async def Subscribe(self, request):
            if False:
                yield None
            raise RuntimeError("backend unavailable")

    monkeypatch.setattr(
        "marty_proto.v1.event_stream_service_pb2_grpc.EventStreamServiceStub",
        ErrorStub,
    )
    failed = _client().get(f"/v1/notifications/events/push?{CONTRACT['valid_query']}")
    assert failed.status_code == 200
    assert failed.text == "".join(CONTRACT["expected_error_frames"])

    for query in CONTRACT["rejected_queries"]:
        assert _client().get(f"/v1/notifications/events/push?{query}").status_code == 403
