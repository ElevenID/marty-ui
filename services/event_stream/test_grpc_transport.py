from __future__ import annotations

import asyncio

from grpc import aio as grpc_aio

import common.grpc_event_bus as event_bus_module
from common.grpc_event_bus import GrpcEventBus, GrpcEventStreamPublisher
from event_stream.grpc_adapter import EventStreamServiceGrpc
from marty_proto.v1 import (
    event_stream_service_pb2 as es_pb2,
    event_stream_service_pb2_grpc,
)


async def test_remote_publish_reaches_only_matching_tenant_stream() -> None:
    event_bus_module._event_bus = GrpcEventBus()
    server = grpc_aio.server()
    event_stream_service_pb2_grpc.add_EventStreamServiceServicer_to_server(
        EventStreamServiceGrpc(), server
    )
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{port}")

    try:
        stub = event_stream_service_pb2_grpc.EventStreamServiceStub(channel)
        org_a_stream = stub.Subscribe(
            es_pb2.EventSubscription(
                event_types=["application.approved"],
                organization_id="org-a",
            )
        )
        org_b_stream = stub.Subscribe(
            es_pb2.EventSubscription(
                event_types=["application.approved"],
                organization_id="org-b",
            )
        )
        org_a_read = asyncio.create_task(org_a_stream.read())
        org_b_read = asyncio.create_task(org_b_stream.read())
        await asyncio.sleep(0.05)

        publisher = GrpcEventStreamPublisher(target=f"127.0.0.1:{port}")
        publisher._channel = channel
        notified = await publisher.publish_fields(
            event_type="application.approved",
            aggregate_id="application-a",
            aggregate_type="application",
            organization_id="org-a",
            data={"application_id": "application-a"},
            event_id="event-a",
            timestamp="2026-08-06T12:00:00+00:00",
        )

        event = await asyncio.wait_for(org_a_read, timeout=2)
        await asyncio.sleep(0.05)
        assert notified == 1
        assert event.event_id == "event-a"
        assert event.organization_id == "org-a"
        assert event.data["application_id"] == "application-a"
        assert not org_b_read.done()
    finally:
        org_a_stream.cancel()
        org_b_stream.cancel()
        org_a_read.cancel()
        org_b_read.cancel()
        await channel.close()
        await server.stop(grace=0)
        event_bus_module._event_bus = None
