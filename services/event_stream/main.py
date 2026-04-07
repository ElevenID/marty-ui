"""
Event Stream Service

Centralized gRPC event bus that replaces RabbitMQ for inter-service
domain event communication.  Runs a gRPC server with server streaming
for subscribers and unary Publish for event producers.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from marty_common.service_setup import create_service_app

logger = logging.getLogger(__name__)

SERVICE_NAME = "event-stream"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(f"Starting {SERVICE_NAME}...")

    grpc_server = None
    grpc_enabled = os.environ.get("EVENT_STREAM_GRPC_ENABLED", "true").lower() == "true"

    if grpc_enabled:
        from common.grpc_factory import create_grpc_server, start_grpc_server_port
        from event_stream.grpc_adapter import EventStreamServiceGrpc
        from marty_proto.v1.event_stream_service_pb2_grpc import (
            add_EventStreamServiceServicer_to_server,
        )

        grpc_port = int(os.environ.get("EVENT_STREAM_GRPC_PORT", "9015"))
        grpc_server, health_servicer = create_grpc_server("event-stream")
        servicer = EventStreamServiceGrpc()
        add_EventStreamServiceServicer_to_server(servicer, grpc_server)
        start_grpc_server_port(
            grpc_server,
            grpc_port,
            service_names=["marty.ui.event_stream.v1.EventStreamService"],
            health_servicer=health_servicer,
        )
        await grpc_server.start()
        logger.info(f"EventStream gRPC server listening on :{grpc_port}")

    yield

    logger.info(f"Shutting down {SERVICE_NAME}...")
    if grpc_server:
        await grpc_server.stop(grace=5)


def create_app() -> FastAPI:
    return create_service_app(
        title="Marty Event Stream Service",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn

    SERVICE_PORT = int(os.environ.get("EVENT_STREAM_SERVICE_PORT", "8015"))
    uvicorn.run(
        "event_stream.main:app",
        host="0.0.0.0",
        port=SERVICE_PORT,
        reload=True,
    )
