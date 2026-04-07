"""
Shared dependency-injection helpers for org-client setup.

Eliminates 4 lines of duplicated gRPC + OrganizationClient boilerplate
from every service lifespan.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from common.grpc_factory import create_grpc_channel
from marty_common.org_authorization import OrganizationClient


async def setup_org_client(
    app: FastAPI,
    service_name: str,
    *,
    redis_client=None,
    cache_ttl: int = 0,
) -> None:
    """Create a gRPC channel to the organization service and attach it to app.state.

    Reads ``ORG_GRPC_TARGET`` (default ``organization:9002``).
    The channel and client are stored as ``app.state._org_grpc_channel``
    and ``app.state.org_client``.
    """
    org_grpc_target = os.environ.get("ORG_GRPC_TARGET", "organization:9002")
    channel = create_grpc_channel(org_grpc_target, service_name=service_name)
    kwargs: dict = {"grpc_channel": channel}
    if redis_client is not None:
        kwargs["redis_client"] = redis_client
    if cache_ttl:
        kwargs["cache_ttl"] = cache_ttl
    app.state.org_client = OrganizationClient(**kwargs)
    app.state._org_grpc_channel = channel


async def teardown_org_client(app: FastAPI) -> None:
    """Close the org-client gRPC channel created by :func:`setup_org_client`."""
    channel = getattr(app.state, "_org_grpc_channel", None)
    if channel is not None:
        await channel.close()
