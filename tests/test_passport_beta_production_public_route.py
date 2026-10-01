"""Production continuity includes the user-facing public route."""

from __future__ import annotations

import pytest

from scripts.probe_passport_beta_host import (
    HostProbeError, production_public_route,
)


class Response:
    def __init__(self, status: int, url: str) -> None:
        self.status = status
        self.url = url

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


@pytest.mark.parametrize("status,url,accepted", [
    (200, "https://elevenidllc.com/", True),
    (503, "https://elevenidllc.com/", False),
    (200, "https://beta.elevenidllc.com/", False),
])
def test_production_route_requires_live_production_origin(
    status: int, url: str, accepted: bool,
) -> None:
    def open_route(request: object, *, timeout: int) -> Response:
        assert request.full_url == "https://elevenidllc.com/"
        assert timeout == 10
        return Response(status, url)

    if accepted:
        assert production_public_route(open_route) == {
            "origin": "https://elevenidllc.com/", "status": 200,
        }
    else:
        with pytest.raises(HostProbeError, match="public route"):
            production_public_route(open_route)
