from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "check_release_absent.py"
SPEC = importlib.util.spec_from_file_location("check_release_absent", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class _Response(io.BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _response(payload: object) -> _Response:
    return _Response(json.dumps(payload).encode())


def test_missing_release_is_the_only_allowed_state() -> None:
    def missing(request: object, *, timeout: int) -> object:
        assert timeout == 30
        raise HTTPError(str(request), 404, "Not Found", {}, None)

    MODULE.ensure_release_absent("ElevenID/marty-ui", "v1.1.1", "token", opener=missing)


@pytest.mark.parametrize("draft,state", [(True, "draft"), (False, "published")])
def test_existing_draft_or_published_release_fails_closed(
    draft: bool, state: str
) -> None:
    def existing(_request: object, *, timeout: int) -> _Response:
        assert timeout == 30
        return _response({"tag_name": "v1.1.1", "draft": draft})

    with pytest.raises(MODULE.ReleaseAlreadyExists, match=state):
        MODULE.ensure_release_absent(
            "ElevenID/marty-ui",
            "v1.1.1",
            "token",
            opener=existing,
        )


def test_lookup_errors_and_mismatched_responses_fail_closed() -> None:
    def unavailable(request: object, *, timeout: int) -> object:
        assert timeout == 30
        raise HTTPError(str(request), 503, "Unavailable", {}, None)

    with pytest.raises(MODULE.ReleaseLookupError, match="HTTP 503"):
        MODULE.ensure_release_absent(
            "ElevenID/marty-ui",
            "v1.1.1",
            "token",
            opener=unavailable,
        )

    with pytest.raises(MODULE.ReleaseLookupError, match="requested tag"):
        MODULE.ensure_release_absent(
            "ElevenID/marty-ui",
            "v1.1.1",
            "token",
            opener=lambda *_args, **_kwargs: _response(
                {"tag_name": "v1.1.0", "draft": False}
            ),
        )


def test_request_is_exact_and_authenticated_without_leaking_the_token() -> None:
    captured: dict[str, object] = {}

    def inspect(request: object, *, timeout: int) -> object:
        captured["request"] = request
        captured["timeout"] = timeout
        raise HTTPError(str(request), 404, "Not Found", {}, None)

    MODULE.ensure_release_absent(
        "ElevenID/marty-ui", "v1.1.1", "secret", opener=inspect
    )
    request = captured["request"]
    assert request.full_url.endswith("/ElevenID/marty-ui/releases/tags/v1.1.1")
    assert request.get_header("Authorization") == "Bearer secret"
    assert captured["timeout"] == 30
