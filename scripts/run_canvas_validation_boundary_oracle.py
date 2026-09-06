"""Published app/router/adapter HTTP boundary with synthetic secret and HTTP ports.

Only the immutable published-image probe invokes this fixture. Application
middleware and dependency validation run unchanged; lifespan is not started.
No deployment endpoint, real secret, or caller-selected file is accepted.
"""

import asyncio
from contextlib import asynccontextmanager, ExitStack
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx


async def observe():
    os.environ["ISSUANCE_API_KEY"] = "synthetic-validation-key"
    from issuance import main
    from issuance.domain.ports import IIssuanceRepository
    from issuance.infrastructure.api import canvas_routes
    from issuance.infrastructure.adapters import canvas_credentials_adapter as adapter

    sources = {}
    for name, module, expected in [
        (
            "main",
            main,
            "bdbbc759b41ba40c9218221c8ac4dc0075cfb5f330e9fd3b33dd99e8aef5b475",
        ),
        (
            "router",
            canvas_routes,
            "f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943",
        ),
        (
            "adapter",
            adapter,
            "24f5c0f22c075af3a11abbb48be52bcc6535e0d4fc31e446f7fb218bfe40d679",
        ),
    ]:
        actual = hashlib.sha256(Path(module.__file__).read_text().encode()).hexdigest()
        assert actual == expected, f"published {name} source drifted"
        sources[name] = actual
    cases = json.loads(
        Path(
            "/verification/contracts/canvas-validation-boundary-scenarios.json"
        ).read_text()
    )["cases"]
    observations = []
    for case in cases:
        files, lookups, requests, exceptions = [], [], [], []

        def open_synthetic(path, mode, *, encoding):
            assert (path, mode, encoding) == ("/synthetic/operator-token", "r", "utf-8")
            values = case["files"]
            assert len(files) < len(values), "unexpected extra operator file read"
            kind = values[len(files)]
            files.append("operator-token")
            if kind == "invalid_utf8":
                raise UnicodeDecodeError(
                    "utf-8", b"\xff", 0, 1, "synthetic invalid UTF-8"
                )
            assert kind in {"value", "empty"}
            return io.StringIO("synthetic-file\n" if kind == "value" else "")

        class Repository:
            async def get_integration_secret(self, identifier):
                assert identifier == "secret-review"
                lookups.append({"kind": "metadata", "secret_id": identifier})
                return SimpleNamespace(
                    id=identifier,
                    organization_id=case.get("secret_organization", "org-review"),
                    enabled=True,
                    provider="canvas_credentials",
                    purpose="api_token",
                )

            async def get_integration_secret_value(self, organization, identifier):
                assert (organization, identifier) == ("org-review", "secret-review")
                lookups.append(
                    {
                        "kind": "value",
                        "organization_id": organization,
                        "secret_id": identifier,
                    }
                )
                return "synthetic-tenant"

        def response(request):
            assert request.method == "GET" and request.url.host == "api.badgr.io"
            requests.append(
                {
                    "method": request.method,
                    "url": str(request.url),
                    "authorization": request.headers.get("authorization"),
                }
            )
            if "response_hex" in case:
                return httpx.Response(
                    case["response_status"],
                    content=bytes.fromhex(case["response_hex"]),
                    headers={
                        "x-request-id": "synthetic-provider",
                        "content-type": case["response_content_type"],
                    },
                )
            return httpx.Response(
                200,
                json={"accepted": True},
                headers={"x-request-id": "synthetic-provider"},
            )

        @asynccontextmanager
        async def client(**kwargs):
            assert kwargs == {"timeout": 20.0}
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(response)
            ) as session:
                yield session

        environment = {
            name: "" for name in os.environ if name.startswith("CANVAS_CREDENTIALS_")
        }
        environment.update(
            {
                "ISSUANCE_API_KEY": "synthetic-validation-key",
                "CANVAS_CREDENTIALS_PROVIDER": case["provider"],
                "CANVAS_CREDENTIALS_PUBLISH_URL": case.get(
                    "publish_url", "https://bridge.example.invalid/publish"
                ),
                "CANVAS_CREDENTIALS_API_BASE_URL": case.get(
                    "api_base_url", "https://api.badgr.io"
                ),
                "CANVAS_CREDENTIALS_ASSERTION_SCOPE": case.get("scope", "badgeclasses"),
                "CANVAS_CREDENTIALS_BADGECLASS_ID": case.get(
                    "badgeclass_id", "badge-review"
                ),
                "CANVAS_CREDENTIALS_ISSUER_ID": case.get("issuer_id", "issuer-review"),
                "CANVAS_CREDENTIALS_API_TOKEN": case.get("direct", ""),
                "CANVAS_CREDENTIALS_API_TOKEN_FILE": "/synthetic/operator-token"
                if "files" in case
                else "",
            }
        )
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, environment))
            stack.enter_context(
                patch.object(adapter, "open", open_synthetic, create=True)
            )
            stack.enter_context(patch.object(adapter, "canvas_http_client", client))
            app = main.create_app()
            app.dependency_overrides[IIssuanceRepository] = Repository

            async def observed_app(scope, receive, send):
                try:
                    await app(scope, receive, send)
                except Exception as error:
                    exceptions.append(type(error).__name__)
                    raise

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(
                    app=observed_app, raise_app_exceptions=False
                ),
                base_url="http://published.invalid",
            ) as session:
                result = await session.post(
                    "/v1/integrations/canvas/canvas-credentials/validate",
                    headers={
                        "x-api-key": "synthetic-validation-key",
                        "x-organization-id": "org-review",
                        "x-request-id": "synthetic-validation",
                    },
                    json={
                        "organization_id": "org-review",
                        "canvas_credentials": case.get("config", {}),
                    },
                )
        assert result.status_code not in {422, 503}, (
            "fixture must pass actual authentication and body parsing"
        )
        expected_exceptions = (
            [case["expected_exception"]] if case.get("expected_exception") else []
        )
        assert (
            exceptions == expected_exceptions
            if "response_hex" in case
            else exceptions in ([], ["UnicodeDecodeError"])
        ), f"unexpected published exception: {exceptions}"
        if result.headers.get("content-type", "").startswith("application/json"):
            body = result.json()
            if "validated_at" in body:
                assert datetime.fromisoformat(
                    body["validated_at"].replace("Z", "+00:00")
                ).tzinfo
                body["validated_at"] = "$timestamp"
        else:
            body = result.text
        observations.append(
            {
                "name": case["name"],
                "status": result.status_code,
                "content_type": result.headers.get("content-type"),
                "body": body,
                "files": files,
                "lookups": lookups,
                "requests": requests,
            }
        )
    return {
        "sources": sources,
        "boundary": "published create_app middleware, managed route and full adapter; lifespan disabled; synthetic repository/file/HTTP ports",
        "observations": observations,
    }


def run():
    return asyncio.run(observe())


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
