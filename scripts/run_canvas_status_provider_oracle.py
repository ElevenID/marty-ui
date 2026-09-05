"""Published status-provider protocol with controlled HTTP/secret boundaries.

Runs only inside the pinned schema probe. No deployment URL or real credential
is accepted; HTTP calls are intercepted by httpx.MockTransport.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
from unittest.mock import patch

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def observe():
    from issuance.domain.entities import CredentialStatus
    from issuance.infrastructure.adapters import canvas_credentials_adapter as adapter
    from issuance.infrastructure.adapters.postgres_repository import (
        PostgresIssuanceRepository,
    )

    root = Path("/verification/contracts")
    scenarios = json.loads((root / "canvas-status-provider-scenarios.json").read_text())
    shared = json.loads((root / "canvas-issued-review-scenarios.json").read_text())
    engine = create_async_engine(
        "postgresql+asyncpg://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test",
        hide_parameters=True,
    )
    repo = PostgresIssuanceRepository(
        async_sessionmaker(engine, expire_on_commit=False)
    )
    observations = []

    def normalize(value, key=""):
        if isinstance(value, dict):
            return {name: normalize(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, str) and key.endswith("_at"):
            assert datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo
            return "$timestamp"
        return value

    try:
        async with engine.begin() as connection:
            for statement in shared["seed"]:
                await connection.exec_driver_sql(statement)
            await connection.exec_driver_sql(
                "INSERT INTO issuance_service.credential_delivery_records "
                "(id,credential_id,transaction_id,organization_id,delivery_target,delivery_mode,status,metadata) "
                "VALUES ('delivery-provider','credential-review','transaction-review','org-review',"
                "'canvas_credentials','mirror','delivered','{}')"
            )
            preserved = (
                await connection.execute(text(shared["preserved_rows_sql"]))
            ).scalar_one()
        for case in scenarios["cases"]:
            environment = {
                "CANVAS_PORTABLE_INTEGRATION_ENABLED": "true"
                if case.get("rollout", True)
                else "false",
                "CANVAS_PILOT_ORGANIZATION_IDS": case.get(
                    "pilot_organizations", "org-review"
                ),
                "CANVAS_CREDENTIALS_PROVIDER": case["provider"],
                "CANVAS_CREDENTIALS_STATUS_SYNC_URL": case.get(
                    "sync_url", "https://bridge.example.invalid/status"
                ),
                "CANVAS_CREDENTIALS_API_TOKEN": "synthetic-operator-token"
                if case.get("operator_token", "operator")
                else "",
                "CANVAS_CREDENTIALS_API_TOKEN_FILE": "",
                "CANVAS_CREDENTIALS_PUBLISH_URL": case.get("publish_url", ""),
                "CANVAS_CREDENTIALS_BADGECLASS_ID": "",
                "CANVAS_CREDENTIALS_ISSUER_ID": case.get(
                    "issuer_id", "configured-issuer"
                ),
                "CANVAS_CREDENTIALS_API_BASE_URL": case.get(
                    "api_base_url", "https://api.badgr.io"
                ),
                "CANVAS_CREDENTIALS_BASE_URL": case.get("legacy_base_url", ""),
                "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST": case.get(
                    "allowed_api_origins", ""
                ),
                "CANVAS_CREDENTIALS_REVOKE_URL_TEMPLATE": case.get(
                    "revoke_url_template", ""
                ),
            }
            requests, secrets = [], []
            credential = await repo.get_credential("credential-review")
            platform = await repo.get_canvas_platform("platform-review")
            delivery = await repo.get_delivery_record("delivery-provider")
            delivery.organization_id = case.get("delivery_organization", "org-review")
            action = case["action"]
            credential.status = {
                "suspend": CredentialStatus.SUSPENDED,
                "revoke": CredentialStatus.REVOKED,
                "reinstate": CredentialStatus.ACTIVE,
            }[action]
            credential.status_updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
            credential.revoked_at = (
                credential.status_updated_at if action == "revoke" else None
            )
            credential.revocation_reason = case.get("revocation_reason")
            platform.organization_id = case.get("platform_organization", "org-review")
            delivery.credential_id = case.get(
                "delivery_credential", "credential-review"
            )
            delivery.transaction_id = case.get(
                "delivery_transaction", "transaction-review"
            )
            delivery.external_credential_id = case.get(
                "external_credential_id", "external-assertion"
            )
            delivery.external_issuer_id = case.get("external_issuer_id")
            delivery.metadata = case.get(
                "metadata", {"canvas_program_binding_id": "binding-review"}
            )

            async def secret(organization, identifier):
                secrets.append(
                    {"organization_id": organization, "secret_id": identifier}
                )
                value = case.get("secrets", {}).get(identifier)
                return "synthetic-tenant-token" if value else None

            def transport(request):
                authorization = request.headers.get("authorization")
                assert authorization in (
                    None,
                    "Bearer synthetic-operator-token",
                    "Bearer synthetic-tenant-token",
                )
                requests.append(
                    {
                        "method": request.method,
                        "url": str(request.url),
                        "headers": {
                            "accept": request.headers.get("accept"),
                            "content-type": request.headers.get("content-type"),
                            "authorization": authorization.replace(
                                "synthetic-operator-token", "$operator-token"
                            ).replace("synthetic-tenant-token", "$tenant-token")
                            if authorization
                            else None,
                        },
                        "body": normalize(json.loads(request.content)),
                    }
                )
                if case.get("transport_error"):
                    raise httpx.ConnectError(
                        "Synthetic transport unavailable", request=request
                    )
                arguments = (
                    {"text": case["response_text"]}
                    if "response_text" in case
                    else {"json": case.get("response_json", {"accepted": True})}
                )
                return httpx.Response(
                    case.get("response_status", 200),
                    headers={"x-request-id": "synthetic-provider-request"},
                    **arguments,
                )

            @asynccontextmanager
            async def client(*, timeout):
                assert timeout > 0
                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(transport)
                ) as session:
                    yield session

            with (
                patch.dict(os.environ, environment),
                patch.object(adapter, "canvas_http_client", client),
                # The real URL validator also resolves DNS before MockTransport
                # is reached. Keep validation active, but make its DNS boundary
                # explicit and deterministic. No socket is opened to this address.
                patch.object(
                    socket,
                    "getaddrinfo",
                    return_value=[
                        (
                            socket.AF_INET,
                            socket.SOCK_STREAM,
                            socket.IPPROTO_TCP,
                            "",
                            ("8.8.8.8", 443),
                        )
                    ],
                ),
            ):
                try:
                    result = await adapter.sync_canvas_credential_status(
                        credential=credential,
                        platform=platform,
                        delivery_record=delivery,
                        lifecycle_action=action,
                        reason=case.get("reason", "synthetic reason"),
                        secret_resolver=secret,
                    )
                    outcome = {"metadata": normalize(result.metadata)}
                except Exception as failure:
                    outcome = {
                        "error_class": type(failure).__name__,
                        "error": str(failure),
                    }
            observations.append(
                {
                    "name": case["name"],
                    "requests": requests,
                    "secrets": secrets,
                    **outcome,
                }
            )
        async with engine.connect() as connection:
            assert (
                await connection.execute(text(shared["preserved_rows_sql"]))
            ).scalar_one() == preserved
        return {
            "boundary": "published status-provider adapter and real repository DTOs; controlled HTTP transport, public DNS result and tenant secret lookup; no external network",
            "adapter_sha256": hashlib.sha256(
                Path(adapter.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "normalization": "validated datetime presence and synthetic bearer-token labels; selected contractual HTTP headers",
            "observations": observations,
        }
    finally:
        await engine.dispose()


def run():
    return asyncio.run(asyncio.wait_for(observe(), timeout=60))
