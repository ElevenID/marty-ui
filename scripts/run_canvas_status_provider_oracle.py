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


async def observe(
    cases=None,
    *,
    delivery_lifecycle=False,
    credential_routes=False,
    capture_diagnostics=False,
    response_projection=None,
):
    from issuance.domain.entities import CredentialStatus
    from issuance.infrastructure.adapters import canvas_credentials_adapter as adapter
    from issuance.infrastructure.adapters.postgres_repository import (
        PostgresIssuanceRepository,
    )

    if delivery_lifecycle or credential_routes:
        from issuance.infrastructure.api import routes as lifecycle_routes

        assert (
            hashlib.sha256(
                Path(lifecycle_routes.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest()
            == "2b6d2eb7cec34bb4596ef9b758d8af02a3172337e89bad3b5d26b558d0dd00b7"
        )

    root = Path("/verification/contracts")
    if cases is None:
        cases = json.loads(
            (root / "canvas-status-provider-scenarios.json").read_text()
        )["cases"]
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
        if key == "status_sync_response" and response_projection is not None:
            return response_projection(value)
        if isinstance(value, dict):
            return {name: normalize(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, str) and key.endswith("_at"):
            assert datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo
            return "$timestamp"
        return value

    async def delivery_snapshot():
        async with engine.connect() as connection:
            return (
                await connection.execute(
                    text(
                        "SELECT to_jsonb(d) FROM issuance_service.credential_delivery_records d "
                        "WHERE id='delivery-provider'"
                    )
                )
            ).scalar_one()

    async def credential_snapshot():
        async with engine.connect() as connection:
            return (
                await connection.execute(
                    text(
                        "SELECT to_jsonb(c) FROM issuance_service.issued_credentials c "
                        "WHERE id='credential-review'"
                    )
                )
            ).scalar_one()

    async def observe_credential_route(route_action, case, requests, sequence):
        from issuance import main
        from issuance.domain.ports import IIssuanceRepository
        from issuance.infrastructure.adapters.postgres_repository import (
            issuance_events_table,
        )
        from sqlalchemy import select

        original = await credential_snapshot()
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE issuance_service.issued_credentials SET status=:status,"
                    "revoked=false,revoked_at=NULL,revocation_reason=NULL "
                    "WHERE id='credential-review'"
                ),
                {"status": "suspended" if route_action == "reinstate" else "active"},
            )
            await connection.exec_driver_sql(
                "UPDATE issuance_service.credential_delivery_records SET "
                'metadata=\'{"canvas_program_binding_id":"binding-review"}\','
                "external_credential_id='external-assertion',last_error=NULL "
                "WHERE id='delivery-provider'"
            )
            events_before = (
                await connection.execute(select(issuance_events_table))
            ).all()
        before = await credential_snapshot()
        delivery_before = await delivery_snapshot()
        first_request = len(requests)
        exceptions, publications = [], []
        sequence.clear()

        async def publication(credential_id, action, reason=None, credential=None):
            sequence.append("publication")
            publications.append(
                {
                    "credential_id": credential_id,
                    "action": action,
                    "reason": reason,
                    "argument_status": credential.status.value,
                    "persisted_status": (await credential_snapshot())["status"],
                }
            )
            return {"success": True}

        save_credential = repo.save_credential
        save_delivery = repo.save_delivery_record

        async def observed_save_credential(value):
            await save_credential(value)
            sequence.append("credential_saved")

        async def observed_save_delivery(value):
            sequence.append("delivery_save_attempt")
            try:
                await save_delivery(value)
            except Exception:
                sequence.append("delivery_save_failed")
                raise
            sequence.append("delivery_saved")

        with (
            patch.dict(os.environ, {"ISSUANCE_API_KEY": "synthetic-validation-key"}),
            patch.object(
                lifecycle_routes, "_delegate_to_revocation_profile", publication
            ),
            patch.object(repo, "save_credential", observed_save_credential),
            patch.object(repo, "save_delivery_record", observed_save_delivery),
        ):
            app = main.create_app()
            app.dependency_overrides[IIssuanceRepository] = lambda: repo

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
                response = await session.post(
                    f"/v1/issuance/credentials/credential-review/{route_action}",
                    headers={
                        "x-api-key": "synthetic-validation-key",
                        "x-organization-id": "org-review",
                        "x-request-id": "synthetic-credential-route",
                    },
                    json={"reason": case.get("reason", "synthetic reason")},
                )
        after = await credential_snapshot()
        delivery_after = await delivery_snapshot()
        async with engine.connect() as connection:
            events_after = (
                await connection.execute(select(issuance_events_table))
            ).all()
        assert len(publications) == 1 and len(requests) - first_request == 1, (
            "fixture must pass authentication, parsing and Canvas delivery gates",
            route_action,
            response.status_code,
        )
        assert events_before == events_after, "published route event behavior changed"
        # Reset only this synthetic credential's lifecycle projection.
        # The outer complete-row preservation check still covers every credential
        # and transaction; unrelated field changes cannot be hidden by this reset.
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE issuance_service.issued_credentials c SET "
                    "status=o.status,status_updated_at=o.status_updated_at,"
                    "revoked=o.revoked,revoked_at=o.revoked_at,"
                    "revocation_reason=o.revocation_reason "
                    "FROM jsonb_populate_record(NULL::issuance_service.issued_credentials,"
                    "CAST(:original AS jsonb)) o WHERE c.id='credential-review'"
                ),
                {"original": json.dumps(original)},
            )
        route_requests = requests[first_request:]
        del requests[first_request:]
        return {
            "action": route_action,
            "http_status": response.status_code,
            "content_type": response.headers.get("content-type"),
            "body": normalize(response.json())
            if response.headers.get("content-type", "").startswith("application/json")
            else response.text,
            "exceptions": exceptions,
            "publication": publications,
            "sequence": list(sequence),
            "requests": route_requests,
            "credential_before": normalize(before),
            "credential_after": normalize(after),
            "credential_changed_columns": sorted(
                name for name in before if before[name] != after[name]
            ),
            "delivery_before": normalize(delivery_before),
            "delivery_after": normalize(delivery_after),
            "delivery_row_unchanged": delivery_before == delivery_after,
            "events_unchanged": events_before == events_after,
        }

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
        for case in cases:
            if delivery_lifecycle:
                # Fresh synthetic delivery state for each independent boundary.
                async with engine.begin() as connection:
                    await connection.exec_driver_sql(
                        "UPDATE issuance_service.credential_delivery_records "
                        "SET metadata='{}',last_error=NULL WHERE id='delivery-provider'"
                    )
                delivery_before = await delivery_snapshot()
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
            requests, secrets, sequence = [], [], []
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
                sequence.append("provider_request")
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
                    {"content": bytes.fromhex(case["response_hex"])}
                    if "response_hex" in case
                    else (
                        {"text": case["response_text"]}
                        if "response_text" in case
                        else {"json": case.get("response_json", {"accepted": True})}
                    )
                )
                headers = {"x-request-id": "synthetic-provider-request"}
                if "response_content_type" in case:
                    headers["content-type"] = case["response_content_type"]
                return httpx.Response(
                    case.get("response_status", 200),
                    headers=headers,
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
                except Exception as failure:
                    outcome = {
                        "error_class": type(failure).__name__,
                        "error": str(failure),
                    }
                else:
                    # Observer failures must never masquerade as adapter errors.
                    outcome = {"metadata": normalize(result.metadata)}
                if delivery_lifecycle:
                    before_lifecycle_requests = len(requests)
                    try:
                        await lifecycle_routes._sync_canvas_lifecycle_delivery_record(
                            delivery,
                            credential,
                            repo,
                            lifecycle_action=action,
                            reason=case.get("reason", "synthetic reason"),
                        )
                        lifecycle = {"returned": True}
                    except Exception as failure:
                        lifecycle = {
                            "error_class": type(failure).__name__,
                            "error": str(failure),
                        }
                    persisted = await repo.get_delivery_record("delivery-provider")
                    lifecycle["persisted"] = normalize(
                        {
                            "metadata": persisted.metadata,
                            "last_error": persisted.last_error,
                            "status": persisted.status.value,
                        }
                    )
                    lifecycle["provider_requests"] = (
                        len(requests) - before_lifecycle_requests
                    )
                    lifecycle["row_unchanged"] = (
                        await delivery_snapshot() == delivery_before
                    )
                    outcome["delivery_lifecycle"] = lifecycle
                if credential_routes:
                    outcome["credential_routes"] = [
                        await observe_credential_route(
                            route_action, case, requests, sequence
                        )
                        for route_action in ("suspend", "reinstate", "revoke")
                    ]
            if "response_hex" in case and not capture_diagnostics:
                assert outcome.get("error_class") == case["expected_error_class"], (
                    case["name"],
                    "unexpected published provider exception",
                    outcome,
                )
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
            **(
                {
                    "credential_routes_boundary": "actual create_app, authenticated credential routes, provider adapter and PostgreSQL saves; only canonical publication and existing HTTP/DNS boundaries controlled; lifespan disabled",
                }
                if credential_routes
                else {}
            ),
            **(
                {
                    "delivery_lifecycle_boundary": "actual delivery sync helper and repository save; independent synthetic starting rows; credential transition and publication not invoked",
                    "lifecycle_routes_sha256": hashlib.sha256(
                        Path(lifecycle_routes.__file__)
                        .read_text(encoding="utf-8")
                        .encode()
                    ).hexdigest(),
                }
                if delivery_lifecycle
                else {}
            ),
            "observations": observations,
        }
    finally:
        await engine.dispose()


def run():
    return asyncio.run(asyncio.wait_for(observe(), timeout=60))
