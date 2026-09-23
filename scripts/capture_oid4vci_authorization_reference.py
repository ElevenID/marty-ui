#!/usr/bin/env python3
"""Capture the protected Python OID4VCI/authorization route behavior.

This is a development oracle, not a production dependency.  It executes the
unchanged marty-credentials routes through an ASGI transport and emits a
deterministic, language-neutral record.  Dynamic UUIDs, timestamps, and
authorization codes are normalized while response status, headers, bodies,
repository calls, and persistent effects remain observable.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SOURCE_COMMIT = "aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26"
SOURCE_TREE = "819b7458a31c75d28043a4660643b029c5ec4567"
SOURCE_FILES = (
    "services/issuance/infrastructure/api/routes.py",
    "services/issuance/domain/entities.py",
    "services/issuance/infrastructure/adapters/memory_repository.py",
    "services/issuance/infrastructure/adapters/postgres_repository.py",
)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def _normalized_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _install_source(credentials_root: Path) -> None:
    for relative in ("services", "packages", "python"):
        sys.path.insert(0, str(credentials_root / relative))


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        value = UUID_RE.sub("<uuid>", value)
        value = value.replace("contract-authorization-code", "<authorization-code>")
        return value
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    return value


async def _capture(credentials_root: Path) -> dict[str, Any]:
    _install_source(credentials_root)

    # The entity reads this value at import time. Pin the released default so
    # the reference cannot inherit an operator's local shell configuration.
    os.environ["ISSUANCE_AUTH_SESSION_TTL_MINUTES"] = "60"

    import httpx
    from fastapi import FastAPI
    from issuance.domain.entities import (
        CredentialStatus,
        IssuanceStatus,
        IssuanceTransaction,
        IssuedCredential,
        Oid4vciRegisteredClient,
    )
    from issuance.domain.ports import IIssuanceRepository
    from issuance.infrastructure.adapters.memory_repository import (
        InMemoryIssuanceRepository,
    )
    from issuance.infrastructure.api import routes

    fixed_time = datetime(2026, 9, 21, 12, 34, 56, tzinfo=UTC)
    valid_public_jwks = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "kid": "key-1",
                "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
                "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            }
        ]
    }
    chronology: list[dict[str, Any]] = []

    class TraceRepository(InMemoryIssuanceRepository):
        def __init__(self) -> None:
            super().__init__()
            self.calls: list[dict[str, Any]] = []
            self.par_store_result: bool | None = None
            self.par_store_error = False
            self.par_consume_error = False
            self.list_error = False
            self.client_read_after_save = True

        def _call(self, method: str, **values: Any) -> None:
            call = _normalize({"method": method, **values})
            self.calls.append(call)
            chronology.append(call)

        async def save_oid4vci_client(self, client):
            self._call(
                "save_oid4vci_client",
                organization_id=client.organization_id,
                client_id=client.client_id,
                redirect_uris=client.redirect_uris,
                active=client.active,
            )
            await super().save_oid4vci_client(client)

        async def get_oid4vci_client(self, organization_id, client_id):
            self._call(
                "get_oid4vci_client",
                organization_id=organization_id,
                client_id=client_id,
            )
            if not self.client_read_after_save:
                return None
            return await super().get_oid4vci_client(organization_id, client_id)

        async def save_pushed_authorization_request(
            self, request_uri, params, *, ttl_seconds
        ):
            self._call(
                "save_pushed_authorization_request",
                request_uri=request_uri,
                params=params,
                ttl_seconds=ttl_seconds,
            )
            if self.par_store_error:
                raise RuntimeError("contract PAR database secret")
            if self.par_store_result is not None:
                return self.par_store_result
            return await super().save_pushed_authorization_request(
                request_uri, params, ttl_seconds=ttl_seconds
            )

        async def consume_pushed_authorization_request(self, request_uri):
            self._call("consume_pushed_authorization_request", request_uri=request_uri)
            if self.par_consume_error:
                raise RuntimeError("contract PAR database secret")
            return await super().consume_pushed_authorization_request(request_uri)

        async def save_authorization_session(self, auth_session):
            self._call(
                "save_authorization_session",
                code=auth_session.code,
                client_id=auth_session.client_id,
                redirect_uri=auth_session.redirect_uri,
                state=auth_session.state,
                organization_id=auth_session.organization_id,
                credential_configuration_ids=auth_session.credential_configuration_ids,
                persisted_lifetime_seconds=round(
                    (auth_session.expires_at - auth_session.created_at).total_seconds()
                ),
            )
            await super().save_authorization_session(auth_session)

        async def get_transaction(self, tx_id):
            self._call("get_transaction", tx_id=tx_id)
            return await super().get_transaction(tx_id)

        async def get_credential_by_transaction_id(self, transaction_id):
            self._call(
                "get_credential_by_transaction_id", transaction_id=transaction_id
            )
            return await super().get_credential_by_transaction_id(transaction_id)

        async def save_transaction(self, tx):
            self._call(
                "save_transaction",
                tx_id=tx.id,
                status=tx.status.value,
                reason=tx.revocation_reason,
            )
            await super().save_transaction(tx)

        async def save_credential(self, credential):
            self._call(
                "save_credential",
                credential_id=credential.id,
                status=credential.status.value,
                reason=credential.revocation_reason,
            )
            await super().save_credential(credential)

        async def list_credentials_by_org(self, organization_id):
            self._call("list_credentials_by_org", organization_id=organization_id)
            if self.list_error:
                raise RuntimeError("contract list database secret")
            return await super().list_credentials_by_org(organization_id)

    active_repo: TraceRepository = TraceRepository()

    def get_repo() -> TraceRepository:
        return active_repo

    async def no_rate_limit() -> None:
        return None

    def native_authorization_response(request_json: str, *, session_lifetime_secs: int):
        request = json.loads(request_json)
        if request["response_type"] != "code":
            raise ValueError("response_type must be code")
        return (
            {
                "code": "contract-authorization-code",
                "state": request.get("state"),
            },
            {
                "code": "contract-authorization-code",
                "credential_configuration_ids": ["config-a"],
                "expires_in": session_lifetime_secs,
            },
        )

    reject_revocation = False

    async def revocation_profile(**kwargs):
        call = {
            "method": "delegate_revocation_profile",
            "credential_id": kwargs["credential_id"],
            "action": kwargs["action"],
            "reason": kwargs["reason"],
        }
        chronology.append(call)
        if reject_revocation:
            raise routes.HTTPException(
                status_code=503,
                detail="Revocation service rejected the status change",
            )
        return {
            "success": True,
            "organization_id": kwargs["credential"].organization_id,
            "index": 42,
            "status_list_url": "https://issuer.example/status/1",
        }

    async def sync_canvas(credential, _repo, *, lifecycle_action, reason):
        call = {
            "method": "sync_canvas_lifecycle_delivery_records",
            "credential_id": credential.id,
            "action": lifecycle_action,
            "reason": reason,
        }
        chronology.append(call)

    routes.oid4vci_create_authorization_response = native_authorization_response
    routes._delegate_to_revocation_profile = revocation_profile
    routes._sync_canvas_lifecycle_delivery_records = sync_canvas
    routes._ISSUANCE_API_KEY = "management-key"
    routes.ISSUER_BASE_URL = "https://issuer.example"
    os.environ["ISSUER_BASE_URL"] = "https://issuer.example"
    os.environ.pop("ALLOWED_REDIRECT_URIS", None)

    app = FastAPI()
    app.include_router(routes.issuance_router)
    app.dependency_overrides[IIssuanceRepository] = get_repo
    app.dependency_overrides[routes._enforce_token_rate_limit] = no_rate_limit
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="https://issuer.example",
        follow_redirects=False,
    )

    observations: list[dict[str, Any]] = []

    def reset() -> TraceRepository:
        nonlocal active_repo, chronology, reject_revocation
        active_repo = TraceRepository()
        chronology = []
        reject_revocation = False
        os.environ.pop("ALLOWED_REDIRECT_URIS", None)
        return active_repo

    def response_record(response: httpx.Response) -> dict[str, Any]:
        headers = {
            name.lower(): _normalize(value)
            for name, value in sorted(response.headers.items())
            if name.lower()
            in {"content-length", "content-type", "location", "retry-after"}
        }
        if not response.content:
            body: Any = None
        elif response.headers.get("content-type", "").startswith("application/json"):
            body = response.json()
        else:
            body = response.text
        return {
            "status_code": response.status_code,
            "headers": headers,
            "body": _normalize(body),
        }

    def observe(name: str, response: httpx.Response, **extra: Any) -> None:
        observations.append(
            {
                "name": name,
                "response": response_record(response),
                "repository_calls": list(active_repo.calls),
                **_normalize(extra),
            }
        )

    async with client:
        # Management authentication is resolved before any repository access.
        reset()
        response = await client.get("/v1/issuance/credentials?organization_id=org-a")
        observe("list_credentials_missing_management_key", response)

        reset()
        response = await client.put(
            "/v1/issuance/oid4vci-clients",
            json={
                "organization_id": "org-a",
                "client_id": "wallet-a",
                "jwks": valid_public_jwks,
            },
        )
        observe("put_registered_client_missing_management_key", response)

        reset()
        response = await client.post(
            "/v1/issuance/transactions/tx-a/revoke",
            json={},
        )
        observe("revoke_transaction_missing_management_key", response)

        reset()
        response = await client.get(
            "/v1/issuance/credentials?organization_id=org-a",
            headers={"X-API-Key": "management-key"},
        )
        observe("list_credentials_missing_tenant", response)

        repo = reset()
        await repo.save_credential(
            IssuedCredential(
                id="cred-active",
                transaction_id="tx-active",
                organization_id="org-a",
                credential_template_id="template-a",
                applicant_id="applicant-a",
                subject_did="did:example:holder",
                status=CredentialStatus.ACTIVE,
                issued_at=fixed_time,
                status_updated_at=fixed_time,
            )
        )
        await repo.save_credential(
            IssuedCredential(
                id="cred-revoked",
                transaction_id="tx-revoked",
                organization_id="org-a",
                credential_template_id="template-a",
                status=CredentialStatus.REVOKED,
                issued_at=fixed_time,
                status_updated_at=fixed_time,
            )
        )
        repo.calls.clear()
        response = await client.get(
            "/v1/issuance/credentials?organization_id=org-a&status=active",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-a",
            },
        )
        observe("list_credentials_exact_status_projection", response)

        repo.calls.clear()
        response = await client.get(
            "/v1/issuance/credentials?organization_id=org-a&status=ACTIVE",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-a",
            },
        )
        observe("list_credentials_status_is_case_sensitive", response)

        reset()
        response = await client.get(
            "/v1/issuance/credentials?organization_id=org-a",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-b",
            },
        )
        observe("list_credentials_rejects_foreign_tenant_before_read", response)

        repo = reset()
        repo.list_error = True
        response = await client.get(
            "/v1/issuance/credentials?organization_id=org-a",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-a",
            },
        )
        observe("list_credentials_repository_failure", response)

        # Registered client management currently trusts body organization_id.
        repo = reset()
        response = await client.put(
            "/v1/issuance/oid4vci-clients",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-b",
            },
            json={
                "organization_id": " org-a ",
                "client_id": " wallet-a ",
                "jwks": valid_public_jwks,
                "redirect_uris": ["https://wallet.example/callback?channel=one"],
            },
        )
        registered = response_record(response)
        if response.status_code == 200 and isinstance(registered["body"], dict):
            registered["body"]["created_at"] = "<timestamp>"
            registered["body"]["updated_at"] = "<timestamp>"
        observations.append(
            {
                "name": "put_registered_client_uses_body_tenant",
                "response": registered,
                "repository_calls": list(repo.calls),
            }
        )

        repo = reset()
        repo.client_read_after_save = False
        response = await client.put(
            "/v1/issuance/oid4vci-clients",
            headers={"X-API-Key": "management-key"},
            json={
                "organization_id": "org-a",
                "client_id": "wallet-a",
                "jwks": valid_public_jwks,
            },
        )
        observe("put_registered_client_requires_read_after_write", response)

        reset()
        response = await client.put(
            "/v1/issuance/oid4vci-clients",
            headers={"X-API-Key": "management-key"},
            json={
                "organization_id": "org-a",
                "client_id": "wallet-a",
                "jwks": {"keys": [{"kty": "EC", "d": "private-secret"}]},
            },
        )
        observe("put_registered_client_rejects_private_key_material", response)

        # PAR persists all fields, gives issuer_org precedence, and is single-use.
        repo = reset()
        response = await client.post(
            "/v1/issuance/par?issuer_org=org-a",
            data={
                "response_type": "code",
                "client_id": "wallet-a",
                "redirect_uri": "https://wallet.example/callback?channel=one",
                "state": "state-a",
                "code_challenge": "challenge-a",
                "code_challenge_method": "S256",
                "organization_id": "org-b",
            },
        )
        request_uri = response.json()["request_uri"]
        observe("par_success_issuer_query_precedes_form", response)

        repo.calls.clear()
        response = await client.get(
            "/v1/issuance/authorize",
            params={
                "request_uri": request_uri,
                "response_type": "attacker-type",
                "client_id": "attacker-client",
                "redirect_uri": "https://attacker.example/callback",
                "state": "attacker-state",
                "issuer_org": "org-b",
            },
        )
        observe(
            "authorize_consumes_par_and_preserves_registered_query",
            response,
            persistent_authorization_sessions=len(repo._authorization_sessions),
        )

        repo.calls.clear()
        replay = await client.get(
            "/v1/issuance/authorize", params={"request_uri": request_uri}
        )
        observe(
            "authorize_rejects_replayed_par",
            replay,
            persistent_authorization_sessions=len(repo._authorization_sessions),
        )

        reset()
        response = await client.get("/v1/issuance/authorize")
        observe("authorize_requires_response_type_and_client_id", response)

        repo = reset()
        response = await client.get(
            "/v1/issuance/authorize",
            params={
                "response_type": "code",
                "client_id": "public-wallet",
                "state": "state-json",
                "scope": "openid",
                "issuer_org": "org-a",
            },
        )
        observe(
            "authorize_json_success_persists_session",
            response,
            persistent_authorization_sessions=len(repo._authorization_sessions),
        )

        reset()
        response = await client.get(
            "/v1/issuance/authorize",
            params={
                "response_type": "not-code",
                "client_id": "wallet-a",
                "redirect_uri": "https://wallet.example/callback?channel=one",
                "state": "state-a",
                "issuer_org": "org-a",
            },
        )
        observe("authorize_native_error_redirect_preserves_query_and_state", response)

        repo = reset()
        await repo.save_oid4vci_client(
            Oid4vciRegisteredClient(
                organization_id="org-a",
                client_id="wallet-a",
                jwks={"keys": []},
                redirect_uris=["https://wallet.example/registered"],
                active=False,
            )
        )
        repo.calls.clear()
        response = await client.get(
            "/v1/issuance/authorize",
            params={
                "response_type": "code",
                "client_id": "wallet-a",
                "redirect_uri": "https://wallet.example/registered",
                "issuer_org": "org-a",
            },
        )
        observe("authorize_rejects_inactive_registered_client", response)

        repo = reset()
        await repo.save_oid4vci_client(
            Oid4vciRegisteredClient(
                organization_id="org-a",
                client_id="wallet-a",
                jwks={"keys": []},
                redirect_uris=["https://wallet.example/registered"],
            )
        )
        repo.calls.clear()
        chronology.clear()
        response = await client.get(
            "/v1/issuance/authorize",
            params={
                "response_type": "code",
                "client_id": "wallet-a",
                "redirect_uri": "https://wallet.example/unregistered",
                "issuer_org": "org-a",
            },
        )
        observe("authorize_rejects_unregistered_client_redirect", response)

        repo = reset()
        repo.par_consume_error = True
        response = await client.get(
            "/v1/issuance/authorize",
            params={"request_uri": "urn:ietf:params:oauth:request_uri:secret"},
        )
        observe("authorize_sanitizes_par_store_failure", response)

        repo = reset()
        oversized = "x" * routes._PAR_MAX_PAYLOAD_BYTES
        response = await client.post(
            "/v1/issuance/par?issuer_org=org-a",
            data={"authorization_details": oversized},
        )
        observe("par_rejects_oversized_encoded_payload_before_store", response)

        repo = reset()
        repo.par_store_result = False
        response = await client.post("/v1/issuance/par?issuer_org=org-a", data={})
        observe("par_failed_store_is_sanitized", response)

        # Deferred and notification endpoints only check the Bearer prefix in
        # the protected source; captures make that security gap non-ambiguous.
        reset()
        response = await client.post(
            "/v1/issuance/deferred-credential", json={"transaction_id": "tx-a"}
        )
        observe("deferred_requires_bearer_prefix", response)

        reset()
        response = await client.post(
            "/v1/issuance/deferred-credential",
            headers={"Authorization": "Bearer unrelated-token"},
            json={},
        )
        observe("deferred_requires_transaction_id", response)

        reset()
        response = await client.post(
            "/v1/issuance/deferred-credential",
            headers={"Authorization": "Bearer unrelated-token"},
            json={"transaction_id": "tx-missing"},
        )
        observe("deferred_rejects_unknown_transaction", response)

        repo = reset()
        tx = IssuanceTransaction(id="tx-a", organization_id="org-a")
        await repo.save_transaction(tx)
        repo.calls.clear()
        response = await client.post(
            "/v1/issuance/deferred-credential",
            headers={"Authorization": "Bearer "},
            json={"transaction_id": "tx-a"},
        )
        observe("deferred_empty_bearer_currently_reaches_pending_transaction", response)

        repo = reset()
        issued_tx = IssuanceTransaction(
            id="tx-issued",
            organization_id="org-a",
            status=IssuanceStatus.ISSUED,
        )
        await repo.save_transaction(issued_tx)
        await repo.save_credential(
            IssuedCredential(
                id="cred-issued",
                transaction_id="tx-issued",
                organization_id="org-a",
                credential_jwt="credential.jwt.value",
            )
        )
        repo.calls.clear()
        response = await client.post(
            "/v1/issuance/deferred-credential",
            headers={"Authorization": "Bearer unrelated-token"},
            json={"transaction_id": "tx-issued"},
        )
        observe("deferred_unbound_bearer_currently_reads_issued_credential", response)

        repo = reset()
        await repo.save_transaction(
            IssuanceTransaction(
                id="tx-issued-without-credential",
                organization_id="org-a",
                status=IssuanceStatus.ISSUED,
            )
        )
        repo.calls.clear()
        chronology.clear()
        response = await client.post(
            "/v1/issuance/deferred-credential",
            headers={"Authorization": "Bearer unrelated-token"},
            json={"transaction_id": "tx-issued-without-credential"},
        )
        observe("deferred_issued_without_credential_is_terminal_error", response)

        repo = reset()
        await repo.save_transaction(
            IssuanceTransaction(
                id="tx-failed",
                organization_id="org-a",
                status=IssuanceStatus.FAILED,
            )
        )
        repo.calls.clear()
        chronology.clear()
        response = await client.post(
            "/v1/issuance/deferred-credential",
            headers={"Authorization": "Bearer unrelated-token"},
            json={"transaction_id": "tx-failed"},
        )
        observe("deferred_reports_terminal_state", response)

        reset()
        response = await client.post(
            "/v1/issuance/deferred-credential",
            headers={"Authorization": "Bearer unrelated-token"},
            content=b"not-json",
        )
        observe("deferred_malformed_json_is_unhandled", response)

        reset()
        response = await client.post(
            "/v1/issuance/notification", json={"arbitrary": ["ignored"]}
        )
        observe("notification_missing_bearer_has_nested_error", response)

        reset()
        response = await client.post(
            "/v1/issuance/notification",
            headers={"Authorization": "Bearer "},
            content=b"not-json-and-not-read",
        )
        observe(
            "notification_empty_bearer_and_unread_body_currently_acknowledged", response
        )

        reset()
        response = await client.post(
            "/v1/issuance/notification",
            headers={"Authorization": "Bearer unrelated-token"},
            json={
                "notification_id": "notification-a",
                "event": "credential_accepted",
            },
        )
        observe("notification_valid_shape_has_no_legacy_effect", response)

        # Transaction revocation orders canonical status publication before
        # local credential and transaction persistence.
        repo = reset()
        tx = IssuanceTransaction(
            id="tx-revoke",
            organization_id="org-a",
            status=IssuanceStatus.ISSUED,
        )
        credential = IssuedCredential(
            id="cred-revoke",
            transaction_id="tx-revoke",
            organization_id="org-a",
            revocation_profile_id="profile-a",
            status_list_entries=[
                {
                    "status_list_id": "profile-a",
                    "status_purpose": "revocation",
                    "index": 42,
                    "type": "BitstringStatusListEntry",
                }
            ],
        )
        await repo.save_transaction(tx)
        await repo.save_credential(credential)
        repo.calls.clear()
        chronology.clear()
        response = await client.post(
            "/v1/issuance/transactions/tx-revoke/revoke",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-a",
            },
            json={"reason": "holder request"},
        )
        body = response_record(response)
        if isinstance(body["body"], dict):
            body["body"]["revoked_at"] = "<timestamp>"
        observations.append(
            {
                "name": "revoke_transaction_canonical_then_local_order",
                "response": body,
                "operation_trace": _normalize(chronology),
            }
        )

        reset()
        response = await client.post(
            "/v1/issuance/transactions/tx-missing/revoke",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-a",
            },
            json={},
        )
        observe("revoke_transaction_missing_transaction", response)

        repo = reset()
        await repo.save_transaction(
            IssuanceTransaction(id="tx-mismatch", organization_id="org-a")
        )
        await repo.save_credential(
            IssuedCredential(
                id="cred-mismatch",
                transaction_id="tx-mismatch",
                organization_id="org-b",
            )
        )
        repo.calls.clear()
        chronology.clear()
        response = await client.post(
            "/v1/issuance/transactions/tx-mismatch/revoke",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-a",
            },
            json={},
        )
        observe("revoke_transaction_rejects_credential_tenant_mismatch", response)

        repo = reset()
        tx = IssuanceTransaction(
            id="tx-reject", organization_id="org-a", status=IssuanceStatus.ISSUED
        )
        await repo.save_transaction(tx)
        await repo.save_credential(
            IssuedCredential(
                id="cred-reject",
                transaction_id="tx-reject",
                organization_id="org-a",
                revocation_profile_id="profile-a",
                status_list_entries=[
                    {
                        "status_list_id": "profile-a",
                        "status_purpose": "revocation",
                        "index": 42,
                    }
                ],
            )
        )
        repo.calls.clear()
        reject_revocation = True
        response = await client.post(
            "/v1/issuance/transactions/tx-reject/revoke",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-a",
            },
            json={"reason": "holder request"},
        )
        stored_tx = await repo.get_transaction("tx-reject")
        stored_credential = await repo.get_credential("cred-reject")
        observe(
            "revoke_transaction_fails_closed_before_local_mutation",
            response,
            stored={
                "transaction_status": stored_tx.status.value,
                "credential_status": stored_credential.status.value,
            },
        )

        repo = reset()
        await repo.save_transaction(
            IssuanceTransaction(id="tx-foreign", organization_id="org-a")
        )
        repo.calls.clear()
        response = await client.post(
            "/v1/issuance/transactions/tx-foreign/revoke",
            headers={
                "X-API-Key": "management-key",
                "X-Organization-ID": "org-b",
            },
            json={},
        )
        observe("revoke_transaction_hides_foreign_resource_after_lookup", response)

    return {
        "schema": "marty.issuance-oid4vci-authorization-python-reference/v1",
        "source": {
            "repository": "ElevenID/marty-credentials",
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
            "files": {
                relative: _normalized_sha256(credentials_root / relative)
                for relative in SOURCE_FILES
            },
            "capture": (
                "unchanged route composition executed through FastAPI ASGI transport "
                "with controlled native-engine and downstream revocation/canvas dependencies"
            ),
        },
        "normalization": {
            "uuid": "<uuid>",
            "authorization_code": "<authorization-code>",
            "timestamps": "<timestamp>",
        },
        "observations": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("credentials_root", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.credentials_root.resolve()
    result = asyncio.run(_capture(root))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"Wrote OID4VCI authorization reference to {args.output}")
        return 0
    if args.verify:
        expected = json.loads(args.verify.read_text(encoding="utf-8"))
        if result != expected:
            print(rendered, end="")
            return 1
        print(f"OID4VCI authorization reference matches {args.verify}")
        return 0
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
