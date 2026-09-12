"""Explicit legacy renewal capture; actual ASGI/owners, controlled external ports.

Requires the pinned reference checkout/dependencies and marty-rs 0.1.60.
Default CI uses only the checked-in fixture/source guards, not this live capture.
No deployed service, operator environment, real key or database is accessed.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import ExitStack
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
import hashlib
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import runpy
import socket
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import uuid


ROOT = Path(__file__).resolve().parents[1]
OWNER = runpy.run_path(str(ROOT / "scripts/capture_didcomm_projector_reference.py"))
SOURCES = {
    **OWNER["SOURCES"],
    "services/issuance/infrastructure/adapters/memory_repository.py": "af5038cb5036b12160badc83e40bfb9830c00fee",
    "services/issuance/application/issuance_idempotency.py": "04ca7252a1d1184877a529b81e13814779f46160",
    "services/issuance/domain/ports.py": "695a2cdd3f3a5c9d3ce6ef12e282cdca6f086a24",
    "services/issuance/application/canvas_sync_service.py": "65252f9b3464e4160969bbc0ef0034192212cd59",
    "services/issuance/infrastructure/adapters/delivery_records.py": "eda21f907f3abd1e4652e06400f5a6dcf424952f",
}
NOW = datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
ISSUER = "did:example:renewal-issuer"
HOLDER = "did:example:renewal-holder"
ORG = "synthetic-org"
SOURCE_ID = "synthetic-source-credential"
SOURCE_TX = "synthetic-source-transaction"
API_KEY = "synthetic-renewal-management-key"
WALLET = "https://wallet.example/renewal-inbox"
GUARDS = (
    "missing-key", "wrong-key", "missing-tenant", "foreign-tenant", "missing-source",
    "inactive-source", "already-renewed", "missing-source-transaction", "not-renewable",
    "missing-source-issuer", "missing-expiry", "before-window", "at-window", "after-expiry",
    "invalid-idempotency-key", "direct-signing-header",
)
CASES = (
    *({"case": name, "guard": name} for name in GUARDS),
    {"case": "ordinary-offer"},
    {"case": "ordinary-keyed-retry", "key": "synthetic-renewal-key", "retry": True},
    {"case": "ordinary-keyed-conflict", "key": "synthetic-renewal-key", "conflict": True},
    *(
        {"case": f"{mode}-{name}", "mode": mode, **options}
        for mode in ("anoncrypt", "authcrypt")
        for name, options in (
            ("automatic-success", {"automatic": True}),
            ("automatic-refused", {"automatic": True, "wallet_status": 503}),
            ("automatic-no-subject", {"automatic": True, "no_subject": True}),
            ("keyed-rejection", {"automatic": True, "key": "synthetic-renewal-key"}),
            ("mixed-keyed-rejection", {"automatic": True, "mixed": True, "key": "synthetic-renewal-key"}),
            ("ordinary-then-direct-delivery", {"direct_after": True}),
        )
    ),
)


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is not None else NOW.replace(tzinfo=None)


def json_value(value, key=None):
    """Only normalize the independently generated Core message identifier."""
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return {name: json_value(item, name) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if key == "didcomm_message_id" and value:
        uuid.UUID(value)
        return "$core-message-id"
    return value


def verify_observations(observed, frozen):
    if observed != frozen:
        raise ValueError("Exact renewal reference observations differ")


def capture(reference: Path):
    # Import-time configuration must also be isolated from the operator environment.
    with patch.dict(os.environ, {}, clear=True):
        return _capture(reference)


def _capture(reference: Path):
    reference = reference.resolve(strict=True)
    OWNER["verify_sources"](reference, SOURCES)
    for package in ("services", "python", "packages"):
        sys.path.insert(0, str(reference / package))
    if importlib.metadata.version("marty-rs") != "0.1.60":
        raise ValueError("Capture requires marty-rs 0.1.60")

    import httpx
    import marty_rs
    from fastapi import FastAPI
    from issuance.application import canvas_sync_service, issuance_idempotency, rust_integration
    from issuance.domain import entities, ports
    from issuance.domain.ports import IIssuanceRepository
    from issuance.infrastructure.adapters import delivery_records, memory_repository
    from issuance.infrastructure.api import routes
    from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc
    from marty_proto.v1 import organization_service_pb2_grpc as org_grpc

    for module, path in (
        (routes, OWNER["HTTP"]),
        (rust_integration, "services/issuance/application/rust_integration.py"),
        (entities, "services/issuance/domain/entities.py"),
        (memory_repository, "services/issuance/infrastructure/adapters/memory_repository.py"),
        (issuance_idempotency, "services/issuance/application/issuance_idempotency.py"),
        (canvas_sync_service, "services/issuance/application/canvas_sync_service.py"),
        (ports, "services/issuance/domain/ports.py"),
        (delivery_records, "services/issuance/infrastructure/adapters/delivery_records.py"),
    ):
        if Path(module.__file__).resolve() != reference / path:
            raise ValueError("Reference import escaped the pinned checkout")

    def document(did, byte):
        # Fixed public vectors for the existing synthetic repeated-byte keys.
        # Capture does not implement key derivation; original Core owns crypto.
        public = bytes.fromhex({
            17: "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13",
            29: "51ddf3cb36a42fdf3d6a81dfcaada9fe17818aa145548a08e51f2d73e9452478",
        }[byte])
        return {
            "id": did,
            "verificationMethod": [{"id": f"{did}#key-1", "controller": did,
                "type": "JsonWebKey2020", "publicKeyJwk": {
                    "kty": "OKP", "crv": "X25519",
                    "x": base64.urlsafe_b64encode(public).decode().rstrip("="),
                }}],
            "keyAgreement": [f"{did}#key-1"],
            "service": [{"id": f"{did}#didcomm", "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": WALLET, "accept": ["didcomm/v2"]}}],
        }

    documents = {ISSUER: document(ISSUER, 17), HOLDER: document(HOLDER, 29)}
    central = {
        function.__code__: function.__name__ for function in (
            routes.renew_issued_credential, routes.initiate_issuance,
            routes._issuance_response_from_transaction, routes._didcomm_sign_and_deliver,
            routes._finalize_credential_renewal, routes.revoke_credential,
        )
    }

    states = {}

    async def observe(case, directory):
        events = []
        active = False
        sequence = 0

        def next_uuid():
            nonlocal sequence
            sequence += 1
            return uuid.UUID(int=sequence)

        def snapshot(repo):
            value = json_value({
                "transactions": [repo._transactions[key] for key in sorted(repo._transactions)],
                "credentials": [repo._credentials[key] for key in sorted(repo._credentials)],
                "delivery_records": [repo._delivery_records[key] for key in sorted(repo._delivery_records)],
                "events": repo._events,
            })
            # Content-addressed full snapshots avoid repeating unchanged rows.
            # This is lossless fixture interning, never an observed-value normalizer.
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(encoded).hexdigest()
            if digest in states:
                assert states[digest] == value
            states[digest] = value
            return {"$ref": f"#/states/{digest}"}

        class ObservedRepository(memory_repository.InMemoryIssuanceRepository):
            def __getattribute__(self, name):
                method = super().__getattribute__(name)
                if name not in {
                    "get_credential", "get_transaction", "save_credential", "save_transaction",
                    "recover_transaction_idempotently", "reserve_transaction_idempotently",
                    "finalize_direct_credential_issuance", "save_event", "save_delivery_record",
                } or not active:
                    return method

                async def observed(*args, **kwargs):
                    record = {"repository": name}
                    if args and isinstance(args[0], str):
                        record["id"] = args[0]
                    elif args and hasattr(args[0], "renewal_of_credential_id"):
                        record.update(transaction_fields(args[0]))
                    events.append(record)
                    return await method(*args, **kwargs)
                return observed

        def transaction_fields(tx):
            return {"transaction_id": tx.id, "status": tx.status.value,
                "renewal_of_credential_id": tx.renewal_of_credential_id,
                "application_id": tx.application_id}

        seen_frames = set()

        def profile(frame, event, _argument):
            # Observe entry without substituting any central coroutine. Keep frames
            # until request completion so resume events/ID reuse cannot duplicate it.
            if event != "call" or frame.f_code not in central or frame in seen_frames:
                return
            seen_frames.add(frame)
            observation = {"owner_enter": central[frame.f_code]}
            tx = frame.f_locals.get("tx")
            if tx is not None:
                observation.update(transaction_fields(tx))
            observation["source_status"] = repo._credentials.get(SOURCE_ID).status.value if SOURCE_ID in repo._credentials else None
            events.append(observation)

        repo = ObservedRepository()
        mode = case.get("mode", "anoncrypt")
        guard = case.get("guard")
        automatic = case.get("automatic", False)
        wallets = [{"wallet_id": "didcomm", "format_variant": "didcomm_v2", "display_name": "Synthetic DIDComm"}] if automatic else []
        if case.get("mixed"):
            wallets.append({"wallet_id": "ordinary", "format_variant": "w3c_vcdm_v2_sd_jwt", "display_name": "Ordinary"})
        tx = entities.IssuanceTransaction(
            id=SOURCE_TX, organization_id=ORG, credential_template_id="synthetic-template",
            application_id="synthetic-application", applicant_id="synthetic-applicant",
            subject_did=HOLDER, issuer_did_override=ISSUER, issuer_algorithm="ES256",
            revocation_profile_id="synthetic-revocation-profile", status=entities.IssuanceStatus.ISSUED,
            renewable=True, renewal_window_days=7, claims={"name": "Synthetic Holder"},
            pre_auth_code="synthetic-source-code", created_at=NOW, expires_at=NOW,
        )
        credential = entities.IssuedCredential(
            id=SOURCE_ID, transaction_id=SOURCE_TX, organization_id=ORG,
            credential_template_id="synthetic-template", applicant_id="synthetic-applicant",
            subject_did=None if case.get("no_subject") else HOLDER, issuer_did=ISSUER,
            revocation_profile_id="synthetic-revocation-profile", expires_at=NOW + timedelta(days=1),
        )
        if guard == "inactive-source":
            credential.status = entities.CredentialStatus.SUSPENDED
        if guard == "already-renewed":
            credential.renewed_to_credential_id = "synthetic-existing-successor"
        if guard == "not-renewable":
            tx.renewable = False
        if guard == "missing-source-issuer":
            tx.issuer_did_override = None
        if guard == "missing-expiry":
            credential.expires_at = None
        if guard in {"before-window", "at-window", "after-expiry"}:
            credential.expires_at = NOW + {
                "before-window": timedelta(days=7, microseconds=1),
                "at-window": timedelta(days=7), "after-expiry": timedelta(days=-1),
            }[guard]
        if guard != "missing-source-transaction":
            await repo.save_transaction(tx)
        if guard != "missing-source":
            await repo.save_credential(credential)

        async def organization(request):
            events.append({"port": "organization", "organization_id": request.organization_id})
            return SimpleNamespace(id=ORG)

        async def template(request):
            events.append({"port": "template", "template_id": request.template_id})
            return SimpleNamespace(id="synthetic-template", credential_type="EmployeeCredential",
                vct="https://issuer.example/credentials/EmployeeCredential", zk_predicate_claims=[],
                selective_disclosure_fields=[], credential_payload_format="w3c_vcdm_v2_sd_jwt",
                revocation_profile_id="synthetic-revocation-profile", issuer_did=ISSUER,
                issuer_algorithm="ES256", wallet_configs_json=json.dumps(wallets),
                validity_rules=SimpleNamespace(default_validity_days=365, renewable=True, renewal_window_days=7))

        class Channel:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                pass

        async def issuer_context(transaction, **_kwargs):
            events.append({"port": "issuer-context", **transaction_fields(transaction)})
            transaction.issuer_profile_id = "synthetic-issuer-profile"
            transaction.issuer_algorithm = "ES256"
            transaction.signing_service_id = "synthetic-signing-service"
            return {"issuer_did": ISSUER, "issuer_profile_id": transaction.issuer_profile_id,
                "algorithm": "ES256", "verification_method_id": f"{ISSUER}#signing-key",
                "service": {"algorithm": "ES256"}}

        async def revocation_binding(**kwargs):
            events.append({"port": "revocation-binding", **kwargs})

        async def allocate(**kwargs):
            events.append({"port": "status-allocation", "credential_id": kwargs["credential_id"]})
            return "synthetic-revocation-profile", []

        async def signer(**kwargs):
            events.append({"port": "credential-builder-and-signer", "credential_id": kwargs["credential_id"]})
            return "synthetic-signed-credential", kwargs["credential_id"]

        async def endpoint(value):
            events.append({"port": "endpoint-policy", "endpoint": value})
            return value

        async def publish(**kwargs):
            events.append({"port": "status-publication", "credential_id": kwargs["credential_id"],
                "action": kwargs["action"], "reason": kwargs["reason"]})

        class WalletClient(Channel):
            def __init__(self, **kwargs):
                assert kwargs == {"timeout": 30.0, "verify": True}

            async def post(self, url, *, content, headers):
                envelope = json.loads(content)
                protected = json.loads(base64.urlsafe_b64decode(envelope["protected"] + "=" * (-len(envelope["protected"]) % 4)))
                events.append({"port": "wallet-http", "endpoint": url, "headers": headers,
                    "encryption_alg": protected["alg"], "encryption_enc": protected["enc"],
                    "response_status": case.get("wallet_status", 202), "state_at_send": snapshot(repo)})
                return httpx.Response(case.get("wallet_status", 202))

        policy = {"mode": mode}
        if mode == "authcrypt":
            policy["sender_x25519_private_key"] = base64.urlsafe_b64encode(bytes([17]) * 32).decode().rstrip("=")
        policy_path = directory / "synthetic-policy.json"
        policy_path.write_text(json.dumps({"version": 1, "issuers": {ISSUER: policy}}), encoding="utf-8")
        app = FastAPI()
        app.include_router(routes.issued_credential_router)
        app.include_router(routes.issuance_router)
        app.dependency_overrides[IIssuanceRepository] = lambda: repo
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://synthetic-reference")
        headers = {"X-API-Key": API_KEY, "X-Organization-ID": ORG}
        if guard == "missing-key":
            del headers["X-API-Key"]
        if guard == "wrong-key":
            headers["X-API-Key"] = "synthetic-wrong-key"
        if guard == "missing-tenant":
            del headers["X-Organization-ID"]
        if guard == "foreign-tenant":
            headers["X-Organization-ID"] = "synthetic-other-org"
        if case.get("key"):
            headers["Idempotency-Key"] = case["key"]
        if guard == "invalid-idempotency-key":
            headers["Idempotency-Key"] = "invalid key"
        if guard == "direct-signing-header":
            headers["X-Signing-Service-ID"] = "synthetic-disallowed-selector"
        before = snapshot(repo)
        responses = []
        socket_attempts = []

        def deny_socket(*_args, **_kwargs):
            socket_attempts.append("unexpected real network operation")
            raise AssertionError("Renewal reference capture must not open a real socket")

        with ExitStack() as stack:
            # Explicit synthetic environment: never inherit operator policy, paths,
            # resolver URLs, tokens, or endpoint trust from the host.
            stack.enter_context(patch.dict(os.environ, {
                "DIDCOMM_ENCRYPTION_POLICY_FILE": str(policy_path),
                "ORG_GRPC_TARGET": "synthetic-org:9002", "CT_GRPC_TARGET": "synthetic-template:9003",
            }, clear=True))
            # The event loop already exists; do not intercept its Windows
            # socketpair initialization. Any unexpected dependency fallback now
            # fails closed even if the legacy handler catches the exception.
            for owner, name in (
                (socket.socket, "connect"), (socket.socket, "connect_ex"),
                (socket, "create_connection"), (socket, "getaddrinfo"),
            ):
                stack.enter_context(patch.object(owner, name, deny_socket))
            for obj, name, replacement in (
                (routes, "_ISSUANCE_API_KEY", API_KEY), (routes, "ISSUER_BASE_URL", "https://issuer.example"),
                (routes, "datetime", FrozenDatetime), (entities, "datetime", FrozenDatetime),
                (memory_repository, "datetime", FrozenDatetime),
                (canvas_sync_service, "datetime", FrozenDatetime),
                (delivery_records, "datetime", FrozenDatetime),
                (entities.uuid, "uuid4", next_uuid), (entities.secrets, "token_urlsafe", lambda _length: "synthetic-pre-auth-code"),
                (routes, "_create_grpc_channel", lambda _target: Channel()),
                (org_grpc, "OrganizationServiceStub", lambda _channel: SimpleNamespace(GetOrganization=organization)),
                (ct_grpc, "CredentialTemplateServiceStub", lambda _channel: SimpleNamespace(GetTemplate=template)),
                (routes, "apply_required_remote_issuer_context", issuer_context),
                (routes, "apply_remote_issuer_context", issuer_context),
                (routes, "_require_active_revocation_profile_binding", revocation_binding),
                (routes, "_allocate_credential_status_list_entries", allocate),
                (routes, "create_sd_jwt_vc_with_remote_signing", signer),
                (routes, "_validated_didcomm_delivery_endpoint", endpoint),
                (routes, "_delegate_to_revocation_profile", publish),
                (routes, "_didcomm_tls_verifier", lambda: True),
                (routes, "didcomm_resolve_did", lambda did: documents[did]),
                (rust_integration, "didcomm_resolve_did", lambda did: documents[did]),
                (httpx, "AsyncClient", WalletClient),
            ):
                stack.enter_context(patch.object(obj, name, replacement))
            active = True
            previous_profile = sys.getprofile()
            sys.setprofile(profile)
            try:
                response = await client.post(f"/v1/issued-credentials/{SOURCE_ID}/renew", headers=headers)
                responses.append({"status": response.status_code, "content_type": response.headers.get("content-type"), "body": json_value(response.json())})
                after_first = snapshot(repo)
                if case.get("retry") or case.get("conflict"):
                    if case.get("conflict"):
                        changed = await repo.get_transaction(SOURCE_TX)
                        changed.claims["name"] = "Changed Synthetic Holder"
                        await repo.save_transaction(changed)
                    events.append({"request": "renewal-retry"})
                    response = await client.post(f"/v1/issued-credentials/{SOURCE_ID}/renew", headers=headers)
                    responses.append({"status": response.status_code, "content_type": response.headers.get("content-type"), "body": json_value(response.json())})
                if case.get("direct_after"):
                    events.append({"request": "direct-delivery-after-renewal-link"})
                    response = await client.post("/v1/issuance/didcomm/deliver", headers=headers, json={
                        "organization_id": ORG, "transaction_id": responses[0]["body"]["transaction_id"], "holder_did": HOLDER,
                    })
                    responses.append({"status": response.status_code, "content_type": response.headers.get("content-type"), "body": json_value(response.json())})
            finally:
                sys.setprofile(previous_profile)
                active = False
                await client.aclose()
            assert not socket_attempts, "A caught dependency error attempted real network access"
        return {"case": case["case"], "input": case, "before": before,
            "responses": responses, "after_first": after_first, "after": snapshot(repo), "observations": events}

    async def observations():
        result = []
        with tempfile.TemporaryDirectory(prefix="synthetic-renewal-reference-") as temp:
            for case in CASES:
                # Seed factories are also deterministic, before repository instrumentation.
                with patch.object(entities, "datetime", FrozenDatetime), patch.object(entities.secrets, "token_urlsafe", lambda _length: "synthetic-pre-auth-code"):
                    result.append(await observe(case, Path(temp)))
        return result

    native_module = Path(marty_rs.__file__).resolve()
    native_binaries = sorted(native_module.parent.glob("*.pyd")) + sorted(native_module.parent.glob("*.so"))
    if not native_binaries:
        raise ValueError("Actual native binding binary provenance is missing")
    return {"schema": "marty.credential-renewal-python-reference/v1", "reference": {
        "repository": "ElevenID/marty-credentials", "source_commit": OWNER["SOURCE_COMMIT"],
        "source_blobs": SOURCES, "binding_version": "0.1.60",
        "binding_binary_sha256": [hashlib.sha256(path.read_bytes()).hexdigest() for path in native_binaries],
        "scope": "Actual unchanged ASGI renewal/auth/tenant, initiation, offer projector, direct DIDComm, original policy/prepared encryption and finalization. Original in-memory repository, NOT PostgreSQL/durable concurrency, gateway or deployment proof.",
        "controlled_ports": ["fixed clock/seeds", "organization/template gRPC", "issuer context", "credential builder/signer", "status allocation/publication", "DID resolution/endpoint trust", "wallet HTTP/TLS"],
        "crypto_scope": "Original marty-rs0.1.60 pack/encrypt with fixed synthetic X25519 fixtures; signer and transport controlled; no KMS claim.",
        "observations": "Central entries observed with sys.setprofile, not substituted; repository calls delegated unchanged. Core message UUID only is validated and normalized; full service responses retain synthetic offer tokens. Complete state snapshots are losslessly interned by canonical-JSON SHA256 and referenced through #/states/<hash>.",
    }, "cases": asyncio.run(observations()), "states": states}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("credentials_checkout", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    observed = capture(args.credentials_checkout)
    if args.check:
        frozen = json.loads((ROOT / "contracts/credential-renewal-python-reference.json").read_text(encoding="utf-8"))
        verify_observations(observed, frozen)
        print(f"Exact unchanged Python renewal reference matched: {len(CASES)} cases")
    else:
        print(json.dumps(observed, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
