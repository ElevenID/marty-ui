"""Actual published worker, OAuth storage and local HTTP on official migrations."""

import asyncio
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import signal
import ssl
import tempfile
from threading import Thread
import time

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from run_canvas_worker_startup_oracle import DATABASE, finish_worker, start_worker
from test_canvas_lti_https import create_loopback_certificate


async def seed_oauth(origin, token):
    from issuance.domain.entities import (
        CanvasOAuthConnection,
        OrganizationIntegrationSecret,
    )
    from issuance.infrastructure.adapters.postgres_repository import (
        PostgresIssuanceRepository,
    )

    engine = create_async_engine(
        DATABASE.replace("postgresql:", "postgresql+asyncpg:", 1)
    )
    try:
        repo = PostgresIssuanceRepository(
            async_sessionmaker(engine, expire_on_commit=False)
        )
        await repo.save_integration_secret(
            OrganizationIntegrationSecret(
                id="worker-rest-token",
                organization_id="org-review",
                name="Synthetic REST token",
                provider="canvas",
                secret_value=token,
            )
        )
        await repo.save_canvas_oauth_connection(
            CanvasOAuthConnection(
                id="worker-rest-connection",
                organization_id="org-review",
                platform_id="platform-review",
                canvas_base_url=origin,
                client_id="synthetic-client",
                client_secret_ref="org_secret://org-review/unused-client",
                access_token_secret_ref="org_secret://org-review/worker-rest-token",
            )
        )
    finally:
        await engine.dispose()


def run(scenario="canvas-worker-rest-scenarios.json"):
    spec = json.loads((Path("/verification/contracts") / scenario).read_text())
    if "extends" in spec:
        base = json.loads(
            (Path("/verification/contracts") / spec["extends"]).read_text()
        )
        spec = {**base, **spec}
    shared = json.loads(
        (Path("/verification/contracts") / spec["shared_seed"]).read_text()
    )
    stage = {}
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "accept": self.headers.get("Accept"),
                }
            )
            response = stage["responses"][self.path] if "responses" in stage else stage
            body = json.dumps(response["body"], separators=(",", ":")).encode()
            self.send_response(response["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for key, value in response.get("headers", {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

    certificates = tempfile.TemporaryDirectory(prefix="canvas-worker-rest-")
    cert, key = create_loopback_certificate(Path(certificates.name))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"https://127.0.0.1:{server.server_port}"
    engine = create_engine(DATABASE, hide_parameters=True)
    os.environ["INTEGRATION_SECRET_MASTER_KEY"] = (
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    observations = []
    try:
        with engine.begin() as connection:
            for statement in shared["seed"]:
                connection.exec_driver_sql(statement)
            if "requirements" in spec:
                connection.execute(
                    text(
                        "UPDATE issuance_service.canvas_program_bindings SET evidence_requirements=CAST(:requirements AS json) WHERE id='binding-review'"
                    ),
                    {"requirements": json.dumps(spec["requirements"])},
                )
            connection.execute(
                text(
                    "UPDATE issuance_service.canvas_platforms SET canvas_base_url=:origin"
                ),
                {"origin": origin},
            )
        asyncio.run(seed_oauth(origin, spec["token"]))
        with engine.connect() as connection:
            preserved = connection.execute(
                text(shared["preserved_rows_sql"])
            ).scalar_one()
            ciphertext = connection.execute(
                text(
                    "SELECT encrypted_secret_value FROM issuance_service.organization_integration_secrets WHERE id='worker-rest-token'"
                )
            ).scalar_one()
        assert ciphertext != spec["token"]
        for index, stage in enumerate(spec["stages"]):
            requests.clear()
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE issuance_service.canvas_evidence_sync_targets SET next_run_at=clock_timestamp() WHERE id='target-review'"
                    )
                )
                connection.execute(
                    text("TRUNCATE issuance_service.canvas_worker_heartbeats")
                )
            child = start_worker(
                {
                    "database_scheme": "postgresql+asyncpg",
                    "environment": {
                        "CANVAS_PORTABLE_INTEGRATION_ENABLED": "true",
                        "CANVAS_PILOT_ORGANIZATION_IDS": "org-review",
                        "CANVAS_PRIVATE_ORIGIN_ALLOWLIST": origin,
                        "MARTY_CANVAS_TEST_CA_FILE": str(cert),
                        "PYTHONPATH": "/verification/worker_trust:"
                        + os.environ.get("PYTHONPATH", ""),
                    },
                },
                "worker-rest",
            )
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    assert child.poll() is None, (
                        "Published worker exited before completing its cycle"
                    )
                    with engine.connect() as connection:
                        jobs = connection.execute(text(spec["jobs_sql"])).scalar_one()
                        heartbeat = connection.execute(
                            text(
                                "SELECT jsonb_build_object('role',role,'metadata',metadata) FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest' AND metadata->>'phase'='idle'"
                            )
                        ).scalar_one_or_none()
                    if (
                        len(jobs) == index + 1
                        and jobs[-1]["status"] in {"succeeded", "retry", "dead_letter"}
                        and heartbeat
                    ):
                        break
                    time.sleep(0.025)
                else:
                    raise AssertionError("Published nonempty worker cycle timed out")
                child.send_signal(signal.SIGINT)
                exit_code = child.wait(timeout=10)
                with engine.connect() as connection:
                    snapshot = connection.execute(
                        text(shared["snapshot_sql"])
                    ).scalar_one()
                    facts = connection.execute(text(spec["facts_sql"])).scalar_one()
                    oauth = connection.execute(text(spec["oauth_sql"])).scalar_one()
                    assert (
                        connection.execute(
                            text(shared["preserved_rows_sql"])
                        ).scalar_one()
                        == preserved
                    )
                    assert (
                        connection.execute(
                            text(
                                "SELECT encrypted_secret_value FROM issuance_service.organization_integration_secrets WHERE id='worker-rest-token'"
                            )
                        ).scalar_one()
                        == ciphertext
                    )
                observations.append(
                    {
                        "name": stage["name"],
                        "requests": list(requests),
                        "jobs": jobs,
                        "heartbeat": heartbeat,
                        "snapshot": snapshot,
                        "facts": facts,
                        "oauth": oauth,
                        "exit_code_after_interrupt": exit_code,
                    }
                )
            finally:
                finish_worker(child)
        return {
            "schema": spec.get("oracle_schema", "marty.canvas-worker-rest-oracle/v1"),
            "source_sha256": {
                name: hashlib.sha256(
                    Path(importlib.util.find_spec(name).origin)
                    .read_text(encoding="utf-8")
                    .encode()
                ).hexdigest()
                for name in [
                    "issuance.canvas_worker",
                    "issuance.infrastructure.api.canvas_routes",
                ]
            },
            "observations": observations,
        }
    finally:
        engine.dispose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        certificates.cleanup()
