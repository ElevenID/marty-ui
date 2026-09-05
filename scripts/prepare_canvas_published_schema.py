"""Run inside the pinned issuance image, against the runner's disposable DB.

This is test orchestration, not a new migration owner. The published service's
official upgrade entry point executes its own migrations. No endpoint arguments
or deployment credentials are accepted.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path

from sqlalchemy import create_engine, text

DATABASE = "postgresql://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test"


def prepare():
    fixture = json.loads(
        Path(
            "/verification/contracts/canvas-worker-consumer-range-oracle.json"
        ).read_text()
    )
    worker = Path(importlib.util.find_spec("issuance.canvas_worker").origin)
    worker_hash = hashlib.sha256(
        worker.read_text(encoding="utf-8").encode()
    ).hexdigest()
    if worker_hash != fixture["observed_source_sha256"]:
        raise RuntimeError("Published worker provenance mismatch")
    os.environ["DATABASE_URL"] = DATABASE
    engine = create_engine(DATABASE, hide_parameters=True)
    try:
        with engine.begin() as connection:
            # Fresh DB only; refuse an existing issuance namespace. The minimal
            # organization dependency is explicit, as in the frozen Python oracle.
            connection.execute(text("CREATE SCHEMA issuance_service"))
            connection.execute(text("CREATE SCHEMA organization_service"))
            connection.execute(
                text(
                    "CREATE TABLE organization_service.organizations "
                    "(id VARCHAR PRIMARY KEY, name VARCHAR, slug VARCHAR)"
                )
            )
        from services.issuance.manage_migrations import upgrade

        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            upgrade()
        with engine.connect() as connection:
            revisions = sorted(
                connection.execute(
                    text("SELECT version_num FROM issuance_service.alembic_version")
                ).scalars()
            )
        if revisions != fixture["migration_revisions"]:
            raise RuntimeError("Published migration head mismatch")
        return {
            "status": "passed",
            "migration_revisions": revisions,
            "worker_sha256": worker_hash,
            "organization_dependency": "synthetic-minimal",
        }
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        print(json.dumps(prepare(), sort_keys=True))
    except BaseException as failure:
        # Never echo database parameters, SQL values, or exception messages.
        print(json.dumps({"status": "failed", "error_class": type(failure).__name__}))
        raise SystemExit(1) from None
