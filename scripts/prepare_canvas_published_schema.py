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
import traceback
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
    expected_revisions = fixture["migration_revisions"]
    overlay = None
    if os.environ.get("MARTY_CANVAS_REVIEW_RECOVERY_SCHEMA") == "1":
        overlay = json.loads(
            Path(
                "/verification/contracts/canvas-review-recovery-migration.json"
            ).read_text()
        )
        source = Path("/app") / overlay["source"]
        normalized = source.read_text(encoding="utf-8").encode()
        if hashlib.sha256(normalized).hexdigest() != overlay["sha256"]:
            raise RuntimeError("Official review recovery migration hash mismatch")
        git_blob = b"blob " + str(len(normalized)).encode() + b"\0" + normalized
        if hashlib.sha1(git_blob, usedforsecurity=False).hexdigest() != overlay["blob"]:
            raise RuntimeError("Official review recovery migration blob mismatch")
        if expected_revisions != [overlay["parent"]]:
            raise RuntimeError("Official review recovery migration parent mismatch")
        expected_revisions = [overlay["revision"]]
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
        if revisions != expected_revisions:
            raise RuntimeError("Published migration head mismatch")
        report = {
            "status": "passed",
            "migration_revisions": revisions,
            "worker_sha256": worker_hash,
            "organization_dependency": "synthetic-minimal",
        }
        if overlay is not None:
            report["review_recovery_overlay"] = overlay
        if os.environ.get("MARTY_CANVAS_REVIEW_LIFECYCLE_ORACLE") == "1":
            import runpy

            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                report["review_lifecycle"] = runpy.run_path(
                    "/verification/scripts/run_canvas_operations_oracle.py"
                )["run"]("canvas-review-lifecycle-scenarios.json")
        if os.environ.get("MARTY_CANVAS_REVIEW_INPUT_ORACLE") == "1":
            import runpy

            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                report["review_inputs"] = runpy.run_path(
                    "/verification/scripts/run_canvas_operations_oracle.py"
                )["run"]("canvas-review-input-scenarios.json")
        for flag, name, key in [
            ("MARTY_CANVAS_WORKER_STARTUP_ORACLE", "worker_startup", "worker_startup"),
            ("MARTY_CANVAS_JSON_DEPTH_ORACLE", "json_depth", "json_depth"),
            ("MARTY_CANVAS_JSON_CONSUMER_ORACLE", "json_consumer", "json_consumer"),
            ("MARTY_CANVAS_UTF7_CONSUMER_ORACLE", "utf7_consumer", "utf7_consumer"),
            (
                "MARTY_CANVAS_VALIDATION_BOUNDARY_ORACLE",
                "validation_boundary",
                "validation_boundary",
            ),
            (
                "MARTY_CANVAS_TIMEOUT_CONSUMER_ORACLE",
                "timeout_consumer",
                "timeout_consumer",
            ),
            (
                "MARTY_CANVAS_PROVIDER_CONFIGURATION_ORACLE",
                "provider_configuration",
                "provider_configuration",
            ),
            (
                "MARTY_CANVAS_STATUS_PROVIDER_ORACLE",
                "status_provider",
                "status_provider",
            ),
            ("MARTY_CANVAS_ENQUEUE_INPUT_ORACLE", "enqueue_input", "enqueue_inputs"),
            ("MARTY_CANVAS_OPERATIONS_ORACLE", "operations", "operations"),
            (
                "MARTY_CANVAS_OPERATIONS_INPUT_ORACLE",
                "operations_input",
                "operations_inputs",
            ),
            ("MARTY_CANVAS_ISSUED_REVIEW_ORACLE", "issued_review", "issued_reviews"),
            ("MARTY_CANVAS_MIXED_ROSTER_ORACLE", "mixed_roster", "mixed_roster"),
            (
                "MARTY_CANVAS_HEARTBEAT_READINESS_ORACLE",
                "heartbeat_readiness",
                "heartbeat_readiness",
            ),
        ]:
            if os.environ.get(flag) != "1":
                continue
            import runpy

            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                report[key] = runpy.run_path(
                    f"/verification/scripts/run_canvas_{name}_oracle.py"
                )["run"]()
        return report
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        print(json.dumps(prepare(), sort_keys=True))
    except BaseException as failure:
        # Never echo database parameters, SQL values, or exception messages.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_class": type(failure).__name__,
                    "frames": [
                        {
                            "file": Path(frame.filename).name,
                            "line": frame.lineno,
                            "function": frame.name,
                        }
                        for frame in traceback.extract_tb(failure.__traceback__)[-5:]
                    ],
                }
            )
        )
        raise SystemExit(1) from None
