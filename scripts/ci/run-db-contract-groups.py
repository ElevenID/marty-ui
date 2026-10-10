"""Overlap independent database owners, preserving serial execution within each suite."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from threading import Lock
from time import monotonic

HEARTBEAT_SECONDS = 30
PREFLIGHT_MODES = (
    "timeout-preflight",
    "lease-expiry-preflight",
)
FULL_QUALIFICATION_PREFLIGHT_MODES = (
    "mixed-roster-preflight",
    "timeout-preflight",
    "body-timeout-preflight",
    "lease-expiry-preflight",
)
EVIDENCE_NAME = "canvas-published-preflights.sha256"
RUN_IDENTITY = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")
TIMING_PREFIX = "MARTY_CI_PHASE_V1 "
TIMING_PHASES = {
    "container_startup",
    "database_readiness",
    "migration_seed",
    "fixture_seed",
    "scenario",
    "cleanup",
    "contract",
    "contract_phase",
    "canvas_serial",
    "canvas_target",
    "image_pull",
    "oracle_case",
    "oracle_phase",
}
TIMING_STATUSES = {"ok", "failed"}
REST_SCENARIOS = frozenset({"rest", "facts", "retry"})
MATRIX_SCENARIOS = frozenset(
    {"retry-after", "validation", "roster-failure", "resources-unavailable"}
)
# The published-process matrix has more case families than the native HTTPS
# scenario timer. These are the only checked-in case IDs allowed to leave the
# Rust probe as migration/seed timing labels.
PUBLISHED_MATRIX_SCENARIOS = frozenset(
    {
        "retry-after",
        "validation",
        "roster-failure",
        "resources-unavailable",
        "resource-race",
        "deadline",
        "timeout",
        "body-timeout",
        "lease-expiry",
        "dispatch",
        "mixed-roster",
        "oauth-revocation",
        "oauth-revocation-fence",
        "oauth-revocation-patch",
        "oauth-revocation-retry-after",
        "oauth-revocation-backoff",
        "oauth-revocation-queue",
        "oauth-revocation-lease",
        "oauth-revocation-selection",
        "oauth-revocation-counters",
        "oauth-revocation-secrets",
    }
)
PUBLISHED_MATRIX_PROBE_NAMES = frozenset(
    f"{scenario}.{case['name']}"
    for scenario in PUBLISHED_MATRIX_SCENARIOS
    for case in json.loads(
        (
            Path(__file__).resolve().parents[2]
            / f"contracts/canvas-worker-{scenario}-scenarios.json"
        ).read_text(encoding="utf-8")
    )["cases"]
)
SCENARIO_NAMES = REST_SCENARIOS | frozenset(
    f"{scenario}.{case['name']}"
    for scenario in MATRIX_SCENARIOS
    for case in json.loads(
        (
            Path(__file__).resolve().parents[2]
            / f"contracts/canvas-worker-{scenario}-scenarios.json"
        ).read_text(encoding="utf-8")
    )["cases"]
)
JSON_CONSUMER_SCENARIOS = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "contracts/canvas-json-consumer-scenarios.json"
    ).read_text(encoding="utf-8")
)
JSON_CONSUMER_CASE_NAMES = frozenset(
    f"json_consumer.{phase}.{case['name']}"
    for phase in ("validation", "provider")
    for case in JSON_CONSUMER_SCENARIOS[phase]
)
# Fixed, test-owned repository matrices; never derive timing identities from
# scenario payloads or include them in the fixture/cleanup phase allowlists.
REPOSITORY_MATRIX_NAMES = frozenset(
    {
        "repository_roster_metadata",
        "repository_roster_expired_before_write",
        "repository_roster_expired_during_lock",
        "repository_resource_race",
        "repository_validation",
    }
)
FIXTURE_NAMES = SCENARIO_NAMES
CONTRACT_NAMES = frozenset(
    {
        "general_contracts",
        "signing_registry",
        "signing_document",
        "issuer_profile",
        "credential_template",
        "presentation_policy",
        "issuance_oid4vci_migration",
        "issuance_transaction",
        "issuance_credential",
        "retention",
        "passport",
        "application_template",
        "internal_application",
        "credential_template_migration",
        "trust_profile_migration",
        "organization_migration",
        "organization_application",
        "organization_repository",
        "canvas_sync_worker_postgres_contract",
        "canvas_oauth_postgres_contract",
        "canvas_mirror_postgres_contract",
        "canvas_management_postgres_contract",
        "canvas_lti_sync_enqueue_postgres_contract",
        "canvas_lti_login_postgres_contract",
        "canvas_lti_evidence_postgres_contract",
        "canvas_lti_deep_linking_postgres_contract",
        "canvas_event_status_postgres_contract",
        "canvas_award_candidate_postgres_contract",
        "proof_nonce_postgres_contract",
    }
)
# Match the Rust fixture's fixed constructor-origin labels. Do not accept
# arbitrary probe output, dynamic case text, or paths as timing identities.
TIMED_PUBLISHED_SCRIPTS = frozenset(
    {
        "enqueue_input",
        "heartbeat_readiness",
        "issued_review",
        "json_consumer",
        "json_depth",
        "mixed_roster",
        "operations",
        "operations_input",
        "status_provider",
        "timeout_consumer",
        "utf7_consumer",
        "validation_boundary",
        "worker_concurrent",
        "worker_facts",
        "worker_provider_completion",
        "worker_provider_final",
        "worker_provider_generation",
        "worker_provider_recovery",
        "worker_provider_recovery_first",
        "worker_provider_signals",
        "worker_reclaimers",
        "worker_reclaimers_retry",
        "worker_rest",
        "worker_retry",
        "worker_startup",
    }
)
TIMING_NAMES = {
    "container_startup": frozenset({"postgres_create"}),
    "database_readiness": frozenset({"postgres_ready"}),
    "migration_seed": PUBLISHED_MATRIX_PROBE_NAMES
    | TIMED_PUBLISHED_SCRIPTS
    | frozenset(
        {
            "published_probe",
            "status_native_seed",
            "worker_validation_template",
        }
    ),
    "fixture_seed": FIXTURE_NAMES | frozenset({"status_native_seed"}),
    "scenario": SCENARIO_NAMES | REPOSITORY_MATRIX_NAMES,
    "oracle_case": JSON_CONSUMER_CASE_NAMES,
    "oracle_phase": frozenset(
        {
            "json_depth.setup",
            "json_depth.validation",
            "json_depth.provider",
            "json_depth.encoding",
        }
    ),
    "cleanup": FIXTURE_NAMES | frozenset({"published_database_removal"}),
    "contract": CONTRACT_NAMES,
    "contract_phase": frozenset(
        {
            "composite_total",
            "initial_schema",
            "schedule_recovery_completion",
            "hinted_retry",
            "privacy",
            "signing_guard",
            "projection_cycles",
            "consumer_ranges",
            "owned_lifecycle",
            "pool_disposal",
            "process_signals",
            "renewal_generation",
            "renewal_write_failures",
            "renewal_job_outcomes",
            "pool_close",
        }
    ),
    "canvas_serial": frozenset(
        {
            "sql_logging",
            "json_consumer",
            "mixed_roster_reference",
            "oauth_lease_reference",
            *PREFLIGHT_MODES,
            "mixed-roster-preflight",
            "body-timeout-preflight",
        }
    ),
    "canvas_target": frozenset({"composition", "flow", "worker", "selfhost"}),
    "image_pull": frozenset({"postgres", "published_probe"}),
}


def _timing_path() -> Path | None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        return None
    return Path(runner_temp) / "rust-build-evidence" / "db-contract-timing.jsonl"


def _safe_phase(line: str, group: str) -> dict[str, object] | None:
    if not line.startswith(TIMING_PREFIX) or len(line) > 256:
        return None
    try:
        value = json.loads(line[len(TIMING_PREFIX) :])
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or set(value) != {
        "phase",
        "name",
        "duration_ms",
        "status",
    }:
        return None
    phase, name, duration, status = (
        value[key] for key in ("phase", "name", "duration_ms", "status")
    )
    if (
        not isinstance(phase, str)
        or phase not in TIMING_PHASES
        or not isinstance(name, str)
        or name not in TIMING_NAMES[phase]
        or not 1 <= len(name) <= 96
        or not all(
            character.isascii() and (character.isalnum() or character in "_-.")
            for character in name
        )
        or isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 0 <= duration <= 43_200_000
        or not isinstance(status, str)
        or status not in TIMING_STATUSES
    ):
        return None
    return {"schema": "marty.ci.db-phase/v1", "group": group, **value}


def _run_identity() -> tuple[str, ...] | None:
    identity = tuple(os.environ.get(name, "") for name in RUN_IDENTITY)
    return identity if all(identity) else None


def _preflight_evidence() -> Path | None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    return (
        Path(runner_temp) / EVIDENCE_NAME if runner_temp and _run_identity() else None
    )


def _canvas_executable() -> Path:
    runner_temp = os.environ["RUNNER_TEMP"]
    artifacts = Path(runner_temp) / "rust-test-artifacts.json"
    with artifacts.open(encoding="utf-8") as source:
        executables = {
            artifact["executable"]
            for line in source
            if (artifact := json.loads(line)).get("reason") == "compiler-artifact"
            and "#marty-canvas-worker-acceptance@" in artifact.get("package_id", "")
            and artifact.get("target", {}).get("name")
            == "canvas_published_worker_contract"
            and artifact.get("executable") is not None
        }
    if len(executables) != 1:
        raise ValueError("Expected exactly one Canvas worker contract executable")
    executable = Path(executables.pop())
    if not executable.is_file():
        raise ValueError("Canvas contract executable is missing")
    return executable


def _executable_digest() -> str:
    digest = hashlib.sha256()
    with _canvas_executable().open("rb") as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_preflight_evidence() -> bool:
    evidence = _preflight_evidence()
    if evidence is None or not evidence.is_file():
        return False
    try:
        expected = (
            "\n".join(
                (
                    _executable_digest(),
                    *_run_identity(),
                    os.environ.get("MARTY_CANVAS_FULL_QUALIFICATION", "0"),
                )
            )
            + "\n"
        )
        return evidence.read_text(encoding="ascii") == expected
    except (OSError, ValueError, KeyError):
        return False


def _record_preflight_evidence() -> None:
    evidence = _preflight_evidence()
    if evidence is None:
        return  # Local preflight runs retain full coverage in the later suite.
    digest = _executable_digest()
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="ascii", newline="\n", dir=evidence.parent, delete=False
    ) as temporary:
        temporary.write(
            "\n".join(
                (
                    digest,
                    *_run_identity(),
                    os.environ.get("MARTY_CANVAS_FULL_QUALIFICATION", "0"),
                )
            )
            + "\n"
        )
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, evidence)


def _wait_for_groups(futures: dict[str, Future[int]], started: float) -> dict[str, int]:
    """Observe completion without streaming either owner's raw log or command."""
    pending = set(futures.values())
    results = {}
    while pending:
        completed, pending = wait(
            pending, timeout=HEARTBEAT_SECONDS, return_when=FIRST_COMPLETED
        )
        elapsed = int(monotonic() - started)
        for name, future in futures.items():
            if future in completed:
                results[name] = future.result()
                print(
                    f"[db-contracts] completed group={name} exit={results[name]} "
                    f"elapsed={elapsed}s",
                    flush=True,
                )
        if pending and not completed:
            names = ",".join(
                name for name, future in futures.items() if future in pending
            )
            print(
                f"[db-contracts] waiting groups={names} elapsed={elapsed}s", flush=True
            )
    # Completion order must not change the original final log/result order.
    return {name: results[name] for name in futures}


def run_groups(commands: dict[str, list[str]], directory: Path) -> dict[str, int]:
    timing_path = _timing_path()
    timing_lock = Lock()

    def record(value: dict[str, object]) -> None:
        print(
            f"[db-timing] group={value['group']} phase={value['phase']} "
            f"name={value['name']} duration_ms={value['duration_ms']} status={value['status']}",
            flush=True,
        )
        if timing_path is None:
            return
        with timing_lock:
            try:
                timing_path.parent.mkdir(parents=True, exist_ok=True)
                with timing_path.open("a", encoding="ascii", newline="\n") as evidence:
                    evidence.write(
                        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
                    )
            except OSError:
                print("[db-timing] optional timing evidence unavailable", flush=True)
                return

    def run(name: str, command: list[str]) -> int:
        group_started = monotonic()
        with (directory / f"{name}.log").open("wb") as log:
            try:
                with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                ) as process:
                    assert process.stdout is not None
                    for line in process.stdout:
                        log.write(line)
                        if not line.startswith(TIMING_PREFIX.encode("ascii")):
                            continue
                        try:
                            marker = line.decode("ascii").rstrip("\r\n")
                        except UnicodeDecodeError:
                            continue
                        phase = _safe_phase(marker, name)
                        if phase is not None:
                            record(phase)
                    status = process.wait()
            except OSError as error:
                log.write(f"Unable to start contract group: {error}\n".encode())
                status = 1
        record(
            {
                "schema": "marty.ci.db-phase/v1",
                "group": name,
                "phase": "contract",
                "name": "group_total",
                "duration_ms": round((monotonic() - group_started) * 1000),
                "status": "ok" if status == 0 else "failed",
            }
        )
        return status

    # Wait for every suite even if another fails, so its assertions and cleanup
    # finish. Separate logs avoid interleaving diagnostics from independent DBs.
    started = monotonic()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {}
        for name, command in commands.items():
            # Names are the caller's fixed, nonsecret group identifiers. Never
            # report command arguments, environment, paths or log contents here.
            print(f"[db-contracts] starting group={name}", flush=True)
            futures[name] = executor.submit(run, name, command)
        return _wait_for_groups(futures, started)


def main(mode: str = "database") -> int:
    scripts = Path(__file__).resolve().parent
    qualification = os.environ.get("MARTY_CANVAS_FULL_QUALIFICATION", "0")
    if qualification not in ("0", "1"):
        raise ValueError("Invalid Canvas qualification mode")
    preflight_modes = (
        FULL_QUALIFICATION_PREFLIGHT_MODES if qualification == "1" else PREFLIGHT_MODES
    )
    if mode in ("database", "canvas"):
        published_mode = ["full-after-preflights"] if _has_preflight_evidence() else []
        commands: dict[str, list[str]] = {
            "published-canvas": [
                "bash",
                str(scripts / "run-published-canvas-contracts.sh"),
                *published_mode,
            ],
        }
        if mode == "database":
            commands["rust-db"] = ["bash", str(scripts / "run-rust-db-contracts.sh")]
    elif mode == "rust-db":
        commands = {"rust-db": ["bash", str(scripts / "run-rust-db-contracts.sh")]}
    elif mode == "worker-canvas":
        # Opt-in owner only. The normal canvas group above is unchanged.
        published_mode = (
            "worker-full-after-preflights"
            if _has_preflight_evidence()
            else "worker-full"
        )
        commands = {
            "published-worker": [
                "bash",
                str(scripts / "run-published-canvas-contracts.sh"),
                published_mode,
            ]
        }
    elif mode == "selfhost-canvas":
        # Additive diagnostic owner; the full Canvas group remains required.
        commands = {
            "published-selfhost": [
                "bash",
                str(scripts / "run-published-canvas-contracts.sh"),
                "selfhost-only",
            ]
        }
    elif mode in ("preflights", "worker-preflights"):
        evidence = _preflight_evidence()
        if evidence is not None:
            evidence.unlink(missing_ok=True)  # A failed rerun cannot reuse old proof.
        # Two workers overlap independent cases. Each exact preflight owns
        # its disposable Docker database and dynamically allocated HTTPS ports.
        commands = {
            name: [
                "bash",
                str(scripts / "run-published-canvas-contracts.sh"),
                f"worker-{name}" if mode == "worker-preflights" else name,
            ]
            for name in preflight_modes
        }
    else:
        raise ValueError("Unsupported contract group mode")
    prefix = (
        "marty-preflight-groups-"
        if mode in ("preflights", "worker-preflights")
        else "marty-db-groups-"
    )
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        directory = Path(temporary)
        results = run_groups(commands, directory)
        for name, status in results.items():
            print(f"===== {name}: exit {status} =====", flush=True)
            print((directory / f"{name}.log").read_text(encoding="utf-8"), flush=True)
        failed = any(status != 0 for status in results.values())
        if mode in ("preflights", "worker-preflights") and set(results) != set(
            preflight_modes
        ):
            failed = True
        if mode in ("preflights", "worker-preflights") and not failed:
            try:
                _record_preflight_evidence()
            except (OSError, ValueError, KeyError) as error:
                print(
                    f"[db-contracts] unable to record preflight evidence: {error}",
                    file=sys.stderr,
                )
                return 1
        return int(failed)


if __name__ == "__main__":
    if sys.argv[1:] not in (
        [],
        ["preflights"],
        ["canvas"],
        ["rust-db"],
        ["worker-preflights"],
        ["worker-canvas"],
        ["selfhost-canvas"],
    ):
        raise SystemExit(
            "Usage: run-db-contract-groups.py "
            "[preflights|canvas|rust-db|worker-preflights|worker-canvas|selfhost-canvas]"
        )
    raise SystemExit(main(sys.argv[1] if sys.argv[1:] else "database"))
