"""Record effective libtest obligations for the existing serial DB runner.

Discovery uses the same executable and selection arguments as execution. libtest
--list includes ignored tests by default, so a second ignored-only discovery is
required before claiming which bodies should actually run. This is evidence of
harness execution, not proof that every assertion inside a test was reached.
"""

import argparse
import codecs
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_NAME = "db-contract-obligations.jsonl"
PREFIX = "MARTY_DB_OBLIGATION_V1 "
RUN_IDENTITY = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_SHA")
FIXTURE_OWNER = ".github/compose/rust-ci-fixtures.yml"
RUNNER_OWNER = "scripts/ci/run-rust-db-contracts.sh"
CASE = r"[A-Za-z_][A-Za-z0-9_:]*"
CASE_RESULT = re.compile(rf"^test ({CASE}) \.\.\. (ok|FAILED|ignored)(?:, .*)?$")
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out; finished in .+$"
)


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def obligation(name: str) -> tuple[str, str, list[dict[str, str]]]:
    """The dispatch owner's declared inputs; environment values never leave it."""
    postgres = "ISSUANCE_POSTGRES_TEST_URL"
    entries = {
        "general_contracts": (
            "marty-revocation-profile",
            "contracts",
            (
                "MARTY_TEST_POSTGRES_URL",
                "MARTY_TEST_REDIS_URL",
                "MARTY_TEST_REVOCATION_MIGRATION_DATABASE_URL",
                "MARTY_TEST_REVOCATION_MIGRATION_DATABASE_NAME",
            ),
        ),
        "signing_registry": (
            "marty-signing-keys",
            "registry_storage_contract",
            ("MARTY_TEST_REDIS_URL",),
        ),
        "signing_document": (
            "marty-signing-keys",
            "document_storage_contract",
            (
                "MARTY_TEST_REDIS_URL",
                "MARTY_TEST_REDIS_DISPOSABLE_NONCE",
            ),
        ),
        "issuer_profile": (
            "marty-signing-keys",
            "issuer_profile_storage_contract",
            ("MARTY_TEST_REDIS_URL",),
        ),
        "credential_template": (
            "marty-credential-template",
            "postgres_integration",
            ("CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL",),
        ),
        "credential_template_migration": (
            "marty-credential-template",
            "migration_contract",
            ("CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL",),
        ),
        "presentation_policy": (
            "marty-presentation-policy",
            "postgres_integration",
            ("PRESENTATION_POLICY_POSTGRES_TEST_URL",),
        ),
        "trust_profile_migration": (
            "marty-trust-profile",
            "migration_contract",
            ("TEST_POSTGRES_URL",),
        ),
        "organization_migration": (
            "marty-organization",
            "migration_contract",
            ("ORGANIZATION_POSTGRES_TEST_URL",),
        ),
        "organization_application": (
            "marty-organization",
            "application_postgres_integration",
            ("ORGANIZATION_POSTGRES_TEST_URL",),
        ),
        "organization_repository": (
            "marty-organization",
            "postgres_integration",
            ("ORGANIZATION_POSTGRES_TEST_URL",),
        ),
    }
    for label, target, variable in (
        ("issuance_oid4vci_migration", "oid4vci_migration_postgres_contract", postgres),
        ("issuance_transaction", "issuance_transaction_postgres_contract", postgres),
        ("issuance_credential", "credential_postgres_contract", postgres),
        (
            "retention",
            "retention_postgres_contract",
            "MARTY_RETENTION_POSTGRES_TEST_URL",
        ),
        ("passport", "passport_postgres_contract", "MARTY_PASSPORT_POSTGRES_TEST_URL"),
        ("application_template", "application_template_postgres_contract", postgres),
        ("internal_application", "internal_application_postgres_contract", postgres),
    ):
        entries[label] = ("marty-issuance-service", target, (variable,))
    canvas = {
        "canvas_award_candidate",
        "canvas_event_status",
        "canvas_lti_deep_linking",
        "canvas_lti_evidence",
        "canvas_lti_login",
        "canvas_lti_sync_enqueue",
        "canvas_management",
        "canvas_mirror",
        "canvas_oauth",
        "canvas_sync_worker",
        "proof_nonce",
    }
    for prefix in canvas:
        target = f"{prefix}_postgres_contract"
        entries[target] = (
            "marty-issuance-service",
            target,
            ("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL",),
        )
    if name not in entries:
        raise ValueError("unknown_dispatch")
    package, target, variables = entries[name]
    inputs = [
        {
            "name": variable,
            "consumer": package,
            "owner": RUNNER_OWNER,
            "provisioner": ".github/workflows/ci.yml"
            if variable.endswith("URL")
            or variable == "MARTY_TEST_REDIS_DISPOSABLE_NONCE"
            else RUNNER_OWNER,
            "requirement": "required",
        }
        for variable in variables
    ]
    # These tests use a Rust-owned HTTPS Signing Keys fixture by default, or an
    # explicitly supplied live route. Record the conditional dependency names,
    # without treating absent optional route inputs as absent test execution.
    if target in {
        "canvas_oauth_postgres_contract",
        "canvas_sync_worker_postgres_contract",
    }:
        inputs.extend(
            {
                "name": variable,
                "consumer": package,
                "owner": "rust/services/issuance/tests/support/remote_integration_secret.rs",
                "provisioner": "Rust-owned fixture or caller-supplied live route",
                "requirement": "optional_live_route",
            }
            for variable in (
                "MARTY_TEST_SIGNING_KEYS_INTERNAL_URL",
                "MARTY_TEST_SIGNING_KEYS_INTEGRATION_SECRET_KEY",
                "MARTY_TEST_SIGNING_KEYS_INTERNAL_CA_FILE",
            )
        )
    return package, target, inputs


def artifact_identity(executable: Path, package: str, target: str) -> dict:
    executable_sha256 = digest(executable)
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            raise ValueError("missing_runner_temp")
        return {
            "provenance": "local_unrecorded",
            "executable_sha256": executable_sha256,
        }
    artifacts = Path(runner_temp) / "rust-test-artifacts.json"
    matches = []
    for line in artifacts.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if value.get("reason") != "compiler-artifact" or not value.get("executable"):
            continue
        if (
            value["package_id"].rsplit("#", 1)[-1].split("@", 1)[0] == package
            and value["target"]["name"] == target
            and "test" in value["target"]["kind"]
        ):
            matches.append(value)
    # Match the existing resolver's unique-path requirement. Workflow preparation
    # copies several binaries to readable aliases; prove byte identity to their
    # same-run Cargo executable instead of rejecting those deliberate copies.
    matches = list({row["executable"]: row for row in matches}.values())
    if len(matches) != 1:
        raise ValueError("missing_or_ambiguous_compiler_artifact")
    [artifact] = matches
    recorded_executable = Path(artifact["executable"])
    same_path = recorded_executable.resolve() == executable.resolve()
    if not recorded_executable.is_file():
        raise ValueError("missing_compiler_artifact_executable")
    if not same_path and digest(recorded_executable) != executable_sha256:
        raise ValueError("compiler_artifact_content_mismatch")
    return {
        "provenance": "same_run_compiler_artifact",
        "compiler_artifacts_sha256": digest(artifacts),
        "features": artifact.get("features", []),
        "binding": "same_path" if same_path else "byte_identical_copy",
        "executable_sha256": executable_sha256,
    }


def libtest_harness(package: str, target: str) -> dict:
    service = (
        "issuance"
        if package == "marty-issuance-service"
        else package.removeprefix("marty-")
    )
    manifest_path = ROOT / "rust/services" / service / "Cargo.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["package"]["name"] != package:
        raise ValueError("foreign_harness_manifest")
    declared = [
        entry for entry in manifest.get("test", []) if entry.get("name") == target
    ]
    if declared:
        if (
            len(declared) != 1
            or not declared[0].get("harness", True)
            or not declared[0].get("test", True)
        ):
            raise ValueError("unsupported_test_harness")
    elif (
        not manifest["package"].get("autotests", True)
        or not (manifest_path.parent / "tests" / f"{target}.rs").is_file()
    ):
        raise ValueError("missing_libtest_target")
    return {
        "manifest": manifest_path.relative_to(ROOT).as_posix(),
        "manifest_sha256": digest(manifest_path),
        "harness": "libtest",
    }


def selection(arguments: list[str]) -> tuple[list[str], str]:
    mode = "default"
    selectors = []
    for argument in arguments:
        if argument in {"--ignored", "--include-ignored"}:
            if mode != "default":
                raise ValueError("ambiguous_ignored_selection")
            mode = argument.removeprefix("--")
        elif argument == "--exact" or argument.startswith("--test-threads="):
            selectors.append(argument)
        elif re.fullmatch(CASE, argument):
            selectors.append(argument)
        else:
            raise ValueError("unsupported_selection_argument")
    return selectors, mode


def list_cases(command: list[str]) -> set[str]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError("libtest_discovery_failed")
    cases = []
    for line in result.stdout.splitlines():
        if match := re.fullmatch(rf"({CASE}): test", line):
            cases.append(match[1])
        elif line and not re.fullmatch(r"\d+ tests?, \d+ benchmarks?", line):
            raise ValueError("unrecognized_libtest_discovery")
    if len(cases) != len(set(cases)):
        raise ValueError("duplicate_discovered_case")
    return set(cases)


def expected_cases(executable: str, arguments: list[str]) -> tuple[set[str], set[str]]:
    selectors, mode = selection(arguments)
    listing = [
        executable,
        *selectors,
        "--list",
        "--format",
        "terse",
        "--color",
        "never",
    ]
    selected = list_cases(listing)
    ignored = list_cases([*listing, "--ignored"])
    if not ignored <= selected:
        raise ValueError("inconsistent_ignored_discovery")
    if mode == "ignored":
        return ignored, set()
    if mode == "include-ignored":
        return selected, set()
    return selected - ignored, ignored


def verify_execution(lines: list[str], expected: set[str], ignored: set[str]) -> dict:
    cases = {}
    summaries = []
    for line in lines:
        if match := CASE_RESULT.fullmatch(line):
            if match[1] in cases:
                raise ValueError("duplicate_executed_case")
            cases[match[1]] = match[2]
        elif match := SUMMARY.fullmatch(line):
            summaries.append(match.groups())
    executed = {name for name, status in cases.items() if status in {"ok", "FAILED"}}
    actually_ignored = {name for name, status in cases.items() if status == "ignored"}
    if len(summaries) != 1:
        raise ValueError("missing_or_ambiguous_libtest_summary")
    status, passed, failed, skipped, measured, _filtered = summaries[0]
    if (
        executed != expected
        or actually_ignored != ignored
        or int(passed) != sum(value == "ok" for value in cases.values())
        or int(failed) != sum(value == "FAILED" for value in cases.values())
        or int(skipped) != len(ignored)
        or int(measured) != 0
    ):
        raise ValueError("selected_executed_mismatch")
    return {
        "executed": sorted(executed),
        "ignored": sorted(actually_ignored),
        "passed": int(passed),
        "failed": int(failed),
        "summary_status": status,
    }


def emit(evidence: dict) -> None:
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        output = Path(runner_temp) / "rust-build-evidence" / EVIDENCE_NAME
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded + "\n")
    print(PREFIX + encoded, flush=True)


def run_contract(name: str, command: list[str]) -> int:
    evidence = {
        "schema": "marty.rust-db-obligation/v1",
        "gate": "test-rust-services/contracts",
        "owner": RUNNER_OWNER,
        "runtime_fixture_owner": FIXTURE_OWNER,
        "run": {key: os.environ.get(key) for key in RUN_IDENTITY},
        "status": "failed",
    }
    status = 1
    try:
        package, target, inputs = obligation(name)
        evidence.update(
            name=name, package=package, target=target, runtime_inputs=inputs
        )
        if os.environ.get("GITHUB_ACTIONS") == "true" and not all(
            evidence["run"].values()
        ):
            raise ValueError("missing_run_identity")
        executable = Path(command[0])
        evidence.update(artifact_identity(executable, package, target))
        # Never probe --list on custom harnesses, which may ignore the flag and
        # execute their bodies. All current dispatches use standard libtest.
        evidence["harness"] = libtest_harness(package, target)
        selection(command[1:])  # Validate before allowing arguments into evidence.
        evidence["selection_arguments"] = command[1:]
        expected, ignored = expected_cases(command[0], command[1:])
        evidence["selected"] = sorted(expected)
        evidence["selected_ignored"] = sorted(ignored)
        if not expected:
            raise ValueError("zero_selected_tests")
        for item in inputs:
            if item["requirement"] == "required" and not os.environ.get(item["name"]):
                raise ValueError("missing_required_runtime_input")
        output = []
        # Presentation only: retain every original selection/serialism argument.
        # Pretty output makes individual case outcomes observable on stable Rust.
        with subprocess.Popen(
            [*command, "--format", "pretty", "--color", "never"],
            # Inherit stderr to preserve live diagnostics, but do not parse it
            # as libtest stdout. Composite timers write directly to stderr and
            # can otherwise split a `test name ... ok` record after its prefix.
            stdout=subprocess.PIPE,
        ) as child:
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            # Forward partial progress lines immediately, just like the outer
            # timed guard's tee; readline would hide a long-running case prefix.
            while chunk := child.stdout.read1(65536):
                decoded = decoder.decode(chunk)
                print(decoded, end="", flush=True)
                output.append(decoded)
            remaining = decoder.decode(b"", final=True)
            print(remaining, end="", flush=True)
            output.append(remaining)
            status = child.wait()
        lines = "".join(output).splitlines()
        evidence["command_status"] = status
        evidence["observed_cases"] = [
            {"name": match[1], "outcome": match[2]}
            for line in lines
            if (match := CASE_RESULT.fullmatch(line))
        ]
        evidence.update(verify_execution(lines, expected, ignored))
        if status != 0 or evidence["failed"] or evidence["summary_status"] != "ok":
            raise ValueError("libtest_execution_failed")
        evidence["status"] = "ok"
    except (OSError, ValueError, KeyError, IndexError) as error:
        # Exception text can contain filesystem/environment values. Only our
        # fixed reason codes are evidence; the unchanged child stream has logs.
        reason = (
            str(error)
            if type(error) is ValueError
            else "inventory_io_or_metadata_error"
        )
        evidence["reason"] = (
            reason if re.fullmatch("[a-z_]+", reason) else "invalid_inventory_data"
        )
        status = status or 1
    emit(evidence)
    return status if status >= 0 else 128 - status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    return run_contract(args.name, command)


if __name__ == "__main__":
    sys.exit(main())
