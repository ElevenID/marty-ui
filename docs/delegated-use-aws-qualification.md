# Delegated-use qualification on the existing AWS development host

This procedure qualifies the selected, default-off delegated-use candidate on
the existing `elevenid-marty-disposable` development instance. It is a runbook,
not an assertion that an AWS run passed. Record the exact tested commit, host,
tool versions, commands, exit codes and retained evidence before making that
claim. Run both managed lifecycle tests; selecting only the older internal test
does not qualify the public client.

## Host and scope

Use only the existing development instance in `us-east-2`, reached as the
ordinary `marty` development user through the established CloudShell/SSM SSH
route. Resolve its instance ID from the authenticated operator inventory; keep
account/resource identifiers and access configuration out of public evidence.
Verify its identity and the current AWS Free plan/remaining credits
before starting it. Preserve its six-hour automatic stop and confirm the
scheduled stop time. Do not create or resize infrastructure, add swap, change
IAM/network rules, reinstall Docker or enable paid Actions to run these gates.

Use a new checkout/evidence directory for this PR. Record existing workloads
before and after the run; leave their containers, volumes, databases, OpenBao
mounts, credentials and diagnostics alone. The commands below start native
loopback-only fixture processes and never use the installed stack's providers.
Stop the instance when this work is complete, after coordinating any other
active worker using it.

The host has two CPUs and 8 GiB RAM. Use one Cargo build job, disable incremental
compilation and retain the automatic stop. Check available memory/disk before
building. If the build cannot fit alongside the existing workloads, retain its
failure and stop; do not stop another worker's services, resize or add swap.

### Isolated builder when the host has no compiler

The November 21 host preflight found no native C/C++ compiler or Rust toolchain.
Its existing official Rust image was verified against the vendor registry at
`rust@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1`.
That image supplies Debian 12 and the required Rust/Cargo 1.95.0. This permits
the same scoped replay in an owned rootless test container without installing
host packages or changing an existing workload.

For this execution mode, create only a new qualification workspace and named
test container. Mount that workspace read/write and, if needed, the verified
Node toolchain read-only; never mount the Docker socket, installed stack configuration,
credentials or provider volumes into the container. Run the qualification as
the image's unprivileged `nobody` user. Keep the root filesystem read-only,
drop Linux capabilities, enable `no-new-privileges`, and use a private temporary
filesystem. Limit the container to 5 GiB memory with no additional swap,
1.5 CPUs and 512 processes, while retaining one Cargo build job. Any ownership
initialization is confined to the new workspace bind and uses a short-lived
rootless helper; it must not change the host user's existing directories.

Permit network access only while fetching verified public tools and exact
source/dependency objects into the owned cache. Disconnect the container's
network before the locked offline build and fixture execution. Publish no
ports. PostgreSQL, OpenBao, Redis and the serving executable then communicate
only over loopback inside that container; none uses an installed-stack provider.
Use native tools compatible with the container distribution and record their
provenance. Paths in the commands below refer to the execution environment;
record their actual container paths in the artifact manifest.

Record the image digest, user, effective resource/security settings, network
disconnection, source revision, tool versions and all results. After exporting
sanitized evidence, stop/remove only the owned qualification container and its
disposable helper. Retain the owned workspace and failure evidence. Compare
the original workloads with the baseline and preserve the host auto-stop.
An AWS result from this mode qualifies the selected composition in an isolated
container on the existing AWS host; it does not attest a bare-host Ubuntu
deployment or the installed application stack.

## Prepare the exact source and tools

Record `git rev-parse HEAD`, `git status --porcelain`, `rustc --version`,
`cargo --version` and the existing host identity. The reviewed source and its
locked private dependencies must already be available through their authorized
cache/export route. Preserve the current branch's reviewed Core/Protocol pins.
Use `--locked --offline`; a missing cache is a preparation failure, not a reason
to change a source pin, lockfile or dependency version.
Use a clean checkout of the recorded candidate commit. If source files change,
repeat artifact capture and the final normal host build before qualification.

Supply independently verified native executables for:

| Tool | Required compatibility |
| --- | --- |
| Rust/Cargo | The reviewed toolchain; the previous caller gate used Rust 1.95 |
| PostgreSQL | Matching `postgres`, `initdb` and `psql`, version 15 or newer |
| OpenBao | 2.5.5 |
| Redis | 7.4.12 |

The fixture version checks prove compatibility only. Keep the previously
verified archive checksums/signature evidence with the host qualification.
Extracting a verified tool archive into this owned workspace does not authorize
replacing a system installation. Do not copy production secrets into the test.

Set the following paths to the observed, verified local locations. The evidence
parent must exist; each gate's evidence directory must be new.

```sh
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR=/home/marty/qualification/pr1994-target
export MARTY_QUALIFICATION_PG_BIN=/path/to/verified/postgresql/bin
export MARTY_QUALIFICATION_BAO=/path/to/verified/bao
export MARTY_QUALIFICATION_REDIS=/path/to/verified/redis-server
export MARTY_QUALIFICATION_EVIDENCE=/home/marty/qualification/pr1994-evidence
```

### Capture the test harnesses, then build the normal host last

The test dependencies intentionally enable local signing fixtures. A binary
built by `cargo test` can therefore have a different feature graph from the
normal serving binary. The actual executable gates must start the normal
`marty-delegated-use` binary, built without test/dev dependencies. Build all
harnesses first, record their exact Cargo artifact paths, then build that host
last into the same target directory. Invoke the recorded harnesses directly;
running `cargo test` again can replace the host with the test-feature build.

Run from the repository root, before creating any short-lived OpenBao identities
or signing tokens. Use a shell that stops on build failure:

```sh
set -euo pipefail
git rev-parse HEAD > "$MARTY_QUALIFICATION_EVIDENCE/source-revision.txt"
test -z "$(git status --porcelain)"
cargo metadata --locked --offline --manifest-path rust/Cargo.toml --format-version 1 \
  > "$MARTY_QUALIFICATION_EVIDENCE/cargo-metadata.json"
cargo test --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-delegated-use --tests --no-run --message-format=json \
  > "$MARTY_QUALIFICATION_EVIDENCE/test-artifacts.jsonl" \
  2> "$MARTY_QUALIFICATION_EVIDENCE/host-test-build.log"
cargo test --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-delegated-authority -p marty-principal-runtime-binding \
  --lib --no-run --message-format=json \
  >> "$MARTY_QUALIFICATION_EVIDENCE/test-artifacts.jsonl" \
  2> "$MARTY_QUALIFICATION_EVIDENCE/authority-test-build.log"
cargo test --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-principal-runtime-binding --test managed_enrollment \
  --no-run --message-format=json \
  >> "$MARTY_QUALIFICATION_EVIDENCE/test-artifacts.jsonl" \
  2> "$MARTY_QUALIFICATION_EVIDENCE/enrollment-test-build.log"
cargo test --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-delegated-receipt-consumer -p marty-delegated-use-client \
  --tests --no-run --message-format=json \
  >> "$MARTY_QUALIFICATION_EVIDENCE/test-artifacts.jsonl" \
  2> "$MARTY_QUALIFICATION_EVIDENCE/client-test-build.log"
cargo test --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-flow --lib --no-run --message-format=json \
  > "$MARTY_QUALIFICATION_EVIDENCE/flow-test-artifacts.jsonl" \
  2> "$MARTY_QUALIFICATION_EVIDENCE/flow-test-build.log"

python3 scripts/ci/check_mmf_security_features.py \
  < "$MARTY_QUALIFICATION_EVIDENCE/cargo-metadata.json"
python3 scripts/ci/check_marty_core_kms_boundary.py \
  < "$MARTY_QUALIFICATION_EVIDENCE/cargo-metadata.json"

cargo check --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-principal-runtime-binding -p marty-delegated-authority \
  -p marty-delegated-receipt-consumer --lib \
  > "$MARTY_QUALIFICATION_EVIDENCE/normal-libraries.log" 2>&1
cargo build --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-delegated-use --bin marty-delegated-use --message-format=json \
  > "$MARTY_QUALIFICATION_EVIDENCE/production-build.jsonl" \
  2> "$MARTY_QUALIFICATION_EVIDENCE/production-build.log"
```

The final command uses the normal development build profile with the serving
package's ordinary features; it adds no test features or feature overrides.
The existing feature guards stay unchanged. Their nested Cargo queries remain
offline because `CARGO_NET_OFFLINE=true` is set.
The separate normal-library check covers the verification-only dependency
selection even for the independent receipt consumer, which is not a normal
host dependency. Its test dependencies must not mask a missing production
verification import.

Resolve executables from this run's Cargo JSON using the exact package identity,
manifest, target kind/name, `profile.test` value and executable field. Reject
missing or ambiguous matches. Do not search old hashes in `target/debug/deps`.
The following also records the normal host SHA-256 and requires its path to be
the same default-profile host path compiled into the test harnesses:

```sh
python3 - "$MARTY_QUALIFICATION_EVIDENCE" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys

root = pathlib.Path(sys.argv[1])
metadata = json.loads((root / "cargo-metadata.json").read_text())
packages = {p["name"]: p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]}
tests = []
for name in ("test-artifacts.jsonl", "flow-test-artifacts.jsonl"):
    tests.extend(json.loads(line) for line in (root / name).read_text().splitlines())
production = [json.loads(line) for line in (root / "production-build.jsonl").read_text().splitlines()]

def artifact(records, package, target, kind, is_test):
    selected = packages[package]
    matches = {
        pathlib.Path(row["executable"]).resolve(strict=True)
        for row in records
        if row.get("reason") == "compiler-artifact"
        and row.get("package_id") == selected["id"]
        and pathlib.Path(row.get("manifest_path", "")).resolve() == pathlib.Path(selected["manifest_path"]).resolve()
        and row.get("target", {}).get("name") == target
        and row.get("target", {}).get("kind") == [kind]
        and row.get("profile", {}).get("test") is is_test
        and row.get("executable")
    }
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one executable for {package}:{target}")
    path = matches.pop()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SystemExit("Recorded artifact is not executable")
    return str(path)

selected = [
    ("marty-delegated-use", "live_lifecycle", "test"),
    ("marty-delegated-use", "live_runtime", "test"),
    ("marty-delegated-use", "runtime_postgres", "test"),
    ("marty-delegated-use", "host_smoke", "test"),
    ("marty-delegated-use", "marty_delegated_use", "lib"),
    ("marty-delegated-authority", "marty_delegated_authority", "lib"),
    ("marty-principal-runtime-binding", "marty_principal_runtime_binding", "lib"),
    ("marty-principal-runtime-binding", "managed_enrollment", "test"),
    ("marty-delegated-use-client", "client", "test"),
    ("marty-delegated-receipt-consumer", "consumer", "test"),
    ("marty-flow", "marty_flow", "lib"),
]
harnesses = {f"{package}:{target}": artifact(tests, package, target, kind, True)
             for package, target, kind in selected}
host = pathlib.Path(artifact(production, "marty-delegated-use", "marty-delegated-use", "bin", False))
expected_host = pathlib.Path(metadata["target_directory"]) / "debug" / "marty-delegated-use"
if host != expected_host.resolve(strict=True):
    raise SystemExit("Normal host does not match the harnesses' default-profile host path")
with host.open("rb") as executable:
    digest = hashlib.file_digest(executable, "sha256").hexdigest()
(root / "harnesses.json").write_text(json.dumps({
    "source_revision": (root / "source-revision.txt").read_text().strip(),
    "harnesses": harnesses, "production_host": str(host), "production_host_sha256": digest,
}, indent=2) + "\n")
with (root / "production-host.sha256").open("w") as record:
    subprocess.run(["sha256sum", str(host)], stdout=record, check=True)
PY

qualification_harness() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["harnesses"][sys.argv[2]])' \
    "$MARTY_QUALIFICATION_EVIDENCE/harnesses.json" "$1"
}
export MARTY_QUALIFICATION_LIFECYCLE_TEST="$(qualification_harness marty-delegated-use:live_lifecycle)"
export MARTY_QUALIFICATION_STARTUP_TEST="$(qualification_harness marty-delegated-use:live_runtime)"
export MARTY_QUALIFICATION_OWNER_TEST="$(qualification_harness marty-delegated-use:runtime_postgres)"
export MARTY_QUALIFICATION_FLOW_TEST="$(qualification_harness marty-flow:marty_flow)"
sha256sum --check "$MARTY_QUALIFICATION_EVIDENCE/production-host.sha256"
```

Keep the JSON build streams, diagnostics, manifest and exit codes. Do not invoke
another Cargo build/test command until these gates finish. The harnesses launch
the recorded normal host through their compiled `CARGO_BIN_EXE` path; their own
local signing fixtures remain confined to the test process.

## Execute the scoped gates

Run the standalone client/consumer and host configuration contracts first:

```sh
"$(qualification_harness marty-delegated-use-client:client)" --test-threads=1
"$(qualification_harness marty-delegated-receipt-consumer:consumer)" --test-threads=1
"$(qualification_harness marty-principal-runtime-binding:marty_principal_runtime_binding)" --test-threads=1
"$(qualification_harness marty-principal-runtime-binding:managed_enrollment)" --test-threads=1
"$(qualification_harness marty-delegated-use:marty_delegated_use)" --test-threads=1
"$(qualification_harness marty-delegated-use:host_smoke)" --test-threads=1
"$(qualification_harness marty-delegated-authority:marty_delegated_authority)" receipt_signing::tests --test-threads=1
"$(qualification_harness marty-delegated-authority:marty_delegated_authority)" use_http::tests --test-threads=1
"$(qualification_harness marty-delegated-authority:marty_delegated_authority)" use_receipt_http::tests --test-threads=1
```

Run both actual executable lifecycle tests with fresh owner databases and
purpose-separated remote signing custody:

```sh
python3 scripts/with_disposable_delegated_use_postgres.py \
  --postgres-bin "$MARTY_QUALIFICATION_PG_BIN" \
  --evidence-dir "$MARTY_QUALIFICATION_EVIDENCE/lifecycle" -- \
  python3 scripts/with_disposable_delegated_use_lifecycle.py \
  --openbao "$MARTY_QUALIFICATION_BAO" --redis-server "$MARTY_QUALIFICATION_REDIS" -- \
  "$MARTY_QUALIFICATION_LIFECYCLE_TEST" --ignored --test-threads=1
```

Run the actual executable's startup/readiness refusal gate separately:

```sh
python3 scripts/with_disposable_delegated_use_postgres.py \
  --postgres-bin "$MARTY_QUALIFICATION_PG_BIN" \
  --evidence-dir "$MARTY_QUALIFICATION_EVIDENCE/startup" -- \
  python3 scripts/with_disposable_delegated_use_runtime.py \
  --openbao "$MARTY_QUALIFICATION_BAO" --redis-server "$MARTY_QUALIFICATION_REDIS" -- \
  "$MARTY_QUALIFICATION_STARTUP_TEST" --ignored --test-threads=1
```

Run local-owner and current-access ingress regressions with separate fresh
PostgreSQL clusters:

```sh
python3 scripts/with_disposable_delegated_use_postgres.py \
  --postgres-bin "$MARTY_QUALIFICATION_PG_BIN" \
  --evidence-dir "$MARTY_QUALIFICATION_EVIDENCE/owners" -- \
  "$MARTY_QUALIFICATION_OWNER_TEST" --ignored --test-threads=1

python3 scripts/with_disposable_delegated_use_postgres.py \
  --postgres-bin "$MARTY_QUALIFICATION_PG_BIN" \
  --evidence-dir "$MARTY_QUALIFICATION_EVIDENCE/ingress" -- \
  "$MARTY_QUALIFICATION_FLOW_TEST" authenticated_ingress --include-ignored --test-threads=1
sha256sum --check "$MARTY_QUALIFICATION_EVIDENCE/production-host.sha256"
```

Require a positive passing test summary for each gate, not just a zero process
exit. The lifecycle must execute both tests. Check the production-host checksum
before and after the executable gates; a changed binary invalidates the run.
The authority selectors use Rust module names, not the source filenames: expect
six receipt-signing, eight command-HTTP and five receipt-HTTP tests. A zero-test
selection is a failed qualification gate.

The PostgreSQL wrapper sets only its own disposable database URLs, verifies that
the loopback server's data directory belongs to this invocation before creating
databases, and starts no provider from the installed stack. Its generated roles
use loopback trust solely inside this disposable cluster. The default child
timeout is 900 seconds; compilation belongs outside the fixture window.

Each evidence directory contains `child.log`, `postgres.log` and `result.json`.
These remain private under mode 0700. On success, stopped PostgreSQL data is
removed along with this invocation's private temporary directory. On
failure/interruption, stopped data, logs and any remaining private temporary
files stay available for diagnosis. The child receives that owned temporary
directory through `TMPDIR`, so interrupted provider files remain inside this
evidence scope. The existing OpenBao wrappers normally remove their temporary
provider audit/credential files when the child exits; those raw audits are not
a permanent evidence export. Do not upload private database state, provider
logs or credential files to GitHub. Preserve the first failure before correcting
and rerunning in a different directory.

## Acceptance and limits

| Gate | Required evidence |
| --- | --- |
| Independent client | Explicit TLS trust, mapped client certificate, one network attempt, original-command recovery, bounded/duplicate-safe responses, exact destination checks |
| Production feature boundary | Unchanged MMF/Core feature guards pass; normal host is built last without test/dev dependencies; its recorded SHA-256 is unchanged across direct harness execution |
| Actual managed lifecycle | Both internal and public tests pass with actual executable, 14 restricted host database roles, native template/policy owners, real managed credential issuance and separate request/credential/receipt signing |
| Public caller | Returned request URL and verified signed response URL are followed; malformed/spoofed/missing-certificate inputs are denied without proof retention or extra signing |
| Replay and original evidence | Exact retries and terminal proof/receipt recovery preserve original bytes, identities and times; claim/signature/grant/consumption counters remain unchanged |
| Serving-process restart | Actual host is terminated after a committed finalization and started with the same configuration; fresh caller recovers original commands/receipt and public terminal proof, with unchanged counters |
| Current authority | Revoked grant denies new use/finalization; withdrawn machine access denies duplicate and historical access; stored evidence survives |
| Fail-closed startup | Disabled host performs no I/O; wrong identities, credentials, public key, unavailable dependencies or role drift fail without admitting commands |
| Cleanup | Every owned fixture process is stopped, existing workloads are preserved, original failure logs are retained, instance stop safeguard remains intact |

A passing AWS replay qualifies this selected composition running on the AWS
development host. Its service traffic is private loopback TLS; it does not prove
production network/origin deployment. The catalog services and Issuance
bootstrap still use a disposable administrator pool; only the delegated-use
child has all fourteen independently restricted serving identities. Human
catalog administration, Compliance, Issuance public HTTP delivery and the four
unselected readiness-only reference adapters remain fixture boundaries.

Process restart covers already committed results. It does not authorize
takeover, re-signing or replay of uncertain pending claims. Production CA
issuance/revocation, caller pin replacement, signing-key rotation, provider
outage/reconciliation and separately provisioned catalog/Issuance serving roles
remain subsequent deployment gates. Required attestation, external authority
and represented-subject SESSION profiles also remain separately selected work.

The executable and public caller remain separately default-off. Public MIP,
Gateway discovery and support declarations stay at their reviewed scope.
`EVIDENCE_ONLY` receipts do not grant Rifare business permission or execute an
operation. Rifare still owns durable intent, domain permission, budgets,
reservations, provider idempotency and business outcomes.

Before the normal protected merge, attach a concise sanitized result summary
with the tested source commit and artifact digests. Preserve required checks
and review requirements; local/AWS evidence is not a fabricated GitHub status.
