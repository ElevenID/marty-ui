# Actual provider-I/O signal reference

Status: independent published reference frozen at `e46f42f26`; native replay
implemented; first Linux execution exposed an internal-fence comparison gap.
The explicit comparison correction is awaiting fresh Linux execution.
No worker cutover, deployment or reachable Python deletion follows from this gate.

The actual pinned Python worker starts on a fresh official PostgreSQL schema for
each signal. Shared seed/OAuth owners create the same synthetic target and
encrypted token as the existing REST corpus. A real HTTPS server records the
authenticated request and holds its response before any body is returned. Only
the owned child receives the selected signal; the provider response is released
after that child exits. Neither application methods nor clocks are patched.

| Signal | Published raw exit | Durable outcome while response is held |
| --- | --- | --- |
| SIGINT | -2 | Job remains leased on attempt 1; no facts or policy result |
| SIGTERM | -15 | Same abandoned leased job; published process has no TERM handler |
| SIGKILL | -9 | Same abandoned leased job; forced exit is not graceful cleanup |

Each before/after projection includes job fields, processing heartbeat, OAuth
state, facts and application/credential/review state. Full issued rows and original
encrypted token bytes are separately asserted unchanged at both observations.
Only a synthetic bearer token is included in request evidence. Production trust
is unchanged; fixture-specific certificate trust is limited to the test child.

Two fresh captures per signal match byte-for-byte:

- SIGINT: `596278fa7d60c42fe0ae3b74c1cc3adcff7d7c5c2db85f7e8327295be36f620c`
- SIGTERM: `e08ba4bbc532f396651aace5187910345e1778102bfa07871346edf9919276c2`
- SIGKILL: `be757ede5519e1ffbde64ae50000f34e0ccd6dcd59027c6bec290e6939df4f9c`

The combined `canvas-worker-provider-signals-oracle.json` preserves their tokens
with whitespace-only formatting. Mandatory configured test
`worker_provider_signals_reference_matches_published_process` regenerates every
signal on an independent disposable database. Existing REST/facts/retry reference
artifacts are unchanged. The extracted HTTPS owner releases pending responses,
joins handler/server threads, removes only its temporary certificates and reports
background-handler failures to its caller. Dedicated tests exercise these paths.

Local validation: all 9 selected worker entries passed in 91.74 seconds. Five
execute reference/startup gates here; four Linux-only parent/helper entries do
not establish native HTTPS runtime behavior on Windows. The 36 unrelated tests
were filtered. All 57 affected Python tests, strict Clippy, formatting and Bash
syntax passed; the owned Docker fixture inventory was empty. Fresh full hosted
CI remains required. Local Python tests used the installed Git OpenSSL toolchain
because Strawberry OpenSSL points to an absent configuration directory; neither
certificate policy nor machine trust was changed.

## Native adoption and remaining qualification

The mandatory `worker_provider_signals_match_frozen_published_process` Linux
parent runs three fresh-schema native children. The same Rust seed, OAuth vault,
connection publication, process owner and issued-row/ciphertext assertions are
shared with the qualified REST/facts/retry replay; all frozen artifacts are retained.

SIGINT and SIGKILL compare the independently recorded before/after state, with
explicit native exit-code/signal normalization. SIGTERM preserves the documented
Rust improvement: drain in-flight work and exit 0. The test requires the process
to remain alive and its state unchanged while the response is held, then releases
the response and compares every recorded durable-state field against the original
positive REST observation. It does not emulate Python's abrupt TERM exit.

Exclusive marker files in the owned temporary certificate directory synchronize
only the test parent and child; no worker, provider adapter, database, outcome or
clock is mocked. The parent verifies the exact authenticated HTTPS request. These
new native cases compile and pass strict lint, with 57 affected Python tests;
Linux runtime behavior and all prior native replays require fresh hosted CI.

These cases do not yet qualify lease renewal during long requests, owner-fence
loss, host crash, reclaim/restart, or finally/disposal execution. Those remain
separate requirements in the complete worker cutover inventory.

## First Linux finding and correction

At `a4b1dd465`, CI34037834308/job101499061972 passed 46 configured entries and
failed the native signal parent before SIGINT delivery (426.66 seconds overall).
Rust CodeQL34037834296 passed. The mismatch was `result.target_config_version=1`
on the leased native job versus an empty published result. No native signal
behavior was qualified by this failure; subsequent signals were not reached.

This existing internal integer is captured by `lease_ready` and used by final
attempt recovery to avoid disabling a reconfigured target. The PostgreSQL worker
contract already tests that a target moved from generation 3 to 4 remains enabled.
The public operations job result uses an explicit allowlist that excludes this
field. Removing the stored generation would lose the native stale-worker fence.

The normative persistence inventory now records this internal extension. The
signal replay builds an explicit native expectation from the unchanged published
observation, adding exactly the fixture's known integer generation 1 to leased
results. It compares the entire resulting state: missing/wrong/type-changed/extra
metadata and unrelated OAuth changes fail. Nothing is stripped from observed
data and no database field is changed. Successful TERM completion still must
match the original positive result exactly, with no internal generation field.
Public-result regression assertions explicitly verify exclusion of the field.

Both focused Rust checks, strict Clippy and 57 affected Python tests pass locally.
All frozen reference artifacts remain unchanged. The three actual native signal
cases still require the fresh configured Linux run before qualification.
