# Actual provider-I/O signal reference

Status: independent published reference frozen; native adoption remains open.
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

## Native adoption requirements

Compare SIGINT and SIGKILL against the independently recorded abandoned state,
with explicit native exit-code/signal normalization. Preserve the documented
Rust improvement: SIGTERM drains in-flight work and exits 0. Prove it remains
alive with the response held, then release the response and compare the complete
positive durable outcome against the original REST reference. Do not change Rust
to emulate the published process's abrupt SIGTERM behavior.

These cases do not yet qualify lease renewal during long requests, owner-fence
loss, host crash, reclaim/restart, or finally/disposal execution. Those remain
separate requirements in the complete worker cutover inventory.
