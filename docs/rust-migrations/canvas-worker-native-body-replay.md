# Native worker response-body replay

Status, 2026-09-08: the original harness is implemented and reviewed. Hosted
execution passed three cases and exposed the roster-progress mismatch recorded
below. Its scoped Rust repair is locally validated but still needs fresh-head
worker parity. Frozen reference inputs, consumer routing and deployment remain
unchanged.

At pushed repair head `3967412b7`,
[CI34212739731](https://github.com/ElevenID/marty-ui/actions/runs/34212739731)
passed header parity in 108.69s but failed the preceding native expiry preflight
in 15.00s, before outcome publication. BODY was skipped, so this run neither
qualifies nor disproves the roster repair. The expiry diagnostic is being
repaired without changing any frozen expectation or BODY schedule.

Local verification passed: complete Python suite 2,365 tests / three explicit
skips in 161.34s; ten shared header/body Rust controls in 0.01s after 51.22s
compilation; all 354 issuance library tests in 16.99s; strict all-target Clippy
in 33.46s; Rust formatting and Python lint/format. Independent review found no
remaining blockers after the post-join lease and writer-completion fixes.
These results are not an actual configured Linux body replay.

Integrated head `ca1dcf00b` reached the BODY preflight in
[CI34207893818](https://github.com/ElevenID/marty-ui/actions/runs/34207893818),
runtime job `102001699788`, but failed after 3.80s on the controller's import:
`ModuleNotFoundError: No module named 'sqlalchemy'`. The header preflight had
passed in 107.46s. No BODY provider request ran and no runtime mismatch was
observed; later mixed/full groups were skipped. The repair provisions a separate
Python 3.12 harness environment with a closed, pinned import-dependency set,
checks actual controller import and frozen inputs, and only then exposes its
interpreter to the Rust preflights/full groups. It does not change the immutable
published worker environment or captured source. New hosted parity remains due.

Repair validation: all 2,545 repository Python tests passed with three explicit
skips in 165.37s. Seven new setup controls exercise the actual shell, failure
ordering and isolated controller import; the combined focused run passed 26
tests. A fresh environment containing only SQLAlchemy 2.0.52, greenlet 3.4.0
and typing_extensions 4.15.0 passed the exact import/input smoke and `pip check`.
Independent source review and Ruff passed. These are dependency/setup checks,
not native body-parity results.

The repaired setup passed on hosted head `53468331f` in
[CI34210124048](https://github.com/ElevenID/marty-ui/actions/runs/34210124048).
Runtime job `102008916081` passed header parity in 104.99s. Actual BODY replay
passed application prompt, roster prompt and application progress, then failed
roster progress with `TerminalRetry`, `TerminalMismatch`, `OutcomeJobs` and
`OutcomeTarget`. This case requires success after its last chunk at 24s; the
native coordinator instead observed retry around the roster's 20s total budget.
BODY preflight failed in 117.33s and later mixed/full groups were skipped.
This is actual evidence for repairing the scoped roster transport to preserve
20s read inactivity, not permission to change frozen expected results.

## Scoped roster repair

The candidate repair selects the existing operation transport for explicit
background-roster REST reads with a 20s inactivity budget. Application REST
retains 15s; unscoped REST, LTI, OAuth and signing policies are unchanged.
Collections and candidate reads use the same bounded response reader, preserving
status, Retry-After, pagination, item-count and response-size handling.

A prepared client validates and resolves its persisted root once before header
construction, then keeps the resulting address private. Same-origin roster
pagination reuses that pin; cross-origin reuse is rejected before connection.
The original hostname still owns Host/SNI and certificate verification. Existing
lazy operation callers are unchanged. No extra preliminary DNS lookup, redirect,
proxy, relaxed private-origin policy or published-reference change is introduced.
Prepared-address Debug output is redacted.

Local repair validation passed all **362 issuance library tests in 15.89s**
after 31.11s compilation, strict all-target Clippy in **24.50s**, and the unchanged
**104-case actual loopback TLS transport matrix**. The full worker contract
executable also compiled in 38.55s. Five prepared-origin tests and three adapter
tests add pin/privacy, protocol, pagination and progressive-read coverage.
The 240ms adapter control proves transport selection, not exact 20s worker
timing; fresh-head hosted BODY/expiry parity is still required.

## Independent authority

[The body capture record](canvas-worker-body-timeout-capture-plan.md) records
six-case A/B captures at `ffb515200`, exact raw byte agreement, and subsequent
configured regeneration at `c092509c7` (263.15s). The permanent corpus contains
46,042 bytes with SHA256
`e97d7fee361a11d4245876b725c8ac417045254d766693f772da53409c9b50eb`.
It preserves full probe reports and numeric spelling. Native expectations are
selected from its `worker_body_timeout` observations, never calculated from
the Rust implementation.

| Cases | Actual body write offsets | Required terminal outcome |
| --- | --- | --- |
| Application / roster prompt | 0, 0.05s | Success after final flush |
| Application / roster progress | 0, 8, 16, 24s | Success after final flush |
| Application stall | 0, 8, 31s | Retry at 15s inactivity, before final attempt |
| Roster stall | 0, 8, 31s | Retry at 20s inactivity, before final attempt |

Offsets specify the fixture's autonomous schedule. Assertions use actual
successful flush start/end observations, not those scheduled offsets. Every
case requires exactly one authenticated GET and the captured body-attempt trace.

## Shared ownership and retained gates

The existing Rust header coordinator is extended through explicit Header/Body
selection. One owner retains fresh database setup, real native worker launch,
the exact first job/attempt/start identity, original lease, held/outcome state,
raw business/job/target comparisons, private output, joined handlers and SIGINT.
The header entrypoint, diagnostic allowlist and seven-marker protocol remain.

The new Python controller reuses the unchanged body fixture and source-pinned
pure timing/schedule functions. Importing these functions requires the existing
SQLAlchemy test dependency; it does not execute the published worker or its
installed-source verifier on the native host. Captured scripts, scenarios and
all sixteen recorded input hashes remain unchanged.

The parent brackets the child's monotonic origin with S/A handshake samples.
The child brackets the first durable terminal transition using the last leased
query start and first terminal query end, separately from the idle snapshot.
The complete projected interval must fit the published actual-flush bounds;
the original scalar idle observation must independently fit its bounds. Anchor
uncertainty is never clipped to marker receipt or absorbed by wider tolerances.

The 35s body terminal observation ceiling accommodates a successful 24s body
and a roster stall near 28s. It changes neither the runtime policy nor the
declared per-case windows; the header observation ceiling remains 25s.
Job120/lease90/poll120 remain fixed. Native generation stamps are verified
separately rather than erased to imitate Python's internal job result.

Final-write ordering, actual schedule and request ledgers remain stable through
the full final-attempt/outcome/last-success-plus-read-budget late window, writer
completion, handler join and worker exit. The original lease is rechecked after
join. Native quiet output and exit130 are observed independently; the published
Python traceback profile is provenance, not simulated native output.

The surviving Rust caller owns Docker resources outside the contained child
process group. Cleanup must run even if the inner coordinator has already
exited. Parent SIGKILL/outer-host death remains outside that containment claim.

## Qualification and next runtime work

The ordinary `worker_body_timeout_reference_matches_published_process` gate
regenerates the published corpus and compares exact bytes. The separate
`worker_body_timeout_matches_frozen_published_process` gate exercises the native
worker; its `worker_body_timeout_native_child` is only the contained coordinator.
All three names are required in the full configured CI inventory. A closed
`body-timeout-preflight` runs the native wrapper after header preflight and before
mixed-roster preflight; it supplements, never replaces, the full suite.

At repair `2d864723f`, hosted header and mixed-roster preflights passed while
the full configured suite was still running. Application REST now selects the
shared15s operation client, but roster still uses its existing20s total policy.
That source difference predicts a possible progressing-body mismatch; the actual
native body replay must establish the result before a further runtime repair.
Do not rewrite the corpus or weaken the gates to accommodate native behavior.

OAuth/LTI/signing, decoder allocation, all consumer configurations, demos,
devices, whole-worker cutover and aggregate beta acceptance remain separate
requirements. Production is unchanged.
