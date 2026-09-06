# Actual worker Retry-After deadline reference

Status: seven independently captured published-worker cases are frozen. Two
complete captures match byte-for-byte with SHA-256
`043023af2b132ed5be9a86be3b3c9b05832baa78f80e762234f8ac873290c017`.
Native replay is implemented; a focused Rust regression demonstrated integer
overflow fallback and the shared parser correction passes locally. Actual Linux
whole-worker qualification of the correction remains pending. This extends
[retry/rejection evidence](canvas-worker-retry-reference.md), not whole-worker
acceptance or permission to delete or switch deployed consumers.

Each case uses a fresh database with the official published migrations, one
actual worker process, encrypted synthetic OAuth storage and one authenticated
HTTPS 429 response. The existing REST process, database, HTTPS and preservation
owners are reused. No job deadline, attempt, lease or application clock is edited.
The existing fixture makes the target due only before starting its first worker.

| Header | Observed durable scheduling requirement |
| --- | --- |
| HTTP date generated 60 seconds ahead at response time | Deadline within 1.1 seconds of that actual HTTP date |
| HTTP date 60 seconds in the past | Normal first-attempt backoff, 15–20 seconds |
| `not-a-delay`, `-9`, `0` | Normal first-attempt backoff, 15–20 seconds |
| `86401`, `184467440737095516160000` | Clamp to 86,400 seconds |

For numeric/backoff cases the database compares `available_at-updated_at`, with
0.1 seconds of tolerance for separately evaluated timestamps. The HTTP-date
allowance accounts for whole-second parsing/truncation; it is checked against
the actual emitted header, not a sampled or rewritten clock. Raw date values
are not frozen. Only the asserted deadline predicate is projected as a stable
boolean alongside the complete existing durable-state and preservation evidence.

Every case requires one attempt-one retry, no facts, the exact idle heartbeat,
OAuth state, preserved issued rows and token ciphertext. The original REST
37-second predicate remains false for these cases. Raw reference SIGINT exit is
-2. The expectation file is whitespace-only formatted from the capture without
reserializing numeric tokens; no native output supplies expectations.

`worker_retry_after_reference_matches_published_process` regenerates every case
and compares its full observation. Scenario/reference key sets and uniqueness
must match. The configured CI runner requires the test by exact name. Fixture
tests cover dynamic dates over real TLS, invalid/conflicting date inputs,
unchanged static headers and ownership cleanup. Full local Python validation:
880 passed, one existing opt-in verifier containerd/Buildx test skipped; strict
Rust Clippy and affected Ruff checks passed.

Configured local worker regression completed: 30 test entries passed in 362.57
seconds, with 36 unrelated entries filtered out. This regenerates the new and
all prior published-worker references after the shared HTTPS fixture change.
Linux-only native parent/helper entries do not establish native execution on
Windows; the new corpus still needs actual native replay and full Linux CI.
The capture-file preservation test, Bash syntax and diff checks also passed.

Review found fixed-width parsing in both the provider and worker Rust helpers.
Focused provider and worker tests using the frozen oversized value both failed
with `None` instead of `Some(86400)` before the correction. This is direct parser
evidence, not an actual Linux whole-worker observation. Preserve the frozen
clamp, existing HTTP/provider behavior and stronger ownership fences.

The new mandatory `worker_retry_after_matches_frozen_published_process` parent
uses the existing native REST child and its official-schema/OAuth/process owner.
Each case starts a separate child/database, so a short earlier retry cannot become
eligible during another case. Every original jobs/heartbeat/facts/OAuth/issuance
and ciphertext assertion remains intact, including native SIGINT exit 130.
The real HTTPS parent compares the emitted request exactly, then checks the
persisted native timestamps against the actual emitted date or frozen delay
bounds. Transient timestamp records are not substituted for frozen expectations.

Comparator tests reject missing/duplicate evidence, naive timestamps, out-of-range
deadlines and a short overflow-fallback delay; positive date/boundary cases pass.
Dispatch tests retain all four REST/fact and five retry stages and require seven
separate new child executions. These fixture tests and Windows compilation are
not native Linux parity evidence. The pushed replay checkpoint `f9ee06b42` keeps
application parsing unchanged so its full Linux run can independently expose the
composed difference. Neither that checkpoint nor a focused parser test closes gate 8.

Native-replay checkpoint local validation: 899 Python tests passed in 44.60
seconds, with the same existing opt-in skip; 52 affected comparator/CI tests
passed. The filtered configured Rust command passed two entries in 43.11
seconds: all seven published cases regenerated, while the Linux-only native
parent returned on Windows. The 65 other entries were filtered, not executed.
Strict all-target Clippy passed. The next full configured Linux suite has 67
entries and must execute the new parent as well as retain all prior cases.

## Shared parser correction

The provider and worker now delegate to one `parse_canvas_retry_after` owner in
`canvas_provider_http`, with one shared 86,400-second constant. It reuses the
already-pinned MMF `PythonConfigInteger` parser, applies the lower/upper bounds
before machine conversion, and retains the existing HTTP-date calculation.
There is no second integer grammar, Python runtime dependency, new crate pin,
new OAuth owner or replacement generation fence.

Read-only inspection of the immutable published issuance image confirmed its
`parse_canvas_retry_after` uses Python `int` followed by the same bounds, with
the 4,300-digit runtime policy. The observed module SHA-256 is
`ab5b5a6de0e1c3ed45838e6ca0c1df1c84f3eb311de41060a60754769d7ac6b3`.
Unit checks cover signed/oversized values, valid and malformed separators,
4,300/4,301-digit boundaries, existing date vectors and missing/non-text headers.
The response adapter still rejects non-text headers; typed integer parsing
retains the platform's Unicode-decimal behavior.

Both previously failing regressions pass. An additional real-HTTP authoritative
provider test observes one authenticated request and a rate-limit result with
the frozen one-day clamp, reusing the original provider/OAuth fixture. This test
has in-memory OAuth state and does not replace the actual-process/schema gate.
Local results: 329 library, 34 management HTTP, 20 OAuth/provider and 23
issuance/worker behavior tests passed; strict all-target Clippy passed; 899
Python tests passed in 41.83 seconds with the same existing opt-in skip.
The frozen reference/scenario files are unchanged. Full Linux runtime and
image qualification of this correction remain required before cutover.

The complete Linux replay at uncorrected `f9ee06b42` subsequently demonstrated
the same defect: CI34050156566/runtime job101532215062 recorded 66 configured
passes and one failure in 1064.79 seconds. Future/past dates, malformed,
negative, zero and ordinary clamp stages passed with actual HTTPS requests;
`huge_integer` alone failed the persisted-deadline comparison. Image
job101532215068 and Rust CodeQL34050156545 passed. Correction `a6826de39`
subsequently passed CI34051487770/Rust CodeQL34051487785. Runtime
job101535819282 recorded all seven actual native HTTPS/deadline cases passing,
including `huge_integer`, and all 67 configured tests passed in 1264.77 seconds
at 18:51:50 UTC. The separate unconfigured 67-test run in 0.34 seconds is not
runtime evidence. Image job101535819407 passed eight entrypoint cases at
18:36:18 UTC and all 24 startup/configuration cases at 18:36:39 UTC, retaining
the original issuance API health check. This qualifies the frozen scheduling
boundary at `a6826de39`, not a whole-worker pass or the newer validation replay.

This corpus establishes retry scheduling, not execution after a one-day delay,
remote OAuth revocation, every header grammar, or all error/privacy boundaries.
Continue the [14-gate cutover inventory](canvas-worker-cutover-readiness.md).
Production, persistent self-host, consumer definitions and reachable Python
features are unchanged.
