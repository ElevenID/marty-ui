# Consolidated Rust Migration Roadmap

**Status:** Waves one through three, the 31-route Rust Canvas cutover, and the canonical Rust verifier implementation are merged. Aggregate `marty-ui@v1.1.217` is published and deployed to beta at source `4596afaca3724e60a8dadbd4e227b6e765cb495c`; its hosted lifecycle and first-party KMS switching recording pass. All-demo/device evidence and the governed soak remain incomplete. The standalone Rust Canvas worker remains unrouted: its shared lossless configuration and native PostgreSQL consumer-range replay now pass locally, but whole-worker/all-consumer cutover gates remain open. Reachable Python features and other-worker crypto work are preserved. Feature-preserving cleanup remains open. No production deployment occurred in this lane.

Prior `v1.1.214` evidence remains retained at source
`24f5d5dc0bb47d3dadb118b4dbe45191c5cf71b1`, release run `33930593794`.
Integration PR `#418` landed its published static pin at
`9f150de07a5a629a46b1eeeb58123ddb3eb86f32`; Integration `v1.2.80` is published
at source `0c0944424c2f19ad05d99bb7482526104cb5b6d1` after PR `#419` and
release run `33931821255`. That historical static pin does not attest a newer
beta aggregate; reconcile it after the next qualified release.

Release-evidence classification remains exact: `v0.1.72` is a valid issuance
component, not a failed verifier artifact; `v1.2.76` is retained held evidence
only and grants no cutover authorization; `v1.2.77` is intermediate evidence
only; and `v1.2.78` is preliminary, non-activating evidence.

**Scope:** Marty backend services, protocol kernels, security-sensitive mobile logic, and licensing

**Initial rollout environment:** Beta only

**Last updated:** 2026-09-06

## Objective

Reduce the amount of Python and other non-Rust protocol code in the Marty stack by replacing it with a single authoritative Rust implementation for each capability. The migration must preserve externally observable features and behavior, improve fail-closed security, and remove superseded Python or Dart implementations after each cutover.

This is not a line-for-line translation project. Rust owns deterministic protocol, policy, validation, cryptographic, and state-machine behavior. Python remains only where it is useful for API composition, persistence adapters, scheduling, OCR, and third-party integrations until a whole service is deliberately replaced. Flutter/Dart remains responsible for application UI and platform integrations.

The immediate deployment boundary is beta. Production and persistent self-host environments are not changed by this roadmap without a separate approval and promotion decision.

## Current execution snapshot — 2026-09-06

### Current transport integration and merge gates

The [final-attempt crash reference](rust-migrations/canvas-worker-provider-final.md)
has two identical independent captures and a mandatory regeneration gate. After
actual attempt-eight renewal and forced process loss, real lease expiry leads
to dead-letter/target-disable with no second provider request. Earlier attempts
are explicitly seeded history, not executed evidence. Native final-attempt
replay is implemented using the shared recovery owner and strict generation
checks; its Linux qualification, concurrency and changed-generation races remain open.

The [actual provider renewal/recovery reference](rust-migrations/canvas-worker-provider-recovery.md)
now has two matching captures per case. A real pending HTTPS request spans lease
and both heartbeat renewal without generation change. After forced process loss,
real lease expiry and retry eligibility lead to the same job succeeding on attempt
two with issuance/token ciphertext preserved. Reference regeneration passes
locally; native replay passed at `d96a45ebe` (CI34039828427 and Rust34039828424),
including actual renewal/recovery HTTPS and all 52 configured tests in 839.16 seconds. Final-attempt,
concurrency and ownership-fence cases remain open.

The [active-provider signal reference](rust-migrations/canvas-worker-provider-signals.md)
now records SIGINT, SIGTERM and SIGKILL against actual published worker processes
while a real HTTPS response is held. Each pair of independent captures agrees;
the job remains leased and issuance/token ciphertext are preserved. Native replay
includes Rust's intentional SIGTERM graceful drain and retains the original
REST/facts/retry regression gates.
The correction is now qualified at `499298659`: CI34038852781 and Rust
CodeQL34038852821 passed; the configured log explicitly records SIGINT, SIGTERM,
SIGKILL and all 49 tests passing in 580.28 seconds. The newer native recovery
qualification is recorded above; subsequent extensions require fresh checks.
This is not crash/restart or cleanup-finally evidence.
The first Linux run failed before signal delivery because native leased jobs
retain an internal target-generation fence absent from Python's result. The
comparison now asserts that exact field explicitly and retains full state checks;
public job results exclude it. No runtime fence or frozen observation was changed.
This correction's Linux qualification is recorded above; fresh checks remain
required for later changes.

The [retry/rejection worker reference](rust-migrations/canvas-worker-retry-reference.md)
now records real database eligibility and unchanged job identity across retry
success, 503 failure and 401 token rejection. Two final captures agree; native
adoption passed Linux CI at `32ec09029`: CI34036161060 and Rust CodeQL34036161086
are successful. The configured job explicitly exercised all five native retry
stages and passed all 44 tests in 653.61 seconds. No clocks, retry timestamps
or job outcomes are patched.

The [all-four-fact worker reference](rust-migrations/canvas-worker-facts-reference.md)
captures actual published assignment, quiz, module and course reads through the
shared worker/HTTPS/OAuth/schema harness. Two captures match byte-for-byte. Its
partial-rate-limit stage preserves three successful fact writes while the job
retries and the negative assignment keeps policy denied. Native adoption is
qualified on Linux at `6977a70ba`: CI34034992317 and Rust CodeQL34034992376 passed;
the configured log confirms 16 all-fact and 4 original requests. The original
assignment-only reference is retained. Its actual native worker gate passed at
`0982a4a2c` with exact-head CI34033818678 and Rust CodeQL34033818668 successful.

The [composed worker REST reference](rust-migrations/canvas-worker-rest-reference.md)
now freezes four actual published worker processes using real HTTPS and encrypted
OAuth persistence on the official schema: positive evidence, later negative
evidence, duplicate reuse and a 429 retry honoring Retry-After37. Two finalized
captures agree byte-for-byte. Issued credential/transaction rows and encrypted
token bytes remain unchanged, with selected job/fact/review/heartbeat projections
recorded. The published HTTPS constraint remains intact; fixture-specific trust
is isolated to the test child. Native assignment replay passed in the configured
Linux database job with the actual binary and native OAuth storage; the fast
unconfigured test run and Windows compile/lint are not runtime evidence. This remains
separate from complete worker qualification. Startup head `017c7e423` now has
successful hosted CI and Rust analysis.

The [actual worker startup gate](rust-migrations/canvas-worker-startup.md) now
freezes eight published process/idle-heartbeat observations from two identical
captures. It reproduced the eager LTI identity failure, then verifies the Rust
repair through actual child processes and the published PostgreSQL migrations.
Missing, partial and invalid identity no longer blocks empty-queue startup;
the shared signer still rejects it before resolution or signing. Both deployed
PostgreSQL URL forms pass this boundary. Windows child isolation retains only
the required OS path; POSIX signal assertions remain Linux CI evidence.
The broader composed worker/provider and all-consumer gates remain open.
All 37 configured image/schema tests pass (322.87 seconds, none ignored or
filtered), plus 325 library, 5 binary, 22 behavior and 53 affected Python tests.
Strict Clippy, formatting and CI Bash syntax pass; owned fixture inventory is
empty. This startup implementation still requires fresh exact-head hosted checks.

The tested native depth implementation is committed and pushed at `185af81d5`;
its fresh CI and Rust analysis are now successful. The owned worktree was
clean after that push. The [whole-worker cutover inventory](rust-migrations/canvas-worker-cutover-readiness.md)
now maps all 14 normative legacy gaps to actual test boundaries and lists base,
beta-overlay, self-host and Kubernetes consumer wiring. It identifies the missing
composed worker/provider/published-schema gate and boot-configuration checks as
the next implementation targets. A cleared-environment local binary diagnostic
now exits 1 when rollout is disabled and the deployment-default LTI identity is
empty; the original process-signal harness always supplied that identity. The
startup checkpoint above now repairs and qualifies that recorded boundary.
Existing codec evidence remains retained; it
must not substitute for worker composition. The issuance plan's stale 32-route/
12-unported-gRPC snapshot is corrected to the coverage contract's 63 native HTTP,
68 remaining HTTP and 12 native gRPC methods, with consumer adoption separate.

Native depth adoption now matches all 64 provider, 64 managed validation and
192 full credential-route observations. The 127-container guard is removed:
one flat parsed arena and iterative writer preserve deep responses, while the
255-container validation policy remains at its own boundary. Stack-safe database
ownership covers lifecycle application/delivery/binding/platform reads, copies,
replacement and destruction, with database literal numbers kept distinct from
Python response-number policy. An additional 32 native follow-up operations read
and retain prior deep responses after provider refusals and preserve newer
success events. Small-stack and literal-number tests cover the ownership paths.
The required native provider and full-route gates reuse the frozen depth
reference; old JSON/UTF-7 artifacts remain unchanged.
See [native depth scope and evidence](../contracts/canvas-json-depth.md).
All 36 configured image/schema gates pass (308.32 seconds, none ignored or
filtered), along with 325 library, 5 worker, 34 managed HTTP, 22 issuance behavior,
102 affected Python and 104 native TLS cases. Strict Clippy, formatting and
CI-runner syntax pass; the exact owned fixture inventory is empty. Reference
head `2d8797be8` is hosted-green; this implementation needs fresh hosted checks.
Whole-worker/all-consumer readiness is the next inventory to refresh, not a
completion claim from this matrix. PR #814 remains draft and unrouted.

The following reference checkpoint is historical and was completed before the
native depth implementation above:

Published depth behavior is now independently frozen across 64 validation,
64 provider/helper and 192 full credential-route cases. Validation allows excerpt
container depth 255 and fails at 256; array payload wrapping adds a level.
Provider parsing and PostgreSQL saves succeed through every tested depth up to
1,600. Therefore the then-current native 127-container guard was a confirmed cutover
gap, not a compatibility policy. The fixture ceiling is not a runtime limit.
Nonrecursive typed structural witnesses preserve deep response evidence without
altering application recursion settings; complete validation wire bodies and
full-route state evidence remain retained. Two raw captures agree byte-for-byte.
The new required configured gate regenerates the entire reference.
See [depth evidence and native next steps](../contracts/canvas-json-depth.md).
That reference checkpoint changed test observation/capture infrastructure, not
runtime behavior. Native depth adoption is recorded above; worker cutover is open.
All 33 configured image/schema tests pass (301.31 seconds, none ignored or
filtered), including unchanged prior JSON/UTF-7 references and native replay.
All 102 affected Python tests, the large exclusive-create capture test, strict
Clippy, formatting and CI-runner syntax pass. Previous implementation head
`52785f6ff` is hosted-green; this depth checkpoint requires fresh hosted checks.

Native JSON response adoption now passes the independently frozen 66-provider,
66-managed-validation and 198-full-credential-route matrix. One parser retains
lossless text/keys, duplicate-key order, non-finite values, signed zero and large
integers. Validation rendering and PostgreSQL representability remain separate:
no early normalization, unchanged delivery rows after late failures, and newer
Rust success events preserved. Shared replay/observation code also retains UTF-7
coverage; wire checks reject duplicate rendered keys before map normalization.
The CI runner requires direct JSON provider and full-route native gates.
See [JSON consumer evidence and native scope](../contracts/canvas-json-consumers.md).

The unchanged reference was captured twice byte-for-byte at `6b127aef0`, whose
hosted CI and Rust CodeQL are now green. Local native gates pass 322 library,
5 worker, 32 managed HTTP, 22 behavior, 88 affected Python and 104 TLS cases,
plus strict Clippy and formatting. All 32 configured image/schema tests pass
(278.86 seconds, none ignored or filtered), regenerating the unchanged reference
artifacts and exercising native routes. The exact owned fixture inventory is
empty after cleanup. That `52785f6ff` implementation subsequently passed its
hosted checks; newer implementation heads require their own checks.

The depth guard from that initial JSON checkpoint is replaced by the native
adoption above. General grammar is not proven by the finite depth matrix.
Whole-worker/runtime/every-consumer adoption and other
exceptional codec/transport gates remain open. PR #814 stays draft and unrouted;
no reachable Python deletion or deployment change is authorized by this matrix.

UTF-7 response bodies are now integrated through shared lossless native text,
metadata and provider-error values. Validation renders retained-surrogate
failures as the published plain HTTP 500. Lifecycle persistence detects invalid
encoding only after canonical publication/credential persistence and provider
completion; typed encoding failures map to 500 without changing generic retry
errors. Native replay passes twelve provider observations, twelve managed HTTP
responses, and all 36 full credential routes with real PostgreSQL and local HTTP.
Complete credential/delivery rows and failure ordering match the frozen reference;
newer Rust success events remain intact, with none emitted after failed saves.
The 28th configured image/schema gate is required by CI. This closes the UTF-7
body integration scope, not JSON/non-scalar parsing, remaining exceptional codecs
or whole-worker/all-consumer adoption. PR #814 remains draft and unrouted.
All 28 configured image/schema tests pass (247.37 seconds, none ignored or
filtered), along with 313 library, 5 worker, 29 managed HTTP, 22 behavior,
70 affected Python and 104 native TLS cases, strict Clippy and formatting.
The preceding `96f55bb6e` head is hosted-green; this implementation checkpoint
requires its own hosted checks before landing.

### Earlier transport checkpoints (historical)

Full published credential-route evidence now covers 36 UTF-7 scenarios through
actual authenticated suspend/reinstate/revoke routes and real PostgreSQL saves.
Two independent captures agree: 18 retained-surrogate cases return HTTP 500
after canonical credential persistence, leaving the entire delivery row unchanged;
18 scalar/truncated cases return HTTP 200 and save the delivery projection.
No issuance events are added by these published routes. Publication/provider/save
ordering is observed, and every earlier validation/provider/helper observation
is unchanged. The required image diagnostic regenerates the expanded artifact.
This settles the previously open published response-policy question; native
lossless body/metadata/error adoption and full-route replay remain unfinished.
The current generic native retry HTTP 503 must not be mistaken for parity with
these late encoding/save failures. See the
[full-route evidence](../contracts/canvas-text-boundaries.md#full-credential-route-continuation).
All 27 configured image/schema tests pass (247.71 seconds, none ignored or
filtered), together with 70 affected Python tests and formatting/lint checks.
The preceding `61c5dd185` head has successful hosted CI and Rust analysis;
this evidence checkpoint still needs its own hosted checks and stays unrouted.

UTF-7 now has one complete-input native decoder for strict and replacement modes,
using lossless Python codepoints. Independent frozen digests cover 2,347,269
inputs per mode, including every supplementary scalar and all single-unit
padding combinations; 134 explicit cases and 39 earlier text boundaries pass.
Strict encoded labels are adopted and match 201 observations across five aliases.
The new tests exposed an embedded-NUL codec-name ValueError, now preserved before
alias normalization at both lookup boundaries. Validation grows 41 to 47,
provider 90 to 97 and TLS 99 to 104, with every old observation unchanged.
The required 27th image test exercises label-error persistence and recovery;
the timeout gate regenerates the full codec evidence. See
[UTF-7 codec scope and evidence](../contracts/canvas-utf7-codec.md).
Response-body/metadata/error adoption and full credential-route qualification
remain open; decoder availability does not close those gates.
All 27 configured image/schema tests pass (257.17 seconds, none ignored or
filtered), together with 312 library, 5 worker, 28 managed HTTP, 22 behavior,
70 affected Python and 104 native TLS cases, strict Clippy and formatting.
Previous `20d7787f9` CI and Rust analysis are green; this checkpoint requires
fresh hosted qualification and remains draft/unrouted.

Lossless native text groundwork now preserves Python codepoints without implicit
replacement, escaping or surrogate folding. Shared excerpt logic uses this owner;
three tests replay the 39 frozen helper text boundaries and verify validation,
supplementary/noncharacter handling and bounded prefix consumption. The decoder
and strict-label continuation above builds on this foundation; response-body
adoption remains unfinished.

Two independent image captures now cover twelve UTF-7 managed-app, twelve
provider and twelve real delivery-helper/save observations. Retained surrogates
produce managed HTTP 500 or a failed delivery save with unchanged persisted state;
truncated-away surrogates and supplementary scalar text succeed. This distinguishes
rendering from provider values and database encoding/JSON validation. A required
26th configured image test regenerates the diagnostic. Full credential transition,
publication and native UTF-7/metadata/error integration remain open; this evidence
does not qualify that broader scope. Details are in the text-boundary document.
Local gates pass: 309 library, 5 worker, 28 managed HTTP, 22 behavior, 70 affected
Python and 99 native TLS cases, plus strict Clippy and formatting. The full 26-test
configured image suite passed in 217.10 seconds. Subsequent whole-row diagnostic
strengthening passed its updated image comparison and the unchanged 90-case
provider comparison. Preceding `a75e2fa43` CI and Rust analysis are green; this
checkpoint still requires fresh hosted qualification.

Continuation-ordinal parity now preserves the published interpreter's 4,300-digit
limit without inventing a machine-integer cap. The previous implementation failed
the independently captured regression; native checks now match all 60 new
parameter/text/excerpt observations and the previous 177 header observations.
The TLS corpus grows from 96 to 99 with old observations unchanged. Independent
published captures expand managed validation from 37 to 41 and status-provider
behavior from 86 to 90, also preserving every previous observation. Actual HTTP
validation replays 21 response cases. The full configured image gate regenerates
the new artifact and adds a required ordinal lifecycle persistence/recovery
scenario, bringing the suite to 25 tests.
All 25 configured image/schema tests pass (214.76 seconds, none ignored or
filtered), alongside 306 library, 5 worker, 28 managed HTTP, 22 behavior and 70
affected Python tests, 99 native TLS cases, strict Clippy and formatting checks.
The preceding `da23f8b4f` head is hosted-green; the ordinal checkpoint still needs
fresh hosted checks and does not authorize routing the draft candidate.

UTF-7 investigation has established a lossless-text requirement, not completed
that codec: 39 independent helper/rendering observations preserve lone surrogates
as numeric codepoints. Fourteen renderings fail, while truncation can remove the
surrogate before rendering and allow success. Rejecting or replacing it during
decoding would lose behavior. Native representation/decoding and full consumer
qualification remain open. See [text boundary evidence](../contracts/canvas-text-boundaries.md).

Seven ISO-2022 variants now share a native stateful decoder, retaining ordinary
text, multi-character mappings and the distinct internal-codec/pending-buffer
errors. Independent image captures cover 134 active-state witnesses, 8,816,262
state inputs and 6,386,038 escape-boundary inputs per mode, and 1,167 responses
across 23 labels. Validation grows 31 to 37, provider 82 to 86 and TLS 85 to 96
without changing old observations. Native 305 library, 5 worker, 28 managed HTTP,
22 behavior, 70 affected Python and 96 TLS checks plus strict Clippy pass.
The new lifecycle persistence/recovery scenario is required by CI. All 24 configured
published-image/schema tests pass (212.24 seconds, none ignored/filtered), including
full artifact regeneration and lifecycle recovery. The prior `e06a90acc` CI and
Rust analysis passed; this continuation still requires fresh hosted qualification.
See [ISO-2022 evidence](../contracts/canvas-iso2022-codecs/README.md).

EUC-KR now preserves both two-byte text and eight-byte Hangul composition through
the shared Rust complete-input owner used by GB18030. Independently captured
evidence covers all 16,777,216 component triples (11,172 valid), 65,792 short inputs,
769 component observations, 98,304 mutated/prefix/suffix inputs per mode and 98
responses across nine labels. The previous fallback failed before repair. Local
303 library, 5 worker, 28 managed HTTP, 22 behavior and 70 affected Python tests
pass, as does strict Clippy. Native TLS matches all 85 observations, preserving
the previous 84. All 23 configured image/schema tests pass (197.45 seconds, none
ignored/filtered), including complete EUC-KR regeneration and unchanged previous
codec artifacts. Fresh hosted qualification remains required.
See [EUC-KR evidence](../contracts/canvas-euc-kr-codec.md).
Other codec families and whole-worker/all-consumer adoption remain open.

GB18030 now has a native compact range/pair decoder shared by response text and
strict encoded labels. Two independent immutable-image captures agreed before
implementation; the previous UTF-8 fallback failed the regression. Rust matches
all 1,587,600 four-byte pointers, all single/two-byte inputs, 88,741 byte-class
sequences per mode and 428 response examples across two labels. The 84-case native
TLS replay passes and preserves the previous 83 observations. Local 301 library,
5 worker, 28 managed HTTP, 22 behavior, 70 affected Python checks and strict Clippy
pass. All 23 configured published-image/schema tests pass (158.38 seconds, none
ignored/filtered), including full artifact regeneration. The preceding `cf8246918`
head is hosted-green; this continuation still requires fresh hosted qualification.
Details and format:
[GB18030 evidence](../contracts/canvas-gb18030-codec.md). PR #814 remains draft and
unrouted; no deployment or reachable-Python deletion occurs.

Multibyte response qualification adds 15 East Asian codecs through a shared native
state-machine decoder, also reused for strict encoded charset labels. Independently
captured immutable-image tables cover 64 labels, 2,415 reachable states and 618,240
byte transitions. Independent HTTPX/strict decoding hashes qualify 620,655 witness
inputs per mode, and 165 response examples retain multi-character mappings and
malformed-input replacement. The old native UTF-8 fallback failed before repair.
The published-helper/native TLS corpus expands from 68 to 83 cases with every old
observation unchanged. Local 299 library, 5 worker, 28 managed HTTP, 22 behavior,
70 workflow/image/ownership/cutover checks, strict Clippy and all 23 configured
image/schema tests pass. No dependencies or runtime Python are added. The prior
integration head `ded29ea7c` CI and Rust CodeQL passed; new source still requires
its own hosted checks. UTF-7 and remaining special/escape codecs,
exceptional metadata/JSON/configuration/transport behavior and whole-worker/all-
consumer adoption remain open. No deployment or reachable-Python deletion occurs.

Protected main advanced through CI/cache repair PR #815 at
`f5c4da685f5723a7614649c883bfaa540dd153f1`, conflicting with PR #814 in the
workflow, workflow tests, worker lifecycle and process-signal diagnostics. GitHub
reported the charset head `3c4995e8e` as unmergeable, with no check suites; this
was an integration conflict, not a failed test or permission configuration.
The reconciliation retains main's cache improvements and concurrent isolated
database runner, moves all 20 newer Canvas assertions into the extracted script,
and keeps the separate TLS gate. Both connection-release and worker-cancellation
cleanup protections remain, with distinct responsibilities and existing tests.
Local 70 workflow/image/ownership/cutover checks, 297 library, 5 worker, 28 managed
HTTP, 22 behavior, strict Clippy and 68 TLS cases pass. The configured worker
PostgreSQL suite passes all three tests (92.63 seconds), including all 60 renewal
outcomes and lifecycle/disposal checks. All 23 configured published-image/schema
tests also pass (140.67 seconds, none ignored or filtered). POSIX process signals still require
hosted Linux evidence; the Windows gate explicitly does not claim to exercise them.
This integration does not approve worker cutover or change any deployment.

Charset-header qualification adds 177 independent observations covering ordinary,
quoted and RFC2231 parameters, continuation ordering, label decoding, registered
dotted aliases, malformed-group error identity, and JSON/empty-body bypasses.
The old native parser failed the frozen corpus. One shared Rust parser now passes
it and reuses the codec registry and strict/replacement Unicode primitive; no
runtime Python or dependency is added. The 326 registry aliases describe lookup
semantics, not a claim that every referenced codec is implemented.
Two independent immutable-image captures also expand validation from 28 to 31
cases and status providers from 79 to 82, preserving every previous observation.
Native managed HTTP and the real validation transport retain the distinct success,
JSON and failure paths. The shared real HTTP/PostgreSQL lifecycle fixture now
also verifies charset diagnostics, committed canonical status and recovery.
Local 297 library, 5 worker, 28 managed HTTP, 22 behavior, 42 workflow/image/
ownership tests, strict Clippy and 68 native TLS cases pass. All 23 configured
published-image/schema tests pass; CI explicitly requires both Unicode and charset
recovery tests. Prior head `137c939561d08c20c59fc6c780294501b9458a1b` CI and Rust
CodeQL completed successfully; this continuation requires its own hosted checks.
Unqualified multibyte/stateful codecs (including encoded parameter labels),
exceptional metadata/JSON/configuration/transport behavior, whole-worker and
all-consumer adoption still prevent cutover approval. No reachable Python is
deleted, no rollout changes, and PR #814 remains draft. Branch reconciliation,
UI/demo/crypto preservation, CSCA follow-up, recordings/device/wallet evidence,
aggregate beta deployment and uninterrupted soak remain in the full active goal.

Status-provider qualification expands the published corpus from 63 to 79 cases,
preserving all earlier observations. Two independent immutable-image captures
freeze success/error response decoding for bridge synchronization and real-provider
revocation. The old native boundary lost Unicode error identity; one typed
`synchronize_provider` owner now preserves it. The existing lifecycle port delegates
to that owner and stores diagnostic text, matching the published route's explicit
`str(exc)` persistence behavior. No message-based error-class inference is used.
The new real HTTP/PostgreSQL runtime scenario proves two decoder failures preserve
committed canonical status, attempt counters and diagnostics; subsequent JSON
success clears the error. It reuses the baseline runtime fixture and retains its
tenant-vault, event-ordering and late-persistence-failure checks.
Local 296 library, 5 worker, 28 management HTTP, 22 behavior, 42 workflow/image/
ownership tests, strict Clippy and all 68 existing TLS observations pass. The full
configured 22-test image suite passes (136.27 seconds, none ignored/filtered);
fresh hosted checks must qualify this continuation. Prior
`81236f778b9a5403a6ad3bc5c9667e509a318361` CI was cancelled after the subsequent
source push; its Rust CodeQL completed successfully. Cancellation is not a pass.
The full goal stays active, PR #814 draft/unrouted, and deployments unchanged.

The Unicode-text continuation adds shared UTF-16/32 decoding for both byte orders
and all 16 published aliases. A new 372-case language-neutral corpus separately
freezes text and JSON/excerpt outcomes, including BOM requirements, invalid
scalars/surrogates, truncated prefixes and JSON precedence. Independent captures
agree; the unchanged native decoder failed, and the replacement passes. The
actual published application corpus expands from 20 to 28 cases: missing required
BOMs return plain HTTP 500, successful provider bodies are not text-decoded, and
short prefixes receive replacement characters. Native full-router replay and an
eight-case real HTTP transport regression preserve these distinctions via typed
decoder errors, not network-failure results. All earlier observations remain.
Local 296 library, 5 worker, 28 management HTTP, 22 behavior, 42 workflow/image/
ownership tests, strict Clippy and the existing 68 TLS cases pass. All 21 configured
published-image tests pass (137.06 seconds, none ignored/filtered); fresh hosted
checks must qualify this continuation. The previous pushed
`ef24ba1a128d2db91b242da99496f9de51dafb80` has successful CI and Rust CodeQL.
PR #814 stays draft and unrouted.

Other multibyte/stateful codecs, extended headers/label normalization, exceptional
JSON behavior remain open. The validation and status UTF-16/32 response boundaries
are now qualified for their frozen inputs; other exception/configuration paths
still need whole-consumer evidence. Whole-consumer cutover, Python deletion,
branch reconciliation, demos/device/wallet/CSCA follow-up and aggregate beta/soak
remain required. The checkpoints below retain prior evidence chronologically.

The preceding single-byte continuation replaces hand-maintained ASCII/Latin-1
branches with one shared Rust table decoder for 73 codecs and 291 registered
aliases. The language-neutral tables come from the exact published response
helper, not WHATWG approximations; the immutable-image gate independently
checks them. Four representative code-page cases extend the TLS corpus to 68,
preserving all 64 prior observations. Native 68-case replay, 294 library, 5 worker,
28 management HTTP, 22 behavior and 42 workflow/image/ownership tests pass;
strict all-target Clippy passes. Windows UTF-8 output and Unicode JSON record
parsing repairs have regression coverage. No runtime Python or new dependency
was introduced. See [the codec contract](rust-migrations/canvas-response-codecs.md).
All 21 configured published-image tests also pass (164.97 seconds, none ignored
or filtered). Fresh hosted qualification remains required for this continuation.
The prior pushed head
`69dbfe4bc2005834efb764d8d37bb91e35565b91` has green CI and Rust CodeQL;
those results do not qualify later source changes. PR #814 remains draft.

Current open gates are multibyte/stateful text codecs, extended charset headers
and decoder exception boundaries; broader provider configuration/transport
behavior; whole-worker/runtime and every deployment consumer; immediate removal
of superseded Python after those gates; branch preservation/cleanup; all-demo,
device/wallet and CSCA lifecycle follow-up; aggregate beta release and a new
uninterrupted soak. Beta 217 does not qualify the current candidate. No deployment
or other-worker change was made. The following paragraphs retain historical
qualification checkpoints, not additional claims about the newest source.

Core text-charset qualification extends the shared TLS corpus to64 observations,
retaining the previous47. Two independent published-source captures freeze
ASCII/Latin-1 mappings and aliases, UTF-8 signature handling, first/quoted charset
parameters, fallback and character-counted excerpts. The unchanged native text
projection failed; a shared Rust text owner now passes native64 replay. Both
consumers retain Content-Type alongside decompressed bytes, while JSON decoding
remains independent. Local293 library tests, supporting suites and strict Clippy
pass. Additional Python codecs and extended charset headers still block blanket
text parity and all-consumer cutover.
The full configured21 published-image tests also pass (none ignored/filtered);
fresh hosted qualification remains required for this continuation.

Compressed-response qualification extends the shared TLS corpus to47 cases,
preserving all31 prior observations. The immutable published image supports
gzip/deflate/identity, not Brotli. Two independent captures freeze16 added
compression, error and progress cases; unchanged Rust failed them. Shared
streaming Rust decoding now passes native47 replay and is used by both failed
response projection and successful validation draining. Actual status transport
also preserves gzip-compressed UTF-16 JSON. General text charset and remaining
transport/configuration/all-consumer gates remain open.
Local291 library tests, supporting worker/API/behavior suites, strict Clippy and
all21 configured published-image tests pass. Offline dependency bans/licenses/
sources pass; fresh hosted advisory and image checks remain required.

Unicode JSON qualification extends the shared TLS corpus to31 cases, preserving
the previous21 observations. The exact published helper accepts UTF-8 BOM and
UTF-16/32 JSON in either byte order, with/without BOM, independently of the text
charset. Two independent captures agree; the unchanged native decoder failed,
and the shared Rust byte decoder now passes all31 native TLS cases. Status
synchronization retains bytes instead of applying lossy text decoding first.
Local288 library,5 worker,28 management HTTP,22 behavior,40 workflow/image/ownership
tests and strict Clippy pass; full configured21 published-image tests pass.
General text charsets, compression and wider adoption gates remain open.

Response-body qualification now extends the real TLS corpus from17 to21 cases,
retaining every prior observation. Two independent published-source captures
confirm valid JSON at/above the former64KiB validation buffer, bounded text
excerpts, and a read timeout after that prefix. Native21 TLS replay passes. A
real validation-transport regression reproduced lost JSON fields at exactly64KiB;
the repair consumes failed responses completely before shared JSON/text projection
and rejects later stalls/truncation. Only non-JSON text excerpts are limited to
1000 characters plus ellipsis; request-body limits and origin policy are unchanged.
Local286 library,5 worker,28 management HTTP,22 behavior,40 workflow/image/ownership
tests and strict Clippy pass. The full configured published-image suite passes
all21 tests (none ignored). Charset/compression and wider transport gates remain.

The [managed validation boundary](rust-migrations/canvas-validation-boundary.md)
now freezes20 responses and lookup/file/HTTP effects from the actual published
application middleware, route and adapter; two independent captures agree. The
native full management router matches all20 after restoring typed UTF-8 failures
as plain500 responses, unsupported-provider short-circuiting, configuration-error
result shape, and the second lazy token lookup that observes file rotation.
Canonical tenant-secret checks are unchanged. Local285 library,5 worker,
28 management HTTP,22 behavior and40 ownership/workflow/image tests plus strict
Clippy pass. The new mandatory published-image gate expands the schema suite to21.
The complete configured21-test run passes (134.71s), with no ignored/filtered cases.
Fresh hosted qualification is required; source completion is not deployment.

The native operation-deadline owner is now wired in the candidate source to both
status synchronization and credentials-validation HTTP. Startup retains the
original floating-point value rather than rejecting Python-accepted timeout
ranges. All19 published import-acceptance cases replay through the actual config,
and all17 native TLS cases match the unchanged published socket oracle using the
new transport and real config. Shared origin/DNS policy remains authoritative;
catalog, OAuth and worker HTTP retain their existing separately qualified policy.

Maintainer review also corrected validation returning success at response headers:
it now drains successful bodies without retaining them, rejects truncation/stalls,
and accepts ongoing progress beyond one total timeout. The new regression failed
before repair. Local qualification passes285 library tests,5 worker tests,
22 behavior tests,40 ownership/workflow/image tests and strict all-target Clippy.
Final full configured schema qualification passes all20 tests (126.72s), including
both lifecycle variants. An earlier19/20 run failed at Docker cleanup; it is
retained as failed evidence, not reclassified or masked by excluding a test.

Draft#814 remains unmerged. Prior hosted head40fccb65e had two failures with one cause:
the loopback certificate fixture's four Python crypto imports lacked ownership
metadata. Exact test-only allowances now document those imports; a regression
proves they authorize neither service imports nor duplicate fixture imports.
No guard logic, scan scope or production crypto owner was relaxed. Native TLS
replay is now a mandatory CI step. Transport headcd5396ef2 completed CI34002852973
and Rust CodeQL34002852955 successfully. The new validation-boundary repair above
requires its own fresh hosted checks; prior-head green checks cannot qualify it.

The20-case validation continuation above supersedes the earlier error/lookup
ordering finding for its frozen inputs. Remaining cutover gates include broader
URL/template/response-encoding behavior, backpressured writes and early replies,
whole-worker/runtime adoption and every deployment consumer. No reachable Python
was deleted or pending-only lifecycle default switched. No deployment changed.
The host restart interrupts beta soak; current beta health is not inferred from
test-container availability. See the latest section in
[provider configuration evidence](rust-migrations/canvas-provider-configuration.md).

### Earlier operations qualification history (superseded where noted above)

Docker became available again. The first full schema run passed19/20, including
the19 fresh adapter imports; the remaining TLS probe lacked writable certificate
storage in its read-only image. A timeout-probe-only8MiB tmpfs fixes that fixture,
and all17 socket observations now pass in the published HTTPX0.26.0/httpcore1.0.9/
AnyIO4.14.2 runtime. A shared native lossless scalar/per-operation deadline runner
is implemented and passes six focused tests plus the280-test library suite, but
is not yet wired into HTTP consumers. The full configured schema rerun now passes
all20 tests (432.49s); new hosted checks remain required. Existing live timeout
policies and production are unchanged.

Timeout qualification now includes 17 independently repeated, real loopback-TLS
observations from the exact published Canvas HTTP factory/pinning transport.
They confirm that Python uses progress-sensitive operation deadlines, whereas
Rust currently uses a whole-response deadline and rejects several values at
startup that Python accepts. A new mandatory image test cross-checks those socket
outcomes; the helper gate additionally verifies 19 full adapter imports in fresh
processes. These new gates await hosted qualification. Native timeout repair and
all-consumer adoption remain open; no cutover is implied by a Python baseline.
See [configuration evidence](rust-migrations/canvas-provider-configuration.md).

The latest [provider configuration continuation](rust-migrations/canvas-provider-configuration.md)
adds one lazy Rust operator-secret owner and 39 independently captured helper
observations (20 secret, 19 timeout), including file rotation, optional I/O,
UTF-8, whitespace and newline handling. Validation's canonical tenant policy and
required non-Canvas secret policies are preserved. MMF float grammar and ordered
timeout evaluation replace the Rust-only parser; actual network timeout/range
and full endpoint error parity remain open. Runtime commit `6fdc86272` passed
CI33997949251 and Rust CodeQL33997949236. New configuration changes require fresh
hosted checks, including the new pinned-image helper cross-check. Docker's Linux
engine is currently unavailable locally; this does not qualify a local full gate
or current deployment health. The reported host restart interrupts continuous
beta-soak evidence. Production remains unchanged by this lane.

The status provider now has shared runtime configuration/HTTP assembly and a
63-case published replay through the actual configuration parser. Eight new cases
correct missing-issuer null projection, legacy BASE_URL trust/fallback and empty
organization gating, preserving all original 55 observations. A real encrypted
tenant-vault + credential/delivery PostgreSQL + loopback HTTP contract verifies
durable mirror failures/recovery and rejects success if the delivery disappears
after the external call. Normal token-file and timeout precedence are tested.
At that checkpoint, eager/missing-file and numeric edge differences remained cutover blockers;
no live consumer has adopted the factory. Prior provider commit `340a0503b` passed
CI33996860721 and Rust CodeQL33996860698; new changes require fresh hosted gates.
The new local runtime/fault tests passed before Docker became unavailable; 267
library tests, 33 workflow/image tests and strict Clippy passed. The final full
schema run was blocked at container creation for all17 Docker-dependent tests;
only its Docker-free replay passed. This is not a green full-suite result. The
daemon reports `Docker Desktop is unable to start`; no restart was attempted.

The initial [Canvas lifecycle status provider candidate](rust-migrations/canvas-status-provider.md)
now implements bridge POST and Badgr DELETE synchronization plus canonical-only
suspend/reinstate, with 55 independently frozen published protocol cases matching
the Rust replay and a fresh published-image capture. Shared provider primitives
retain validation's distinct secret policy. Actual loopback HTTP tests cover
wire payloads/headers and non-followed redirects; environment/factory wiring,
TLS/transport edge cases and all-consumer cutover remain open. Draft #814's prior
head `8b75c27c0b64c437356bbb0e6dd1cb692cc4d36e` completed CI33995364201 and
Rust CodeQL33995364199 successfully, including the packaged-worker contract that
previously failed. New provider changes require their own hosted qualification.
The expanded local candidate passes all 17 configured schema tests, 266 library
tests, 5 worker tests, 22 combined behavior tests, 33 workflow/image tests and
strict all-target Clippy. Two final deterministic-DNS provider captures preserve
all 55 observations. No new deployment or Python deletion occurred.

The [actual lifecycle/delivery candidate](rust-migrations/canvas-lifecycle-delivery.md)
adds17 independently frozen published cases covering durable credential/delivery
effects, provider failures, cancellation and competing resolution. It exposes and
replaces the pending-only delivery behavior for the explicitly configured candidate;
the default runtime adapter is not yet cut over. Bridge/Badgr provider qualification
and all-consumer adoption remain required. A separate configured database regression
reproduces a SQLx return-to-pool cancellation race consistent with the hosted worker
signal failure; bounded post-operation connection validation fixes the local race
without changing active-query or graceful-drain policy. Linux CI passed at the
prior head identified above; subsequent changes must retain that gate.
The expanded candidate passes15 configured schema tests,264 library tests,
5 worker executable tests,22 combined behavior tests,33 workflow/image tests
and strict Clippy locally. No new deployment or superseded Python deletion occurred.

The [manual review resolver candidate](rust-migrations/canvas-review-resolution.md)
completes implementation of all eight operations in the candidate router, still
unrouted. All46 corrected-schema published HTTP/state cases pass without manual
case exclusions, with supplementary audit rollback, token/action fences and
shared application-lock checks. The actual credential service/PostgreSQL adapter
is exercised for suspend/revoke with controlled publication. The exact official
credentials#266 migration is mounted read-only and hash-verified for these tests;
this is source-overlay qualification, not a newly released component. All12
configured schema gates,260 library tests and20 focused CI/image tests pass locally.
An additional45-case published manual-request capture agrees across two runs;
native replay now matches syntax/body/content-type/auth-order and actor-header
behavior for that corpus, after a reproduced empty-body negative control.
Broader encoding/transport cases, lifecycle failure/cancellation/provider coverage,
full hosted qualification and worker/all-consumer cutover remain open.

Job operations #813 merged as `04e2ea2c7ca6107c4c9dc12809272c1190393b1c`
after source and protected-queue CI/CodeQL passed. Its merged tree
`e8469359abe331d66e92525e280821ed8451f50b` matches the verified union of the
reviewed job branch and #807's CI work. Manual review continues in draft #814.
The rebased candidate passes13 configured schema tests,261 library tests,
22 combined behavior tests,33 workflow/image tests and all-target Clippy locally.
The merged #813 worktree/local branch are retired, with both ignored caches
preserved; no Python runtime feature or other-worker branch was removed.

The [native operations read candidate](rust-migrations/canvas-operations-reads.md)
implements four read APIs in the existing issuance crate, without live routing.
All25 frozen read cases and75 supplementary published input/status cases replay
locally, alongside500-row review-window and unavailable-database checks.
Its seven configured schema gates and258 library tests pass, with full CI and
CodeQL green at reviewed #812 head `70e82b8b6068f377a417997b1a5dd68adde7e747`.
After green queue CI/CodeQL, #812 merged as
`91db72daa1256d5cdee27c61a1a73e3b5480eaf8`, retaining its reviewed tree.

The [job operations candidate](rust-migrations/canvas-job-operations.md) now adds
enqueue and dead-letter retry/resolve using the shared enqueue owner. All35
read/job cases from the unchanged46-case golden pass, plus native official-schema
concurrency, rollback, canonical-ID and LTI compatibility checks. Review exposed
and corrected the shared non-object metadata merge. A supplementary published
capture adds28 actual enqueue HTTP/database cases and23 identifier conversions;
it reproduced and corrects numeric display and control-whitespace differences.
One shared Rust formatter consumes the frozen published Unicode15.0 text rules,
with no runtime Python or new dependency. Ten configured schema gates,
260 library tests,51 candidate/LTI behavior tests and20 focused CI/image tests
pass locally. The manual candidate above adds the last write; broader input/worker-interleaving qualification, hosted
checks and all-consumer cutover remain required. No live routing has changed.

The [operations baseline](rust-migrations/canvas-operations-freeze.md) captures
46 HTTP/state scenarios across all eight remaining Canvas operations APIs using
the published Python router, authentication, service and real PostgreSQL.
It merged through #811 as `aac7d9377891564e947042a98a3db24ed8ba92b0`.
Two independent captures agree; all five original configured published-schema tests,
all-target issuance Clippy and twenty focused CI/image tests pass locally.
Full hosted/cutover qualification remains pending; the combined candidate does
not authorize consumer switching or deletion from its current passing corpus.

The failed-handler recovery scenario exposes a published schema defect:
the internal `evidence_recovered` claim is rejected by the manual-action-only
constraint, leaving recovery pending. The frozen outcome is a historical
negative control, not desired Rust behavior. An official forward migration,
model alignment and real-database recovery/audit/claim-fencing tests are required
before operations cutover. Credentials #266 merged that forward-only fix as
`51f0a758a076777cb18a30b1db3f89c74ac23e01`, retaining its reviewed tree after
complete fresh CI and protected landing. Actual PostgreSQL recovery and both
published/current consumer replays pass with respective schema heads and
unchanged worker outcomes. Aggregate adoption remains pending.
No reachable Python feature has been removed.

### Current heartbeat readiness qualification

The [published heartbeat readiness gate](rust-migrations/canvas-heartbeat-readiness.md)
freezes seventeen actual Python/database observations before Rust replay.
It compares the full heartbeat readiness check through the shared native SQL,
runtime and policy owners, including microsecond freshness boundaries,
competing workers, strict boolean metadata and a real database failure.
It exposed and corrects a zero-age minimum difference; the deployed 120-second
setting is unchanged. Four native writer/readiness checks additionally cover
all heartbeat phases and original-start preservation. The configured readiness
gate and full hosted CI/CodeQL pass. #810 merged as
`38f29b14f43b83bf5a8122e2203de0eb9f43db9a`, retaining its reviewed tree.
This is not complete binding activation or permission to route/delete the worker.

### Current Canvas initialized-owner adoption

Credentials #265 is merged at protected `e3e79c96ab655f4ac699074c6452cd8c4c43dcb6`:
60 actual complete-job cases freeze outcome persistence after renewal failure,
including later owner/expiry/attempt fences and the legacy cancellation-masking
behavior. The native [per-job write authorization](rust-migrations/canvas-processor-job-authorization.md)
follow-up now carries an explicit lease into independent repository handles,
checks the durable job before resource locks and again before committing effects,
and rejects unscoped writes across all seven processor effect entry points.
UI #801 is merged at protected `e19ef225872f3198b8411bd404101da25c632c21`.
The native [renewal-job outcome follow-up](rust-migrations/canvas-worker-renewal-job-outcomes.md)
now preserves bounded processing after operational renewal errors, attempts only
lease-fenced durable outcomes, and observes the original renewal error afterward.
Its real PostgreSQL 60-case matrix consumes the unchanged frozen corpus; external
cancellation remains prompt and is not masked by renewal failure. UI #802 is
merged at protected `9da0581d3be2b1e37be044200e2a22cdf752460c`, with its exact
reviewed tree retained.

The next [published-schema processor gate](rust-migrations/canvas-published-schema.md)
passes locally against the pinned published migrations. It discovered and fixes
a JSON/JSONB comparison failure in the native learner fact-commit guard. Real
roster and learner effects, four fact types, repeat reads, provider-error head
preservation and stale-context rejection now execute on the actual issuance
schema. The provider is controlled and the organization dependency is minimal;
UI #804 is merged at protected `e8d4b54c22f79d95a919d302a1a81c01f6e4ff0f`,
with its reviewed tree retained and queue CI/CodeQL green.
The [issued-review differential](rust-migrations/canvas-issued-review-parity.md)
captures ten published Python lifecycle stages before the Rust replay. Both
implementations pass locally on separate migrated databases, preserving manual
claims, recovery, older history and all credential/transaction rows. No runtime
change was needed for those scenarios. Original hosted CI/CodeQL and the
configured two-test database gate pass. #805 is merged at protected
`907aaff8e85052cf8cc76559d8a6aecdcc95ebe4`, with its reviewed tree retained.

The next [mixed-roster differential](rust-migrations/canvas-mixed-roster-parity.md)
freezes twelve actual published Python stages before native replay. Local parity
now covers missing/unverified/quarantined identities, active mixed-source joins,
observation reuse, outages, negative/recovered AGS evidence and claimed/dismissed
state. It discovered and restores the omitted native `roster_remaining` result;
partial-batch and completed-cycle unit assertions accompany the real-schema
replay. #806 is merged at protected
`6cae40752ceed969e5869dc316f828763484bebe`, with queue CI/CodeQL green and
its reviewed tree retained. This uses controlled transport, not the actual HTTP provider.

The [HTTP-provider follow-up](rust-migrations/canvas-authoritative-http.md) adds
three passing real REST transport tests using the actual provider/OAuth service
and shared in-memory OAuth fixtures. It also reproduces an AGS candidate hash
difference with the provider's full observation shape and restores Python's
candidate-only projection, preserving learner fields. The unchanged mixed-roster
baseline and all three configured schema contracts pass locally. #808 merged
as `c63eb029229e9326ac3884ed85d5d68bcfeec45d`, retaining its reviewed tree.
The [actual LTI HTTPS gate](rust-migrations/canvas-lti-https.md) is now implemented
with child-scoped synthetic trust, untrusted-certificate rejection and real
token/AGS/NRPS requests. #809's mandatory Linux step passed in job
`101350558900`: four token requests, three AGS reads and two NRPS pages;
full CI `33982630708` and Rust CodeQL `33982630748` passed. #809 merged
as `2bbf74a58c35bddcadddbdab66b400ee29a192a9` after fresh source and queue
CI/CodeQL success, retaining its reviewed tree.
Full provider/processor differentials,
concurrency/rollback, manual resolver, all-consumer cutover and acceptance remain
required. Reachable Python is retained until those gates pass.

The integrated [renewal-progress follow-up](rust-migrations/canvas-worker-renewal-progress.md)
retains the initialized pool owner and actual process-signal gate while correcting
three reproduced differences: processing/deadline stalls during renewal I/O,
suppressed process liveness after target CAS loss, and non-ISO target-heartbeat
timestamp serialization. It landed as #799 on protected main at
`9a7b0ad013713446d9e9887e618c0f161dde15e6`, with the reviewed UI readiness test
fix retained. Provider and whole-worker gates remain required.

The separate native renewal failure-boundary test now exercises actual PostgreSQL
lease, target-heartbeat and process-heartbeat write errors after two processors
start. All three local cases pass on unchanged worker code; durable rows and
rollback-surviving attempt counters verify partial commits and suppression of
later writes. A reversed-heartbeat-order negative control fails as intended and
was restored. Those baseline tests landed as #800 at protected
`6cf634705bf4221ce360428321d90a5545c36593`, after configured Linux and normal
merge-queue checks passed. This proves the
maintainer's write boundaries, not whole-job equivalence. The newer outcome
follow-up above retains these assertions while changing processor lifetime after
operational errors to preserve legitimate results. Full authoritative processor/
provider outcomes and all-consumer cutover remain open.

The [process-signal follow-up](rust-migrations/canvas-worker-process-signals.md)
freezes actual published Python SIGINT exit130, corrects the native exit mapping,
registers Unix handlers before worker startup, and adds actual-binary Linux
SIGINT/SIGTERM tests during idle and blocked-SQL phases. Local Windows tests
cannot establish POSIX delivery; that mandatory hosted gate remains required.
This does not clear authoritative-provider, published-schema or full-worker parity.

UI #795 is merged at protected `354374618014add2611280cbcb7a63703af0daf2`;
the configuration candidate below has therefore landed. MMF #102/#103 are
merged, with current protected revision
`b4376cda59b3921598e1749f550595d7293e4624`. The standalone worker now adopts
that shared async owner, closes its actual PostgreSQL pool before acknowledging
initialized exits, and preserves cancellation separately from graceful drain.
Its binary tests are enabled for normal workspace test execution.
See [initialized lifecycle evidence and remaining limits](rust-migrations/canvas-worker-awaited-pool-disposal.md).

The pool-disposal replay supplements, rather than replaces, UI #796's owned-job
cancellation proof and the existing configuration/recovery/renewal/fencing gates.
It uses synthetic PostgreSQL schema and controlled processors; published-schema,
process-signal, provider and whole-worker parity remain separate requirements.
The worker remains unrouted, with Python and all production consumers retained.

There are now four retained beta217 operational samples, latest captured at
`10:50:14Z`, not a completed 7–14-day soak. The user confirmed the unexpected
host reboot caused Docker restarts; uptime before and after reboot stays
separate. Read-only production verification at `11:37:04Z` still matches the
post-reboot 29-container baseline. No new deployment is part of this adoption.
The historical three-sample and pending-configuration statements below are
superseded by this checkpoint; all broader acceptance and cleanup gates remain.

### Current 1.1.217 evidence and Canvas configuration progress

UI `#793` and activation `#794` have merged through protected gates. Release
run `33954137368` and hosted lifecycle run `33955914598` are terminal successes
at exact source `4596afaca3724e60a8dadbd4e227b6e765cb495c`. Official beta deployment
completed at `08:36:34Z`. The fresh KMS recording passes all five assertions,
loads the custom ElevenID Keycloak theme, and restores provider configuration.
It is one recording, not the complete demo portfolio or external device proof.
Three operational soak samples pass, latest captured at `10:05:15Z`; this does
not complete the required 7–14-day soak. The host reboot remains an explicit
interruption. Read-only inspection at `10:24:29Z` matches the post-reboot
29-container production baseline; no production mutation is part of this work.

Credentials `#260` freezes 64 actual-Python numeric lexical vectors; `#262`
freezes 36 real PostgreSQL consumer cycles and three two-cycle error-recovery
loops. MMF `#101` merged the shared Rust numeric parser at protected revision
`9534d0e3be66bd63d65ee672516da8b8df5206af`. This candidate adopts that owner,
preserves OS-generated/explicit identity behavior and arbitrary-size integer
configuration, and checks bounds at the SQL, timestamp and OAuth consumers.
There is no second parser or new Python runtime implementation.

Local native evidence: 133 full-factory vectors; 247 library, three worker and
five factory tests; all ten issuance Canvas/proof-nonce PostgreSQL contract
executables; all-target issuance clippy; and the three issuance candidate
contract tests pass. The SQL worker executable replays all 36 cycles and three
two-cycle loops using actual production repositories and actual worker entry
points. An altered expected OAuth row count fails the real replay; the original
fixture was restored and the suite passed again. The native suite uses an
isolated synthetic contract schema, not published-migration proof. Full hosted
workspace CI and protected landing remain required for this candidate.
See [configuration and consumer evidence](canvas-worker-lossless-configuration.md).

Next: land the reviewed candidate, reconcile the remaining loader/lifecycle,
active-job/provider/concurrency and readiness observations, then change every
intended worker consumer and delete superseded Python only after those gates.
Complete remaining recordings, genuine device evidence, aggregate acceptance,
integration repinning and feature-preserving owner-branch cleanup. These local
tests do not authorize worker routing, Python deletion or another deployment.

### Historical 1.1.217 selection — prerequisites subsequently completed

The following records the selection-time findings; the current snapshot above
supersedes its pending prerequisite/publication/deployment statuses.

Release `v1.1.216` (run `33945270048`, source `89c66b07aceb937366390ae194e75ff09fd528b2`)
passed publication signatures/provenance, exact image/source binding and official
beta deployment at `05:22:04Z`. Its KMS recording passes create, issue, provider
switch, stable DID and unpublished-key rejection, with the custom ElevenID
Keycloak theme and restored provider configuration. This is one completed demo,
not all recordings or a completed acceptance soak.

Lifecycle run `33947284515` failed because browser contract tests preceded the
Chromium install. Direct public demo checks also found CSP-blocked Cloudflare
injection and consented YouTube embedding. Private recorder run `33947609446`
failed against a pending source template rather than the retained deployment
receipt. These are acceptance/integration gaps after migration, not evidence that
the Rust service implementation or all release acceptance was already complete.

Forward corrections now included:

- UI `#789` (`ce9b5dbf09c6febf0ff06ed82f258f02d0fb6afa`): include the signed
  release transaction in future complete release checksums; preserve published216.
- UI `#790` (`05fa28eb830e70472713b0dbe6277b7ea87dc18b`): install Chromium and
  its system dependencies before the unchanged browser contract suite.
- UI `#791` (`0db570ebf50ae686afba78834bad9c2ca4b687d1`): exact HTTPS CSP
  origins for the existing beacon and consented YouTube capability, preserving
  WASM and rejection of inline/eval/unapproved origins.
- UI `#792` (`136a11bfeb2787a5f11fca0ea0fc0644ae780b94`): native lossless
  transport of the original three deployment evidence files. Byte/hash integrity
  is not a replacement for provenance or live portfolio validation.
- Private recorder `#39` and `#41` are merged; current reviewed main
  `7858b5843306fbb08e441340f702d9ac3f3f4e21` accepts original official receipts,
  unpacks private evidence with the exact released Rust utility and emits only a
  sanitized qualification report. Local qualification passes13 scenarios; an
  actual hosted run with the new aggregate is still required.
- UI `#793`, reviewed head `d43161c7dcd640f8bf1c4c388f5522cb910ac0fc`, makes
  completed private qualification a checked public lifecycle prerequisite. It
  binds run/reviewed recorder/source/release/original receipt/signed stack hashes,
  preserves all existing acceptance gates and corrects unsupported recorder
  protection labels. Its protected merge remains a prerequisite of this draft.

The current recorder repository plan cannot enforce branch protection. Select
its exact reviewed revision only after terminal green checks; do not treat main
equality or a private repository's `--auto` option as enforced approval. Published
216's bound recorder `88079b1b91bd7dc4771fde6a5e672323a57689a3` and original
receipts/videos remain immutable. New deployment and recording evidence gets a
fresh release/source/recorder binding, never a relabeled old artifact.

The lock changes only the aggregate coordinate to `1.1.217`. Keep Python issuance
`0.1.72`, integration qualification `1.2.79`, every immutable component pin and
calendar/demo VERSION `2026.08.0`. After prerequisite and activation merges,
claim the exact protected source, publish/verify it, deploy beta only, run private
intake to completion and then the full public lifecycle, all recordings, genuine
external device evidence and governed soak. See the
[release and acceptance checklist](rust-migrations/beta-acceptance-follow-up-1.1.217.md)
and [private qualification operator sequence](rust-migrations/private-demo-qualification-lifecycle.md).

Owned UI `#789`–`#792` and recorder `#39`/`#41` clean merged worktrees/branches
were retired after content proof, with caches and failed browser evidence retained.
Crypto-owned local commits/worktrees remain untouched. The post-host-reboot
29-container production baseline remained unchanged at `06:46:36Z`; the reboot
does not justify claiming uninterrupted runtime or changing production.

### Historical 1.1.216 selection — now published and deployed

The candidate includes merged worker-result PR `#784`, Canvas storage PR `#786`
at `fdcdf7e3b72749db29cb9cef3bf97ad1479075e4`, and token storage PR `#785`
at `895218b408f20922bda741d51886ec0744a0754f`. Their reviewed changes were
independently matched against protected merge contents before retiring owned
branches/worktrees. Shared Rust acceptance-lineage PR `#787` is also included
at reviewed combined candidate `28b46b4006ed71f330d10041082fb93f5920bd6d`;
it was queued when that draft was prepared and subsequently merged through
protected gates before activation `#788` and the successful216 release claim.

That activation changed only the aggregate coordinate to `1.1.216`; all component
pins, verifier qualification inputs and retained Python worker are unchanged.
See [required release and acceptance evidence](rust-migrations/beta-acceptance-follow-up-1.1.216.md)
and [shared Rust acceptance-lineage correction](rust-migrations/acceptance-release-run-lineage.md).
The prior beta recording's token failure subsequently passed in216's unchanged
KMS scenario; broader acceptance remains open as recorded above.

Owned merged branches/worktrees for `#784`, `#785`, `#786` and the older `#775`
branch were retired only after content/merge proof; build/test caches were
preserved separately. The recorder is clean. Other-worker crypto commits on
local UI/credentials main and crypto worktrees remain preserved and need their
own handoff/review; they are not implicitly selected as release inputs.

### Historical 1.1.215 deployment and real-schema token exchange correction

`v1.1.215` is published (release run `33937499784`, release ID `383105509`)
and successfully deployed to beta at exact source
`1866528ab859ea7007ca34671ad80a62131fd79d`, finishing `02:34:56Z`. Source-bound
provenance, signatures, all assets, local/public markers and all 29 production
before/after invariants passed. An earlier attempt hit a transient local Vite
port conflict; its failed evidence remains, and no production process was changed.

Verifier governance and the first `1.1.215` soak sample passed. The actual
release-bound recording now passes the custom Keycloak theme and organization
selection, but token exchange returns HTTP 500 because the native query assumes
JSONB while the deployed transaction claims column is JSON. Merged PR `#785` fixes
the Rust query and executes the same contract against both physical types;
the recorded failure was reproduced before the fix. No live schema change or
weakened demo assertion is involved. A new immutable release and recording are
still required; the failed partial video is not acceptance evidence.

See [JSON storage parity and resolved adjacent findings](rust-migrations/issuance-json-storage-parity.md).
The adjacent Canvas storage assumptions and another roster-cursor consumer were
reproduced and corrected in separately reviewed PR `#786`, with real JSON/JSONB
contract coverage; its protected merge and review equivalence passed. Worker result-parity
PR `#784` merged at `380ffbb71edb4a42f98125b70df1ad4c94a1f293`; neither worker
result parity nor the token/Canvas storage corrections are in deployed `1.1.215`.
Full worker/consumer parity, feature-preserving branch cleanup, demos and the
governed acceptance soak remain open. The host-restart explanation resolved the
earlier coordination hold; no production deployment occurred in this lane.

### Merged lossless worker result parity

Credentials result-oracle PR `#259` merged at
`85329f647c1d8c51ad709f1eed97cedcb3bb6464` after all protected queue checks.
Its full tree matches the reviewed source; the owned worktree and branch were
removed only after proof, retaining all source/tests on main. Rust replay of
its unchanged JSON fixture reproduced 34 large-integer mismatches. The fix in
PR `#784` preserves raw JSON values through the processor/result/persistence
boundary; all 483 JSON combinations and the isolated PostgreSQL result-write
test pass. See [scope and evidence](rust-migrations/canvas-worker-result-parity.md).
Whole-worker parity and Python deletion gates remain open.

Release activation PR `#783` merged at
`1866528ab859ea7007ca34671ad80a62131fd79d`. Claim `33937440015` succeeded;
ordinary release run `33937499784` used the same immutable source and finished
successfully. Its qualified publication and beta deployment are recorded above.
The subsequently merged worker change is separate from that published release.

The user confirmed an unplanned host restart at `2026-09-05T01:32:02.5000000Z`.
The old deployment audit is retained; a separate 29-container post-restart
production baseline was stable through `02:00:54Z`. The coordination hold is
resolved. This migration lane made no production deployment/restoration and
must use fresh before/after production invariants for the next beta rollout.
The interruption does not count as a completed acceptance soak.

### Historical 1.1.215 browser correction and activation

The preceding activation selected `v1.1.215` for the beta acceptance corrections, with every
component pin unchanged. Native verifier migration automation (`#781`) and the
production UI WebAssembly policy correction (`#782`) are merged; the combined
protected source is `f20f3e0f5071fdf94078a9222b517188cdd82a82`.
That release subsequently passed publication/deployment, but not full recording
acceptance. Preserve the immutable `v1.1.214` and `v1.1.215` releases and failed
demo evidence. Every follow-up must pass the same exact-source, image, verifier
and public-stack gates. See [historical follow-up plan](rust-migrations/beta-acceptance-follow-up-1.1.215.md).

Actual `v1.1.214` browser testing passed authentication and the custom ElevenID
Keycloak theme, then failed organization selection because production CSP
blocked Rust WebAssembly startup. The fix retains Rust ownership and JavaScript
eval/inline restrictions. Its Chromium regression test covers both permitted
WASM and a negative control. A test-browser-only header diagnostic restored the
organization state, but is not qualifying release evidence. Full credential and
KMS-switching recordings must run against the newly published and deployed
artifact, without diagnostic overrides. No successful release-bound recording
or completed 7/14-day acceptance soak is claimed.

Credentials renewal oracle PR `#258` merged at
`d6b6dd67fd9674eb14388320e65d3ae9642b3b42`, preserving the previously local work
with 17 new cases and 98 combined passing tests. It observes the
real Python renewal loop, durable fences and partial heartbeat failures without
changing runtime or crypto behavior. This does not close PostgreSQL or
whole-worker parity, configuration-duration differences, readiness or
all-consumer routing gates; the Rust worker remains unrouted and reachable
Python remains intact. Owned worktrees are removed only after protected merge
and exact review-to-merge proof; other workers' changes remain preserved. The
renewal worktree and branch have now been cleaned after that proof.

Recorder PR `#38` separately merged the targeted `qs` dependency correction at
`88079b1b91bd7dc4771fde6a5e672323a57689a3`. All 163 Node tests and three
narration tests passed, and the refreshed locked installation reports zero npm
audit vulnerabilities. Recording scenarios, assertions and publication controls
are unchanged. Use the verified recorder revision when binding the next release;
do not reinterpret previous failed recordings as successful evidence.

### Successful aggregate beta cutover (supersedes preflight checkpoint below)

`v1.1.214` deployed successfully at **2026-09-05T00:37:57Z**, exact source
`24f5d5dc0bb47d3dadb118b4dbe45191c5cf71b1`. Local and public beta release
markers passed; all 29 production container invariants remained unchanged.
Dedicated pilot governance was explicitly authorized, provisioned and validated
against the running Rust verifier. A skipped native migration was rehearsed
twice on the backup copy, applied to beta, and the unchanged release redeployed.
The runner fix now makes that migration explicit in official and local modes.
See [incident and evidence](rust-migrations/beta-native-verifier-migration-incident-2026-09-05.md).

The first post-cutover event-stream/revocation-profile soak sample passed. Demo
binding remains `DEPLOYED_PENDING_EVIDENCE`; full credential/browser acceptance
and the governed 7/14-day soak windows are NOT complete. Theme checks subsequently
passed as recorded above. This checkpoint does not itself clear release gates
or authorize production promotion. Canvas worker whole-behavior parity and
all-consumer routing remain.

Credentials lifecycle oracle PR `#257` merged at
`84532fe506855417eb37b714b1c33cba83689ce8`, preserving the crypto worker's
preceding changes. Its owned clean worktree/branch and UI roadmap PR `#780`'s
owned clean worktree/branch were removed after exact merge proof. The subsequent
lease-renewal oracle work merged in PR `#258`; crypto-worker work remains
preserved, not silently deleted.

### Historical published release and beta preflight checkpoint

Both release boundaries are complete: immutable UI `v1.1.214` and the separate
static-pin integration `v1.2.80`. The latter does not change the aggregate's
original `v1.2.79` qualification lock. Keep all historical controls, binding
consumers and still-reachable Python worker features intact.

The first official beta deployment attempt on September 5 at 00:08 UTC passed
source/recorder validation, exact image pulls/labels, backup and UI migration
rehearsal on an isolated beta copy. It stopped before live migration or
application cutover: beta's environment lacks `VERIFICATION_GOVERNANCE_JSON`,
which the enabled Credentials compatibility surface requires. The current beta
verification container likewise has no such registry; copying an existing
runtime value is therefore not an available fix. The registry must bind the
intended beta client, organization, required-check policy, presentation
definition and trusted issuers. Do not disable compatibility, relax its
fail-closed guard, or install the integration-test registry as runtime authority
to make deployment pass.

The wrapper's completed production invariant passed: 29 containers before and
after, identical IDs/images/start-state digest, no changes. The three isolated
rehearsal containers were removed; beta backup evidence remains available.
At this historical checkpoint no successful beta cutover, release recording,
or acceptance soak was claimed; the successful cutover above supersedes it.
Windows PowerShell 5 also failed a read-only Docker-label argument preflight;
the unchanged release script passed those same arguments under independently
hash- and Microsoft-signature-verified portable PowerShell 7.6.5. No source
change or new UI release is needed for that host-runtime issue.

Wave three's MMF replacement and ordered Rust service plane are complete. The
follow-on 31-route Canvas management cutover merged through protected PR
`ElevenID/marty-ui#717` at `a6b375bb0ecc649f30db7053ba34e3ac64a23998`.
Bootstrap stack `v1.1.208` is published at source commit
`7c8fa31500acd8f2ec589781232c444fe81dd22e` and contains the first immutable
Rust services artifact with the merged verifier. A consumer pin to that image
merged as `ElevenID/marty-integration-tests#396` and was released as
`v1.2.76`; the standalone Python verifier deletion then merged as
`ElevenID/marty-credentials#250` and was released as issuance-only `v0.1.72`.
The final release audit found that this sequence did not respect the later
post-merge hold: readiness-supervision and canonical session-ID corrections
merged through protected PR `ElevenID/marty-ui#721` at
`b2b2953f9fe00d848761830623935773419bdf60`, after the `v1.1.208` source.

Annotated tag `v1.1.209` records the correction binder at
`7e9b7faac2bed828e21f7051aadc290224cc46f7`, but no GitHub release was
published. Annotated `v1.1.210` records aggregate commit
`4326524a1c6a265bad6f6b46945e248345af0451`; it was tagged before the explicit
eligibility interlock and its repeated release attempts were canceled. It has
no GitHub release and no services artifact. Both `v1.1.209` and `v1.1.210`
nevertheless published UI-only registry coordinates before cancellation. Their
exact digests, preparation/run evidence and containment controls are recorded
in [`the release incident record`](rust-migrations/verifier-release-incident-2026-08-31.md).
Those coordinates are quarantined and must not be retargeted or deployed.

Protected `ElevenID/marty-integration-tests#398` merged the intermediate
artifact differential at `e95bb5998818cc502ce28051b5e650efa7ac6238`.
Immutable `marty-integration-tests@v1.2.77` was published from
`5c008faa44859eb7d7528adc1ee2dba55bcca19a`; its checksums, five Sigstore
bundles and five GitHub provenance attestations were independently verified.
The source archive is
`sha256:39356e447f121f7eb9bc587d71f2d99b0ad9988601771c26631902b81448b52b`
and its SPDX SBOM is
`sha256:ff2afea7146954c51f8f7e3612443ad80853fb036f43d7e65307eaa07e56e4ac`.
It preserves Python verifier `v0.1.71` as the passing oracle and proves that
Rust `v1.1.208` fails only the expected session transaction-ID scoping gate.
It is trustworthy intermediate evidence, not authorization to deploy the
rejected Rust candidate or clear cutover.

Protected integration PRs `#400` through `#403` then closed the identified
privacy, evidence-comparison, session-identifier, migration and compatibility
gaps. PR `#404` packaged that protected tree as immutable
`marty-integration-tests@v1.2.78` at merge commit
`3baad4b5dbccc720a50ff9ae5a280349180c02a8`. This is a preliminary harness
release only: it retains `release_clearance=blocked` with
`canonical.oid4vp-positive-runtime-not-exercised`, does not pin a corrected
Rust services image, and does not select or activate a product release.

Protected integration PR `#406` repaired the frozen negative control so
generic readiness and exact native-service identity are checked separately.
PR `#407` then closed raw tar-scanner versus `tarfile` offset ambiguity for
PAX size overrides and non-data headers. PR `#408` binds the candidate pin and
archive to private snapshots before exact-subject attestation and execution.
PR `#409` carries the original bounded pin bytes through staging and digest
verification so semantic reserialization cannot hide a byte-identity change.
The exact consumer harness is now protected integration commit
`bdd3b33b9268ca4c8c3d37126e7c253ec8fce710`, including PR `#414`'s
repository-qualified containerd load verification. Protected UI PR `#746` merged the
authenticated positive OID4VP runtime contract at
`7f8c35b8dcdc10352c1cf029fe2afbf399fbf954`. The candidate lane now uses a
separate default-branch `workflow_run` consumer: it authenticates the producer
run, source ancestry, exact five-file bundle and both attestations before
executing that immutable harness. Producer run `33465702948`, attempt `1`, was
dispatched from exact protected-main commit
`2fa1ffa3b36a0c978a41377dd64ab084bc8fc204` before the consumer landed. The run
failed bundle validation with `OCI layer tar is empty` before attestation or
artifact upload. It is diagnostic evidence only, not candidate acceptance or
release evidence. UI PRs `#759` and `#760` pinned the repaired harness and
fetched its complete ancestry. Producer run `33490549237`, attempt `1`, then
built and authenticated the exact candidate at protected-main commit
`7a1e2d6f31a563b33832b46921ec3376cd124113`; trusted consumer run
`33491836719`, attempt `1`, inspected and executed it successfully. The
comparison is `matched_with_runtime_blocker`: all 19 language-neutral checks
match, the candidate-only default-disabled-route check passes, and
`canonical.oid4vp-positive-runtime-not-exercised` is the sole release blocker.

Protected integration PR `#415` then merged the immutable exact-digest release
transaction verifier at `92f03818b13335b86cc271e7d3335aa304b462de`.
Protected release PR `#416` published that protected lineage as
`marty-integration-tests@v1.2.79` from
`7d24c73c1ef7e7dfb7e5cf119c6552321e58fa71`. Its source archive is
`sha256:622e878e47a9c8239160bc2e38fe2423d6fe9843de18e6c953433ccd32a905b7`
and its SPDX SBOM is
`sha256:3606d43a02379764b804ad22e29f1426edc66d0b7248152a0c159a947ec0821f`;
both assets and their GitHub attestations were independently verified.
Protected UI PR `#762` merged the real trusted-positive OID4VP execution gate at
`339660c4418f824251edba5c0c5ff27cf27fd1ba`. It issues and verifies a
holder-bound SD-JWT with ephemeral P-256 keys, evaluates the authenticated facts
through the shared Rust policy projection, and emits only minimized ordered
PASS evidence. The binary is packaged for the release verifier but remains
unrouted as a service entry point.

Protected `ElevenID/marty-ui#727` merged the fail-closed `release_state`
decision at `569d74b10fcae9d6eadc6fceaf9f6d3eaf9b7c5b`. Tag preparation and
tag/dispatch publication share the same decision. Protected `marty-ui#763`
then merged the digest-first resumable release transaction at
`4e817b32f6d65f88c763af79e2f07df1eb8a1ce7`. Protected activation PR `#766`
made the live aggregate lock exactly `eligible`, retained `hold` in the example
lock, and pinned independently verified `marty-blog@v0.1.8`; the internal
release state remains omitted from the public manifest. Its merge commit is
`bc4d93fd58e3309be9dc0748becf3d32bbc5e9dd`. Claim run `33896525605`
durably reserved `v1.1.211` from that exact source. Release run `33896763851`
failed before checkout because the pre-checkout `gh run download` command
omitted `--repo`; it created no tag, image, GitHub release, or deployment.
Protected recovery PR `#767` repaired every workflow download and forced stable
LF stack-lock bytes at `21eacfbbf2039655c0eb46322c1f375ccc6216a5`.
Tombstone run `33899690771` terminally sealed the claim in artifact
`9947135634`; `v1.1.211` must not be reused. Protected activation PR `#768`
selected verified-absent `v1.1.212` at
`fef62e464c87d5fd585c2d1f725a07d9688344f3`; PR `#771` then pinned independently
verified UI/demo content `marty-blog@v0.1.9`. Claim `33918005955` reserved
`v1.1.212` from `3a91fde0f59e5f862c476657c77aa1d7f876b03b`. Release run
`33918094173` failed integration-source attestation before builds. Protected
PR `#776` corrected the immutable release ref at
`3a8fccdb35ea51e06a023fe67d523e0888cd3e72`, and tombstone run `33920259321`
sealed that claim in artifact `9954730289`. Protected activation PR `#777`
selected `v1.1.213` at `3bf4cc05d719161a0dc026351ca6f4f12075179a`.
Claim `33922450526` and release `33922539581` built and signed all three
images and passed public-stack integration. The verifier stopped before
comparison because its archive lacked required Git history. Protected PR
`#778` repaired that binding at `ae00413780a5a3408af476aca5dca5eb6553bb62`;
tombstone run `33926833221` sealed the digest checkpoint in artifact
`9957092310`. Local diagnostics with the unchanged released harness and exact
services digest passed 21 Rust checks and all 19 shared Python comparisons
with no blockers; these do not replace protected qualification or acceptance.
Activation PR `#779` selected `v1.1.214` with unchanged component pins.
Claim `33928810880` bound source `24f5d5dc0bb47d3dadb118b4dbe45191c5cf71b1`.
The initial run `33928890712` built and signed all three images and passed
verifier comparison, but a connection reset interrupted the previous-release
manifest download. Same-source resume `33930593794` reused those digests,
passed both qualification gates and published immutable release ID `383068679`.
All 11 release asset hashes, exact-source provenance, manifest component pins,
and the terminal published transaction were independently verified. Manifest
digest is `sha256:990c976800f85db83fd2631594e2426a523b34ed6d3b67eb3206e13eca83ab23`.
The preceding repair history is in the [harness-history incident](rust-migrations/stack-release-harness-history-incident-2026-09-04.md).
The deleted Python image remains immutable parity evidence; its separate public
binding and still-used Credentials adapter were not deleted. Production is not
in scope and its deployment configuration remains unchanged.

| Artifact | State | Meaning |
|---|---|---|
| `marty-ui@v1.1.208` | Published, verified, rejected | First Rust verifier services artifact; predates required PR `#721` corrections |
| `marty-ui@v1.1.209` | Quarantined partial publication | UI-only registry coordinate; no services/migrations image or GitHub release |
| `marty-ui@v1.1.210` | Quarantined partial publication | Pre-interlock UI-only registry coordinate; no services/migrations image or GitHub release and never deployable |
| `marty-integration-tests@v1.2.76` | Published; retained under hold | Bootstrap evidence only; grants no cutover authorization |
| `marty-integration-tests@v1.2.77` | Published and independently verified intermediate evidence | Trustworthy immutable Python baseline plus `v1.1.208` bounded negative control; not cutover clearance |
| `marty-integration-tests@v1.2.78` | Published preliminary, non-activating evidence | Packages protected PRs `#400`-`#403`; remains blocked and does not pin a corrected Rust runtime |
| `marty-integration-tests@v1.2.79` | Published and independently verified transaction harness | Supplies immutable exact-digest transaction pinning, real Rust positive-runtime invocation, and fail-closed release comparison; it does not itself prove an unpublished `marty-ui` digest |
| `marty-blog@v0.1.9` | Published, independently digest- and provenance-verified, and pinned by PR `#771` | Supplies the repaired demo/UI package plus the infrastructure-economics evidence update at exact protected-main commit `587274a4e1d4281f8fa4d71cea212141759f0435` and archive digest `sha256:1dda635bd284d9cb254e3c2c51fc09890cfae21b48a4c2095985621ad86cb358` |
| `marty-ui@v1.1.211` | Tombstoned without artifact writes | Claim run `33896525605` binds the coordinate to `bc4d93fd58e3309be9dc0748becf3d32bbc5e9dd`; release run `33896763851` failed before checkout, and tombstone run `33899690771` terminally sealed it in artifact `9947135634` |
| corrected-Rust-pinned integration release `v1.2.80` | Published and independently verified | PRs `#418` and `#419` merged; artifact workflow `33931284801` passed all three lanes, both comparisons and containerd contracts. Release `33931821255` published immutable ID `383073207`; all ten asset hashes, checksums and exact-source attestations verified |
| `marty-ui@v1.1.212` | Tombstoned without image, tag, release, or deployment writes | Claim `33918005955`; release `33918094173` stopped before builds; repair PR `#776`; terminal artifact `9954730289` from run `33920259321` |
| aggregate `marty-ui@v1.1.213` release | Tombstoned; never reusable or deployable | All image digests and public-stack evidence retained; verifier stopped before comparison; terminal artifact `9957092310` |
| aggregate `marty-ui@v1.1.214` release | Qualified, published, independently verified; not deployed | Release run `33930593794` passed with no verifier blockers; all 19 shared checks and both Rust-only checks passed. Immutable release ID `383068679`; beta, recordings and soak remain |

The 31-route language-neutral Canvas management floor is
`contracts/issuance-canvas-management.json`.

| Canvas management state | Routes | Current evidence / owner |
|---|---:|---|
| Implemented and merged in Rust | 31 | The complete frozen surface: platform lifecycle, registration/install, probes, readiness, scope/catalog, program-binding CRUD/validation/activation/deactivation, encrypted integration-secret CRUD, provider validation, application approval, evidence-event status, and the three default-disabled legacy evidence/AGS/NRPS adapters through one shared Rust ingest kernel. PR `#717` merged at `a6b375bb0` |
| Provenance-bound native beta routing merged | 31 | `ElevenID/marty-credentials#248` merged as `7f09c1e5a767f1401dff3b22adae9f8ae8cc1465`; PR `#717` binds its canonical-LF hash, declares all 31 routes native, updates Gateway routing and supplies the beta-only Canvas configuration. Production and self-host routing remain unchanged |
| Standalone synchronization worker | Fenced Rust candidate implemented; routing and Python deletion not started | `contracts/issuance-canvas-sync-worker.json` pins the complete Python worker/processor/oracle boundary. PR `#742` merged the bounded Rust candidate at `50b0985f4`; PR `#754` adds generation-fenced application/platform/candidate/cursor persistence, canonical target reload, persisted LTI trust-profile binding, explicit OAuth 429 handling, shutdown and deployed-secret parity, and target-reconfiguration race coverage. Credentials `#254`, `#260` and `#262` freeze baseline, lexical and real PostgreSQL consumer observations. This candidate adopts MMF `#101` and passes all 133 startup vectors plus 36 native SQL cycles and three two-cycle loops locally, including the previously flagged whitespace/non-finite/separator/integer-range differences. Full hosted CI and protected landing remain required. The candidate remains non-routed until all legacy oracle gaps, whole-worker differential, database rollback, readiness, consumer-routing and beta-soak deletion gates pass |

Thus, all 31 routes and their beta routing are merged but not yet deployed.
The final post-rebase maintainer and protected-queue gates passed 220 Rust
issuance library tests and every
issuance integration/executable target; 99 Gateway library tests and three
executable tests; strict all-target Clippy and formatting; 116 Python service
tests; 472 repository release, ownership, security and packaging tests; the
three-case issuance cutover/provenance gate; all nine Canvas issuance contracts
against fresh disposable PostgreSQL; and an actual beta Compose render with
synthetic immutable artifact pins. The unchanged 27-case Python Canvas
Credentials adapter oracle had already passed before rebase. Review also made
all nine PostgreSQL contracts mandatory in CI and removed four avoidable
production invariant panics. These counts are merged pre-deployment evidence,
not live beta acceptance; merged coverage is bound to PR `#717`.

### Remaining work in the active wave

1. Protected `marty-ui#763` landed the digest-first, resumable release
   transaction with exact-coordinate preflight, immutable checkpoints, conflict
   tombstones, and cancellation-point tests at
   `4e817b32f6d65f88c763af79e2f07df1eb8a1ce7`. PR `#737`
   introduced the candidate producer; its first dispatch occurred only after
   the later hardening described below.
   PR `#741` hardened the producer but retained raw tar-header offset defects.
   PR `#744` corrected those specific defects. Producer run `33465702948`,
   attempt `1`, was dispatched from exact protected-main commit
   `2fa1ffa3b36a0c978a41377dd64ab084bc8fc204` before the trusted consumer
   landed. It failed bundle validation with `OCI layer tar is empty` before
   attestation or artifact upload, so it supplies no admissible candidate-gate
   acceptance. The repaired lane subsequently passed from protected-main commit
   `7a1e2d6f31a563b33832b46921ec3376cd124113`: producer run `33490549237`,
   attempt `1`, and authenticated consumer run `33491836719`, attempt `1`,
   both succeeded. Protected
   `ElevenID/marty-integration-tests#406` through `#409` completed the public
   runtime, archive-boundary, private-snapshot and byte-identity harness at
   exact commit `bdd3b33b9268ca4c8c3d37126e7c253ec8fce710`. Protected UI PR `#746` completed
   the authenticated positive OID4VP runtime capability at
   `7f8c35b8dcdc10352c1cf029fe2afbf399fbf954`. The separate trusted consumer is
   pinned to that harness and still requires `release_clearance=blocked`; it
   cannot publish, release or deploy. Its historical result is
   `matched_with_runtime_blocker`: all 19 language-neutral checks matched, the
   Rust-only default-disabled-route check passed, and the sole blocker is
   `canonical.oid4vp-positive-runtime-not-exercised`. The detailed requirements
   and immutable incident evidence are in
   [`verifier-release-incident-2026-08-31.md`](rust-migrations/verifier-release-incident-2026-08-31.md).
   Public integration release `v1.2.79` packages the immutable transaction
   verifier, and protected UI PR `#762` merged the real trusted-positive OID4VP
   Rust gate at `339660c4418f824251edba5c0c5ff27cf27fd1ba`. Those changes close
   the missing-capability gap; they do not yet clear an exact services digest.
   Protected recovery PR `#767` bound every workflow artifact download to its
   explicit repository and stabilized stack-lock bytes; tombstone run
   `33899690771` then sealed the claimed `v1.1.211` transaction. Protected
   activation PR `#768` selected verified-absent `v1.1.212` at
   `fef62e464c87d5fd585c2d1f725a07d9688344f3`; PR `#771` merged the reviewed
   `marty-blog@v0.1.9` pin. The `v1.1.212` release failed before builds;
   PR `#776` repaired its attestation-ref check and run `33920259321` sealed
   the claim. The next `v1.1.213` attempt built all images but failed the harness
   Git-history guard before comparison. PR `#778` repaired that boundary and
   run `33926833221` tombstoned the digest checkpoint. This release step is now
   complete for `v1.1.214`: resume `33930593794` passed every qualification gate
   against the exact original content-addressed images before promotion and
   publication. The annotated tag binds source, claim and transaction; image
   and SBOM attestations correctly retain their original protected-main ref.
   Independent published-artifact verification passed. Do not rebuild this
   immutable coordinate or substitute changed source.
2. Execute public `marty-integration-tests@v1.2.79` against that exact corrected
   services image and SBOM inside the release transaction. Replace the bounded
   `v1.1.208` expected failure with a fully passing Rust candidate and run every
   oracle/candidate group before promotion. After the immutable product digest
   exists, retain its static pin in a new protected integration release.
   `v1.2.76` remains held
   evidence only; intermediate `v1.2.77` and preliminary, non-activating
   `v1.2.78` likewise provide evidence, not cutover authorization. Protected
   `ElevenID/marty-integration-tests#400` already
   merged the post-`v1.2.77` strengthening at
   `a2ab449d2bbaa8c42734de1a6890c5f2d9868a2b`: deterministic Ed25519 fixtures,
   canonical input-digest and verification-method assertions, malformed-input
   ordering, and a bounded retry scoped only to the known negative control.
   Protected follow-up `#401` merged at
   `bd3abf0792bad5c61faa2ff3b0f56fb4df0807d7`, adding exact VDS-NC outcome/code
   projections and mutation-tested response/database privacy minimization for
   decoded claims, malformed terminal rows, expired sessions and worker lease
   fields. Protected `#402` then merged at
   `cfdbebb4def784794aee9f0671e742c90cedffad`, removing generic
   canonical-omission retries and allowing bounded pre-submission resampling
   only for exact frozen artifacts whose generated session identifiers violate
   the downstream grammar. Future Rust artifacts remain fail-closed with no
   allowance. Base the corrected repin on that protected-main tree rather than
   reapplying any superseded local commit. PR `#404` published those merged
   harness corrections as `v1.2.78`; protected PRs `#415` and `#416` then
   published the transaction-capable `v1.2.79` harness. That released harness
   now passed the exact corrected digest in protected UI release qualification.
   Integration PR `#418` additionally merged a third, published-Rust subject
   without replacing the immutable Python oracle or rejected Rust control.
   All three artifact lanes and both comparisons passed. Integration `v1.2.80`
   then published in run `33931821255`; its exact source archive contains that
   reviewed pin and all asset hashes, checksums and provenance verify. This
   artifact-release step is complete; beta acceptance remains separate.
3. Treat the already-merged standalone Python verifier deletion as provisional
   until step 2 passes. Preserve the immutable legacy image as the differential
   oracle and fix Rust if any corrected-artifact comparison fails. Continue to
   preserve the separate
   `python/marty_credentials/adapters/services/verification_service.py` adapter
   and public Python binding; neither belongs to the deleted standalone image.
4. The published and independently verified `marty-ui@v1.1.214` aggregate binds public
   `marty-integration-tests@v1.2.79` and issuance-only
   `marty-credentials@v0.1.72` and retains the independently verified
   UI/demo content pin `marty-blog@v0.1.9`. Stack, provenance and upgrade/rollback
   qualification passed. Keep that immutable component set unchanged; the new
   static integration release is follow-up regression evidence, not a reason
   to rebuild or repin the already-qualified aggregate.
5. Perform exactly one official beta-only deployment of that aggregate, record
   the release demos (including the ElevenID Keycloak theme), run acceptance
   checks and complete the governed soak. Production and persistent self-host
   deployments remain unchanged.
6. Keep the Python webhook handlers as the production and self-host parity
   oracle during this beta-only canary: those consumers
   still route to the Python issuance image, so deleting the handlers now would
   fail the no-feature-loss gate. Delete them immediately only after every
   deployed profile routes the operations to Rust. The standalone
   `canvas-sync-worker` and its
   `process_authoritative_canvas_sync_target` processor remain the deployed
   Python implementation in this wave. Rust now has an unrouted native
   worker/processor candidate covering Canvas API polling, leases, retries,
   heartbeats and reconciliation, including generation-fenced side effects;
   implementation coverage alone is not deletion evidence. Their
   language-neutral whole-worker contract is frozen in
   `contracts/issuance-canvas-sync-worker.json`; implementation remains gated
   on closing the enumerated Python oracle gaps, whole-worker mutation/failure
   differential parity, fresh-PostgreSQL migration/rollback and race evidence,
   readiness parity, every deployment-consumer change and the beta-only soak.
   Continue extending the existing Rust Canvas OAuth, PostgreSQL OAuth,
   integration-secret and readiness owners rather than duplicating them.
7. The Canvas, mdoc, Canvas Credentials, base verifier implementation and
   verifier contract worktrees have been tree-equivalence checked and removed
   after their protected merges. Integration cleanup is also complete: the
   v1.2.77 release worktree, detached PR `#398` audit, smaller scoped session
   regression, pre-merge differential branches and PR `#400`/`#401` review
   worktrees were removed only after proving protected-main or
   immutable-release tree equivalence. A generated, untracked integration
   `uv.lock` that was absent from both reviewed PRs was deleted as non-release
   resolver output. Retain the owned verifier release-binder stream and
   Credentials deletion evidence until the corrected release/pin gates
   complete. Finish with a read-only branch/worktree audit, retain only release
   evidence still required for the final aggregate, and preserve unrelated
   user-owned files such as the untracked `marty-credentials/uv.lock`. The
   authorized UI/MMF history rewrite, old-tag retirement, and protection
   restoration are complete; no additional destructive history operation is
   planned.

### Next execution target

The three ingest endpoints now share one DRY Rust event-ingest kernel for
signature verification, canonical event mapping, replay protection, evidence
persistence and application-policy transitions, with three thin HTTP adapters.
The next Canvas boundary is therefore not another route port. The digest-first
resumable release transaction is protected in `marty-ui#763`, recovery PR
`#767` repaired its pre-checkout download boundary, and activation PR `#768`
selected verified-absent `v1.1.212`. That transaction failed before builds;
PR `#776` repaired the attestation-ref check and run `33920259321` tombstoned
the claim. The reviewed `marty-blog@v0.1.9` pin is merged. The next
`v1.1.213` attempt built all images but failed the harness history guard;
PR `#778` repaired that boundary and run `33926833221` tombstoned the digest
checkpoint. The corrected `v1.1.214` aggregate has now passed protected
qualification, publication and independent verification, and its static pin
is merged in integration PR `#418` and published in verified `v1.2.80`.
The immediate critical path is the single aggregate beta-only canary,
recordings and acceptance soak. Every corrected-artifact oracle/candidate
group passed; this proves artifact parity, not deployed beta acceptance or
the separate all-consumer deletion gates.
Do not duplicate either the Canvas ingest kernel or verifier decisions while
wiring consumers, and keep differential tests against preserved Python oracles
until each distinct all-consumer deletion gate passes.

The eventual deletion boundary is route-level, not file-level, until the whole
issuance service is native. Python's large `canvas_routes.py` module also owns
the deployed standalone synchronization processor loaded through
`CANVAS_SYNC_PROCESSOR`; deleting that module during the webhook canary would
remove production capability. Keep the three handlers for non-beta consumers,
and keep the worker plus all helpers reachable from it, until their respective
consumer and whole-worker gates prove behavioral and persistence parity. This
is an explicit delayed deletion gate, not permission for a permanent fallback.

The Canvas whole-worker contract freeze and unrouted Rust implementation are
already merged; do not start duplicate ports. The next independent migration
work is closing the legacy oracle gaps and reconciling shared fixtures with
that candidate. Credentials PR `#254` freezes actual-Python configuration
observations, with 44 combined new/existing worker tests passing. PR `#255`
merged the actual processor-loader oracle at
`d035a31790c4895431585a44804639a90dbdad94`, with 71 combined tests passing.
PR `#257` merged ten actual loop/disposal/cancellation observations at
`84532fe506855417eb37b714b1c33cba83689ce8`. Subsequent `#260` and `#262` add
lexical and real SQL range/loop observations. The current Rust candidate passes
their numeric/identity factory and consumer replay locally using shared MMF
`#101`; full hosted landing remains required. Loader/disposal/active-job and
whole-worker lifecycle parity are still open. Coordinate ownership with
the crypto worker before touching shared Credentials files. Python deletion
remains gated on whole-worker differential, failure, persistence, readiness,
every-consumer routing and beta-soak evidence.

### Verification-image consolidation release and deletion gate

The separately published Python verification image has been implemented in the
canonical Rust verification service and its implementation worktrees have been
cleaned after protected merge. This is distinct from the already completed
wave-three verification service cutover: it preserves and absorbs the extra
seven-operation Credentials image compatibility surface instead of deleting it
or creating a second Rust verifier.

The Rust implementation is merged. The Credentials source-surface,
governance and migration-dispatch work merged through protected PR
`ElevenID/marty-credentials#249` at `f802d45a0eea6d3b36cf423fd722f30c967b03ad`;
its 124-test Python parity-oracle suite and 40 focused contract/migration tests
pass. The 38-slice UI implementation merged through protected PR
`ElevenID/marty-ui#718` at `1f6c65cf398f222997d01f07411961971ec62915`,
covering governed startup, typed compatibility DTOs and HTTP behavior, durable
PostgreSQL session state, migration ownership, canonical decisions, native use
cases, runtime activation, beta-only packaging, bounded readiness, secret
redaction and removal of avoidable invariant panics.

Strict Rust formatting and Clippy pass; 66 library, six service-behavior, five
session-behavior and the real-PostgreSQL atomic repository tests pass; the
fresh native image ran the released migration twice to Alembic head
`202608091200` and started both ordinary and
compatibility-enabled runtimes healthy. Beta Compose renders the migration and
runtime from one immutable image. Production, self-host-production and
Kubernetes-production manifests have no changes. Differential fixtures define
the same ten-gate artifact matrix for both image contracts. The dual-target
consumer
harness merged through `ElevenID/marty-integration-tests#394` at
`32861513dc4c74b3232975e4e5e6a396a452ab1a` and was published in immutable
integration release `v1.2.75` from
`60b58b0812b92319ab67129dca22cae733d916d4`. Bootstrap release `v1.1.208`
published the first Rust services artifact, but it is not cutover-eligible. Its
governed annotated tag was prepared with evidence SHA-256
`c679572cb42a9ff091a3aba8af49e795b7082df7f72e8a7d514eb85912d49bc3` and pushed
only after temporarily authorized tag-rule bypass was restored to no bypass.
Protected PR `ElevenID/marty-ui#721` merged the database-monitor supervision,
scoped canonical session identifiers, and a same-image CI smoke that proves
two migrations, readiness, governed creation, canonical fail-closed
submission, terminal persistence and nonce minimization. Its independent
implementation, contract and deployment reviews and both PR-head and
merge-group protected gates are clean.
The release workflow runs its same-image smoke against the exact pushed shared
services digest through `/app/services/entrypoint.sh` before signing, so its
dispatcher and migration override cannot diverge from the dedicated image.

A release-order audit found that `marty-integration-tests#396` and immutable
`v1.2.76` pinned bootstrap `marty-ui@v1.1.208`; that release is retained under
the held lock as evidence only and grants no cutover authorization.
`marty-credentials#250` then deleted the standalone Python verifier before a
post-`#721` artifact existed. That sequence is rejected as cutover evidence
even though its checks passed for the artifact it named. The corrected code is
merged and no beta or production deployment occurred. Pre-interlock
`v1.1.210` is quarantined because its canceled attempts never produced a
complete stack release. Intermediate differential PR
`marty-integration-tests#398` and independently verified release `v1.2.77`
preserve the Python passing oracle and expose the rejected `v1.1.208` session
scoping defect as a bounded negative control. Release `v1.2.78` packages the
protected post-release harness corrections through PR `#403` but deliberately
remains preliminary, non-activating and blocked. Release `v1.2.79` packages the
protected exact-digest transaction verifier through integration PRs `#415` and
`#416`; its source, SBOM, checksums and attestations were independently
verified. The eligibility interlock is
merged. PR `#737` introduced the candidate producer; its first dispatch occurred
only after the later hardening described below. PR `#741` hardened the producer
but retained raw tar-header offset defects. PR `#744` corrected those specific
defects. Producer run `33465702948`, attempt `1`, was dispatched from exact
protected-main commit `2fa1ffa3b36a0c978a41377dd64ab084bc8fc204`
before the trusted consumer landed. It failed bundle validation with
`OCI layer tar is empty` before attestation or artifact upload, so it supplies
no admissible candidate-gate acceptance. The corrected protected-main lane
later passed: producer run `33490549237`, attempt `1`, and authenticated,
inspected consumer run `33491836719`, attempt `1`, succeeded at exact commit
`7a1e2d6f31a563b33832b46921ec3376cd124113`. Integration PRs
`#406` through
`#409` closed the remaining public-harness service-identity, archive-offset,
private-snapshot and pin byte-identity boundaries at
`bdd3b33b9268ca4c8c3d37126e7c253ec8fce710`;
UI PR `#746` merged
the authenticated positive OID4VP runtime contract at
`7f8c35b8dcdc10352c1cf029fe2afbf399fbf954`; UI PR `#762` then merged its real
trusted-positive Rust execution gate at
`339660c4418f824251edba5c0c5ff27cf27fd1ba`. The producer now has a separate,
trusted default-branch consumer pinned to that harness. The candidate matched
all 19 shared checks and passed its Rust-only default-disabled-route check.
The subsequent `v1.1.214` transaction executed trusted-positive OID4VP and every
differential group against its exact content-addressed services image, passed
qualification and published in run `33930593794`. Integration PR `#418` now
retains the verified published static pin and passed fresh artifact regression.
Integration `v1.2.80` is now published and independently verified. Deploy that
single qualified aggregate to beta for recordings and acceptance; production
remains unchanged.

### Verification consolidation guardrails

The separately published Python verification image in `marty-credentials` was
retired by the coordinated verifier release-binder stream and
`rust-verification/delete-python-verifier-v1` Credentials deletion gate. Its
reviewed implementation and source deletion have merged. The corrected
immutable Rust artifact gate now passes; final acceptance still requires the
beta-only deployment, recordings and soak above.
Other workers must not start a second verifier port or duplicate verification
decisions in a new crate.

The workstream first freezes implementation-independent HTTP, configuration,
governance, persistence, migration, concurrency, failure and release contracts
from the Python service. It then reconciles those contracts with the existing
canonical `marty-ui/rust/services/verification` binary and the reusable
`marty-core` verification kernels. Shared policy, protocol, cryptographic,
canonical-result and evidence-validation behavior remains at the lowest
reusable Rust layer; the service crate owns only domain use cases, transport
adaptation, repositories and provider composition. Generic lifecycle,
configuration, authorization-context, migration, resilience and observability
behavior must come from MMF rather than being copied into the service.

No Python route, supported purpose, governed trust decision, processing state,
storage guarantee, migration path, deployment mode or public error may be
removed merely because it is difficult to port. The Python runtime and image
remain the parity oracle until positive, negative, malformed-input, tenancy,
authorization, replay, idempotency, concurrency, dependency-failure,
secret-redaction, migration and packaging gates pass against the Rust service.
Deletion is mandatory only after those gates prove that the canonical Rust
service preserves the intended contract and every consumer has moved. Each
focused commit receives a maintainer-style self-review followed by an
independent reviewer pass; findings are fixed and re-reviewed until no issues
remain. The resulting image cutover joins a reviewed aggregate beta release;
production remains unchanged without separate approval.

## Wave three — Rust service plane and complete MMF replacement

Wave three replaces the remaining deployed Python service plane with Rust and
replaces the Python Marty Microservices Framework with a complete, reusable,
DRY Rust platform. Removing MMF must not remove either currently consumed or
intended framework features. The authoritative feature inventory and crate
architecture live in `marty-microservices-framework` at
`docs/RUST_PLATFORM_MIGRATION_ROADMAP.md`.

The MMF work is a replacement, not a retirement shortcut. Its Rust workspace
must preserve REST/gRPC/hybrid runtime behavior; configuration and secret
providers; SQL, MongoDB and Redis infrastructure; migrations; Kafka, outbox,
DLQ and replay; workflows, saga, CQRS and event sourcing; security and identity;
observability; resilience; discovery, gateway and service mesh; plugins; push;
ML; documentation and contract tooling; deployment support; built-in services;
testing; and the developer CLI.

### DRY ownership rule

Generic service behavior lives once in feature-oriented MMF crates and is
consumed by every Rust service. `marty-ui` service binaries may contain only
their domain routes, use cases, repositories and provider adapters. They may
not copy service lifecycle, health/readiness, configuration, secret loading,
migrations, event envelopes, outbox, retry/circuit-breaker, telemetry,
authorization-context, discovery or error-normalization implementations.
`marty-core` remains the sole owner of protocol, policy, verification and
cryptographic kernels.

### Ordered `marty-ui` ports

Work proceeds in descending removable Python size after the MMF foundation is
available. Completed services retain their historical production-source
estimates. Services are remeasured from all tracked Python below the
service boundary, including implementation-specific tests and migrations that
will be replaced by language-neutral contracts and Rust-owned schema history;
generated protobufs and caches remain excluded.

| Order | Service | Approximate removable Python | Required preservation |
|---|---|---:|---|
| 1 | Gateway (cut over) | 16,962 | Complete: every public/internal route, proxy behavior, auth context, tenancy, signing/KMS orchestration, provider routing, limits, errors and observability now execute in Rust |
| 2 | Flow | 9,154 | OID4VCI/OID4VP/SIOP/mDoc/DIDComm transaction orchestration, persistence, callbacks, outbox, idempotency and expiry |
| 3 | Organization | 7,952 | Organization, membership, RBAC, SCIM, invitations, tenant boundaries, events and storage |
| 4 | Auth | 6,498 | OIDC, Keycloak administration, provisioning, sessions, claims, tenancy, errors and audit behavior |
| 5 | Credential template | 13,418 | CRUD/versioning, issuance context, wallet registry and routing, delivery destinations, validation, seeds and storage |
| 6 | Presentation policy | 11,631 | CRUD/versioning, trust resolution, credential-format dispatch, status lookup, native evaluation adaptation and exact decision responses |
| 7 | Trust profile | 8,618 | CRUD/versioning, registry synchronization orchestration, trust material, scheduling, storage and authorization |
| 8 | Applicant | 5,652 deleted | Applicant/application state transitions, vetting, evidence, biometrics, reviewer locks, issuance orchestration and storage |
| 9 | Device registration | 3,220 at cutover | Registration lifecycle, atomic challenge consumption, versioned key rotation, preferences, organization checks, legacy adoption and storage |
| 10 | Verification | 3,529 deleted | Complete: session APIs, OID4VP/SIOPv2 construction, provider/service integration, Redis coordination, HTTP/gRPC compatibility and canonical results now execute in Rust |
| 11 | Deployment profile | 3,010 deleted | Complete: all 14 profile/lane operations, complete runtime configuration, one-time API keys, tenant authorization, atomic device assignment, PostgreSQL migration/seed ownership and Gateway contract consolidation now execute in Rust |
| 12 | Compliance profile | 1,194 deleted | Complete: all eight profile operations, complete policy metadata, four-profile system catalog, exact tenant authorization, durable PostgreSQL ownership and native deployment now execute in Rust |

### Gateway port status

The gateway's 434 method/path declarations and eight-middleware execution
order are frozen in `contracts/gateway-routes.json`. The Rust gateway now
builds one MMF route table, classifies public and gateway-owned boundaries,
uses the canonical MMF reverse proxy, and has provider adapters for static
service discovery and bounded Reqwest transport. Gateway-specific tenant
authorization is separated from the reusable Cedar engine: route permissions,
resource-owner lookups, authorization skips, and published API-key scope
compatibility execute `contracts/gateway-authorization-behavior.json`, while
schema validation and policy evaluation remain solely in `mmf-security`.

Generic protocol-version, content-type, ETag, and idempotency behavior now
lives once in `mmf-platform`; rate limiting remains in `mmf-security`. Marty
policy values, auth-provider ports, exact rate-key behavior, and normalized MIP
errors are covered by `contracts/gateway-middleware-behavior.json`. A bounded,
timeout-aware gRPC adapter now validates sessions, API keys, and exact tenant
memberships without exposing backend details; malformed successful responses
fail closed. The Axum library runtime now composes the frozen MIP, distributed
rate-limit, authentication, content-type, ETag, tenant authorization,
distributed idempotency, and credentialed-CORS stages in their exact legacy
execution order. Organization resolution preserves path, resource-owner,
query, JSON body, and authenticated-state precedence; membership/API-key
decisions inject only trusted downstream identity. The language-neutral
`contracts/gateway-runtime-authorization.json` and black-box Axum tests cover
that boundary, including provider failures and observable middleware order.

The Rust binary is now executable. Fail-closed environment and `_FILE` secret
configuration, production Redis enforcement, static discovery, bounded HTTP
resource-owner lookup, authenticated gRPC identity/membership channels,
optional gRPC CA validation, graceful shutdown, readiness checks and release
identity are composed at startup. The real binary starts and serves health in
an executable smoke test. `/ready` and `/health/ready`, which the original AST
extractor missed because FastAPI registered them dynamically, are now explicit
members of the language-neutral route contract. The shared service image
dispatches `gateway` directly to `marty-gateway`, and the dedicated CI image
has a non-Python Gateway target plus an executable health smoke test.
Publication still requires the temporary MMF worktree paths to be replaced by
the landed immutable MMF revision.

The complete 688-test Python gateway suite passed as the final baseline before
deletion. Post-deletion, the Rust gateway's 80 unit and black-box tests plus
three executable health/fail-closed tests and strict Clippy are green. The post-executable
adapter audit is now closed: service-credential injection, route-bound tenant
projection, request DTO canonicalization, response privacy projection,
dependency preflight, organization composition, Hosted Pilot purge
orchestration and scheduling, and the tenant-filtered gRPC-to-SSE bridge all
execute in Rust under shared behavioral contracts. The superseded Python
runtime and implementation-specific suite have been deleted, and production
has no Python fallback. No deployment has occurred, and beta will not be
updated until all wave-three slices land.

The proxy trust-boundary slice now has executable parity for issuance service
credentials and public Canvas exceptions, trusted identity forwarding,
resource-owner lookup credentials, special service ownership, applicant
evidence rewrites, retired state-addressed Canvas HTTP 410 responses, and
organization query projection. `contracts/gateway-proxy-trust-boundary.json`
runs against Python and Rust. The shared MMF proxy now exposes a distinct
trusted-query override channel at local MMF commit `c3a378e`; unlike ordinary
query defaults, these post-authorization values replace forged client tenant
selectors. Rust black-box tests verify the replacement at the upstream request
boundary. Body-scoped request canonicalization is complete in the DTO slice.

The first privacy projection and request-canonicalization kernels are also
active in Rust. Python and Rust
execute `contracts/gateway-issuance-response-projection.json` for issuance
initiation, transaction lists, transaction records, issued-credential records,
lifecycle mutations and renewal offers. Lifecycle revoke, suspend and reinstate
requests are canonicalized in Rust and reject undeclared custody or provider
state. The Rust gateway removes redemption, custody and delivery-routing
state, restores public defaults, validates status enums, rewrites management
reads to the canonical transaction paths, and fails malformed successful
upstream payloads with HTTP 502. Issuance creation now executes in Rust under
`contracts/gateway-issuance-create-behavior.json`: strict public request
validation rejects custody selectors and private wallet keys, template
ownership and issuer-DID consistency are enforced, signing identity resolution
fails closed, optional public wallet-client registration is preserved, and
only the canonical DID plus public issuance fields reach the issuance service.
Authenticated DIDComm delivery now also has explicit Rust request and response
ownership under `contracts/gateway-didcomm-delivery-behavior.json`. Rust rejects
unknown resolver/provider selectors, binds the request organization to the
authenticated session rather than a query/body projection, injects only the
issuance service credential, and strips provider delivery receipts from exact
public responses. The same fixture executes against the Python parity oracle
and Rust, including malformed and cross-tenant failures.
Organization create/update canonicalization and public response validation now
execute in Rust under `contracts/gateway-organization-behavior.json`. The
adapter preserves create defaults and partial-update semantics, strips the
body tenant selector in favor of the authorized path scope, rejects legacy
no-op/private request fields, validates nested public membership projections,
omits null public optionals exactly as Python does, and returns a normalized
HTTP 502 when the organization service adds any undeclared/private field.
Credential-template claim translation and public privacy projection now run in
Rust under `contracts/gateway-credential-template-behavior.json`. Public claim
display, derived-claim and mdoc namespace fields are translated to the one
canonical service representation; responses reverse that mapping while
removing derivability hints, validation constraints, custody selectors and
unknown internal metadata. Draft updates and creation execute through this
kernel. Creation now preserves the Python model defaults and format-specific
identity validation, verifies optional trust-profile existence, verifies
compliance-profile existence and tenant ownership, and resolves the issuer DID
through the canonical signing service before forwarding the canonical internal
request. Rust rejects cross-tenant or malformed dependencies and private JWK
material fail closed. One language-neutral fixture now exercises the create
request, claim translation, and privacy-safe response in both implementations.

Issuer-entity and trust-profile issuer-relationship request and response
contracts now execute in Rust under
`contracts/gateway-trust-behavior.json`. The Rust adapter preserves create
defaults, partial-update semantics, case-insensitive accreditation uniqueness,
relationship policy defaults and exact protocol UUID shapes. It recursively
rejects custody selectors and private JWK parameters from public metadata and
strictly projects successful single and list responses, omitting only declared
null optionals and failing closed on service drift. The same Rust kernel now
owns trust-profile create/update defaults, nested validation rules, revocation
and time policies, credential-free standard-port HTTPS registry-source checks,
and exact profile and registry-sync response projections. The Axum path and
shared Python/Rust fixture exercise these policies end to end.

OID4VP verification-flow start now executes as a composed Rust operation under
`contracts/gateway-verification-flow-behavior.json`. Rust validates and
canonicalizes response type, transport, request-URI method, HAIP constraints,
expiry, verifier DID and tenant scope; resolves presentation-policy and optional
trust-profile ownership through the resource-owner provider; and forwards only
the canonical request. The response is reduced to the exact public verification
request resource, so flow-definition and signing selectors cannot escape.

Presentation-policy create and update now execute as composed Rust operations
under `contracts/gateway-presentation-policy-behavior.json`. The Rust kernel
validates every nested requirement, requested claim, predicate, alternative,
holder-binding proof, issuer/freshness constraint and ranking policy; accepts
proof-only policies without weakening the obligation rule; and rejects private
or undeclared selectors. Every referenced credential template is loaded in the
authenticated tenant, and its canonical payload format replaces caller input
before forwarding. Successful create/update/get/list/activate responses are
allowlisted, validated and normalized, with disabled holder binding reduced to
the exact public `{required:false}` shape.

Deployment-profile and lane adapters now execute in Rust under
`contracts/gateway-deployment-behavior.json`. Profile creation preserves the
public defaults and biometric compatibility alias, requires a trust profile and
at least one effective presentation policy, verifies policy/template ownership,
and forwards only canonical fields. Profile and lane responses restore public
defaults, remove API keys/device secrets/internal runtime state, and fail closed
on malformed service output. The shared fixture runs against both language
implementations and the Axum test exercises preflight and projection end to end.

Flow-definition and flow-instance request and response kernels now execute in
Rust under `contracts/gateway-flow-behavior.json`. Definition writes preserve
all built-in flow types, approval modes, hooks, triggers and custom extension
steps/transitions; preflight every credential, application, presentation,
delivery and trust dependency; and forward canonical defaults. Instance starts
recursively reject tokens, KMS selectors, private keys and signing state from
initial context. Definition, instance and verification-result reads strip
internal execution fields and fail closed if private service state appears in
context, step results, metadata or history. Verification results now deeply
validate and project every credential and claim result, preserve all public
trust/freshness/signature/revocation fields and defaults, and strip nested
provider state under the same language-neutral fixture.

Organization cross-service composition now executes in Rust under
`contracts/gateway-organization-composition-behavior.json`. The gateway derives
runtime issuance/verification readiness from live credential-template, policy,
deployment and flow artifacts; counts applicant lifecycle states; renders
configured integration quick-start metadata; and composes organization
lifecycle data with issuance retention summaries. Manual Hosted Pilot purge is
a bounded transaction that validates retention enablement, forwards the exact
retention window, privacy-projects the purge result and best-effort persists the
last-purge timestamp only after successful deletion. The Rust executable also
runs the paginated due-only automatic sweep with the legacy enabled/interval/
batch configuration and cancels it during shutdown. Shared Python/Rust vectors,
Axum route tests and a complete scheduled-sweep transaction test pass.

Tenant-filtered event delivery now executes in Rust under
`contracts/gateway-sse-behavior.json`. The gateway subscribes to the canonical
event-stream gRPC service, binds organization and optional user filters to the
authenticated session, rejects forged cross-tenant selectors and unsafe event
types, drops cross-tenant backend events, and emits the exact connected, event
and public failure SSE frames. The response uses bounded buffering and cancels
and drops the live backend stream when the HTTP client disconnects. Streaming
responses bypass ETag body buffering so an unbounded SSE body cannot deadlock
the middleware chain. Shared Python/Rust vectors, backend-failure tests and a
live disconnect/drop test pass.

### Flow port status

The Flow migration inventory is frozen before implementation. The removable
surface is 9,154 lines of production Python excluding tests, migrations and the
migration runner. It contains 28 explicit HTTP operations, 16 gRPC operations,
12 built-in flow types, custom extension graphs, PostgreSQL persistence,
atomic nonce consumption and terminal-result finalization, application-event
idempotency, leased callback delivery, expiry, and protocol-provider calls.
The port must preserve all of these behaviors; the Python package remains the
parity oracle until the complete executable and persistence gates pass.

Protocol ownership is already consolidated: the pinned `marty-core` revision
owns lifecycle transitions, graph validation and next-step selection, OID4VP
request construction/evaluation, mDoc handover binding, HAIP response-key and
JWE operations, verifier DID/X.509 identity, and SIOPv2 token verification.
The Rust Flow binary will call those crates directly and will not reproduce
their decisions. Generic durable workflow, messaging, retry and callback
delivery behavior belongs to MMF. The MMF messaging crate now has
language-neutral fenced-lease behavior at local commit `05d858a`, including
expired-lease recovery, stale-worker rejection, retry/dead-letter transitions,
and bounded-retention payload scrubbing. This framework primitive will be
shared by Flow and later service ports. MMF Push also owns tenant-bound callback
destination templates at `a1806b9` and the canonical header-and-payload-bound
event HMAC at `6d4462f`, eliminating two more Flow-only Python utilities.
Its registry now exposes its configured/empty state at local commit `d6743be`,
allowing Flow to require at least one valid deployed destination without
copying MMF's private registration representation or matching rules.

The first `marty-flow` crate slice now executes the checked-in
`contracts/flow-service-behavior.json`. Twelve Rust tests freeze all 28 HTTP and
16 gRPC operations, every built-in type/reference/sequence, public status and
private-context behavior, callback defaults, and atomicity obligations. The
corrected HTTP inventory counts the separately released GET and POST Request
Object retrieval operations that the first frozen catalog omitted; retaining
both methods preserves the live wallet and Digital Credentials API surface.
The domain delegates transitions and graph validation directly to
`marty-verification`; callback retries use `mmf-workflow`, delivery composition
uses `mmf-push`, and fenced storage uses `mmf-messaging`. Its repository tests
prove concurrent finalization commits one nonce/result/callback exactly once,
terminal decisions are immutable, application event plans are replay-safe and
payload-conflict-safe, and issuance artifacts are transaction-idempotent.

The PostgreSQL repository now implements the same fenced finalization and
callback lifecycle over the released `flow_service` tables. It uses database
clock time and one SQLx transaction for expired-nonce cleanup, nonce insertion,
live-state compare-and-swap, terminal result persistence and callback enqueue.
Callback claims use `FOR UPDATE SKIP LOCKED` and per-attempt UUID leases;
completion, retry and dead-letter updates reject stale workers and successful
delivery scrubs the destination and payload. The Rust-service CI job now
provisions the isolated `marty_atomic_test` database. Its behavioral test runs
the concurrent-winner, expiry rollback, retry/reclaim, stale-lease rejection
and retention-scrubbing vectors against PostgreSQL. Compilation and all
non-container tests pass locally; the real PostgreSQL execution remains a CI
landing gate because the local Docker daemon is unavailable.

The native HTTP and gRPC application adapters are complete. The remaining Flow
gates are listener/lifecycle composition, container startup/readiness,
packaging parity and the final executable acceptance suite. Provider, DTO,
definition mutation, generic instance execution, start-side-effect, Request
Object retrieval, OID4VP and SIOPv2 submission, application-event processing,
terminal persistence and all 16 released gRPC operations now share the same
Rust records and kernels. After those executable gates pass, the Python Flow
runtime and its service dependencies are deleted immediately; this pre-v1
migration has no compatibility waiting period. No deployment occurs during
these slices; beta receives one aggregate update only after all wave-three work
lands.

The public request boundary is now also represented in Rust. Strict DTOs cover
definition create/PATCH (including unset-versus-explicit-null semantics),
custom extension graphs, hooks and triggers, instance start/advance, OID4VP and
SIOP starts/submissions, Digital Credentials API responses, and authenticated
application-approved events. Unknown fields, missing type-specific references,
private context injection, invalid graph topology, unsupported OID4VP transport
combinations, oversized fields and unsafe callback destinations fail with
normalized codes. `contracts/flow-api-behavior.json` supplies 12 accepted and
13 rejected transport-neutral vectors. Four Rust tests pass, and a Python
conformance test consumes the same vectors so the legacy boundary remains the
parity oracle until deletion. That Python test compiles locally but its runtime
execution is deferred to service CI because the available local environment is
missing `grpc_health`; CI installs the full locked service dependency set.

Provider ownership is now explicit and fail-closed. A shared tenant-membership
port and authorization decision live in `mmf-security` at local commit
`1a2bf0a`, with nine language-neutral allow/deny vectors; this removes the need
for Flow to create another membership model and gives the gateway a later DRY
consolidation target. `marty-flow` declares typed ports for all seven required
runtime capabilities: tenant membership, credential templates, presentation
policies/evaluation, issuance, signing identity, flow-key envelopes and
physical-document operations. Startup composition reports every absent port
instead of enabling a partial runtime. Signing identities and signatures are
bound to the exact organization, public DID, verification method, purpose,
credential format and algorithm; private JWK members, mismatched curves and
mismatched signer responses are rejected. The provider behavior contract now
also freezes all seven physical-document operations and exact downstream
method/path pairs. Live gRPC and bounded HTTP adapters consume these contracts;
common mTLS/channel composition and executable readiness remain in the active
provider step.

The released protobuf contracts now generate Rust clients and the future Flow
server directly at build time. Live typed gRPC adapters cover organization
membership, credential-template lookup, presentation-policy lookup/evaluation
and issuance initiation. They propagate the internal service token, bound JSON
responses to one MiB, preserve nested issuance claims through the canonical
JSON field, normalize gRPC failure classes, and reject mismatched tenant,
resource, policy/nonce, template and issuance identities. The crate compiles,
all 23 non-container behavior tests pass, and strict Clippy is clean. The HTTP
adapters now cover signing-identity resolution/signing, tenant-bound flow-key
wrap/unwrap and every physical-document lifecycle operation. They preserve
gateway path prefixes, disable redirects, bound response bodies to one MiB,
apply operation timeouts, reject malformed or incomplete responses, and accept
the generic signature field only when its declared encoding is raw IEEE P1363.
The public definition, instance, verification-result and artifact projections
now also execute in Rust against `contracts/flow-response-behavior.json`.
These DTOs preserve protocol status, resolved steps, tenant/subject metadata,
timestamps, references, hooks, trigger, verification details and artifact
lifecycle fields while recursively removing private service state. Malformed
persisted timestamps, custom extensions, context types and protocol fields fail
closed. The same golden vectors compile into the Python parity suite; all 25
Rust non-container tests pass individually and strict Clippy is clean. The
Windows host cannot link every test binary concurrently because of its PDB
limit, so the aggregate suite remains a Linux CI landing gate. Flow now
consumes the canonical `mmf-platform` channel factories for all organization,
credential-template, presentation-policy and issuance clients. Both eager
startup/readiness and lazy development composition inherit the shared bounded
plaintext, TLS and mutual-TLS policy; no Flow-local endpoint or certificate
constructor remains. The focused provider suite, all applicable Rust test
groups, and strict Clippy pass. HTTP/gRPC executable
composition is now the next Flow runtime gate. Its first prerequisite is now
frozen in `contracts/flow-startup-behavior.json` and implemented by the Rust
configuration boundary. Beta and production must explicitly configure
PostgreSQL, Redis, all nine downstream endpoint origins and all four service/webhook
credentials; every secret is at least 32 bytes, endpoint origins are
credential-free, listener addresses cannot collide, and connection/database
bounds fail closed. Local development may default only non-secret service
locations. Four behavioral tests and strict Clippy pass. The next executable
slice must connect these dependencies into MMF lifecycle/readiness and must
expand the Rust persistence records to preserve every released definition,
instance and artifact field before any application operation is advertised as
ready. That record boundary is now implemented under
`contracts/flow-persistence-behavior.json`: 28 definition fields, 20 instance
fields and 17 artifact fields round-trip losslessly, then feed the smaller
canonical protocol kernels and privacy-safe public projections through
explicit fail-closed conversion. This preserves legacy step details,
preconditions, retry/resume settings, all linked profiles, localized offers,
issuance lifecycle data and timestamps instead of narrowing storage to the
security kernel. Three behavioral tests and strict Clippy pass. The contract
also requires a dedicated `state_history` JSON column during Rust migration;
the Python object previously accumulated this history in memory but its
PostgreSQL adapter never stored it. Rust now also owns the complete install and
upgrade schema under an advisory lock, adding dedicated `state_history` and
`retry_cooldown_minutes` columns without replacing Alembic's legacy version
record. SQLx CRUD covers definition create/update/get/list/delete, immutable
terminal instance create/update/get/filtered-list, and transaction-idempotent
artifact create/update/get/list/code lookup. The existing atomic nonce,
terminal result and callback transaction now persists state history as well.
Two migration contract tests, three record tests, the PostgreSQL integration
binary (which runs the real migration/CRUD/atomicity vectors when its isolated
CI database is configured), and strict Clippy pass. Seed ownership and MMF
lifecycle/readiness are the next sub-gates before the HTTP/gRPC listeners are
enabled. The reusable lifecycle portion is now complete at local MMF commit
`06a52ac`: required components block activation unless healthy and immediately
remove live readiness when they degrade. Flow consumes that primitive under
`contracts/flow-runtime-behavior.json`, registers PostgreSQL, Redis nonce
storage, four typed gRPC dependencies, three HTTP provider adapters, callback
delivery and both application listeners as mandatory, and exposes the shared
`/health`, `/ready`, `/version` routes plus native backend/version/capability
diagnostics. Two Flow runtime tests, five MMF runtime tests and strict Clippy
pass. Dependency connection, seed ownership and HTTP/gRPC application listener
composition are now complete in the executable described below.

The startup boundary also preserves the released container contract instead
of requiring a flag-day configuration rewrite. It accepts the existing
`ORG_GRPC_TARGET`, `FLOW_SERVICE_PORT`, `FLOW_GRPC_PORT`, `ISSUANCE_API_KEY`
and AsyncPG-tagged PostgreSQL URL forms, normalizes them to the canonical Rust
types, and loads all four mandatory credentials from the existing `_FILE`
secret convention. Direct values take precedence; unreadable or empty secret
files fail startup, and configuration diagnostics redact database, Redis and
all secret values. Six startup/unit vectors and strict Clippy pass. The
checked-in base and self-host manifests now carry Flow's explicit
reference-owner endpoints; these source changes are not a deployment. Beta
remains queued for one aggregate cutover after every wave-three slice lands.

Rust migration ownership now also includes the complete built-in Flow seed
surface. `contracts/flow-seed-behavior.json` freezes the Open Badge login flow,
both legacy-member and verified-badge issuance flows, the bootstrap instance,
the Marty deployment-profile link, effective protocol types, template IDs and
structured trigger events. The seed SQL stores the post-MIP custom extension
graphs directly, inserts missing records without overwriting administrator
changes, and only touches the cross-service deployment-profile table when it
exists. The isolated PostgreSQL CI vector loads every seeded definition back
through the fail-closed Rust kernel and public projection. Three migration
contract tests and strict Clippy pass; live SQL execution remains in the
configured CI database gate.

The gRPC connection plan now preserves Flow's asymmetric released trust
boundary. Typed configuration requires complete inbound and outbound workload
certificate/key/CA groups in beta and production, rejects partial groups, and
requires an explicit deployed plaintext decision for the three legacy token-
authenticated channels. The presentation-policy channel alone upgrades its
existing target to mutual TLS with private-CA trust, while organization,
credential-template and issuance continue through the shared bounded MMF
factory under the explicit compatibility flag. No service-local endpoint,
certificate loader or channel constructor is reintroduced. Six provider tests,
five startup tests, the secret-file unit vector and strict Clippy pass.

The executable dependency connection step is now implemented under
`contracts/flow-connection-behavior.json`. Startup opens a bounded PostgreSQL
pool, runs the Rust-owned schema and seed migrations under their advisory lock,
executes a live query, canonicalizes and connects the configured Redis nonce
database, requires `PING`/`PONG`, eagerly connects all four typed gRPC clients
through the shared MMF transport factory, probes all three bounded HTTP
provider adapters and all four reference-owner services,
and rejects an incomplete provider registry. Each required component becomes
healthy only after its own probe succeeds; any database, migration, Redis,
transport, HTTP, credential or registry error aborts startup before lifecycle
activation. The language-neutral connection contract test, Redis database
selection test and strict Clippy pass. Inbound gRPC security now consumes MMF's
shared workload server-TLS and exact method-authorization primitives under
`contracts/flow-grpc-security-behavior.json`. Every RPC requires the configured
service token using constant-time comparison; sensitive verification start and
application-approved calls additionally derive identity only from the verified
client certificate URI SAN parsed by `marty-crypto`, then require the exact
Auth or Applicant SPIFFE identity. A bearer value cannot replace certificate
identity, partial server credentials fail startup, and missing versus wrong
identities map to unauthenticated versus permission-denied status. Two focused
security tests, the language-neutral contract test and strict Clippy pass. The
complete application surface is now attached in the crate; the next executable
slice must bind both listeners and activate only after both are serving.

The first executable HTTP operation slice is complete under
`contracts/flow-http-read-behavior.json`. Axum now serves the public MIP 0.5.0
capability document plus tenant-authorized definition, instance, terminal
verification-result and artifact reads directly from Rust-owned PostgreSQL
records. Pagination is bounded to 500, removed lifecycle aliases stay rejected,
nonterminal result polling returns conflict, tenant permissions are checked
through the shared MMF membership policy, and every projection recursively
removes private context. Malformed stored records and missing providers fail
closed without returning storage diagnostics. Physical-document support is now
derived from the mandatory healthy downstream provider instead of duplicating
its private configuration in Flow. Three focused handler tests, the shared
behavior-vector test and strict Clippy pass. Definition and instance mutation
are subsequently complete; verification HTTP adapters, webhook, QR and DID
routes remain before the HTTP listener can be advertised as complete.

The same HTTP surface now includes the first two complete mutation paths:
tenant-authorized draft-definition deletion and instance cancellation.
Cancellation first validates the transition through the canonical Rust state
machine, then uses one PostgreSQL statement to compare-and-set any nonterminal
instance to `cancelled`, persist its completion time and append the
`flow_cancelled` history event. Concurrent or replayed cancellation returns
conflict and cannot overwrite a terminal result. The isolated PostgreSQL
behavior suite now exercises the persisted transition and replay rejection.
The authoritative reference catalog port is now complete. Application
Templates resolve from issuance with the internal API key; delivery
destinations, trust profiles and deployment profiles resolve from their owning
services with the authenticated user identity. Exact returned IDs, bounded
responses, redirects, malformed bodies, unavailable owners and non-success
statuses all fail closed. The catalog is one mandatory readiness component and
all four owners must pass health probes before activation. Beta and production
must explicitly configure the credential-template, trust-profile and
deployment-profile origins; local development alone may use defaults.
`contracts/flow-provider-behavior.json` freezes the four method/path/auth
triples, and the focused startup, provider and HTTP-adapter suites plus strict
Clippy pass.

Definition mutation parity is now attached to that catalog. Rust serves create,
PATCH, validate, dry-run test and activate in addition to the existing reads
and draft-only delete. Standard definitions preserve all twelve protocol graph
families and released defaults; custom definitions preserve extension actions,
configuration, timeouts, transitions and entry-step identity. PATCH retains
unset-versus-null behavior, cannot move a definition between tenants, increments
the version exactly once and returns the definition to draft. Draft writes
require every reference to exist and be tenant-bound but continue to allow
inactive dependencies; validation and activation require every direct and
policy-nested dependency to be active and bind each credential template's
public issuer DID to its exact organization, format, purpose, algorithm and
public signing key. System-owned delivery destinations are the sole tenant
exception. `contracts/flow-reference-validation-behavior.json` and the expanded
HTTP contract execute these rules, including one-resolution-per-template
caching and side-effect-free dry runs. The focused definition, reference and
HTTP suites plus strict Clippy pass. The remaining HTTP surface is QR
generation, native verification adapters, verifier DID publication,
application-approved webhooks and protocol-specific verification starts.

The provider-independent instance execution kernel is also complete under
`contracts/flow-instance-execution-behavior.json`. Active-definition and exact
tenant binding, initial status/history, definition-driven expiry, protocol
context, recursive private-state rejection, canonical next-step selection,
wallet-resume transitions, terminal success/failure and step-result history now
execute in Rust. Initial history preserves the released nullable prior state,
while every subsequent transition remains a typed canonical state. Direct
starts fail closed on application-approval, unknown or malformed preconditions;
only separately supplied server-authenticated evidence can satisfy the
application-approved control. Three execution vectors, persistence and atomic
repository regressions, and strict Clippy pass.

Public instance start and advance are now composed around that kernel under
`contracts/flow-instance-side-effects-behavior.json`. OID4VCI starts use only
the typed issuance provider, bind idempotency to the Flow instance (or the
existing application-flow digest), reconstruct missing per-wallet offers with
the pinned `marty-oid4vci` implementation and the complete template wallet
configuration, persist the released MIP 0.3.1 `CredentialOffer` envelope and
preserve every artifact/context field. Deployed public origins are explicit,
origin-only HTTPS configuration and fail closed. Physical-document starts
consume rather than persist raw applicant/MRZ/data-group input, then call the
typed provider for initialization and all six subsequent lifecycle operations.
Provider operation, flow and tenant identities are checked before state is
accepted. PostgreSQL inserts each new instance and optional artifact in one
transaction; advancement compares both source status and `updated_at`, so a
concurrent stale transition cannot win. Three side-effect vectors, startup,
HTTP, persistence and PostgreSQL contract suites, plus strict Clippy pass.
Manual OID4VCI QR/offer regeneration is also native: each retry has a
flow-and-attempt-bound idempotency key and one transaction expires prior active
artifacts, inserts the replacement and updates instance offer context. The
verification route set is now native. The remaining Flow gate is the other
protocol route set and actual HTTP/gRPC listener composition; no partial
executable is activated or deployed.

OID4VP presentation-query construction is now composed in Rust before route
signing and transport work. The typed credential-template provider preserves
VCT, mDoc doctype, supported formats and claim namespace/element mappings, and
reads active wallet formats from the owning service's wallet registry rather
than copying its catalog into Flow. Exact active policy/template tenant
bindings and requirement shapes are checked before the pinned
`marty-oid4vci::presentation_request` builder produces the equivalent
Presentation Exchange and DCQL artifacts. Missing templates, malformed claims,
empty wallet format catalogs and provider failures have no fallback. The
language-neutral composition contract, two focused vectors, provider
regressions and strict Clippy pass. Request-object signing, URL-query/message
composition, submission evaluation and terminal callback persistence are now
implemented by the subsequent native verification slices below.

Standard DID-bound OID4VP and SIOPv2 Request Object construction is now native
under `contracts/flow-request-object-behavior.json`. Each fetch re-resolves the
exact organization + issuer DID + `oid4vp_request_signing` +
`oauth-authz-req+jwt` + ES256 identity, builds the canonical OAuth/OID4VP or
SIOPv2 claims, delegates only the base64url signing input to the typed signing
provider and validates the returned identity before assembling compact JWS.
Flow never receives signing private key material. The request records exact
state, audience, response URI and the released MIP `PresentationRequest`
envelope. HAIP now generates a fresh native P-256 response-encryption key per
flow, advertises only its public JWK and `direct_post.jwt`/ECDH-ES/A256GCM
metadata, and persists the private JWK only through the organization- and
flow-bound signing-service envelope provider. Re-fetch reuses the bound
envelope and never serializes the private key into Flow context. Three
request-object vectors and strict Clippy pass. The unsigned URL-query profile
now composes the same native DCQL artifact with redirect-URI client identity,
direct-post state/audience binding, canonical client metadata and the same MIP
message, then enforces the released minimum/configured maximum URI bounds. It
rejects HAIP and SIOP combinations and never invokes the signing provider.
Four request-transport vectors and strict Clippy pass. The route remains
private to the Rust crate until persistence and expiry transitions are
complete. Verification-flow start composition is now native under
`contracts/flow-verification-start-behavior.json`: every start generates a
32-byte cryptographic nonce, validates an exact active tenant policy with
nonempty requirements, resolves the exact DID-bound ES256 Request Object
identity, checks optional callbacks through the shared MMF tenant registry,
and builds request-URI, signed by-value, bounded unsigned DCQL, or SIOP
authorization requests before returning one complete persistable instance.
The deployed startup contract now requires a nonempty, well-formed
`FLOW_CALLBACK_DESTINATIONS`; missing, empty, malformed, credentialed, or
unsupported destinations fail before service activation. Two focused start
vectors, startup regressions and strict Clippy pass. The HTTP start route stays
unadvertised until request retrieval expiry/CAS behavior, DC API transport and
submission/finalization are all native, preventing a partial Rust cutover from
dropping an existing verifier profile.

The configured verifier identity matrix is now native as well. Flow accepts
the released redirect-URI, decentralized-identifier and `x509_hash` client-ID
schemes plus `did:web`, canonical `did:jwk` and canonical P-256 `did:key`
derivation. DID derivation delegates to pinned `marty-didcomm`; `x509_hash`,
leaf-key matching, certificate thumbprinting and leaf-first `x5c` shaping
delegate to `marty-verification`. X.509 Request Objects omit `kid` and carry
only the validated chain. The LISSI compatibility profile retains raw DID
client identity, `client_id_scheme=did`, Presentation Exchange rather than
DCQL, no standard client metadata and an explicit HAIP incompatibility. Strict
client metadata, branding, HAIP enablement, both request-size limits and PEM or
file-backed verifier certificates are typed startup configuration; unsupported
values, missing X.509 material, insecure deployed logo URLs and out-of-range
limits fail closed. The focused request-object suite now has five vectors, the
startup suite has six vectors, and strict Clippy passes. Route exposure is now
gated on atomic retrieval/expiry, DC API transport/origin parity and complete
submission/finalization rather than verifier identity support.

Wallet Request Object retrieval is now a native, persistence-neutral kernel
under `contracts/flow-verification-request-behavior.json`. It accepts only
`awaiting_wallet` or `in_progress` snapshots, returns an explicit expired
record carrying the `request_expired` terminal history for repository CAS,
rejects URL-query flows, enforces POST-only retrieval and a nonempty
`wallet_nonce` when configured, and re-resolves the signing identity on every
fetch. Standard and LISSI retrieval share the same profiled builder. Digital
Credentials API retrieval now emits `openid4vp-v1-signed` / `dc_api.jwt`, binds
the exact configured HTTPS origins, omits redirect/state fields, creates the
native per-flow encrypted-response key, stores only its tenant/flow-bound
envelope and advertises ECDH-ES with A128GCM/A256GCM receiver support. The
public origin is the default exact DC API origin; configured comma-separated
origins are normalized, deduplicated and rejected if they are not deployed
HTTPS origins. Three retrieval vectors, six Request Object vectors, startup
regressions and strict Clippy pass. The HTTP adapter now persists either the
ready context or expiry transition with status-and-`updated_at` CAS and returns
the released `Cache-Control: no-store` and `Pragma: no-cache` response headers.

OID4VP submission evaluation and terminal composition are now native under
`contracts/flow-verification-submission-behavior.json`. The kernel binds exact
state in constant time, validates Presentation Submission shape, unwraps the
single-token DCQL transport form, and delegates cryptographic verification
only to the typed presentation-policy provider with exact nonce, audience,
trust and verifier context. The pinned ISO 18013 implementation supplies mDoc
session-transcript binding; pinned verification code validates and decrypts
HAIP JWE responses through a tenant/flow-bound key envelope. Provider failure,
empty credential evidence or any non-valid signature is retryable and consumes
neither state nor nonce. An authenticated allow completes; an authenticated
deny fails terminally and clears claims. Raw tokens and submissions are
discarded in favor of canonical SHA-256 digests. Same-payload terminal replay
returns the stable result while a different digest conflicts. The kernel emits
the released MIP 0.3.1 VerificationResult and a tenant-registered MMF callback,
requiring a minimum 32-byte delivery secret. PostgreSQL finalization now takes
the complete `FlowInstanceRecord` and atomically preserves subject, external
reference, histories, context, result and timestamps while consuming the nonce
and enqueuing the callback; organization and definition identity are immutable
CAS fences. Six language-neutral submission vectors, including the shared
HAIP interoperability JWE, the PostgreSQL contract binary and strict all-target
Clippy pass.

SIOPv2 submission is now native under
`contracts/flow-siop-submission-behavior.json` and reuses the same terminal
finalization unit rather than creating another transaction implementation. The
pinned `marty-oid4vci` verifier exclusively owns JOSE parsing, ES256/EdDSA
policy, public `sub_jwk` signature validation and RFC 7638 thumbprint binding.
Flow then enforces `iss == sub`, exact string-or-array audience membership,
constant-time nonce equality, numeric `iat`/`exp`, the released 60-second clock
skew and the rule that a token cannot predate its transaction. Success stores
only the self-attested subject, subject syntax, signing algorithm and canonical
submission digest; the raw ID token is discarded. Subject identity, both
history transitions, terminal result and nonce consumption commit through the
full-record PostgreSQL compare-and-set, with no callback for this protocol.
Same-token replay returns the stable terminal response and a different token
conflicts. Four focused behavior groups, the OID4VP regressions, PostgreSQL
contract binary and strict all-target Clippy pass. The HTTP adapters now commit
retrieval, expiry and both terminal protocols through their corresponding
compare-and-set transactions. `/v1/flows/verify` and standalone
`/v1/flows/siop` starts require authenticated `verification:execute`
membership; Request Object GET/POST, direct-post, Digital Credentials API and
SIOPv2 submission routes expose the released envelopes without a Python
fallback. Direct post rejects terminal replay, while Digital Credentials API
and SIOPv2 repeat submissions are idempotent only for the exact canonical
digest. Different terminal payloads conflict. Digital Credentials API binds
the exact HTTPS origin into `origin:{origin}` audience and native encrypted
response processing. Retryable provider failures persist and consume nothing;
expiry and terminal changes use full-record status-and-`updated_at` atomic
compare-and-set. Startup accepts an explicit `OID4VP_ISSUER_DID`, the retained
`MARTY_ISSUER_DID` alias, or a public-origin-derived `did:web` identity and
fails closed on malformed identity. The route behavior is frozen in
`contracts/flow-verification-http-behavior.json` and exercised through the
live Axum router.

Application-approved issuance planning is now native under
`contracts/flow-application-approved-behavior.json`. The reusable
Applicant-to-Flow security boundary lives once in `mmf-security` at local
commit `54b5805`: canonical Unicode JSON, dedicated purpose-bound HMAC,
producer/audience/version binding, freshness, minimized evidence, deferred
atomic replay consumption and one-winner replica races share a
transport-neutral contract. Flow no longer duplicates that cryptographic
kernel. Its native planner selects only active application-approved OID4VCI
definitions, preserves exact optional template targeting, orders flows by ID,
requires object claims and canonical manual-issuance UUIDs, and recreates both
released v1 and v2 logical offer identities. The complete definition,
applicant and claims snapshot is canonically hashed so a reused logical flow
with changed semantics conflicts. PostgreSQL now reserves the authenticated
event receipt and all selected instances in one transaction, recovers an exact
replay plan, and rejects changed event payloads or changed offer semantics.
Focused language-neutral planning, trusted-precondition, PostgreSQL contract
and strict Clippy gates pass. The HTTP adapter now authenticates before plan
reservation, consumes the shared Redis replay key only after durable planning,
recovers exact planned replays, and completes each OID4VCI offer through the
typed issuance provider. Offer completion is flow-idempotent and race-safe:
an existing active artifact is reused, while concurrent first completion uses
snapshot CAS and reloads the winner. Provider failures retain the released
per-flow partial-failure response and remain retryable through the durable
plan. The gRPC adapter now consumes this exact kernel and security evidence; no
Python fallback is permitted.

The `/oid4vp/did.json` compatibility endpoint is native under
`contracts/flow-did-http-behavior.json`. It resolves the exact configured
organization + issuer DID + `oid4vp_request_signing` +
`oauth-authz-req+jwt` + ES256 identity, publishes only the sanitized public
JWK as `JsonWebKey2020`, preserves authentication/assertion relationships and
the released DID media type, no-store and CORS headers, and fails closed when
the signing-identity provider is absent or invalid. The default organization
UUID and application-event freshness/replay settings are now typed startup
configuration; deployed environments require the dedicated 32-byte event key.

All 16 released Flow gRPC operations are now implemented by one native adapter
under `contracts/flow-grpc-behavior.json`. Legacy protobuf definition, instance,
artifact and verification DTOs translate into the same PostgreSQL records,
provider registry, graph/transition kernels, protocol side effects and atomic
mutations used by HTTP. Ordinary RPCs require constant-time service-token
authentication plus tenant membership and method-specific permission;
verification start and application approval additionally require their exact
mTLS SPIFFE identities. Application-event protobuf strings recover canonical
JSON before the shared MMF HMAC check. Starts persist their optional artifact
atomically, advances use snapshot compare-and-swap, cancellations fence terminal
state, and verification/application starts preserve their existing idempotency
units. Public projections redact private context. Streaming is tenant-bound,
supports instance and flow-type filters, uses a bounded 256-event channel and
terminates a lagging subscriber explicitly instead of silently losing events.
Health probes the live database and requires service authentication. Four
adapter unit vectors, two language-neutral contract tests, all-target compile
and strict Clippy pass.

The native Flow executable is now composed under
`contracts/flow-executable-behavior.json`. It connects and probes every required
dependency, binds both listener sockets, starts the durable callback worker and
only then activates shared MMF readiness and the standard gRPC health service.
HTTP merges all application routes with shared lifecycle/version/native-backend
diagnostics; gRPC serves the complete adapter with optional development
plaintext and required deployed mTLS. Shutdown transitions to draining, marks
gRPC not serving, gracefully closes both listeners, stops the callback worker
and then records stopped. The callback worker preserves the released bounded
retention, attempts, lease, poll, retry and batch configuration; uses
`SKIP LOCKED` fenced claims; revalidates the tenant destination for every
attempt; signs the canonical event; forbids redirects; distinguishes HTTP,
timeout and network failures; retries with bounded exponential delay;
dead-letters removed destinations; and scrubs delivered or expired payloads.
The optional PostgreSQL integration gate now drives a real loopback callback
receiver and verifies signed delivery, payload scrubbing and destination
dead-lettering in addition to the existing lease races. Executable, callback,
runtime, submission and strict Clippy gates pass locally; real PostgreSQL
delivery remains a configured Linux CI execution gate. Native container
packaging is now complete: the shared service image builds and contains
`marty-flow`, the production-equivalent Rust service image has a dedicated
non-Python `flow` target with HTTP and gRPC ports plus a native health check,
and CI builds that target as `marty-flow:ci`. The language-neutral packaging
contract verifies all three boundaries. The source cutover is now complete:
the shared image dispatches Flow only to `marty-flow`, the shared Python
migration runner no longer owns the Flow schema, and Rust startup runs the
advisory-locked schema and seed migrations. The complete `services/flow`
package and its obsolete Python-only PostgreSQL contract image are deleted,
removing 19,935 Python, migration, fixture and image-contract lines while
retaining the language-neutral contracts and native tests. The Rust
PostgreSQL integration gate now explicitly owns event-plan races, payload and
semantic conflicts, artifact idempotency, callback leases, migration and seed
behavior in CI.

Development is explicitly configured as development. Beta is explicitly
deployed and fail closed: Flow receives distinct inbound and outbound workload
certificates, presentation-policy receives its server identity, and auth,
applicant and verification receive separate client identities. A beta-only
provisioning helper creates short-lived identities with exact DNS and SPIFFE
URI SANs without printing keys; the release runner validates every required
secret, file, chain and expiry before stack mutation. The three documented
legacy downstream gRPC channels retain their explicit beta plaintext decision,
but sensitive Flow RPC authorization still derives only from verified client
certificates. Local full-suite, strict Clippy, optimized binary, packaging,
Compose and anti-reintroduction gates pass. Remaining Flow work is external CI
container/PostgreSQL execution and branch landing; no beta deployment has
occurred.

### Organization port status

The Organization whole-service port is active on its own worktree and branch
from the completed Flow cutover. The authoritative source scan freezes 62
unique HTTP method/path contracts spanning organization CRUD, membership,
join flows, API keys, preferences, lifecycle, audit, RBAC, Cedar policy sets,
onboarding and SCIM 2.0. It also freezes all 12 intended protobuf RPCs and
records the four RPCs declared by the protocol but never implemented by the
Python server (`CreateOrganization`, `UpdateOrganization`,
`ListOrganizations` and `RemoveMember`). Rust must implement the full intended
12-method surface rather than preserve that omission.

The first implementation slice establishes `marty-organization` and ports the
organization, membership, role, permission, API-key, join-code and policy-set
domain behavior plus deterministic SCIM pagination, equality-filter parsing,
error envelopes and role-name normalization. Both languages consume the same
`contracts/organization-domain-behavior.json`; the complete route, RPC and
event inventory is frozen in `contracts/organization-service-surface.json`.
Six Rust vector groups, three Python parity groups, locked tests, formatting
and strict Clippy pass. Rust migration ownership is also established over the
released `organization_service` schema: an advisory-locked, idempotent final
schema creates or validates all 11 tenant, membership, key, preference, join,
RBAC, policy and audit tables and records an independent Rust migration head.
It preserves existing Alembic installations while adding the intended API-key
`scope_type`, `deployment_profile_id`, `enabled` and `updated_at` fields that
the Python entity exposed but did not persist. A language-neutral persistence
contract and Rust source gate pass; live PostgreSQL execution is configured as
a CI gate because no local Organization database URL is present. The next
slices add the application use cases over shared MMF event publication,
authorization and audit policy, all HTTP and gRPC adapters, executable
composition, packaging, PostgreSQL acceptance and same-slice deletion of
`services/organization` after those gates pass. No beta deployment occurs
during these slices.

All nine Python persistence adapter families are now consolidated into one DRY
`PostgresOrganizationStore`. It owns organization, member, API-key,
console-preference, join-code, permission, role/member-role, policy-set and
audit storage without duplicating connection/session lifecycle. Tenant-owned
lookups bind organization IDs in SQL, membership email matching remains
case-insensitive, role replacement is transactional, assignments are
idempotent, audit filters are parameterized and bounded, persisted enum drift
fails closed, and released lowercase/DRAFT compatibility values remain
accepted deliberately. The optional live PostgreSQL contract exercises the
complete round trip and cascade behavior when
`ORGANIZATION_POSTGRES_TEST_URL` is configured. Locked unit/source tests,
strict Clippy, cross-language domain vectors and the ownership guard pass
locally; live execution remains a CI gate.

The 104-entry permission catalog is now frozen as language-neutral data and
consumed by both Python and Rust. Rust derives all eight intended system roles
from that single catalog: owner, admin, access administrator, catalog
administrator, reviewer, operator, viewer and applicant. Owner/admin retain
the complete catalog; reviewer/operator keep their exact view and action
supplements; applicant remains the sole default role and has no organization
console access. Permission IDs and new system-role IDs are deterministic,
while released database IDs are retained on reseed. Catalog and role seeding
are idempotent and included in the optional PostgreSQL round-trip gate. Four
Python parity tests, ten Rust unit/contract groups and strict Clippy pass.

Organization cache behavior now consumes the canonical production Redis
adapter in `mmf-data`; no service-local Redis client or command implementation
was added. MMF commits `b566451` and `9f9be66` provide fail-closed Redis
operations, TLS/startup health enforcement, namespace-bounded `SCAN`, complete
ordinary/sorted-set behavior and multiple keyspaces over one multiplexed
connection. `marty-organization` derives three scoped views that preserve the
mixed-deployment keys exactly: `org_membership:{user}:{organization}`,
`member_permissions:{user}:{organization}` and `org:{organization}:plan`.
The language-neutral `contracts/organization-cache-behavior.json` freezes those
keys and default-plan semantics. Rust tests prove dual membership/permission
invalidation, plan synchronization, namespace compatibility and rejection of
empty identifiers/plans; the full Organization suite and strict Clippy pass.
The optional live MMF Redis acceptance gate remains configured through
`MMF_REDIS_TEST_URL`; no endpoint is available locally, so it is compiled but
not executed here.

All 12 Organization domain-event families now have one native envelope and
audit projection under `contracts/organization-event-behavior.json`:
organization create/update, member invite/add/remove, API-key create/revoke,
and role create/update/delete/assign/remove. The surviving Python audit
publisher and Rust execute the same action, category, resource, actor,
severity, message and event-data vectors. Rust additionally projects every
event into the canonical `mmf-messaging` at-least-once envelope with exact
tenant partition, event deduplication identity, topic/routing key and bounded
retry metadata. `OrganizationEventPublisher` persists the audit record before
using the provider-neutral MMF transport and propagates audit, projection and
transport failures instead of converting an unavailable live event path into
success. Mutating application paths no longer use that non-atomic sequence:
the native `OrganizationApplication` locks updates and commits organization,
owner membership, the complete permission/role seed, owner-role assignment,
audit projection and the canonical MMF PostgreSQL outbox message in one
transaction. Existing permission IDs are resolved from the upsert before role
links are written, preserving databases seeded by Python. Acknowledgement only
occurs after the durable event is queued. Default-plan cache synchronization
runs after commit as derived state and is returned as a typed warning when it
fails, avoiding both silent drift and unsafe client retries after a successful
database commit.

`contracts/organization-application-behavior.json` now freezes create defaults,
owner membership, the 104-entry catalog, partial-update ordering,
explicit-null clearing, settings merge behavior and the open-join/public-only
invariant across Python and Rust. Native reads cover get, bounded list,
discoverable filtering and active user memberships. Twenty-two Rust tests,
all 65 surviving Python Organization tests, formatting and strict Clippy pass;
the atomic PostgreSQL acceptance test is compiled and runs when
`ORGANIZATION_POSTGRES_TEST_URL` is available. The remaining Organization
slices are member/join/API-key/preference/RBAC/policy/audit application
mutations, Cedar authorization, all HTTP and gRPC adapters, event-outbox
dispatch/readiness, executable/container packaging, acceptance gates and
same-slice deletion of the Python service. No beta deployment occurs before
those slices and the rest of wave three land.

The largest remaining Organization application family—membership and
joining—is now native as well. Invitations, acceptance, tenant-bound role
replacement, owner-role retention, owner-removal rejection, member reads and
removal, idempotent direct provisioning, pre-seeded email linking, default
role selection, Marty/demo-admin promotion, join-code consumption and direct
open joins all execute through `OrganizationApplication`. Member, role-link,
join-code-counter, audit and MMF outbox writes share one transaction; update
and code rows are locked before decisions, and membership/permission cache
invalidation is an explicit post-commit warning. The direct-provisioning
planner centralizes role deduplication and the applicant-to-admin promotion
rule rather than duplicating it across callers. Owner retention is enforced on
direct provisioning as well as ordinary role replacement.

`contracts/organization-membership-behavior.json` freezes direct-role
resolution and join-code failure precedence across Python and Rust. It also
corrects the legacy ambiguity where an exhausted code with a future expiry was
reported as expired: inactivity wins first, then actual expiration, then
exhaustion. The optional PostgreSQL acceptance gate now covers invite,
acceptance, role replacement, owner protection, removal, code/open joins and
direct provisioning while asserting one durable audit/outbox pair for every
emitted mutation. Twenty-five Rust tests, all 67 surviving Python Organization
tests, formatting and strict Clippy pass. API keys and preferences are next,
followed by RBAC/policy/audit application mutations and the adapter/runtime
cutover.

API-key and console-preference application behavior is now native. API-key
creation validates the complete MIP scope allowlist, organization versus
deployment-profile binding, positive rate limits and future expiry before
persisting every intended field. Creation and tenant-bound revocation commit
the key, audit record and MMF outbox event atomically; validation hashes the
presented secret, performs the domain's constant-time verification and rejects
disabled, revoked or expired keys. Tenant-scoped list/get operations no longer
permit a path organization to select another tenant's key. The raw secret is
retained only in the one-time creation result.

Console preferences now distinguish an omitted active-organization field from
explicit null and an explicit UUID, lock an existing preference during partial
updates and preserve the default applicant/no-active-organization behavior.
This fixes the surviving Python command's `hasattr` ambiguity, which made every
request appear to contain `last_active_org_id` and could clear it during an
unrelated view-mode update. `contracts/organization-api-preference-behavior.json`
drives both languages for key scope/binding cases and preference
omit/clear/replace semantics. Twenty-seven Rust tests, all 69 surviving Python
Organization tests, formatting and strict Clippy pass. The optional PostgreSQL
gate now also validates key creation, constant-time lookup, cross-tenant
revocation rejection, revocation, and persisted preference partial updates.
Policy-set and audit-query application behavior remains before the
adapter/runtime cutover.

Organization RBAC application behavior is now native. Custom role creation,
partial update and tenant-bound deletion; permission resolution; default-role
uniqueness and transfer; member assignment/removal; system-role deletion
protection; owner-role retention; last-role retention; and role/permission
reads all execute through `OrganizationApplication`. Each mutation locks its
decision rows and commits role, member-role, audit and canonical MMF outbox
state in one PostgreSQL transaction. Cache invalidation occurs only after
commit and reports typed warnings. Role deletion reassigns members that would
otherwise become roleless and fails closed when a required replacement is
missing or invalid.

`contracts/organization-rbac-behavior.json` freezes replacement selection,
default transfer, missing-role and self-replacement behavior across Python and
Rust. The temporary Python oracle was corrected to transfer default status
rather than deleting the only default, and its behavior remains covered until
the native adapter/runtime cutover deletes the Python service. Twenty-seven
Rust tests, all 70 surviving Python Organization tests, formatting, strict
Clippy and the ownership guard pass. The optional PostgreSQL acceptance gate
compiles RBAC create/update/assign/remove/delete behavior, system-role
protection and exactly one durable audit/outbox pair per successful mutation;
live execution still awaits `ORGANIZATION_POSTGRES_TEST_URL`. Policy-set and
audit-query application behavior is next, followed by authorization and the
adapter/runtime cutover. No beta deployment occurs before all wave-three
slices land.

Policy-set lifecycle and audit-query application behavior are now native.
`marty-organization` creates, reads, filters, partially updates, validates,
activates, archives and tenant-binds deletion of structured Cedar policy sets.
Mutations lock their tenant and policy rows; activation atomically archives
the previously active set of the same type, enforcing the domain's intended
one-active-set-per-organization/type invariant that the Python implementation
documented but did not enforce. Missing native validation fails before any
database access. Legacy Cedar text still projects into the stable structured
response shape, while malformed, duplicate, effect-mismatched, disabled-only
and schema-invalid policy documents fail closed.

The reusable implementation belongs to `mmf-security`, not the Organization
service: MMF commit `e87a538` adds one bounded `CedarPolicyValidator` for JSON
or human-readable schemas and shares strict parsing/schema validation with
the existing authorization engine. Organization consumes that API rather
than adding a second Cedar kernel. All 69 MMF security unit and integration
tests plus strict Clippy pass.

Native audit reads now preserve tenant-bound detail lookup, total counts,
bounded page/per-page and legacy limit/offset semantics, exact category,
event, resource, action and severity filters, actor substring matching,
metadata IP matching, full-text search, explicit ISO date bounds and positive
hour/day/week windows. `contracts/organization-policy-audit-behavior.json`
freezes policy validation, active-set replacement, legacy projection, audit
pagination and time-window behavior across Python and Rust. Thirty Rust tests,
all 73 surviving Python Organization tests, formatting, strict Clippy and the
ownership guard pass. The optional PostgreSQL gate compiles complete
policy-set lifecycle, active-set replacement, filtered/count-consistent audit
queries and cross-tenant detail denial; live execution still awaits
`ORGANIZATION_POSTGRES_TEST_URL`. Organization authorization and HTTP/gRPC
adapter/runtime packaging are next. No beta deployment has occurred.

Organization authorization decisions are now native and shared rather than
reimplemented in the service. MMF commit `707425d` extracts active,
tenant-bound membership authentication from permission evaluation; both paths
retain the same typed fail-closed outcomes for absent identity, missing or
cross-tenant membership, inactive membership and denied actions. Organization
projects persisted roles and effective permissions into that primitive and
adds exact gateway-forwarded API-key binding: the synthetic principal, key ID,
tenant and minimized route permission must agree, and API keys cannot satisfy
owner-only actions. Membership-only routes preserve the released behavior
without weakening permissioned routes.

`contracts/organization-authorization-behavior.json` executes the same user,
owner and API-key cases against Python and Rust, including missing identity,
inactive membership, permission mismatch, tenant mismatch and owner-only
denial. Stable application errors replace implicit `None` or permissive
fallbacks. Thirty-one Rust tests, all 74 surviving Python Organization tests,
all 69 MMF security tests, formatting and strict Clippy pass. The remaining
Organization work is the trusted HTTP/gRPC adapter boundary, runtime and
outbox composition, executable/container packaging, PostgreSQL acceptance and
same-slice Python deletion. No beta deployment has occurred.

The complete intended 12-method Organization protobuf service now executes in
Rust, including `CreateOrganization`, `UpdateOrganization`,
`ListOrganizations` and `RemoveMember`, which were declared but absent from
the Python server. Generated Tonic types remain authoritative; DTO projection,
UUID and enum validation, API-key validation, member permissions, filtered
organization totals and stable gRPC status normalization are implemented at
the adapter boundary. Every RPC requires the configured service token using a
constant-time comparison, while deployed runtime configuration will also
require mutual TLS before the server can bind. Member removal now carries and
checks the path organization in the application command, closing a latent
cross-tenant selector gap before exposing that previously missing RPC.

The frozen 12-method list is asserted against the compiled adapter and the
existing protobuf/Python surface oracle remains green. Thirty-three Rust
Organization tests, the focused six-test Python protobuf/domain oracle,
formatting and strict Clippy pass. HTTP/SCIM adapters, deployed trust-boundary
composition, runtime/outbox workers, executable/container packaging and the
final acceptance/deletion gate remain. No beta deployment has occurred.

The inbound HTTP trust boundary is now defined once before route migration.
MMF commit `fe6e6b5` owns minimum-length service-token configuration,
production-required startup failure and constant-time request authentication;
Organization gRPC and HTTP consume that shared primitive. The HTTP adapter
accepts forwarded user or API-key context only after the gateway credential is
validated, and API-key contexts additionally require a valid tenant UUID and
nonempty minimized permission. Missing, malformed and partial contexts return
typed failures before membership or domain code runs.

`contracts/organization-http-trust-behavior.json` freezes trusted user/API-key
projection and every missing/wrong credential branch. Thirty-four Rust
Organization tests, all 71 MMF security tests, formatting and strict Clippy
pass. The gateway must inject the same service credential on proxied HTTP
requests before the deployed Organization runtime can require it; that wiring
is part of the remaining executable cutover, not a fallback. No beta
deployment has occurred.

Fourteen of the 62 frozen HTTP contracts now execute through Axum:
organization create/list/discovery/mine/get/update, public and internal
lifecycle reads, public environment read/update, trusted internal settings,
console preferences and onboarding status. The adapters preserve creation
defaults and disablement, strict unknown-field rejection, explicit
omit/null/replace update semantics, membership and exact permission checks,
owner membership projection, no-store preferences, Hosted Pilot retention
projection and stable error envelopes. Organization type, join mechanism and
view-mode parsing now live in the domain and are shared with gRPC rather than
being duplicated per adapter.

Black-box Axum tests prove missing gateway credentials and malformed/private
bodies fail before storage access and preserve the released onboarding
projection. The optional `ORGANIZATION_POSTGRES_TEST_URL` gate exercises
creation, owner membership, authenticated reads, permissioned updates,
preferences, internal settings, lifecycle projection and cleanup through the
actual HTTP router. Forty Rust Organization tests, all 74 surviving Python
tests, formatting and strict Clippy pass. The remaining 48 HTTP contracts are
join/member/API-key, RBAC, policy/audit and SCIM families, followed by runtime,
outbox worker, gateway credential injection, packaging and deletion. No beta
deployment has occurred.

Twenty-five of the 62 frozen HTTP contracts now execute through the same Axum
router. The second adapter slice adds join-code admission and validation,
direct open joining, team snapshots, paginated member list/invite/role-update/
removal and paginated API-key create/list/revoke. It preserves 201 join
responses, trusted forwarded email requirements, pending-versus-active team
buckets, per-member role-alias de-duplication, sorted effective permissions,
one-time raw API-key disclosure, tenant-bound member/key mutation and the Marty
default-organization membership-removal prohibition. Gateway service
authentication and user/API-key authorization run before application storage
access, and malformed identifiers, emails, role sets, scopes and unavailable
storage fail closed through stable envelopes.

Language-neutral black-box route tests assert that the 25 native declarations
remain unique members of the frozen 62-route surface, untrusted requests stop
before database access and join admission refuses missing trusted email.
Projection tests freeze team role buckets and one-time key-secret behavior. The
optional PostgreSQL HTTP gate now also executes direct join, team snapshot,
API-key create/list/revoke and tenant-bound member removal through Axum. Forty-
two Rust Organization tests, all 74 surviving Python tests, formatting and
strict Clippy pass. The remaining 37 HTTP contracts are RBAC, policy/audit and
SCIM families, followed by runtime, outbox worker, gateway credential
injection, packaging, full PostgreSQL acceptance and same-slice Python
deletion. No beta deployment has occurred.

Thirty-five of the 62 frozen HTTP contracts now execute natively. The third
adapter slice exposes the complete intended RBAC surface: grouped permission
catalog, role list/create/get/update/delete, replace/add/remove member-role
assignments and current-member permissions. It preserves permission ID and
legacy `resource:action` key inputs, deterministic de-duplication, role member
counts, default-role behavior, response projections and 201/204 status
semantics. Every read and mutation is tenant-bound and requires its exact
`role:view`, `role:create`, `role:edit`, `role:delete` or `role:assign`
permission after gateway service authentication; missing memberships,
cross-tenant IDs, system-role deletion, owner-role removal, empty final role
sets and unknown permissions fail closed.

The shared frozen-route assertion now covers all 35 native HTTP declarations,
and black-box requests prove RBAC routes reject missing trust before storage.
The optional PostgreSQL HTTP scenario now includes grouped catalog reads,
permission-key resolution, custom-role create/update, owner permission
projection and role deletion through Axum. Forty-four Rust Organization tests,
all 74 surviving Python tests, formatting and strict Clippy pass. The remaining
27 HTTP contracts are the policy/audit and SCIM families, followed by runtime,
outbox worker, gateway credential injection, packaging, full PostgreSQL
acceptance and same-slice Python deletion. No beta deployment has occurred.

Forty-two of the 62 frozen HTTP contracts now execute natively. Because the
1,012-line Python SCIM adapter is the largest remaining deletion target, its
discovery/read half moved next: service-provider configuration, schemas,
resource types, paginated/filterable/sortable Users and Groups collections,
and tenant-bound User/Group detail. The Rust adapter reuses the canonical SCIM
parsers and pagination helpers, emits the registered core and MIP extension
URNs, preserves metadata locations and timestamps, projects effective role
membership, and returns typed SCIM `invalidFilter` and 404 envelopes.
Discovery requires the trusted gateway service credential even though it is
storage-independent; resource reads additionally require an active
organization membership.

Black-box tests freeze trust-first discovery and the expanded 42-route subset,
while language-neutral projection/filter tests cover extension keys, email,
external-ID and active-state behavior. The optional PostgreSQL HTTP scenario
now traverses SCIM User and Group collection projections through Axum. Forty-
seven Rust Organization tests, all 74 surviving Python tests, formatting and
strict Clippy pass. The remaining 20 HTTP contracts are eight SCIM User/Group
provisioning mutations and twelve policy/audit routes, followed by runtime,
outbox worker, gateway credential injection, packaging, full PostgreSQL
acceptance and same-slice Python deletion. No beta deployment has occurred.

Fifty of the 62 frozen HTTP contracts now execute natively, completing the
entire intended SCIM 2.0 surface. User POST/PUT/PATCH/DELETE preserves primary
email selection, external IDs, active/deactivated state, default or explicit
roles, PATCH operation/path behavior, uniqueness responses, extension fields,
Location headers and owner deprovisioning protection. Group
POST/PUT/PATCH/DELETE preserves display-name slugging, permission-key
resolution, member references, filtered member removal, extension metadata,
system-role immutability and SCIM status/error envelopes.

Unlike the superseded Python adapter's independent repository writes, Rust
commits SCIM User profile/status/role transitions and Group role/permission/
membership replacements in one PostgreSQL transaction with canonical audit,
outbox and cache effects. All IDs are tenant-bound and validated before
mutation. The frozen-route assertion covers all 50 native declarations, pure
behavior tests freeze payload/projection semantics, and the optional live
PostgreSQL HTTP scenario now traverses User and Group provisioning lifecycles.
Forty-nine Rust Organization tests, all 74 surviving Python tests, formatting
and strict Clippy pass. The remaining 12 HTTP contracts are nine policy-set
and three audit routes, followed by runtime, outbox worker, gateway credential
injection, packaging, full PostgreSQL acceptance and same-slice Python
deletion. No beta deployment has occurred.

All 62 frozen Organization HTTP contracts now execute through the native Axum
router. The final slice adds policy-set list/create/templates/validate/get/
update/archive/activate/delete and audit list/export/detail. Policy requests
preserve strict document shapes, omit/null/replace updates, status/type
projection, starter templates, active-set replacement and 201/204 semantics;
all Cedar decisions use the shared MMF validator and fail closed when it is
unavailable. Audit requests preserve exact `audit:view`/`audit:export`
authorization, modern and legacy pagination, category/event/resource/action/
actor/severity/search/IP/date/time-range filters, tenant-bound detail lookup,
JSON export and correctly escaped CSV export.

The router contract now asserts exact set equality—not merely subset
membership—against all 62 frozen routes. The optional PostgreSQL HTTP scenario
adds policy create/archive/activate/delete and audit list/export to the full
native lifecycle. Fifty-two Rust Organization tests, all 74 surviving Python
tests, formatting and strict Clippy pass. The remaining Organization work is
runtime and outbox-worker composition, gateway credential injection,
executable/container packaging, configured live PostgreSQL acceptance and
same-slice deletion of the superseded Python service. No beta deployment has
occurred.

The native Organization executable and its operational composition are now
implemented in commit `de0baf57`. Startup validates deployed configuration and
service credentials, connects PostgreSQL and the gateway Redis database,
loads the shared MMF Cedar validator, runs idempotent schema/outbox migration,
reconciles system roles and the configured Marty admin/reviewer memberships,
then serves the complete Axum and tonic surfaces with MMF health, readiness,
version and native-backend diagnostics. The gateway now injects its configured
service token as a trusted override only for Organization HTTP upstreams;
client headers cannot select that credential.

Durable event publication remains one shared MMF implementation rather than an
Organization worker. MMF commits `c6355b0` and `4abb2ae` add the reusable
leased PostgreSQL outbox dispatcher with fenced acknowledgement, bounded
exponential retry, dead-letter transitions, reconnect and graceful shutdown.
Organization maps its canonical event envelope to the existing event-stream
protobuf and treats an event-stream outage as observable degradation while the
transactional outbox retains delivery. Ten MMF messaging unit tests, two MMF
PostgreSQL behavior tests, the complete Organization Rust suite (including 24
crate unit tests and all language-neutral service tests), the focused gateway
credential-injection test, formatting, and strict Clippy pass. The remaining
Organization cutover work is to publish and immutably pin the MMF commits,
switch the service image/entrypoint to the Rust binary, run configured live
PostgreSQL/Redis/event-stream executable acceptance, then delete the Python
service and its Python-only dependencies in the same passing slice. No beta
deployment has occurred.

Commit `9ab00486` adds the native Organization binary to the shared service
image, dispatches `SERVICE_NAME=organization` directly to that binary, and
marks the beta overlay as a deployed environment so missing service
credentials fail closed. Twelve focused packaging/entrypoint tests pass. The
image build remains gated by publication of the MMF branch because the Marty
UI workspace still intentionally points at its clean MMF worktree; GitHub CLI
authentication is invalid and connector writes are prohibited by the current
execution policy. A PostgreSQL listener is available locally but its test
credential is not, and Docker API access is denied, so no unsafe guess or
shared-database mutation was used to manufacture live acceptance evidence.
Python deletion therefore remains pending the immutable MMF pin, image build,
and configured executable acceptance. No beta deployment has occurred.

The Organization source cutover is complete in commit `ce882181`. The native
crate is now the sole runtime and migration owner; the Python migration runner
no longer imports the deleted service, and the ownership manifest marks
`organization-service` as `native-active` with an anti-reintroduction guard.
The cutover removed all 86 tracked files below `services/organization`,
including 8,145 production Python lines and 16,437 tracked service lines in
total, while retaining the frozen 62-route HTTP surface, all 12 intended gRPC
methods, PostgreSQL schema, Redis state, Cedar policy behavior, SCIM, audit,
startup reconciliation and durable MMF outbox delivery in Rust.

The final local gate is 61 passing Rust tests, including two executable
fail-closed tests, formatting and strict Clippy under Rust 1.95. Thirty-five
focused ownership, packaging, release and migration-history checks pass;
base-plus-beta Compose and the Kubernetes/self-host YAML models validate. CI
now builds a dedicated Organization image, smoke-tests it against pinned
PostgreSQL and Redis containers, and runs the migration, application and
repository PostgreSQL executables with a required database URL. Those live
gates cannot execute on this host because its Docker daemon and test database
are unavailable, so merge remains contingent on the configured CI jobs rather
than weakening or silently skipping them. MMF publication and immutable pinning
remain aggregate landing work. No beta deployment has occurred.

### Auth port status

Auth is active in dependent worktree `marty-ui-rust-auth-wave3` on branch
`agent/marty-ui-rust-auth-wave3`, based on the complete Organization head so
the service can consume the same MMF platform without copying framework code.
The measured deletion target is 7,578 non-test Python lines. Commit
`bfcbbfcd` freezes all 14 HTTP routes and six gRPC methods in
`contracts/auth-behavior.json`; the contract explicitly preserves the two
retired gRPC mutation methods as `UNIMPLEMENTED`. Shared Python/Rust vectors
cover claim precedence, Keycloak realm/resource role merging, organization
claim extraction, display-name precedence, session validity and RFC 7636 PKCE
S256 output.

The first native application slices are complete. Commit `9f7b2fd6` ports the
OIDC login/registration and callback orchestration, single-use state and nonce
binding, validated-claims-only session creation, provisioning port, event
families, activity refresh, invalid-session cleanup and idempotent logout.
Commit `df1f194d` ports session and PKCE persistence against the shared MMF
cache contract, including user-session indexes, bulk user logout, exact TTL
behavior and typed fail-closed malformed-cache errors. MMF commit `db47333`
adds atomic cache consume and expiring set primitives once in `mmf-data`, with
equivalent memory and Redis implementations, instead of embedding Redis
commands in Auth.

Commit `636216f6` ports the complete Keycloak OIDC provider boundary. Bounded
no-redirect discovery, JWKS and token fetches preserve internal/external issuer
separation and trusted JWKS-origin/path validation; key rotation performs
exactly one forced refresh. Signature, algorithm, issuer, audience, authorized
party, nonce, time and `at_hash` decisions execute directly in the pinned
canonical `marty-oid4vci` kernel, and access tokens remain opaque. Commit
`0f18de11` ports JIT applicant upsert planning and organization membership
enrichment, with shared Python/Rust name vectors and observable optional
organization degradation. Commit `f6408648` ports credential-login identity
enrichment, including deterministic fallback IDs, DID extraction, Keycloak and
credential role/context merging, provisioning fallback and Canvas defaults.
Commit `a5af692b` ports Keycloak Admin user lookup/create, verified-user policy,
role and organization enrichment, native-validated RFC 8693 token exchange,
bounded transport and container URL normalization. Thirty-three Rust
behavioral tests, the focused Python oracle suites, formatting and strict
Clippy pass.

Commit `c281dec2` ports Auth persistence. Auth owns a non-destructive,
advisory-lock-protected schema migration for audit logs and session history.
The beta deployment gate subsequently exposed that its original JIT adapter
also depended on an alleged externally owned `public.applicants` table that no
service or migration actually owned. That dependency is removed: canonical
Applicant-service profile persistence now owns JIT identity, serializes access
inside its durable store, keys profiles by tenant plus OIDC subject or email,
fails closed when those keys identify different records, preserves existing
names on incomplete later claims, and merges JIT vetting metadata. Auth reaches
that owner through the bounded shared MMF HTTP transport and fails closed at
the JIT boundary. Its PostgreSQL repository now only writes each
authentication/logout audit pair with its session-history mutation in one
transaction; audit and session-history query behavior remains available. The
language-neutral persistence and transport contracts cover owned-schema
migration idempotency, JIT updates, the four event families, and revocation
history.

Commit `adf28056` ports the Canvas learner-identity and credential callback
state kernels. The callback is bound to the canonical MMF event signature,
decision digest, audience, event ID, timestamp window, pending flow, policy and
organization. Completion/failure polling, crash-safe claims, deterministic
retry session IDs and final session-cookie handoff are single-use and
replica-safe. Canvas identities preserve stable issuer/subject derivation,
fallback email and username, LTI LIS name precedence, constrained applicant
roles and tenant context. `contracts/auth-login-state-behavior.json` runs
against both Python and Rust. MMF commit `1ab07f1` adds the required expiring
atomic `set_if_absent` lease once to `mmf-data`, with memory and Redis contract
coverage, rather than embedding a service-specific Redis command. Thirty-nine
Rust Auth tests, 51 focused Python callback/Canvas tests with one optional Redis
skip, formatting and strict Clippy pass.

Commit `17172606` ports the credential callback business orchestrator on top of
that state machine. It preserves Keycloak account eligibility and optional
creation, native-validated token context, provisioning fallback, deterministic
retry sessions, denial normalization, revocation status and already-processed
idempotency. Commit `41f40038` ports all SpruceKit and LISSI wallet-link
behavior, including platform templates, Android intent packages, legacy LISSI
compatibility, DID client-ID normalization and fail-closed duplicate or
mismatched outer request parameters.

MMF commit `8b79e82` adds one bounded no-redirect outbound HTTP client to
`mmf-platform`. It validates URLs, methods, headers, timeouts and response
limits; streams bodies under the configured bound; and normalizes timeout and
transport failures. Auth consumes that shared primitive rather than adding a
service-local client. Commit `58459daf` uses it for Canvas experience-session
transport and ports Canvas session finalization, optional applicant profile
enrichment, tenant shape, client context and positive TTL enforcement.

Commit `c523851e` ports all six Auth gRPC methods from the frozen contract.
Session validation, invalidation and status use the canonical Rust application;
health remains serving; direct session minting and the retired gRPC credential
callback fail explicitly with `UNIMPLEMENTED`. Commit `62fe4864` ports trusted
UI-origin selection, post-auth redirect resolution, OIDC callback URLs and
Keycloak/handoff impersonation context. One shared fixture executes in Python
and Rust. Network-path redirects such as `//attacker.example` now fail closed
instead of retaining an open-redirect interpretation.

Commits `16aae0d0`, `c52579b7` and `16a31cfd` now expose all 14 frozen HTTP
routes through one Axum service, including the six credential-login asset,
start, poll, finalize and callback routes. Commit `18a82ba1` moves credential
page and error rendering into Rust, preserves every SpruceKit/LISSI operator
override, and compiles four shared assets from one source. Exact Python/Rust
page hashes pass, and 710 embedded Python asset lines were deleted immediately
after that gate.

Commit `b7ad9c03` ports the remaining Flow verification, Organization
provisioning, Applicant profile and event provider boundaries. Flow and
Organization channels are created only through the shared MMF gRPC factory;
Applicant requests use the bounded no-redirect MMF HTTP client; Auth events use
the canonical MMF envelope. `contracts/auth-service-transport-behavior.json`
freezes request defaults, incomplete-response rejection, organization
degradation behavior, exact Applicant headers/bounds and all four event types.

Commit `e665f9b7` establishes fail-closed Auth configuration, MMF lifecycle and
readiness, organization-scoped events, a PostgreSQL MMF outbox publisher and a
bounded event-stream gRPC transport. `contracts/auth-executable-behavior.json`
requires every database, cache, OIDC, provider, outbox, event-stream and
listener component to be healthy before activation; it explicitly forbids a
Python fallback and any per-slice beta deployment. The complete Rust Auth
suite, strict Clippy and the focused Python parity suite (71 passed, one
optional configured integration skipped) are green.

Commit `78f9e821` completes the Auth source cutover. The native executable now
connects and validates the Auth PostgreSQL schema, MMF PostgreSQL outbox, MMF
Redis session/PKCE/credential state, MMF Redis sliding-window rate limiter,
OIDC discovery/JWKS, Flow and Organization gRPC, Applicant and Canvas/issuance
HTTP health, and event-stream gRPC before readiness. Flow uses the shared MMF
workload-mTLS client when configured; production configuration additionally
requires an inbound workload server identity. Both listeners bind before
activation, the durable outbox dispatcher starts and drains with the process,
gRPC health changes with lifecycle state, and shutdown drains HTTP, gRPC and
outbox work in order.

The service image builds and installs `marty-auth`, and the entrypoint dispatches
Auth directly to that binary without a Python path. The beta Compose model now
selects the beta environment explicitly, carries the Rust-compatible PostgreSQL
URL and required identity values, preserves outbound Flow workload identity,
and renders successfully without changing the running beta deployment. The
complete pre-deletion Python oracle gate passed 95 tests with one optional
configured integration skipped; the post-cutover Rust gate passes all 76 Auth
tests, executable/packaging checks, formatting and strict Clippy. The same
change deleted 9,724 superseded lines, leaving only the four Rust-compiled
credential-login assets below `services/auth`, removed Python Auth migration
dispatch, marked Auth `native-active`, and added anti-reintroduction ownership
checks.

Auth source migration is complete. Its remaining release gates are the shared
wave-three immutable MMF pin plus configured PostgreSQL/Redis/provider and
container acceptance in the aggregate landing branch. No beta deployment has
occurred.

### Credential-template port status

Credential Template is now the largest remaining source-deletion target after
Organization when tracked Python migrations and implementation-specific tests
are included. Work is active in dedicated worktree
`marty-ui-rust-credential-template-wave3` on branch
`agent/marty-ui-rust-credential-template-wave3`, based on the completed Auth
source cutover. The first slice establishes `marty-credential-template` and
moves credential-format aliases, public and signing wire names, payload-format
defaults, issuance-protocol aliases, SD-JWT VCT and mdoc doctype requirements,
wallet inner-URI policy, wallet route rendering, and delivery-destination
tenant invariants into one Rust domain implementation.

`contracts/credential-template-domain-behavior.json` is the language-neutral
oracle for canonical, legacy and invalid format names—including the retained
VDS-NC family—registered and HTTPS VCTs, placeholder-origin rejection,
environment-specific URI schemes, encoded and inline credential offers, and
system versus organization delivery destinations. The surviving Python oracle
and Rust execute the same fixture; four tests pass in each language, and strict
Clippy passes. This parity pass caught and closed an initial VDS-NC inventory
omission before any caller or data was moved.

The persistence slice now consolidates the three Python repository families
into one `PostgresCredentialTemplateStore`. Rust owns a non-destructive,
advisory-locked and idempotent schema migration for credential templates,
wallet profiles and delivery destinations, including compatibility upgrades
for every retained column. The final schema deliberately does not resurrect
the cached issuer-profile/KMS routing columns retired in August 2026; live
`issuer_did` plus `issuer_algorithm` remain the complete template-side signing
selector. The Rust model closes two transition data-loss gaps by persisting the
domain-level `issuance_protocol` and every validity field, including
`not_before_offset_seconds`. Legacy claim rows retain Python-compatible UUIDv5
identity, type aliases and display defaults, while malformed records fail
closed. Tenant destination listings include system entries, exclude other
tenants and sort system-first by case-insensitive name without an application
side re-sort or N+1 hydration.

`contracts/credential-template-persistence-behavior.json` is the shared
language-neutral persistence oracle. `credential-template-service-surface.json`
now freezes all 24 HTTP operations and all 12 intended gRPC methods against
both Python decorators/protobuf and Rust-owned constants, preventing a partial
port from being mistaken for a complete service. The first application kernel
also owns PascalCase/reverse-domain credential-type validation, unique and
referentially sound claims, released seconds-to-days validity aliases and
rounding, canonical not-before precedence, draft-only mutation/deletion,
activation, deprecation and lossless new-version creation under
`credential-template-lifecycle-behavior.json`.

Rust now also owns all ten intended system wallet profiles and all four system
delivery destinations under `credential-template-system-catalog.json`, not
only the profiles currently used by a caller. One DRY catalog builder preserves
SpruceKit, Marty, generic OID4VCI, LISSI, disabled walt.id interoperability,
Sphereon, DC4EU, Google Credential Manager, Apple Wallet and DIDComm V2
capabilities plus both wallet and Canvas delivery modes. Startup seeding inserts
only missing IDs so operator-managed existing rows are not overwritten.

The template application layer now owns all ten template use cases behind one
repository and one fail-closed control-plane boundary: create, tenant-scoped
list/get, draft update, activate, deprecate, new version, delete, add claim and
internal active-template listing. Membership is enforced inside every public
use case. Create/update resolve the active issuer live; activation additionally
requires an active revocation profile and an accepting trust profile. Provider
failure occurs before persistence. The update plan now preserves claims,
derived attributes and display style exposed by the released request model but
previously left unwired by the Python handler.

Nine template HTTP operations are now executable through Axum: create, list,
get, update, activate, deprecate, new-version, delete and add-claim. Every route
requires the shared MMF service token plus a trusted forwarded user before the
application-level membership decision. Request DTOs reject undeclared fields,
validity aliases resolve against existing state, and responses reproduce the
public claim/privacy/TTL projection while omitting issuer algorithms, supported
formats, wallet configuration and null optionals. Black-box tests exercise
create/update/activate/delete and prove untrusted requests fail before use-case
execution.

The complete wallet-compatibility kernel now also runs in Rust under
`credential-template-wallet-compatibility.json`. All eight intended AAMVA,
ICAO, EUDI, Open Badges, enterprise and generic profiles plus unknown-format
fallbacks are retained. Organization overrides are active-only and tenant
bound, match canonical protocol aliases, sort by descending precedence with a
stable ID tie-breaker, and preserve exact unique APPEND versus component-wise
REPLACE behavior. Both languages prove the complete profile inventory from the
same fixture.

The registry application and HTTP slice now makes all 22 external operations
executable in Rust: ten template and compatibility operations, seven wallet
registry operations and five delivery-destination operations. One DRY registry
repository covers PostgreSQL wallets and destinations. Membership and explicit
wallet/destination administration remain fail-closed control-plane decisions;
system records are immutable; wallet ownership cannot be transferred; private
overrides are tenant-bound; aliases, same-device routing, capabilities and open
links use the shared Rust domain kernels. Unscoped wallet and destination lists
now return only global/system records. This closes an unsafe legacy Python
delivery-list behavior that could expose tenant entries when no organization
scope was supplied.

`credential-template-registry-behavior.json` is the shared route-level oracle
for catalog sizes, canonical formats and protocols, iOS routing, write status
codes, success bodies and tenancy rules. Rust black-box tests execute complete
wallet and destination CRUD plus compatibility and open-link behavior against
it; the surviving Python catalog and normalization oracle consumes the same
fixture, and its route suite proves the corrected unscoped destination rule.

The final two internal HTTP operations are now native as well, completing all
24 frozen routes. The issuance-context route preserves the public projection
and adds only the signing algorithm, supported formats, issuance protocol,
selective-disclosure fields, predicates, wallet configurations and full
validity rules needed by trusted issuance callers; retired cached profile,
provider, service and KMS coordinates remain absent. Dynamic OID4VCI metadata
advertises active DID-backed SD-JWT, mdoc and VC-JWT templates in their actual
production formats, skips unsupported or incomplete entries and treats the
issuer display-name lookup as optional. Unlike the legacy Python endpoint, a
repository failure now returns a dependency error instead of silently
publishing an empty successful configuration set.

`credential-template-internal-behavior.json` is the shared behavioral oracle
for the safe issuance snapshot, three advertised OID4VCI formats, skipped
formats, fail-closed repository behavior and optional display lookup. Rust
black-box and application tests and the surviving Python configuration kernel
consume the same cases.

All 12 frozen gRPC methods are now implemented by one native Tonic service over
the same template and registry applications as HTTP. The former Python adapter
implemented only get/list/configuration/wallet/health queries and deliberately
left six declared mutations absent; Rust now executes create, update, activate,
deprecate, version and delete as authenticated, tenant-authorized operations.
Every call requires the shared MMF service token, and tenant operations also
require trusted forwarded user identity. Repository/control-plane failures map
to unavailable, authorization failures map to permission denied and malformed
requests fail as invalid arguments.

The pre-v1 protobuf now carries the already-intended compliance, trust,
revocation, derived-attribute, full-validity, wallet-override and routing state,
plus an update mask so empty collections can be distinguished from omitted
fields. Removed custody selectors remain reserved and absent. The native
configuration method reuses the exact HTTP metadata kernel instead of the
legacy gRPC adapter's JWT-only approximation and empty-on-error fallback.
`credential-template-grpc-behavior.json` language-neutrally covers the complete
method inventory, authentication failures, lifecycle sequence, wire format,
wallet lookup, health and forbidden private fields.

The service now has its native executable and MMF lifecycle composition as
well. Fail-closed configuration normalizes the legacy asyncpg URL, rejects
invalid listener and dependency endpoints, and requires both the shared
service token and signing-key internal credential in beta and production. MMF
owns `/health`, `/ready`, `/version`, lifecycle transitions and required
component gating; the service adds explicit native-backend/version/capability
diagnostics. Startup connects PostgreSQL, applies and validates the Rust schema,
reconciles the system wallet/destination catalog, constructs the real control
plane, and binds Axum and Tonic with coordinated graceful shutdown.

One native control-plane adapter now consolidates organization membership and
administration, organization display names, active revocation profiles,
managed issuer DID resolution and trust-profile issuer acceptance. It preserves
the existing gRPC and internal HTTP protocols, forwards service credentials,
checks exact tenant/resource identities, rejects inactive or cross-tenant
responses, and refuses signing responses with incomplete identity state or
private JWK fields. `credential-template-control-plane-behavior.json` is the
shared language-neutral oracle for key-purpose selection, DID/method
normalization, disabled trust sources and fail-closed signing identity rules.

Credential Template did not previously publish domain events, so this port
does not invent a non-atomic event contract merely to enable an idle outbox.
The MMF transactional-outbox implementation remains the single shared Rust
implementation for services that own event behavior; Credential Template will
adopt it only with a documented event schema and atomic repository operation.

The Rust crate now passes 37 HTTP, gRPC, application, control-plane, runtime,
configuration, wallet, domain, lifecycle, catalog, surface, migration,
persistence and configured-PostgreSQL tests. The complete surviving Python
service oracle passes all 178 tests; formatting and strict Clippy pass. The
configured PostgreSQL tests run when `CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL`
is supplied.

The historical migration translation is now explicit rather than inferred.
`credential-template-migration-history.json` assigns each of the 45 Python
Alembic revisions to exactly one Rust owner: final schema/retired columns,
authoritative system catalog, legacy template reconciliation or history-only
merge. Rust migration head `rust_credential_template_0002` applies one-way,
idempotent repairs for compliance references, conformant Open Badge VC-JWT,
obsolete Spruce selectors and retired ICAO/mDL prototypes. Environment-aware
Rust reconciliation preserves public VCT and issuer-DID backfills, sole-active
revocation binding, fail-closed deprecation and the self-host login-only
catalog. Schema validation rejects every retired cached custody column and a
nullable compliance dependency.

This audit caught stale in-memory catalog behavior that had diverged from the
released safety migration: Apple is again an inactive compatibility
placeholder with no generic deep link, and the generic OID4VCI wallet no longer
claims unverified mdoc support. The Rust system catalog is authoritative for
immutable system IDs on every startup while organization overrides remain
untouched. Both surviving Python and Rust behavior now consume the corrected
fixtures; all 178 Python service tests and all 37 Rust tests pass, as do strict
Clippy and formatting. Docker/PostgreSQL configured execution is still gated
because this workstation cannot access the Docker API and no
`CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL` is configured.

Fresh-install ownership is now complete. The Rust catalog creates the final
released Marty login badge with its stable identity, public issuer/VCT/image,
eleven claims, compliance, trust and revocation dependencies, VC-JWT format and
ES256 signing behavior. A language-neutral catalog contract proves the final
shape on an empty store while startup remains idempotent and does not overwrite
an existing operator-managed record.

Native packaging is also wired without deployment. The shared service image
builds and dispatches `credential_template` directly to
`marty-credential-template`; the native CI image exposes ports 8003 and 9003;
base, beta and Oracle Kubernetes configuration supply the fail-closed runtime
dependencies; and readiness uses `/ready` rather than process-only health.
The complete beta Compose overlay renders successfully, four static packaging
contracts pass and an optimized release binary builds locally. CI now builds
the native image and executes the configured PostgreSQL migration,
reconciliation and repository contract against the database job.

The workspace-wide all-target compatibility gate exposed and fixed one
cross-service tenancy defect before cutover: Flow now passes the actual
organization ID when querying the credential-template wallet registry. Three
Flow behavioral suites assert that tenant propagation and all eight tests pass;
`cargo check --workspace --all-targets` is green.

Remaining Credential Template work is the aggregate immutable-MMF pin, a real
configured PostgreSQL run, container build/health acceptance, and external
provider acceptance. The local Docker daemon is unavailable and the Marty
workspace still points to MMF crates in a sibling worktree that is outside the
container build context, so an image result cannot yet be claimed. Once those
gates pass, delete the Python implementation, all 45 Alembic revisions and
implementation-specific Python tests immediately, retain the shared behavioral
fixtures, and add anti-reintroduction ownership checks. No beta deployment has
occurred; the only permitted beta update remains the single aggregate wave-three
deployment after every service slice lands.

Credential Template source cutover is complete in commit `9072bc8f`. The Rust
crate is now the sole runtime, domain, catalog, persistence and migration owner;
the Python migration runner no longer imports the service, and ownership marks
`credential-template-service` as `native-active` with a source-reintroduction
guard. The change removes all 78 tracked files under
`services/credential_template`, including 4,202 production Python lines and
15,795 tracked service linesâ€”plus the obsolete Python patch image.

The deletion audit found one external Python dependency on the old in-memory
wallet catalog. Verification now reads active wallet formats through the native
Credential Template gRPC service, fails closed when that service or catalog is
unavailable, and keeps the Rust system catalog as the single implementation.
The post-cutover gate passes 39 Rust tests, formatting, strict Clippy under Rust
1.95, 49 focused caller/ownership/packaging/release checks, Ruff syntax checks,
and the base-plus-beta Compose model. CI now independently runs the idempotent
migration executable and a pinned-PostgreSQL container health smoke in addition
to the repository contract. This host has no Docker daemon or configured test
database, so those live jobs remain merge requirements rather than being
silently skipped or weakened. No beta deployment has occurred.

### Presentation-policy port status

Presentation Policy has completed its local source cutover on the dedicated
`marty-ui-rust-presentation-policy-cutover-wave3` worktree and
`agent/marty-ui-rust-presentation-policy-cutover-wave3` branch, stacked on the
complete Credential Template slice. Rust is now the only tracked runtime,
domain, persistence, migration, catalog, verification and authorization
implementation. The cutover deletes all 26 tracked files under
`services/presentation_policy`: 13,172 Python lines in total, including 6,437
production Python lines. No Python runtime or migration fallback remains.

The baseline is frozen before implementation. All 193 surviving Python service
tests pass. `presentation-policy-service-behavior.json` records all ten HTTP
operations, all ten gRPC methods, four lifecycle states, eleven claim
constraints, eight request purposes, both legacy holder-binding normalization
cases, every released credential-format alias and all nine Alembic revisions.
Python executes the same contract rather than relying on a Rust-specific unit
test inventory.

The `marty-presentation-policy` crate owns the service domain and calls
`marty_verification::policy::evaluate_service_policy` directly. It does not
copy the decision engine currently reached through `_marty_rs`. The first Rust
behavioral tests prove surface completeness, holder-binding normalization,
format aliases, fail-closed lifecycle transitions, lossless new-version
creation and the existing cross-language verified-fact golden vector.

Rust now also owns the lossless PostgreSQL record, canonical policy document,
legacy-row upgrade, idempotent schema migration and tenant-scoped repository.
CI bundles and executes its configured PostgreSQL integration contract. The
shared application layer owns every lifecycle mutation and all authorization
actions. All ten frozen HTTP operations execute through that layer, including
saved and inline evaluation. Public DTO conversion preserves generated nested
identities, protocol-first required-claim bridging, holder-binding
normalization, paging and response projections without exposing internal IDs.
Raw tokens can enter the decision kernel only through a required verification
orchestrator that supplies cryptographically verified facts; an unavailable
or malformed verifier fails closed. All ten declared gRPC methods now use the
same application and verification layers, require authenticated service and
principal identities, preserve paging/filtering and expose complete nested
policy data. The Rust gRPC create path also rebuilds credential and alternative
requirements that the superseded Python adapter silently ignored.

The native executable, fail-closed deployed configuration and shared MMF
runtime are complete. Startup migrates and validates PostgreSQL, reconciles the
canonical built-in catalog, connects the live organization/trust/status control
plane, activates readiness only after every required dependency is healthy and
serves both Axum HTTP and tonic gRPC with graceful shutdown. Sensitive Flow and
Verification RPCs require exact workload mTLS URI identities. Managed issuer
scope preserves all explicit deployment aliases and the released public-URL/
organization-slug derivation rather than requiring a new beta-only setting.

Rust owns the final catalog produced by all historical seed and repair
revisions: the three email-only MemberLogin variants, conformant OpenBadgeLogin
with trust/revocation/freshness requirements and the private online age-proof
mDoc policy. Deterministic nested identifiers and repository-level
reconciliation make repeated startup idempotent. The language-neutral
`presentation-policy-catalog-behavior.json` freezes the final identities,
formats, claims, versions and trust behavior.

Native container packaging and entrypoint dispatch are wired for local and CI
images, and CI has a dedicated Presentation Policy image build. The complete
crate now has 28 green behavioral, startup, catalog and persistence tests and
passes formatting and strict Clippy. All 195 surviving Python service and
packaging tests pass, beta Compose renders with the complete immutable-artifact,
secret and workload-mTLS contract, and the full locked Rust workspace passes.
The workspace acceptance run also removed two unrelated nondeterministic gates:
Auth credential HTML now renders canonical LF output from either checkout style,
and Notification webhook JSON is recursively key-sorted before HMAC calculation
regardless of Cargo feature unification.

The verifier orchestration layer is now native and deterministic. It routes with
the canonical `marty-verification` format detector, applies request/policy/
requirement trust-profile precedence, supplies verifier-owned nonce and audience
context only when binding requires it, enforces trust-profile tenant identity,
enriches authenticated credentials with authoritative status evidence, and
projects every result into the one strict verified-facts request consumed by the
policy kernel. Malformed formats never reach a credential kernel and unavailable
trust dependencies fail closed. The language-neutral
`presentation-verification-facts.json` contract freezes this projection and its
trust/status normalization.

Concrete native credential adapters are now present for VC-JWT, VCDM Data
Integrity, SD-JWT and Open Badges v2/v3. JWT verification keys are selected from
exact active Trust Profile relationships or system overrides using the
unverified issuer and `kid` only as selectors; ambiguous keys, private JWK
material and untrusted relationships deny verification. The adapter preserves
the authenticated VC object while applying Open Badges profile verification,
so normalized claims cannot replace signed material. Malformed routes and the
temporarily unpinned mdoc route fail closed with no Python compatibility path.

Rust also owns the presentation-policy control-plane client at commits
`9dee79d4` and `774934e0`. It enforces live organization membership and action
permissions, loads tenant-bound Trust Profiles for every decision, evaluates
issuer relationship lifecycle/trust/compliance evidence, projects governed
Data Integrity methods and performs authenticated managed-issuer credential
status reads. `presentation-control-plane-behavior.json` freezes those
cross-service semantics independently of implementation language.

Complete mdoc issuer and holder authentication is also consolidated in the
shared `marty-verification` crate on the dedicated
`agent/marty-core-presentation-verifier-wave3` branch at commit `7169663`. The
Python extension delegates to that implementation and no longer directly owns
COSE, ISO mdoc, PEM, time or test-certificate dependencies. Ten focused mdoc
kernel tests and the complete 302-test verification suite pass. Publication and
the immutable Marty UI pin remain pending. The forced
loopback Git proxy is unavailable; bypassing it reaches GitHub but the local
credential is invalid, while connected GitHub writes cannot be approved under
the current session policy.

The native mdoc adapter, complete credential evidence projection and MMF Cedar
authorization path are enabled and covered by language-neutral fixtures. All 38
Presentation Policy Rust tests pass, including executable fail-closed startup,
mdoc lifecycle, replay-boundary, Cedar denial, catalog and configured PostgreSQL
contracts. Strict Clippy, formatting, the ownership scanner, focused cutover
checks and base-plus-beta Compose rendering pass locally. The consolidated
`presentation-policy-migration-history.json` assigns all nine retired Alembic
revisions to the native idempotent schema/upgrade and catalog owners; CI already
packages and runs the PostgreSQL migration/repository executable independently,
so a second migration binary would duplicate the same acceptance boundary.

Remaining work is publication and configured acceptance rather than source
porting: publish the shared mdoc and MMF security commits, replace the temporary
local core path and mixed Marty 0.1.57/0.1.59 graph with one immutable 0.1.59
revision, then run the locked image, PostgreSQL and external-provider CI gates.
No beta deployment has occurred; the only permitted update remains the single
aggregate wave-three beta deployment after every service slice lands.

### Applicant port status

Applicant has completed its local source cutover on the dedicated
`marty-ui-rust-applicant-cutover-wave3` worktree and
`agent/marty-ui-rust-applicant-cutover-wave3` branch. Rust is now the only
tracked runtime, domain, persistence, migration and protocol-orchestration
implementation. The cutover deletes all ten tracked Python files under
`services/applicant`, removing 5,652 lines immediately after the
implementation-neutral behavior, native executable, packaging and ownership
gates passed. There is no Python runtime or migration fallback.

The language-neutral `applicant-service-behavior.json` contract freezes all 32
canonical self-service and organization-review HTTP operations, the shared
Applicant/Application lifecycle, claim and evidence states, upload limits,
reviewer-lock TTL and all eleven intended capabilities. A second neutral vector
freezes the lossless MIP 0.2-to-0.3 JSON-store migration, including metadata
partitioning, template resolution, idempotency and fail-before-mutation
behavior. Both the retired Python oracle and the Rust crate executed these
contracts before deletion.

The `marty-applicant` crate owns one DRY lifecycle state machine, strict
template-derived field validation, tenant-bound profiles and applications,
biometric metadata, bounded and digest-verified evidence, reviewer locks,
vetting checks, request-information/review/withdrawal decisions and
retry-stable Flow issuance. Issuance reservations and exact claim snapshots are
persisted before external effects; a generated offer remains `OFFERED` until
the issuance transaction reports `issued`; expired offers and missing active
flows produce stable fail-closed claim blockers. Reads reconcile transaction
state through the Issuance service without reimplementing the canonical Rust
issuance transition kernel.

Production adapters preserve every intended service integration. Application
Templates and issued-credential inventory remain Issuance-owned; Flow offer
creation uses the purpose-bound `ApplicationEventAuthenticator` from
`mmf-security`; tenant-scoped domain events publish to the central Rust event
stream and governed Notification ingestion; and approval uses the single MMF
Cedar policy in `mmf-security` rather than an Applicant-local evaluator. The
shared image and entrypoint dispatch directly to `marty-applicant`, the
dedicated CI image owns its binary/health gate, startup runs the native
one-way store migration, and health diagnostics report the required Rust
backend and crate version.

The post-cutover local gate passes all 21 Applicant Rust behavior tests,
formatting, strict Clippy, the locked native binary build, 13 focused packaging,
ownership and runner regressions, the ownership scanner and base Compose
rendering. Four ownership-guard self-tests that require pytest temporary
directories remain host-blocked by the existing Windows/OneDrive temporary
ACL; the scanner they exercise passes directly. The local Docker daemon and a
configured live service stack are unavailable, so the dedicated image build,
health smoke and cross-service acceptance remain CI landing gates. No beta
deployment has occurred; Applicant will ship only in the single aggregate
wave-three beta update after every remaining service slice lands.

### Device Registration port status

Device Registration has completed its implementation and pre-deletion gates
on the dedicated `marty-ui-rust-device-registration-cutover-wave3` worktree and
`agent/marty-ui-rust-device-registration-cutover-wave3` branch. The
`marty-device-registration` crate is the single service implementation: Axum
owns all six released HTTP routes and stable response models; SQLx owns the
registration, immutable key-history and transition repositories; Redis owns
atomic one-time challenge allocation and compare-and-delete consumption; and
tonic preserves fail-closed active organization-membership checks.

The service does not duplicate cryptography. Canonical PKCS#1 RSA parsing, RFC
7638 thumbprints, PS256 proof verification, challenge message construction and
expiry/binding decisions, plus current/retiring key eligibility remain in
`marty-verification::device_auth`. The service crate adds only durable
allocation and lifecycle concerns. Key rotation is an exact PostgreSQL
compare-and-swap that moves the old key to bounded `RETIRING`, creates exactly
one next `CURRENT` version, updates the current-key projection and records the
transition in one transaction. Deletion is an idempotent, audit-preserving
deactivation that revokes current and retiring keys; re-registration receives
a new identity and history.

`contracts/device-registration-service-behavior.json` freezes the complete
route, challenge, failure, lifecycle and deployment contract independently of
either language. Rust also executes the shared `device_auth.json` challenge
golden vectors. The native migration uses an advisory lock, creates the same
schema constraints and partial indexes, rejects incomplete legacy key
projections, losslessly adopts complete legacy projections as version one and
never exposes a downgrade that could discard key history. The shared Python
migration runner no longer imports or owns this schema; native startup applies
and verifies it before binding the service listener.

The pre-deletion evidence is 27 passing Python-oracle tests (two configured
PostgreSQL/Redis tests skipped), nine Rust language-neutral/domain/HTTP/
migration tests, formatting, strict all-target Clippy, a locked native binary
build, Compose rendering and the dedicated non-Python image/CI target. The
remaining local limitation is the unavailable Docker daemon and PostgreSQL
test URL, so live image health, migration races and Redis replica acceptance
remain configured CI gates. After the ownership and packaging checks pass, all
21 tracked files under `services/device_registration` (3,220 lines) are deleted
in this same cutover; no Python fallback remains. No beta deployment occurs at
this stage. Device Registration joins the one aggregate wave-three beta update
after Verification, Deployment Profile and Compliance Profile have also
landed; production remains unchanged.

### Verification port status

Verification has completed its native implementation, behavioral gates and
same-slice Python deletion on the dedicated
`marty-ui-rust-verification-cutover-wave3` worktree and
`agent/marty-ui-rust-verification-cutover-wave3` branch. The
`marty-verification-service` crate is the only standalone Verification service
implementation. Axum owns all eight released HTTP operations, tonic preserves
the seven-operation legacy gRPC contract for development/internal callers, and
one shared application service owns both transports. Deployed inbound gRPC
remains fail closed because the released protobuf has no authenticated tenant
principal and has no production caller; beta and production configuration
reject enabling that ingress.

The port deliberately does not create another protocol implementation.
Presentation-policy and credential-template visibility, active-state and
tenant checks are resolved once through the public `marty-flow` presentation
resolver. OID4VP/DCQL request artifacts come from the canonical Flow and
`marty-core` implementation, while presentation evaluation remains in the
native Presentation Policy service. The standalone crate owns only session
orchestration: API-key and membership authorization through `mmf-security`,
Redis-backed storage, shared Redis time, atomic digest claims, stale-lease
recovery, fenced terminal commits, pagination and compatibility projections.
SIOPv2 `id_token` sessions preserve the intended no-policy `scope=openid`
path rather than manufacturing DCQL.

`contracts/verification-service-behavior.json` is the language-neutral
contract for routes, transport parity, stable protocol fields, status and
failure mappings, submission outcomes, public-wallet boundaries, fail-closed
dependencies and terminal-data minimization. Raw presentation tokens,
disclosed values, inspection payloads and callback destinations are never
retained in terminal records; only bounded decision evidence and digests
remain. Optional inspection is still supported through an explicit configured
gRPC method and remains non-fatal, without exposing its raw payload.

Before deletion, the Python oracle passed 38 tests with its two live-Redis
acceptance cases skipped because no local Redis service was configured. After
deletion, 14 Rust configuration, contract, state-machine, HTTP and gRPC tests,
the two shared Flow presentation-request tests, formatting, strict all-target
Clippy, a locked native binary build, 20 focused packaging/regression tests,
the ownership scanner and base/beta Compose rendering pass locally. All nine
tracked Python files under `services/verification` were then removed, deleting
3,529 lines with no fallback. The four ownership-guard self-tests that require
pytest temporary directories remain blocked by the known Windows/OneDrive ACL;
the scanner they exercise passes directly. Docker image execution and live
Redis replica behavior remain configured CI gates because the local Docker
daemon and service stack are unavailable. No beta deployment has occurred;
Verification joins the one aggregate wave-three beta update after Compliance
Profile lands, and production remains unchanged.

### Deployment-profile port status

Deployment Profile has completed its native implementation, behavioral gates
and same-slice Python deletion on the dedicated
`marty-ui-rust-deployment-profile-cutover-wave3` worktree and
`agent/marty-ui-rust-deployment-profile-cutover-wave3` branch. The new
`marty-deployment-profile` crate is the single implementation for all 14
released profile and lane operations. It preserves profile lifecycle,
environment and site bindings, callbacks, API-key/OAuth2/mTLS/JWT settings,
rate limits, all general and Canvas feature flags, complete branding and QR
configuration, trust/policy/template/default bindings, network and key-access
modes, environment and update policy, offline TTL, operator biometrics, audit
settings, enabled flows, one-time API-key disclosure and lane/device behavior.

The port closes three latent Python feature defects without changing the
intended API: callback/auth/rate/branding updates are now durably persisted,
all accepted QR and mTLS fields survive create/update storage, and lane
deletion checks the actual `device_ids` collection. Device assignment is
idempotent and unique across a profile under a PostgreSQL advisory lock and
row locks, eliminating the prior read-then-write race. Profile responses keep
private runtime configuration and complete API keys out of the public
projection.

`contracts/deployment-profile-service-behavior.json` freezes the transport,
enum, configuration and failure invariants independently of Python or Rust.
The same crate owns the Gateway canonical request/dependency/response contract,
so the 553-line duplicate Gateway implementation has been deleted. Generic
lifecycle, health/readiness, bounded gRPC transport and exact active tenant
membership authorization come from MMF crates rather than service-local
copies. Deployed startup requires PostgreSQL, a service token and workload
mutual TLS and has no Python fallback.

Rust now owns additive install/upgrade migration, final-schema verification,
legacy biometric-column adoption, migration history and the current Marty
Open Badge login seed under one advisory lock. The shared Python migration
runner no longer imports or creates this schema. Before deletion, the Python
oracle passed all nine tests. After deletion, 12 Rust contract/config/domain/
HTTP/migration tests, all 78 Gateway tests, formatting, strict all-target
Clippy, a locked binary build, 70 focused packaging/migration/Kubernetes tests,
the ownership scanner and base/beta/self-host Compose rendering pass locally.
All 18 tracked files under `services/deployment_profile` were removed, deleting
3,010 lines; the separate 553-line Rust Gateway contract duplicate was also
removed, and an ownership guard prevents Python reintroduction.

The dedicated native image and shared compatibility image both dispatch the
Rust binary. CI, beta, self-host and Kubernetes manifests include its workload
identity and native health path. The local Docker daemon and PostgreSQL URL are
unavailable, so built-container health and live migration concurrency remain
configured CI gates. No beta deployment has occurred. Deployment Profile joins
the one aggregate wave-three beta update after Compliance Profile lands, and
production remains unchanged.

### Compliance-profile port status

Compliance Profile has completed its native implementation, behavioral gates
and same-slice Python deletion on the dedicated
`marty-ui-rust-compliance-profile-cutover-wave3` worktree and
`agent/marty-ui-rust-compliance-profile-cutover-wave3` branch. The new
`marty-compliance-profile` crate is the single implementation for all eight
released HTTP operations. It preserves DRAFT, ACTIVE, SUSPENDED and DEPRECATED
status semantics; every credential format and issuance protocol; issuer
artifact and trust-profile constraints; API-surface metadata; discovery;
framework references; retention, consent and audit policy; data minimization;
jurisdiction and residency constraints; age verification; lifecycle changes;
pagination; and the four OID4VC, ISO 18013-5, Open Badges 3.0 and ICAO VDS-NC
system profiles.

The port reuses the canonical `CredentialFormat` parser from
`marty-credential-template` rather than maintaining another format map. Generic
lifecycle/readiness, bounded gRPC transport, service identity and exact tenant
permission checks come from MMF crates. Seeded system profiles are now
migration-owned and immutable: public discovery remains anonymous and returns
only active discoverable profiles, while organization profiles require the
exact action permission. This closes the Python path that allowed API callers
to create or mutate system profiles through broad role aliases. The parity
audit also caught and fixed an initial Rust seed coupling so ISO 18013-5
correctly requires DID material without incorrectly requiring JWK material.

`contracts/compliance-profile-service-behavior.json` freezes all routes, enum
families, seven policy sections, system catalog and fail-closed invariants
independently of either implementation language. The public response remains
protocol-scoped and does not expose internal retention, consent, audit,
minimization, jurisdiction, age or framework policy, while PostgreSQL stores
the complete profile as a durable JSONB policy aggregate under indexed tenant,
status and discovery projections. Native startup owns additive schema history,
scope constraints, indexes and idempotent system seeds under an advisory lock;
there is no process-local production repository or Python fallback.

Before deletion, all five Python behavior-oracle tests passed. After deletion,
11 Rust contract/config/domain/HTTP/migration tests, formatting, strict
all-target Clippy, a locked native binary build, 62 focused packaging,
ownership, Kubernetes and workload-identity tests, the direct ownership
scanner, JSON and PowerShell syntax validation, and base/beta/self-host Compose
rendering pass locally. The four ownership-guard self-tests that manufacture
temporary repositories remain blocked by the known Windows/OneDrive temporary
directory ACL; the real scanner they exercise passes directly and those tests
remain configured in CI. Both tracked Python files under
`services/compliance_profile` were removed, deleting 1,194 lines, and an
ownership guard prevents reintroduction.

The dedicated non-Python image, CI build target, beta and self-host Compose
profiles, Kubernetes manifest and deployment helpers now provision the native
binary with a service-scoped client certificate. The local Docker daemon and
PostgreSQL URL remain unavailable, so executable container health and live
migration concurrency are configured CI gates. No beta deployment has
occurred. Compliance Profile completes the ordered wave-three service ports;
publication/pinning, aggregate CI and one aggregate beta-only deployment and
soak remain. Production remains unchanged.

### Aggregate landing status

The completed service stack is integrated on
`agent/marty-ui-rust-wave3-aggregate` with current `main` merged cleanly. All 62
focused post-cutover packaging, Kubernetes, workload-identity and stack
contract tests pass, and the Rust ownership scanner reports no duplicate
Python service implementation.

The canonical dependencies are now published and merged: MMF PR #89 landed at
`1c6a9d180fec3670b435d36fda5170a669405ab2`, and `marty-core` PR #247 landed at
`4a2d2c32f9f1e3641a402ce9bb18cd47c4d7da2d`. The aggregate Cargo workspace is
pinned to those immutable revisions; no service depends on a migration
worktree path. Both repositories passed their protected CI and merge-queue
gates, and normal review protection was restored immediately after merge.

The full aggregate Rust workspace passes locked all-target tests, strict
Clippy, formatting, and immutable-revision compilation across every shared and
service crate. Remaining work is to land the aggregate UI PR through protected
CI, create one coordinated commit-pinned release snapshot, perform exactly one
beta-only deployment, and record the behavioral acceptance soak. No wave-three
beta deployment has occurred yet, and production remains unchanged.

### Trust-profile port status

Trust Profile has completed its local native cutover on the dedicated
`marty-ui-rust-trust-profile-wave3` worktree and
`agent/marty-ui-rust-trust-profile-wave3` branch, stacked on the complete
Presentation Policy state. Rust now owns the service runtime, application,
domain, PostgreSQL repository, additive schema migration, system catalog,
control-plane authorization, all HTTP adapters, internal decision projection,
registry transport, scheduled refresh and lifecycle diagnostics.

`trust-profile-service-behavior.json` is now the implementation-neutral oracle.
It freezes all 32 public and internal HTTP operations, twelve enum families,
three system frameworks, eight durable tables, the complete ten-revision chain,
registry synchronization bounds and atomicity, destination/TLS/redirect policy,
80%-of-interval scheduled refresh, per-profile scheduler failure isolation,
decision-time certificate revalidation, tenant permissions, internal service
authentication, issuer uniqueness, cascade behavior and custody-metadata
scrubbing. Rust tests execute the oracle directly; no Python behavior oracle or
native wheel is required.

The `marty-trust-profile` crate owns that domain and surface inventory. It
does not copy trust-registry synchronization: protocol constants, catalog,
URL/destination policy, import decisions, feed validation, sequence handling and
certificate-state revalidation remain in the existing
`marty_verification::trust_sync` kernel. Generic guarded outbound HTTP, DNS/IP
classification, redirect suppression, body bounds and operator CA handling live
once in `mmf-platform`. The parity audit found and closed two pre-deletion gaps:
scheduled registry refresh and legacy-compatible fail-closed 503 decisions for
unsynchronized, stale, malformed or unsupported registry state.

Commits `8c2282a9` and `cbb35827` add the scheduler/decision parity and native
packaging. The shared service image, dedicated CI image, development, beta,
self-host and Kubernetes manifests now select the Rust binary and supply its
fail-closed configuration. CI packages and executes the real PostgreSQL
migration contract. The full Rust suite, strict Clippy, 16 cutover/migration
tests, 90 stack/Compose/release tests, nine entrypoint tests and rendered base
and beta Compose models pass locally.

The superseded `services/trust_profile` runtime, adapter, native bridge,
scheduler, implementation-specific tests and all ten Alembic revisions have
been deleted immediately after those checks: 10,241 tracked lines were removed.
The Python migration runner no longer claims the schema, and anti-reintroduction
tests require the Rust runtime and migration owner. Remaining external gates are
publication and immutable pinning of the clean MMF branch, the configured CI
PostgreSQL execution, and a built-container health check; Docker is unavailable
on this workstation. No beta deployment has occurred, and production remains
unchanged. These gates join the aggregate wave-three landing before the single
permitted beta deployment and acceptance soak.

The frozen contract contains 64 explicitly gateway-owned declarations: 18
well-known discovery routes, 14 internal signing-key compatibility routes,
9 organization-scoped discovery/DID routes, 6 credential metadata routes, 3
VC-API routes, 4 health/readiness routes, 5 organization composition routes,
4 retired Canvas state routes and the event-stream bridge. Rust now owns VC-API
JWT/JOSE-envelope/Data-Integrity representation adaptation, inline
OID4VCI offer parsing, issuer extraction, evaluation request construction, and
verification-result mapping. Both Python and Rust execute
`contracts/vc-api-adapter-behavior.json`; the complete existing Python VC-API
suite remains green. All three VC-API handlers are executable through the Axum
runtime. Verification delegates cryptographic decisions to the canonical
presentation-policy service. Issuance delegates transaction creation, token
redemption, nonce issuance, and credential production to the canonical
issuance service; its holder proof comes directly from the pinned
`marty-oid4vci` crate, and the adapter fails closed unless exactly one native
`ldp_vc` Data Integrity credential is returned for the requested issuer DID.
The superseded Python VC-API module was deleted with the Gateway runtime after
the executable, packaging and language-neutral behavioral gates passed.

Rust also owns the exact Marty and Canvas credential badge metadata, criteria,
well-known VCT aliases, and SVG assets. Shared fixtures compare complete JSON
bodies and byte-level asset digests in Python and Rust. Gateway-local health,
OpenID, MIP and release documents now execute in Axum. Issuance-backed root,
organization-scoped, insertion-style, appended-style, walt.id,
credential-manager, Apple Wallet, JWKS, OAuth and generic credential-type
discovery aliases are planned and normalized in Rust while the issuance
service remains the canonical metadata source.

Both public `did:web` resolution routes now execute in Axum and delegate slug
lookup and DID document persistence to the existing Rust signing-key service.
The gateway adapter preserves public-domain port encoding, exact scoped-record
integrity, safe legacy-document retargeting, empty-document compatibility,
`application/did+json`, five-minute caching and fail-closed registry errors.
`contracts/gateway-did-web-behavior.json` runs against both languages.

The 14 service-to-service signing-key compatibility operations are frozen in
`contracts/gateway-internal-signing-behavior.json`. Their dedicated API key is
checked independently in constant time and is replaced with the configured
gateway-to-service credential before proxying. List, get and delete
issuer-profile operations already execute against the canonical Rust profile
store; delete retains the legacy response envelope. Flow-key wrapping and
unwrapping now execute in the Rust signing service through one bounded OpenBao
Transit provider. The encrypted envelope is bound to the organization, flow,
schema and OID4VP response-decryption purpose; malformed key material,
provider failures and binding mismatches fail closed. The gateway replaces any
client-supplied organization field with its authenticated service scope before
forwarding. Issuer-context selection also executes in the Rust signing
service: it resolves by DID or the explicit `org_managed` default mode, requires
exactly one active profile, validates the profile/service/registry binding,
preserves profile-level X.509 material and rejects the removed private profile
selector. Organization-scoped issuer-DID resolution and both profile identity
projections now also execute in Rust. They select exactly one compatible active
profile, bind it to the registered service and DID assertion method, strip
private JWK parameters, preserve public certificate material without exposing
provider credentials, reject cross-tenant or ambiguous records, and retain the
legacy profile/public response shapes. Python and Rust execute the same
`contracts/gateway-issuer-identity-behavior.json` fixture, while Axum black-box
tests cover all three gateway adapters. All 14 operations now execute in Rust:
direct-service and DID-mediated signing, profile creation/update, and
certificate attachment joined the previously completed read, delete,
envelope, context and identity operations. Signing delegates to the canonical
KMS provider, profile writes reuse the canonical profile/document kernels,
managed OpenBao keys retain create-and-retry behavior, and certificate chains
are persisted and re-resolved without exposing custody configuration.

#### Gateway completion slices

The remaining gateway work proceeds in descending removable Python size and
dependency order. Each slice first records behavioral HTTP/provider fixtures,
runs them against Python and Rust, and deletes the superseded Python behavior
as soon as the full gate passes.

| Order | Slice | Required parity before deletion |
|---|---|---|
| 1 | Proxy trust-boundary policies | Complete: issuance/internal service credentials, trusted identity headers, special ownership/path rewrites, trusted path/query organization projection, request/response bounds, retries and public protocol exceptions pass |
| 2 | Public DTO and privacy adapters | Complete: the route-by-route audit covers organization, issuance creation/lifecycle, credential templates, trust/issuer/registry sync, presentation policies, OID4VP flow start, flow definitions/instances/results, deployment profiles/lanes, VC-API and all corresponding privacy projections |
| 3 | Cross-service composition | Complete: organization dashboard counts, runtime readiness, integration metadata, lifecycle/retention aggregation, dependency preflight, manual Hosted Pilot purge and the paginated scheduled sweep execute in Rust |
| 4 | Streaming transport | Complete: tenant-filtered event-stream gRPC subscription is exposed as bounded SSE with exact frames, disconnect cancellation, backend-failure handling, ETag bypass and cross-tenant rejection |
| 5 | Cutover and deletion | Complete locally: final 688-test Python baseline, 80 Rust tests, three executable tests, strict Clippy, ownership/stack/Compose gates, Python deletion and anti-reintroduction checks pass; remote Redis/container CI and immutable MMF publication remain aggregate landing gates |

The gateway branch currently uses temporary local paths for the unpublished
MMF platform/security commits through local commit `498fb39`. It must be
repinned to the landed MMF commit
before publication; no branch with local worktree dependencies may merge.

Distributed rate-limit and idempotency state now uses the canonical MMF Redis
adapters. Both adapters are atomic, expose health checks, preserve all four MMF
rate-limit strategies, and use owner-token idempotency leases. Gateway provider
composition permits canonical process-local adapters only in explicit
development mode; production startup and any configured Redis failure refuse
local fallback. The composed release executable is built locally and its
process-level tests prove both missing and unavailable Redis terminate startup.
CI now provisions a pinned disposable Redis instance and explicitly exercises
all four strategies plus idempotency lease ownership, in-flight repetition,
payload conflict, completion and exact replay through the production provider
composition.

The CI-only native service image has a dedicated non-Python gateway target and
container health smoke test. The ownership manifest records the gateway as
`native-active`, and its guard rejects every Python source reintroduced below
`services/gateway`. The deletion removed 37,048 tracked lines across the
Python runtime, implementation-specific tests and obsolete Python AST route
extractor. The remaining aggregate landing gates are publication of MMF commit
`498fb39` at an immutable remote revision and execution of the Redis and
container gates in CI. The public-protocol gate no longer imports the Python gateway: it freezes
all 40 exact DTO field/required sets, compares them with the pinned protocol,
rejects recursively exposed private state, and requires every gateway behavior
vector to execute in Rust. The superseded 1,306-line Python-runtime checker was
deleted. Docker cannot be executed in the current Windows
sandbox, and GitHub publication is unavailable because the configured token is
invalid and the configured local proxy cannot reach GitHub; neither condition
permits a silent local substitute.

### Delivery and deletion rules

1. Capture language-neutral HTTP, gRPC, event, storage, configuration,
   observability and provider fixtures before implementation.
2. Implement shared behavior in MMF crates first and domain behavior in the
   owning Rust service.
3. Run the same fixtures against Python and Rust until parity, including
   malformed input, unavailable dependencies, concurrency, timeout, retry and
   disconnect cases.
4. Switch packaging and deployment dispatch to Rust, verify startup and public
   behavior, then delete the Python service and implementation-specific tests
   in the same slice.
5. Guard against reintroduction of Python services and duplicated MMF behavior.
6. Land and test all wave-three slices without repeatedly updating beta. After
   every slice and cross-repository release has landed, perform one aggregate
   beta deployment and soak. Production remains unchanged.

## Implementation status (2026-08-15)

The first-wave deterministic protocol, cryptographic, policy, validation,
state-machine, wallet, licensing, DTC, and VDS-NC kernels have one canonical
Rust owner. The machine-readable inventory records all 19 governed
capabilities as `native-active`. Remaining Python and Dart files listed by the
inventory are orchestration, transport, storage, provider, DTO, UI, platform,
or deliberately thin native adapters; they do not contain a second maintained
decision kernel.

| Gate | Final state | Accepted evidence |
|---|---|---|
| Event-stream whole-service removal | Complete: `services/event_stream` is deleted and the shared image dispatches the canonical Rust executable in every stack | Executable-level public HTTP/gRPC behavior, tenant filtering, health, packaging, and regression contracts pass in CI |
| Revocation-profile whole-service removal | Complete: the Python service, status-list kernel, and Alembic ownership are deleted; the shared image dispatches the canonical Rust executable | Public issuance/status/revocation/re-verification behavior plus failure, concurrency, storage, migration, packaging, and regression contracts passed before merge |
| Phase 9 release and evidence | Complete at the approved beta boundary | Immutable Rust/UI releases, a single beta update, commit-pinned composition evidence, fail-closed checks, and the protected public lifecycle run are recorded in the [final migration evidence](rust-migrations/final-migration-evidence-2026-08-14.md) |
| Wave-two port, deletion, and aggregate acceptance | Complete at the approved beta boundary | All nine ordered workstreams, release artifacts, fail-closed rollout findings, final v1.1.194 beta deployment, and protected lifecycle acceptance are recorded in the [wave-two final evidence](rust-migrations/wave-two-final-evidence-2026-08-15.md) |

All first-wave implementation, deletion, enforcement, packaging, and beta
behavioral gates have passed. A follow-up inventory found eight initial
second-wave targets that still contain deterministic security decisions or
whole-service behavior in Python, JavaScript, or Dart. Implementation exposed
a ninth target: the remaining Python eMRTD elementary-file, DG15, and
biometric-template parsers. Completed and active workstreams are recorded
below. Production and persistent self-host configurations remain unchanged.

The notification/webhook workstream is now `native-active`: the Rust service
owns REST, gRPC, PostgreSQL migrations and persistence, Transit-bound secrets,
SSRF-resistant delivery, and the durable outbox. Language-neutral HTTP, gRPC,
HMAC, migration, concurrency, and PostgreSQL/OpenBao contracts passed before
the superseded Python service, adapters, migrations, and implementation tests
were deleted. The cutover was not deployed separately; it is active as part of
the accepted v1.1.194 aggregate beta update.

The subscription API-key workstream is implemented in
[`marty-subscriptions` PR 31](https://github.com/ElevenID/marty-subscriptions/pull/31).
The private `marty-license` crate now owns key material, format and hash
validation, scope and CIDR decisions, expiry, plan quotas, consumption costs,
minute-rate decisions, webhook secrets and signatures, and Square webhook
verification. Python retains database, Redis, HTTP, and DTO orchestration only;
the previous Python cryptographic and policy kernels were deleted after the
same language-neutral fixture passed in Rust and through the installed wheel.
The PR merged as `4c8d7f553c5c9cfe8acdbbe5d85b4278829f6cf1`.

The trust-registry synchronization workstream is implemented in
[`marty-core` PR 236](https://github.com/ElevenID/marty-core/pull/236) and
[`marty-ui` PR 546](https://github.com/ElevenID/marty-ui/pull/546). Rust now
owns the registry catalog, URL and resolved-destination policy, request plans,
strict feed and persisted-state schemas, public and remote sync tokens,
pagination, sequence checks, scheduling, atomic deltas, removals, certificate
validity, and CSCA/DSC profiles. Python retains DNS, TLS, bounded HTTP
streaming, DTO, repository, and task orchestration. The unused hard-coded
Python catalog and superseded Python state-machine, IP, URL, Pydantic, and
X.509 decision implementations were deleted after the embedded
language-neutral fixture and the existing service behavior suite passed.
The canonical and consuming PRs merged as
`780ea7c45164b6c314ac62e4a7704c030ad7c45b` and
`ed43849c4eae11be9e896bbe417b8209ed1afb11`, respectively.

## Wave two — ordered by removable non-Rust implementation

Wave two is delivered in descending order of the non-Rust implementation that
can be removed after parity. Line counts are physical source estimates used to
order work, not completion metrics and not permission to discard behavior.

| Order | Workstream | Baseline removable source | Status | Canonical destination |
|---|---|---:|---|---|
| 1 | Signing-key and KMS service | approximately 7,820 deleted Python lines | Complete on `main`: Core 0.1.57 is published and the complete Rust signing/KMS service stack, exact wheel pins, behavioral contracts, and deletion checks passed through protected merge trains | shared key/JWK/certificate decisions in `marty-core`; Rust service in `marty-ui` |
| 2 | Marty CLI and API client | 7,218 deleted handwritten JavaScript lines | Complete on `main`: native CLI and Rust/WASM browser client are compatibility-tested, packaged, and merged | native Rust workspace, executable, and browser/WASM client in `marty-cli` |
| 3 | Notification and webhook service | 7,142 deleted Python/service lines | Complete on `main`: public REST/gRPC, storage, outbox, delivery, secret-envelope, migration, and packaging contracts passed before the Python service was deleted | Rust service in `marty-ui` using the established service foundation |
| 4 | Credential attestation, evidence, governance, and VCDM decisions | 1,804 deleted Python lines in the current slices | Complete on `main`: Core decision and attestation kernels, fail-closed adapters, shared behavioral fixtures, Python implementation deletion, and complete cross-platform native-wheel, Python, Rust, WASM, PostgreSQL race, security, and packaging matrices passed | `marty-oid4vci` and `marty-verification`, consumed by `marty-credentials` |
| 5 | Passport-chip protocol and integrity kernels | more than 1,300 deleted Python lines in the current slices | Complete on `main`: Core BAC, PACE compatibility, EAC, active-authentication, ISO 9796, APDU, and integrity kernels plus Marty compatibility adapters and Python implementation deletion passed | `marty-verification::chip_io`, `marty-verification::active_authentication`, and `marty-crypto::iso9796` |
| 6 | Remaining eMRTD EF, DG15, and biometric-template parsing | approximately 1,300 deleted Python lines | Complete on `main`: bounded Rust parsers, bindings, DTO/chip-I/O adapters, exact cross-language vectors, deletion checks, and consuming CI passed | `marty-verification` eMRTD parser modules |
| 7 | Subscription API-key lifecycle | approximately 539 Python lines plus duplicated plan/webhook kernels | Complete on `main`: canonical Rust policy/cryptography, fail-closed adapters, shared Rust/Python vectors, Redis/SQL orchestration tests, and deletion checks passed | `marty-subscriptions/packages/verifier_entitlements/marty-license` |
| 8 | Trust-registry synchronization kernel | approximately 433 Python lines | Complete on `main`: canonical Rust policy/state/X.509 kernel, fail-closed adapter, startup diagnostics, exact shared vectors, service regression suite, and Python implementation deletion passed before both PRs merged | `marty-verification` trust registry plus `marty-crypto` certificate validation |
| 9 | Wallet status-list and liveness decisions | at least 378 deleted Dart kernel lines | Complete on `main`: bounded Core status decoding, Rust bridge kernels, shared behavioral fixtures, fail-closed adapters, and Dart implementation deletion passed the complete Flutter, Android, iOS configuration, generated-binding, coverage, and policy suites | `marty-status` and `marty-biometrics` through Flutter Rust Bridge |

The ordering applies to starting each workstream. A prerequisite canonical
crate PR may land before its consuming service PR, but a smaller workstream is
not substituted for an unfinished larger one merely to improve language
statistics.

### Wave-two porting requirements

This wave is a functionality-preserving port, not a feature-reduction project.
Before deleting any source, each workstream must inventory intended behavior
from public routes, schemas, CLI help and output, provider contracts, storage
semantics, configuration, error responses, observability, and tests. Existing
implementation defects are captured as explicit negative fixtures; security
corrections must retain the surrounding feature rather than remove its path.

1. **Signing-key and KMS:** preserve all service, key lifecycle, CSR,
   certificate, JWKS, DID, issuer-profile, wrapping, signing, rotation, audit,
   provider-capability, and provider-interoperability behavior. Provider SDK
   transports become Rust trait adapters. Python route, KMS, migration, and JWK
   conversion implementations are deleted after public HTTP and provider-stub
   contracts pass.
2. **CLI:** preserve command names, aliases, options, config/environment
   precedence, authentication, secret handling, API requests, stdout/stderr,
   machine-readable output, and exit codes. The current black-box HTTP-stub
   suite runs against both executables before the Node package is replaced.
3. **Notification:** preserve REST and gRPC APIs, schemas, HMAC payloads,
   destination security, subscription and webhook lifecycle, atomic outbox
   leasing, idempotency, retries, circuit breaking, secret envelopes,
   persistence, metrics, and provider delivery contracts.
4. **Credential decisions:** preserve key-attestation claims and trust policy,
   token-status validation, evidence transitions and reconciliation, canonical
   governance digests, purpose authorization, and VCDM validation. Python keeps
   external fetching, tenant composition, persistence, and API orchestration
   only when those layers do not determine the result.
5. **Passport chip:** preserve every intended BAC/PACE/EAC, active
   authentication, APDU, secure-messaging, DG15, and ISO 9796 outcome. Placeholder
   or mock cryptography is never treated as valid behavior; standards vectors
   and APDU transcripts define the replacement. A feature may be retired only
   through an explicit public-caller and contract inventory proving it was not
   intended or exposed.
6. **eMRTD data parsing:** preserve bounded BER-TLV/DER handling, EF.COM data
   group discovery, TD2/TD3 DG1 results, DG2 facial/fingerprint/iris metadata,
   quality outcomes, DG15 SPKI algorithms, RSA parameters, fingerprints, and
   existing typed Python models. Run malformed-length, truncation, oversized,
   unsupported-algorithm, and valid standards vectors directly in Rust and
   through the Python adapter before deleting the parser implementations.
7. **API keys:** preserve key formats, hashing, masking, scopes, CIDR rules,
   expiry, rotation, plan quotas, storage, and audit behavior. Redis quota
   consumption becomes atomic and unavailable enforcement fails closed in
   production-like profiles.
8. **Trust registry:** preserve bounded destination fetching, pagination,
   sequence and token handling, atomic delta application, removals, certificate
   profile checks, persistence, and synchronization scheduling. Rust owns feed,
   state-machine, and X.509 decisions; orchestration may retain HTTP and storage
   adapters.
9. **Wallet status and liveness:** preserve supported status purposes, caching,
   user-visible states, challenge steps, camera flow, and offline behavior.
   Rust owns signed status-list trust/freshness/bit decisions and canonical
   liveness challenge signing/validation. Status-check failure cannot silently
   produce a valid credential, and no embedded development secret is accepted
   as a production trust root.

Every workstream adds language-neutral fixtures that execute directly against
Rust and through the public wrapper, service, mobile bridge, or executable.
Tests that import private functions from the implementation being removed do
not satisfy the parity gate.

### Active wave-two evidence

- Signing-key/KMS implementation is split across
  [marty-core PRs 229](https://github.com/ElevenID/marty-core/pull/229) and
  [233](https://github.com/ElevenID/marty-core/pull/233), plus
  [marty-ui PRs 515](https://github.com/ElevenID/marty-ui/pull/515),
  [518](https://github.com/ElevenID/marty-ui/pull/518),
  [520](https://github.com/ElevenID/marty-ui/pull/520),
  [522](https://github.com/ElevenID/marty-ui/pull/522),
  [524](https://github.com/ElevenID/marty-ui/pull/524), and
  [527](https://github.com/ElevenID/marty-ui/pull/527). The final shared
  signing/JWK conversion and minimal-feature dependency correction merged as
  `34cf79d77161feba79934cb78700f885edf07a75` after the complete protected
  merge-group matrix passed. [Core 0.1.57](https://github.com/ElevenID/marty-core/releases/tag/v0.1.57)
  was published from `54ff554906f5fa2791b7fcb6a5965d7e8db8b0e8` and pinned by exact
  release-wheel hashes. The service foundation and five deletion slices
  merged as `4dc470150fe5816a74bf9a09c291d725a5316b02`,
  `ac15bfd9886a56babfa5e847f6481c02ab07718a`,
  `56bcaaddd0ff12c0b616bacf0891b94d9d18d54e`,
  `c0c7f53d5f8daa05f58dc4bb5e67829f766b2720`,
  `91f60663026cb1411fbc5ce362ff5863cc0a9c6c`, and
  `5b62726c380766d324a0a5417875e89b74c3e1e7`. The top-stack Rust suite
  executed 42 tests successfully, with three Redis integration tests
  intentionally ignored when no test Redis URL was configured; all 19
  release contracts and every protected PR and merge-group matrix passed.
- [marty-cli PR 14](https://github.com/ElevenID/marty-cli/pull/14) replaces the
  Node executable and browser HTTP kernel with one Rust implementation. Its
  language-neutral command vectors, native HTTP tests, Rust/WASM compatibility
  tests, release-shaped package check, unchanged UI service suite, and UI
  production bundle passed before the superseded handwritten JavaScript was
  deleted. It merged as `60e438802a83a201ebe8a7db5e31194a116dc161`.
- [marty-ui PR 529](https://github.com/ElevenID/marty-ui/pull/529) implements
  the notification/webhook service as one Rust executable and deletes 7,142
  superseded Python/service lines after public HTTP/gRPC, provider, outbox,
  persistence, migration, security, and image contracts passed. It merged as
  `3dc00a96be73c2d122b9a167ead111912944f8bc`.
- Credential policy/evidence and key-attestation work is implemented in
  [marty-core PRs 230](https://github.com/ElevenID/marty-core/pull/230) and
  [231](https://github.com/ElevenID/marty-core/pull/231), with fail-closed
  Python adapters in
  [marty-credentials PRs 182](https://github.com/ElevenID/marty-credentials/pull/182)
  and [183](https://github.com/ElevenID/marty-credentials/pull/183).
  The Core PRs merged as `918ad5e167ba4424a8fa5d8b045bf073bd640cb4`
  and `2d7419847fc01641bbe726627397280df258b5e6`. The consuming PRs
  merged as `b9e305da4c7b84471a5f0de7ee849cb36817248c` and
  `dc942c8f4a72e640579b75a2ba0c8b2cb7cf3695` after both PR matrices
  and both protected merge-group matrices passed the complete native-wheel,
  Python, Rust, WASM, PostgreSQL race, security, packaging, and
  language-neutral behavior lanes. The immutable 0.1.64 consumer release is
  prepared in [marty-credentials PR 187](https://github.com/ElevenID/marty-credentials/pull/187)
  for the final aggregate stack pin; no migration slice was deployed
  independently.
- Passport protocol/integrity work is implemented in
  [marty-core PR 232](https://github.com/ElevenID/marty-core/pull/232) and
  [Marty PR 51](https://github.com/ElevenID/Marty/pull/51). The Core PR merged
  as `eb28f3dbfe48bb5c40d883466e512ea3d8f35a2c`; the fully green
  consumer merged as `8467c7a4d82ee5f0e1bb39675bccb4dbff414cb6`.
  The remaining
  eMRTD EF/DG15/biometric parsers are implemented separately in
  [marty-core PR 235](https://github.com/ElevenID/marty-core/pull/235) and
  [Marty PR 54](https://github.com/ElevenID/Marty/pull/54). The same
  language-neutral fixture runs directly in Rust and through preserved Python
  DTOs; malformed or unavailable native paths fail closed, and the Python
  struct/ASN.1/hash implementations plus their `pyasn1` dependency are removed.
  The consuming PR merged as
  `97a0c9cba664639f162ed40a3e4eaf61803bd582`.
- [marty-subscriptions PR 31](https://github.com/ElevenID/marty-subscriptions/pull/31)
  moves the API-key lifecycle and adjacent subscription webhook cryptography
  into `marty-license`. One JSON fixture executes directly against Rust and
  through the installed PyO3 wheel; Redis cost/expiry behavior, exact quota
  boundaries, plan compatibility views, missing-native failures, and missing
  Redis enforcement are covered before the Python `hashlib`, `hmac`,
  `ipaddress`, `secrets`, and literal plan-policy implementations are removed.
- [marty-core PR 236](https://github.com/ElevenID/marty-core/pull/236) and
  [marty-ui PR 546](https://github.com/ElevenID/marty-ui/pull/546) move the
  trust-registry catalog, destination policy, request construction, feed/state
  schemas, public and remote tokens, pagination, sequences, scheduling, atomic
  deltas, removals, and certificate profiles into Rust. One embedded JSON
  fixture executes directly in Rust and through the installed `_marty_rs`
  wheel; the unchanged registry route/sync tests prove transport, TLS, SSRF,
  storage, and response compatibility before the Python kernels are removed.
  The Core and consuming PRs merged as
  `780ea7c45164b6c314ac62e4a7704c030ad7c45b` and
  `ed43849c4eae11be9e896bbe417b8209ed1afb11`.
- [marty-core PR 238](https://github.com/ElevenID/marty-core/pull/238)
  adds bounded W3C status-list decoding over the existing language-neutral
  recommendation vector, and
  [marty-authenticator PR 35](https://github.com/ElevenID/marty-authenticator/pull/35)
  moves status entry/list parsing and final bit decisions plus liveness
  challenge creation, signing, and verification into Rust. Dart retains only
  HTTP/cache, camera, gesture, and UI orchestration. The Dart Base64/GZIP/HMAC
  and random-ID kernels are deleted in the same PR, guarded against
  reintroduction. Generated bindings are current; the Flutter unit, Android,
  iOS configuration, build, and shared quality lanes pass. Maintained Dart
  line coverage is 90.47% (655/724) after excluding seven generated files,
  with production adapter, cache, compatibility, endpoint-failure, and
  unsupported-purpose behavior exercised. The consumer merged as
  `8bc37873484cacf7a0424214bb01443d4ce97ee7`. Its unrelated OID4VCI
  dependency remains on the previously validated revision because updating
  that crate would remove format-only issuance behavior; this preserves the
  public feature while keeping status-list and liveness ownership canonical
  in Rust.
- No wave-two slice updated beta independently. The commit-pinned v1.1.194
  aggregate was deployed after all workstreams landed, and protected lifecycle
  run 31916804935 accepted its real issuance, presentation, verification,
  renewal, suspension, reinstatement, revocation, and authorization behavior.
  Exact artifacts and the fail-closed rollout history are recorded in the
  [wave-two final evidence](rust-migrations/wave-two-final-evidence-2026-08-15.md).

## Non-negotiable outcomes

1. There is exactly one maintained implementation of each migrated kernel, written in Rust.
2. Python and Dart callers use that implementation through generated or deliberately thin bindings; they do not reproduce its decisions.
3. Existing REST, gRPC, event, storage, and mobile-facing contracts retain feature parity unless a versioned change is explicitly approved.
4. Required native code fails closed. Production-like environments never silently fall back to Python, Dart, permissive defaults, `None`, empty results, or mock validation.
5. Superseded source, tests, dependencies, feature flags, and fallback branches are deleted as soon as implementation-independent behavioral, failure, ownership, packaging, and regression gates pass.
6. Rollback selects a previous deployable image or release. Runtime fallback to a second implementation is not an accepted rollback mechanism.

## Architecture and ownership

The canonical implementation must live at the lowest reusable Rust layer. A binding, service, or application may adapt inputs and outputs, but it must not fork the algorithm.

The machine-readable ownership inventory is
[`rust-migration-ownership.json`](rust-migration-ownership.json). CI validates
its schema, exact production Python crypto-import baseline, and source rules
that prevent unsigned token decoding or direct native binding surfaces from
being added. Every migration PR that removes an approved non-Rust import must
shrink the manifest in the same change; stale allowances fail CI.

| Capability | Canonical owner | Consumers | Consolidation rule |
|---|---|---|---|
| Cryptography, document verification, presentation policy, status lists, OIDC validation, device proof, DID/JWK utilities | `marty-core` | Python services, credential packages, wallet, Rust services | Public reusable kernels live in one `marty-core` crate or module and are re-exported rather than copied. |
| Credential issuance and verification packaging | `marty-credentials` | Issuer/verifier services | Compose `marty-core`; do not maintain duplicate crypto, policy, protocol, or status-list algorithms. |
| Service transport and storage orchestration | Owning service repository, primarily `marty-ui` | Deployed backend | Rust service binaries may own HTTP/gRPC/event and repository adapters, while shared decision logic stays in `marty-core`. |
| Mobile protocol handling | `marty-core` exposed through Flutter Rust Bridge | `marty-authenticator` | Dart owns UI, camera, deep links, and platform APIs; Rust owns protocol parsing and verification. |
| License verification and entitlement evaluation | `marty-subscriptions/packages/verifier_entitlements/marty-license` | Backend and packaged applications | Extend the existing private Rust crate and remove equivalent Python evaluators. |
| Legacy compatibility | `Marty` adapters only | Older callers during migration | Compatibility code may translate contracts temporarily but may not contain an independent kernel. Delete it when callers move. |

### Binding surfaces

- Python uses the existing `_marty_rs` package as the preferred public native surface. Additional extension modules require an explicit reason and shared error/version conventions.
- Flutter uses generated Flutter Rust Bridge bindings from canonical crates. Hand-written Dart protocol implementations are not compatibility layers.
- Rust services depend directly on canonical crates through pinned workspace or released dependencies.
- Every binding exposes backend name, semantic version, build revision, enabled features, and a readiness result.
- Native errors map to stable, normalized service error codes. Binding-load failure and invalid native operations are typed errors.

## Contract-preservation inventory

Before implementation begins for a workstream, its PR must capture a feature-parity matrix covering all applicable contracts:

- REST routes, methods, status codes, request/response schemas, and error bodies;
- gRPC services, methods, protobuf field semantics, deadlines, and status codes;
- produced and consumed event types, ordering, idempotency, and retry behavior;
- database schema, transaction boundaries, Redis keys, TTLs, and concurrency guarantees;
- environment variables, defaults, secret references, health checks, and readiness behavior;
- authentication, authorization, tenancy, rate limiting, and audit events;
- metrics, logs, traces, dashboards, and alerts;
- supported algorithms, credential/protocol formats, limits, and interoperability fixtures;
- mobile deep links, QR payloads, user-visible outcomes, and offline behavior where applicable.

The matrix becomes executable contract tests wherever possible. A Rust replacement is incomplete if it passes unit tests but drops an existing contract or operational behavior.

## Current findings and immediate safeguards

The investigation identified these high-value targets beyond the document-verification and ISO 18013 migrations already underway:

1. Presentation-policy evaluation.
2. Revocation-profile and status-list processing.
3. OIDC token validation.
4. Device registration, challenge proof, and key rotation.
5. Event-stream service replacement.
6. Flow state-machine and DID/JWK utilities.
7. Wallet QR and OID4VC protocol parsing.
8. License and entitlement evaluation.
9. Conditional legacy DTC and VDS-NC migration or retirement.

The initial investigation found that `main` already rejected unknown presentation constraints and verified device challenge signatures; those fail-closed behaviors became migration baselines. It also found unsigned OIDC claim decoding, PKCE incorrectly treated as token validation, and divergent Python/Rust status-list compression semantics. Phase 0 replaced those paths with complete native validation and authoritative standards-tested Rust behavior before their callers were cut over.

## Delivery roadmap

Phases are ordered by shared dependency and risk. Workstreams inside a phase may run in parallel only when they do not create competing canonical implementations.

### Phase 0 — Inventory, guardrails, and security corrections

**Purpose:** Establish a trustworthy baseline before moving callers.

- Create a machine-readable ownership manifest mapping each kernel to its canonical Rust module and all current non-Rust implementations.
- Add CI checks that reject new protocol/crypto implementations in designated Python and Dart paths without an approved exception.
- Standardize native backend diagnostics and typed unavailable/operation errors across Python bindings.
- Record contract snapshots and shared fixtures for every selected service.
- Replace the OIDC adapter's unsigned claim decoding with complete Rust-backed validation: discovery/JWKS handling, signature, issuer, audience, authorized party where required, nonce, time claims, and algorithm policy.
- Add regression tests preserving fail-closed unknown presentation constraints and device proof-of-possession.
- Resolve status-list compression semantics with standards fixtures and make the Rust output authoritative.
- Detect and reject mock or placeholder validation in beta runtime paths.

**Exit gate:** Ownership is unambiguous, immediate security defects are closed, native availability is visible in readiness, and CI can detect reintroduced fallback code.

### Phase 1 — One presentation-policy engine

**Canonical owner:** `marty-core/marty-verification`

- Inventory every constraint and policy composition behavior used by backend and wallet callers.
- Implement the complete evaluator and normalized decision/error model in Rust.
- Expose the same evaluator through `_marty_rs` and Flutter Rust Bridge.
- Run backend Python, mobile Dart, and direct Rust against the same golden policy vectors.
- Convert Python and Dart policy layers into mapping/orchestration adapters only.
- Delete Python and Dart constraint evaluators, duplicate normalizers, permissive branches, and their now-unused dependencies.

**Parity gate:** Existing policy fixtures produce equivalent decisions and reasons; malformed or unsupported constraints are denied; no caller contains independent evaluation logic.

### Phase 2 — Rust service foundation and event stream

**Canonical shared logic:** `marty-core`; **binary owner:** `marty-ui`

Use the event-stream service as the first whole-service replacement because it has a narrow transport contract and establishes the reusable Rust service template.

- Build the common service foundation: configuration, structured logging/tracing, metrics, health/readiness, graceful shutdown, authentication middleware, error envelopes, and database/Redis clients.
- Reimplement the event-stream HTTP/gRPC and event-bus behavior in Rust while preserving protobuf and operational contracts.
- Run Python and Rust implementations against shared contract, ordering, reconnection, backpressure, and failure tests.
- Deploy the Rust image to beta, observe it, then remove the Python service and packaging.

**Exit gate:** The template is reusable, the beta deployment has no Python event-stream process, and all consumers pass unchanged integration tests.

### Phase 3 — Status and revocation consolidation

**Canonical owner:** a public `marty-core` status module/crate; **service binary owner:** `marty-ui`

- Move or refactor the existing status-list Rust implementation out of credential-specific ownership into the canonical public layer.
- Temporarily re-export it from `marty-credentials` to avoid a second implementation or a flag-day dependency change.
- Cover Token Status List and Bitstring Status List encoding, compression, allocation, mutation, validation, and error semantics with standards and property tests.
- Rebuild revocation-profile orchestration as a Rust service, preserving REST, gRPC, persistence, Redis atomicity, issuer configuration, tenancy, and events.
- Keep certificate-provider or external revocation integrations as adapters to the canonical Rust decisions.
- Run advisory-lock-protected Rust schema migrations before downstream shared migrations, then delete `status_list_manager.py`, Alembic ownership, and the superseded Python service after implementation-independent behavioral, parity, and failure gates pass.

**Parity gate:** Existing credentials remain readable, indices and status transitions are preserved, concurrent allocation is safe, and all published bytes match the approved vectors.

### Phase 4 — OIDC and device-authentication kernels

**Canonical owner:** new or existing focused crates in `marty-core`

- Consolidate OIDC discovery, JWKS caching/rotation, authorization response checks, token validation, and normalized identity extraction in Rust.
- Consolidate device public-key parsing, RFC 7638 thumbprints, challenge construction, proof verification, replay prevention, expiry, and key-rotation eligibility in Rust.
- Preserve Python service routing, persistence, organization checks, and provider adapters initially.
- Use shared vectors for valid and invalid signatures, key rotation, stale JWKS, nonce mismatch, replay, algorithm confusion, issuer/audience mismatch, and clock boundaries.
- Delete unsigned JWT decoding and Python cryptographic/proof code as each caller moves.
- Evaluate full Rust service replacement only after the kernels are stable; do not duplicate them inside a service binary.

**Parity gate:** All authentication paths validate the complete trust context, device behavior remains compatible, and no production-like path can accept decoded-but-unverified claims.

### Phase 5 — Flow engine and DID/JWK utilities

**Canonical owner:** `marty-core`, reusing `marty-didcomm` and existing credential/protocol crates

- Specify the flow lifecycle as a versioned Rust state machine with legal transitions, guards, terminal states, replay/idempotency rules, and normalized failures.
- Move graph validation, request-object validation, DID/JWK normalization, key selection, and protocol-specific decision logic to Rust.
- Keep database repositories, API composition, and third-party callbacks in orchestration layers until a whole-service replacement is justified.
- Differentially replay recorded beta flows through old and new paths, comparing state, events, responses, and side effects.
- Remove Python state-transition, DID/JWK, and request-validation implementations after all callers use Rust.

**Parity gate:** Recorded and synthetic flows remain behaviorally equivalent, invalid transitions fail closed, and exactly one state machine determines outcomes.

### Phase 6 — Wallet QR and OID4VC consolidation

**Canonical owner:** existing `marty-core` ISO 18013 and OID4VC crates, exposed through Flutter Rust Bridge

- Inventory every supported QR/deep-link form and user-visible routing outcome.
- Move protocol-aware classification, parsing, validation, and request evaluation to the existing Rust crates.
- Keep camera capture, UI navigation, permissions, secure platform storage, and OS integration in Dart.
- Replace mock validation and hand-written Dart protocol parsers with generated bindings and typed results.
- Share malformed-input, size-limit, Unicode, deep-link, mDoc, OID4VCI, and OID4VP vectors across Rust and Flutter tests.
- Delete superseded Dart protocol code after mobile beta parity.

**Parity gate:** Every supported QR journey retains its user-visible behavior; malformed or unsupported requests fail safely; no Dart protocol evaluator remains.

### Phase 7 — License and entitlement runtime

**Canonical owner:** `marty-subscriptions/packages/verifier_entitlements/marty-license`

- Inventory Python license parsing, signature validation, expiry, feature, quota, organization, cache, and telemetry behavior.
- Extend the existing private Rust crate to cover the complete runtime contract.
- Provide a backend-safe binding or sidecar interface with typed decisions and diagnostics.
- Preserve billing/provider synchronization adapters in Python where they are integration orchestration rather than entitlement decisions.
- Disallow development allow-through behavior in beta/production-like profiles; missing keys, malformed licenses, invalid signatures, and unavailable native code fail closed.
- Delete duplicate Python license and entitlement evaluators after parity.

**Parity gate:** All licensed features and quotas behave identically for valid inputs, failure behavior is stricter and explicit, and only the Rust crate decides entitlements.

### Phase 8 — DTC and VDS-NC decision gate

These legacy services are conditional targets. For each service, make and record one decision:

- **Retain:** place create/sign/verify/encode/decode/validate behavior in a canonical Rust crate, migrate all callers, and delete the Python kernel; or
- **Retire:** migrate required data/callers, remove the deployed service, and delete the Python implementation.

Maintaining an unused Rust rewrite beside a legacy Python implementation is not an acceptable outcome.

**Decision:** Retain both capabilities. DTC create/sign/verify and governed
lifecycle validation are canonical in `marty-verification::dtc`. VDS-NC
canonicalization, barcode policy, create/sign/inspect/verify, field consistency,
and temporal validation are canonical in `marty-oid4vci` and
`marty-verification`. Marty preserves its gRPC, storage, provider, DTO, and visa
mapping adapters, but no longer owns a cryptographic or protocol kernel. The
evidence and allowed adapter boundary are recorded in
[`rust-migration-phase8-dtc-vds-decision.md`](rust-migration-phase8-dtc-vds-decision.md).

**Exit gate:** Satisfied for implementation and caller cutover. Final completion
still follows the roadmap-wide beta evidence and removal enforcement gates.

### Phase 9 — Removal and enforcement

**Status:** Complete at the beta deployment boundary. The final evidence
package records the deleted-code inventory, immutable artifacts, source and
dependency composition, protected behavioral lifecycle, and unchanged
production/self-host boundary.

- Delete all superseded Python/Dart implementation files and fallback flags.
- Remove no-longer-used packages and native build exceptions from manifests and images.
- Add dependency and source-boundary checks preventing canonical logic from returning to orchestration layers.
- Remove compatibility re-exports after downstream consumers have migrated.
- Update architecture, operations, SBOM, threat-model, and contributor documentation.
- Compare language composition, image size, startup time, p50/p95/p99 latency, memory, failure rates, and native-backend errors against the baseline. Generate commit-pinned source and dependency measurements with [the language-composition evidence tool](rust-migrations/language-composition-evidence.md).
- Prepare a separate production/self-host promotion proposal using beta evidence. Do not promote as part of this phase without approval.

## Per-workstream migration method

Every workstream follows the same sequence:

1. **Inventory:** locate all implementations and callers; record behavior, dependencies, contracts, and test gaps.
2. **Specify:** define canonical Rust inputs, outputs, error taxonomy, resource limits, and fail-closed semantics.
3. **Vectorize:** turn current valid/invalid behavior and standards fixtures into language-neutral golden vectors.
4. **Implement once:** add the capability only to its canonical Rust owner.
5. **Bind/adapt:** expose generated or thin adapters; no business decision may be repeated in the adapter.
6. **Compare:** run differential, property, fuzz, contract, integration, and performance tests.
7. **Cut over beta:** deploy one Rust-backed path, with observability and image-level rollback.
8. **Remove:** delete the old implementation and dependencies in the same workstream or an immediately linked cleanup PR.
9. **Enforce:** add a CI rule or architectural test that prevents the duplicate from returning.

## Python/Dart deletion gate

Non-Rust implementation code can be removed only when all of the following are true, and removal is mandatory once they are true:

- every production-code caller in scope uses the canonical Rust implementation;
- shared golden vectors and differential tests pass;
- REST/gRPC/event/mobile contracts and integration suites pass;
- malformed, unsupported, unavailable-backend, and adversarial inputs fail closed;
- beta or an isolated production-like lane shows acceptable correctness, reliability, and latency;
- rollback uses an earlier image rather than an alternate implementation;
- repository search confirms no runtime imports or references remain;
- package manifests and container images no longer carry dependencies used only by the removed code;
- tests of the removed implementation are either deleted or converted into canonical Rust/binding tests;
- a CI ownership check prevents reintroduction.

Adapters that contain serialization, DTO mapping, or framework glue may remain temporarily, but they must be small enough to review as adapters and must not select trust, protocol, policy, or cryptographic outcomes.

## Test strategy

### Shared conformance and golden vectors

- Keep language-neutral fixtures in one versioned location with provenance and expected normalized results.
- Execute the same vectors directly in Rust and through every supported binding.
- Cover valid, invalid, malformed, boundary, unsupported-algorithm, missing-trust, replay, concurrency, and oversized inputs.
- Include interoperability fixtures from standards or external suites where licensing permits.

### Rust assurance

- Unit and integration tests for every public decision path.
- Property tests for parsers, encoders, state transitions, allocation, and normalization.
- Fuzz targets for untrusted JWT, CBOR/COSE, QR/deep-link, policy, DID/JWK, status-list, and license inputs.
- Resource limits for input size, nesting, decompression, collection count, and execution time.
- Dependency auditing, unsafe-code review, and reproducible release artifacts.

### Service and application parity

- Behavioral tests must target published protocols, generated schemas, fixtures,
  executable artifacts, or public APIs. They must not instantiate, mock, import,
  or inspect the implementation being replaced as proof of parity.
- OpenAPI and protobuf compatibility checks.
- Recorded-request differential tests with secrets and personal data removed.
- Database/Redis migration and concurrency tests.
- Event ordering, duplicate delivery, retry, and reconnect tests.
- Mobile integration tests for QR routing and user-visible outcomes.
- Fault injection for unavailable native libraries, stale keys, external-provider failures, storage failures, and disconnects.

### Performance

Benchmark the canonical kernel and end-to-end caller before cutover. Rust must not introduce an unacceptable regression in p95 latency, throughput, memory, startup, or binary/image size. Security and correctness take precedence over microbenchmark gains.

## Beta rollout and observability

Wave one used staged beta deployment. During wave two, each workstream builds,
tests, and produces immutable artifacts in CI or isolated local test lanes, but
does not repeatedly update the shared beta deployment. After all wave-two PRs
land, one commit-pinned aggregate is deployed to beta and the full smoke,
conformance, end-to-end, failure, and observability suite is run once against
that aggregate.

The final aggregate check observes normalized failure codes, native
availability, panic/crash rate, latency, memory, event lag, provider errors,
and public contract failures. Production and persistent self-hosted deployment
remain unchanged. Rollback redeploys the prior beta artifact rather than
enabling a non-Rust implementation.

Before v1, elapsed-time soak windows are supporting release evidence rather than
code-deletion blockers. A superseded implementation is removed as soon as its
implementation-independent behavioral, failure, ownership, packaging, and
regression gates pass. A release owner may still require an explicit soak for a
specific promotion, but that does not preserve a second runtime implementation.

Daily read-only service samples use the sanitized
[`marty.rust-beta-soak/v1`](rust-migrations/beta-soak-evidence.md) collector.
Each sample is supporting evidence only; it does not replace contract,
lifecycle, failure, or protected-device gates.

Rollback redeploys the last known-good beta artifact. Databases and events must remain forward/backward compatible across the rollback window or have a tested forward repair. No phase modifies production or persistent self-host deployment configuration.

## Git and delivery workflow

- Use one clean git worktree per repository and workstream; never implement in a dirty primary checkout.
- Branch from the current protected default branch using a focused name such as `rust/<capability>-kernel`, `rust/<service>-migration`, or `cleanup/remove-<capability>-python`.
- Keep canonical-crate, binding, caller, deployment, and deletion changes in reviewable PRs with explicit dependency ordering.
- Sign off every commit as required by project contribution guidance.
- Merge prerequisite Rust API PRs before dependent binding/service PRs. Temporary compatibility re-exports must have a tracked removal PR.
- Include the feature-parity matrix, test evidence, beta rollout effect, rollback procedure, and deleted-code inventory in each migration PR.
- Do not mix unrelated cleanup or user worktree changes into migration commits.

## Measures of completion

Wave one met the following completion conditions on 2026-08-14. The complete
roadmap meets them again only after every wave-two workstream is `native-active`
and the final aggregate beta evidence is accepted:

- all unconditional workstreams have passed their deletion gates;
- every conditional DTC/VDS-NC service has been migrated or retired;
- each migrated capability has one identified Rust owner and no second Python/Dart implementation;
- required native backends fail closed and report useful health/version diagnostics;
- beta uses the Rust service images and bindings for all migrated paths;
- public and operational contracts retain feature parity;
- language-composition reporting shows the corresponding Python/Dart source and runtime dependencies removed;
- CI enforces the ownership model; and
- a production promotion package exists, based on beta evidence, for separate approval.

The wave-one evidence for these conditions is captured in
[`final-migration-evidence-2026-08-14.md`](rust-migrations/final-migration-evidence-2026-08-14.md),
and the accepted wave-two aggregate is captured in
[`wave-two-final-evidence-2026-08-15.md`](rust-migrations/wave-two-final-evidence-2026-08-15.md).
Promoting the accepted artifacts beyond beta remains explicitly out of scope.

## Deliberate non-targets

The following should not be rewritten merely to increase Rust percentages:

- React/TypeScript user interfaces;
- Flutter widgets and platform UI integration;
- Canvas/LTI and other provider-specific orchestration;
- OCR model invocation and image-processing integrations unless profiling identifies a concrete bottleneck;
- database migrations and straightforward repository mapping code;
- billing, email, CRM, and similar third-party adapters.

They become candidates only when a measured correctness, security, reliability, deployment, or performance problem justifies the migration.

## Key risks and controls

| Risk | Control |
|---|---|
| Behavior is lost during translation | Feature-parity inventory, contract snapshots, differential replay, and deletion gates. |
| A second Rust copy replaces a Python duplicate | Canonical ownership table, dependency reviews, re-exports, and CI source-boundary checks. |
| Native packaging fails at runtime | Required-backend readiness, version diagnostics, packaging tests, and fail-closed startup. |
| Standards behavior diverges | Shared external/golden vectors, fuzzing, and one canonical encoder/validator. |
| A large service rewrite stalls | Kernel-first slices, event-stream service template, focused PRs, and independent beta gates. |
| Rollback depends on insecure fallback | Immutable deployable artifacts and image-level rollback only. |
| Language reduction becomes vanity work | Target ranking is based on security, duplication, operational simplification, and whole-service removal. |
| Beta changes leak into persistent environments | Beta-only deployment changes and separate production/self-host approval. |

## Completed wave-one dependency order

The implementation landed in the following dependency order:

1. Phase-zero ownership/CI/native diagnostics and OIDC verification correction.
2. Canonical presentation-policy engine.
3. Rust service foundation plus event-stream replacement.
4. Canonical status module, followed by revocation-profile replacement.
5. Device-auth consolidation and the remaining OIDC migration.
6. Flow/DID/JWK consolidation.
7. Wallet QR/OID4VC consolidation.
8. License/entitlement consolidation.
9. DTC/VDS-NC retain-or-retire decisions.
10. Cross-repository cleanup, dependency removal, and beta evidence package.

Dependency adjustments were recorded in the implementation PR chain and
preserved the single-owner rule.

Wave two followed the removable-source order above. Its dependency chain,
deleted-source inventory, immutable aggregate, fail-closed rollout findings,
and protected beta lifecycle are commit-pinned in the wave-two final evidence.
