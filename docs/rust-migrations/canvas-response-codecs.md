# Canvas response codec contract

The candidate uses one Rust response-text owner for validation error excerpts
and status-provider error bodies. JSON stays byte-first and independent of the
Content-Type charset. This checkpoint qualifies stateless single-byte text
decoders and UTF-16/32 text plus its validation exception boundary; it does not
establish whole-provider or whole-worker cutover parity.

## Independent observations

`contracts/canvas-single-byte-codecs.json` contains 73 canonical mapping tables,
each with exactly 256 Unicode scalars, and 291 registered aliases. The test-only
oracle discovers installed single-byte codec modules, but captures their values
through the hash-verified published `_response_json_or_excerpt` helper and actual
HTTPX responses. It does not substitute Python's table constants for observed
HTTPX behavior. Undefined bytes retain the published replacement characters.

Two independent captures agreed before integration. The mandatory configured
`canvas_published_schema_contract` gate regenerates the same data inside the
immutable published issuance image and compares the complete artifact. A stdlib
alias key, `csHPRoman8`, is not actually registered after Python normalization;
its observed unknown-charset UTF-8 fallback is recorded separately and tested.

All 64 previous TLS observations remain unchanged. Four additional real TLS
cases carry every byte under Windows-1252, CP037, KOI8-R and MacRoman headers.
The unchanged native decoder failed those cases before replacement. Rust unit
tests exercise all bytes for every registered alias, including normalized
uppercase/hyphen labels. The native TLS replay now matches all 68 observations.

## Implementation and review

`canvas_response_text.rs` embeds the language-neutral artifact and initializes
one validated registry with `OnceLock`. One indexing algorithm serves every
single-byte encoding. No runtime Python, codec package, dependency or lockfile
change is needed. The former hand-maintained ASCII/Latin-1 branches are removed;
their behavior remains covered by the captured tables and existing focused tests.

The Windows replay harness reads artifacts and subprocess output explicitly as
UTF-8. It splits JSON observations only at physical newline records: Unicode
NEL, line separator and paragraph separator can occur inside valid JSON strings.
A process-free regression reproduced the earlier `splitlines()` failure and
passes after the repair; no expected observations were changed to hide it.

Local verification passes 294 library, 5 worker, 28 management HTTP, 22 behavior,
42 workflow/image/ownership tests, strict all-target Clippy and all 21 configured
published-image/schema tests (164.97 seconds, none ignored or filtered). Both
native TLS replays pass all 68 cases. Hosted checks must qualify the new commit
separately; these local results do not prove deployment acceptance.

## Unicode text and validation exceptions

`contracts/canvas-unicode-text-oracle.json` freezes 372 observations for the six
UTF-16/32 codec variants and records all 16 registered aliases. Text and excerpt
results are captured separately: valid JSON can bypass a text decoder that would
otherwise reject a missing BOM. The corpus includes opposite byte orders,
repeated BOMs, supplementary characters, lone surrogates, invalid UTF-32 scalars,
truncated prefixes and incomplete surrogate pairs. Independent captures agree;
the initial unchanged native decoder failed before repair. The image gate checks
the artifact using the actual published helper and HTTPX text decoder. Aliases
and normalized uppercase/hyphen labels are checked against the published decoder;
Rust replays the corresponding vectors for every alias.

One shared Rust Unicode text implementation returns typed missing-BOM errors,
replaces invalid scalar sequences as observed, and preserves explicit-endian BOM
characters. JSON and text retain separate detection/projection rules; the later
header continuation shares their strict/replacement Unicode code-unit primitive.
`CanvasCredentialsProviderResponse::from_body` is the single complete-body
projection boundary used by the actual HTTP validation transport and native
application replay. Transport failures and response-text failures are distinct;
successful validation bodies are drained without text decoding.

The actual published application corpus now has 28 cases, preserving all prior
20. Eight additions prove plain HTTP 500 for missing required BOMs, successful
responses ignoring those charsets, valid BOM decoding and replacement of short
prefixes. Both the full native router and real HTTP transport replay these cases.
The Unicode continuation passes 296 library, 5 worker, 28 management HTTP,
22 behavior, 42 workflow/image/ownership tests, strict Clippy, the existing
68 TLS observations, and all 21 configured published-image tests (137.06 seconds,
none ignored/filtered). Fresh hosted qualification is still required.

## Status-provider boundary

The status-provider continuation expands its independent immutable-image corpus
from 63 to 79 observations with raw response bytes and Content-Type. Both bridge
synchronization and real-provider revocation retain Unicode failure identity,
JSON-before-text success behavior, decoded HTTP failure text and short-prefix
replacement. The previous native generic error type failed the new corpus.
`CanvasCredentialsStatusError` now preserves runtime versus response-text errors
inside the single `synchronize_provider` implementation. The existing lifecycle
trait delegates to it and intentionally projects only diagnostic text, matching
the published lifecycle route's `str(exc)` persistence (credentials source
`51f0a758a076777cb18a30b1db3f89c74ac23e01`, `routes.py` catch/save boundary).
The native real HTTP/PostgreSQL runtime fixture also checks Unicode failure
persistence and later recovery, canonical status, attempt counters, unrelated
metadata, tenant-secret usage, publication/event ordering and late save failure.
This is composed provider/persistence evidence, not a separately captured full
published lifecycle HTTP trace. The complete configured image suite passes all
22 tests (136.27 seconds, none ignored/filtered). Local 296 library, 5 worker,
28 management HTTP, 22 behavior, 42 workflow/image/ownership tests, strict Clippy
and the existing 68 TLS observations pass. Fresh hosted checks remain required.

## Remaining gates

UTF-7 and remaining special/escape codecs, including their encoded-parameter-label use,
exceptional header metadata such as Python's decimal-conversion limit for very
long continuation ordinals, exceptional JSON values and other configuration or
exception paths still need qualification. The header corpus below qualifies its
specified forms, not every possible metadata/codec combination. Existing unsupported-codec
fallback is an adoption gap, not an approved reduction of supported functionality.

Complete provider configuration/network behavior and whole-worker/all-consumer
deployment adoption remain separate gates. Keep reachable Python until its
replacement passes those gates, then remove it immediately. This checkpoint
changes neither beta nor production and does not restart the interrupted soak.

## Charset parameters and consumer error boundaries

`contracts/canvas-charset-headers-oracle.json` freezes 177 observations: 59 header
forms crossed with non-JSON bytes, valid JSON and an empty body. Each separately
records the published charset getter, HTTPX response text and actual adapter
excerpt helper, including error class and diagnostic. Two independent captures
agree, and the immutable-image gate checks the complete artifact. The unchanged
native parser failed before repair; the replacement passes all observations.

The shared Rust parameter owner preserves first/bare/empty charset behavior,
quoted and angle-unquoted values, published escaped-quote counting, ordinary
parameter precedence, encoded labels, reordered/gapped/duplicate continuations,
and the TypeError caused by mixing bare and numbered segments, including in
unrelated groups. Empty response text and valid JSON excerpts bypass that error
as the published consumers do. Registered dotted aliases use the frozen registry
lookup rule; a canonical module name is not automatically a dotted alias. The
326 registry entries are metadata, not implementation coverage for all codecs.

Parameter labels use strict decoding; generic UTF-16/32 labels without a BOM
use native byte order. Response text retains its distinct BOM requirement and
replacement rules. JSON byte detection and precedence are unchanged. All three
reuse one Unicode code-unit primitive, with strict versus replacement behavior
explicitly selected; no duplicate codec implementation or dependency is added.

The independent full-app validation corpus grows 28 -> 31 and the provider
corpus 79 -> 82, with every old observation unchanged. A failed non-JSON validation
response exposes the header error as plain HTTP 500; success ignores text and
valid JSON remains a structured excerpt. Status synchronization instead decodes
failed-response text even when its bytes contain JSON. Typed errors preserve
these distinct boundaries without inferring classes from diagnostic messages.
An eleven-case real HTTP validation replay and full managed router replay agree.

The shared runtime fixture now supports baseline, Unicode and charset response
scenarios without duplicating setup or persistence assertions. Real tenant vault,
HTTP and PostgreSQL checks prove charset failure diagnostics survive canonical
status updates and later successful synchronization clears both error fields.
Attempt counters, unrelated metadata, publication ordering and the late delivery
save failure remain checked. This composes captured provider behavior with native
persistence and the previously inspected published catch/save boundary; it is
not an independently captured full published lifecycle HTTP trace.

Gates: 297 library, 5 worker, 28 management HTTP, 22 behavior, 42 workflow/image/
ownership, strict Clippy, 68 native TLS and all 23 configured image/schema tests
pass. CI explicitly requires both decoder-recovery tests to exist before running
the complete suite. Fresh hosted checks must qualify the committed source.

## Shared East Asian multibyte machines

The [machine artifacts](../../contracts/canvas-multibyte-codecs/README.md) add 15
published codecs through one Rust decoder: Big5/Big5-HKSCS, CP932/949/950,
GB2312/GBK, Johab, three Shift-JIS variants, three EUC-JP variants and HZ.
They retain single-byte exceptions, invalid/truncated input, state transitions,
multi-character mappings, finalization and strict decoding for parameter labels.
All 64 recorded canonical/alias labels are exercised against full HTTPX responses.
No WHATWG-to-Python equivalence assumption or runtime Python codec shim is used.

Two independent immutable-image captures agree for each complete machine before
the native implementation. The old UTF-8 fallback failed the new Big5 response
corpus. There are 2,415 reachable states, 618,240 transitions and 620,655 complete
witness-prefix observations for each of replacement and strict decoding. Expected
digests come from fresh HTTPX decoders and Python strict decode, not table replay.
Rust independently replays those inputs and 165 full-response examples. Generated
tables use compressed language-neutral data; bounds and indices are checked once
on lazy initialization, and all machines reuse one decoding loop.

The actual published HTTP/response-helper TLS corpus grows 68 -> 83, retaining all
earlier observations and adding every machine. Two independent captures agree;
native TLS matches all 83. The exact new fixture paths were added to the existing
test-only allowlist after its first replay correctly rejected unknown paths.
No production origin or transport policy was relaxed.

All 23 configured published-image/schema tests pass (145.31 seconds), including
complete machine regeneration/comparison and the expanded TLS corpus. Local 299
library, 5 worker, 28 managed HTTP, 22 behavior, 70 workflow/image/ownership/cutover
tests and strict Clippy pass. Dependencies, lockfile, reachable Python and
deployments are unchanged. Other codec families and broader adoption gates above
remain open; this is not whole-worker cutover approval.

## GB18030 continuation

The [GB18030 artifact](../../contracts/canvas-gb18030-codec.md) preserves its
distinct variable-width consumption behavior with 207 compact mapping ranges,
a two-byte table and one shared strict/replacement Rust decoder. Two immutable
image captures agreed before implementation; the old UTF-8 fallback failed the
new response corpus. Native tests compare independent published decoder hashes
for every single/two-byte input, all 1,587,600 four-byte pointers, and 88,741
byte-class sequences per mode. All 428 full-response examples pass for both
recorded labels, including supplementary/noncharacter and malformed input.

The shared response/strict-label dispatch initializes only the selected codec
family. Dependencies and lockfiles are unchanged; Python additions are offline
test capture tooling, not a runtime shim. The published-image gate regenerates
and compares the complete GB18030 artifact. Two published-helper TLS captures
agree, retain all earlier 83 observations, and match the native 84-case replay.
Whole-worker and all-consumer adoption remain open; reachable Python and
deployments are unchanged.

Final gates: 301 library, 5 worker, 28 management HTTP, 22 behavior, 70 affected
workflow/image/ownership/cutover tests and strict Clippy pass. All 23 configured
published-image/schema tests pass in 158.38 seconds with none ignored/filtered,
including complete GB18030 regeneration and the expanded TLS observations.
The preceding `cf8246918` hosted checks are green; the continuation requires its
own hosted qualification before landing.

## EUC-KR continuation

The [EUC-KR artifact](../../contracts/canvas-euc-kr-codec.md) preserves ordinary
two-byte mappings and eight-byte Hangul composition, not an assumed CP949 subset.
Two independent immutable-image captures agreed before the new native module;
the previous UTF-8 fallback failed the response regression. Rust matches both
decoding modes for all 16,777,216 component triples, every single/two-byte input,
769 component observations and 98,304 mutated/prefix/suffix sequences. All 98
response examples pass across nine labels, including all 11,172 valid composition
results in the exhaustive hash replay.

The Rust implementation shares pair-table validation and complete-input error
consumption with GB18030. Both strict parameter labels and replacement response
text use the same codec facade; tests share observation/hash helpers. Offline
capture scripts likewise share one fresh-decoder observer, pair capture and
alias-response check. The existing GB18030 artifact is unchanged. No runtime
Python, dependency or lockfile is added. Independent TLS captures grow 84 to 85
with every prior observation unchanged, and native TLS matches all 85.
Final gates pass: 303 library, 5 worker, 28 managed HTTP, 22 behavior, 70 affected
Python tests and strict Clippy. All 23 configured image/schema tests pass in
197.45 seconds with none ignored/filtered, including complete EUC-KR regeneration
and unchanged earlier codec artifacts. Fresh hosted qualification is required.
No deployment or reachable-Python deletion occurs in this continuation.

## ISO-2022 continuation

[Seven independently captured variants](../../contracts/canvas-iso2022-codecs/README.md)
now share a Rust stateful decoder. Two complete immutable-image captures agree
for each variant before native implementation. Coverage includes 134 active-state
witnesses, 8,816,262 state inputs and 6,386,038 escape/prefix/mutation inputs per
mode, plus 1,167 full responses across 23 labels. The unchanged native fallback
failed before repair. Exact hashes retain multi-character mappings, pass-through,
shift/reset behavior and both normal replacement and exceptional outcomes.

Typed response errors preserve the published internal-codec RuntimeError and
incremental pending-buffer UnicodeError. Strict encoded labels share the owner,
but do not incorrectly apply the incremental pending limit. Published JSON-first
and successful-validation bypasses remain intact. The independent validation
corpus grows 31 to 37, provider 82 to 86, and TLS 85 to 96, with prior observations
unchanged. Native 17-case real-HTTP validation, managed router and 96-case TLS
replays pass. A new shared runtime scenario verifies diagnostic persistence and
recovery; the CI runner requires that test's presence.

Local 305 library, 5 worker, 28 managed HTTP, 22 behavior and 70 affected Python
tests pass, as does strict Clippy. All 24 configured published-image/schema tests
pass in 212.24 seconds with none ignored/filtered, including full artifact
regeneration and the new lifecycle recovery scenario. Fresh hosted qualification
remains required. No dependency, runtime Python, reachable Python deletion or
deployment change is introduced.
