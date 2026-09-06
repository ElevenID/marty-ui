# Canvas response codec contract

The candidate uses one Rust response-text owner for validation error excerpts
and status-provider error bodies. JSON stays byte-first and independent of the
Content-Type charset. This checkpoint qualifies stateless single-byte text
decoders; it does not establish whole-provider or whole-worker cutover parity.

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

## Remaining gates

Multibyte/stateful codecs, extended/RFC2231 charset headers, less common codec
label normalization, and decoder exception propagation still need published
observations and native implementation. Their current fallback is an adoption
gap, not an approved reduction of supported functionality. Generic UTF-16/32
text decoding can raise errors when byte-order markers are absent; qualify the
actual adapter/application boundary before choosing a Rust error projection.

Complete provider configuration/network behavior and whole-worker/all-consumer
deployment adoption remain separate gates. Keep reachable Python until its
replacement passes those gates, then remove it immediately. This checkpoint
changes neither beta nor production and does not restart the interrupted soak.
