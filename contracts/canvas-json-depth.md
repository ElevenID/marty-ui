# Published JSON depth consumer boundaries

This is independent reference evidence, not native depth qualification. No
production parser, recursion setting, database driver or deployment changed in
this checkpoint. The existing native 127-container guard remains a known open
cutover gap; the observations below must guide its replacement.

## Scope and provenance

The same immutable issuance image, source hashes, actual app/adapter/repository,
published PostgreSQL migrations and synthetic ports as
[the JSON consumer reference](canvas-json-consumers.md) execute unchanged.
The fixture is isolated and never accepts a deployment endpoint or credential.

The declared scenario generator produces 64 cases: array and object chains at
16 depths, each with provider status 200 and 403. Depths bracket 127/128 and
254/255/256, extend around 1,000 and reach 1,600. Each leaf is integer zero.
The 1,600 fixture ceiling is NOT an observed application limit and must not be
turned into an arbitrary native runtime limit.

Two complete captures agree byte-for-byte:
`E54295A9C64D8931C352976CF2F5C12FE1D26DCFFE1E35695C842EA91A49AE20`
(SHA256 of the compact generated JSON file, including its final newline).
The formatted reference changes whitespace only.
The captured interpreter is Python 3.12.13 with recursion setting 1,000. That
setting alone does not predict these consumer results.

## Observed behavior

| Actual consumer | Result in this matrix |
| --- | --- |
| Successful validation | All 32 cases discard the provider response body. |
| Refused-provider validation | Excerpt container depth 255 renders successfully; 256 fails with plain HTTP 500 and observed ValueError. |
| Array versus object input | An array is wrapped in the excerpt's payload object, adding one container level; an object is passed through. Thus array depth 254 and object depth 255 succeed, while array 255 and object 256 fail. |
| Direct provider, HTTP 200 | All 32 bodies parse and retain their trees, including both shapes at depth 1,600. |
| Direct provider, HTTP 403 | All 32 retain the existing RuntimeError/text-excerpt policy, not JSON projection. |
| Delivery helper | All 64 return successfully and save either provider data or the recorded refusal. |
| Full credential routes | All 192 suspend/reinstate/revoke cases return HTTP 200 and save delivery state. |

Validation totals are 45 HTTP 200 and 19 HTTP 500. Every full route retains the
observed sequence: publication, canonical credential saved, provider request,
delivery-save attempt, delivery saved. Complete credential/delivery row
projections, changed credential columns, request bodies and event-row equality
remain in the artifact. Published routes add no events; preserve newer Rust
success events during native adoption.

These finite cases establish neither an upper provider/JSON/storage depth limit
nor universal behavior for other tree shapes or grammar. In particular, a
single shared 127- or 255-level parse limit would drop working provider behavior.

## Nonrecursive observation integrity

Only the selected `response_excerpt` and `status_sync_response` fields use an
explicit `marty.json-tree/v1` structural witness AFTER the actual consumer
returns. The witness includes SHA256, value-node count and maximum container
depth. The iterative observer neither changes interpreter limits nor recursively
walks the application tree. Complete validation wire bodies are retained as
strings alongside the witness.

The digest begins with ASCII `marty.json-tree/v1\n`, followed by one compact
ASCII JSON token and newline for each value in preorder:

- Object: `["object", CODEPOINT_KEY_ARRAYS]`, with keys sorted by codepoint,
  followed by child values in that order.
- Array: `["array", LENGTH]`, followed by values in their original order.
- Null/boolean/integer: `["null"]`, `["bool", VALUE]`, or
  `["integer", DECIMAL_STRING]`.
- Float: `["float", BIG_ENDIAN_F64_HEX]`; NaNs use the string `"nan"`.
- Text: `["text", CODEPOINT_ARRAY]`.

Object insertion order is not a JSON semantic difference; key identities and
all values remain covered. Integer versus float, signed zero, array order and
surrogate codepoints remain distinct. Literal application witness-shaped
objects are hashed normally, never recognized as generated markers. Fourteen
unit cases cover token stability, distinctions, unchanged inputs, depth 1,600
without recursion, and unsupported non-JSON objects.

Provider result normalization now occurs outside the adapter exception handler,
so an observer error cannot be mislabeled as an application exception. Existing
observers keep their default exception assertions and full-value representation;
the new diagnostic options do not weaken their frozen reference gates.

## Reproduction and next implementation

Use `capture_canvas_published_oracle json-depth --output ABSOLUTE_NEW_FILE`.
The capture utility exclusively creates a new file and refuses to overwrite
existing evidence. A test verifies a capture larger than the terminal's 1 MiB
transport limit, numeric preservation and refusal to overwrite. The original
stdout mode remains available for smaller captures.

The required configured gate is
`json_depth_diagnostic_matches_published_boundaries`, with
`MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1`; an unset flag does not qualify it.
It regenerates and compares the whole artifact, not just summary counts.

Next, implement stack-safe native parsing/value traversal and persistence
handling, with the independently observed typed-validation depth policy kept at
its own boundary. Replay all 64 provider/validation cases and 192 full routes,
including database reads of retained nested metadata. Do not just raise serde's
parse limit and overlook serialization, cloning, dropping or database decoding.
General grammar, remaining codec/transport boundaries, whole-worker/every-consumer
cutover and Python deletion gates remain open. PR #814 stays draft and unrouted.
