# Published JSON consumer boundaries

This is independent behavioral reference evidence, not native JSON parser
qualification or worker-cutover authorization. No runtime parser changed here.

## Source and scope

The disposable fixture uses the published issuance image
`ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`
and real PostgreSQL migrations/repository. Existing app/router/adapter source-hash
assertions remain active. Canonical publication, provider HTTP and DNS are the
same controlled synthetic ports as the prior UTF-7 reference. No deployment URL,
real credential or production configuration is accepted.

Two final captures agree byte-for-byte before native implementation: 66 managed
validation observations, 66 direct provider observations, 66 delivery-helper/save
observations, and 198 full suspend/reinstate/revoke routes. The matrix has 33
response-body patterns, each with provider HTTP 200 and 403. It includes escaped
and raw UTF-8/16/32 surrogate values, top-level/nested keys and values, paired
surrogates, key collisions, NUL values/keys, non-finite numbers, signed zero,
large integers, the 4,300/4,301-digit boundary, duplicate keys, malformed JSON,
invalid UTF-8, BOM handling and literal diagnostic-marker-shaped objects.
`application/json; charset=latin1` deliberately distinguishes JSON byte detection
from the separate response-text codec.

## Observed distinctions

| Boundary | Published behavior in this matrix |
| --- | --- |
| Successful validation | Discards the provider body without JSON/text decoding. |
| Validation of non-finite JSON numbers | Renders `null`, including nested array values. |
| Validation of a lone surrogate value | HTTP 500 with observed UnicodeEncodeError. |
| Validation of a top-level excerpt surrogate key | HTTP 200; the key becomes three U+FFFD codepoints. |
| Validation of a nested surrogate key | HTTP 500 with observed UnicodeEncodeError. |
| Colliding top-level keys after rendering | Last value wins; normalized wire-body evidence confirms one resulting key. |
| Successful provider JSON parsing | Retains exceptional values/keys until persistence; it does not use validation's rendering substitutions. |
| Provider HTTP refusal | Uses the separately decoded text excerpt rather than JSON projection. |
| Non-finite, surrogate or NUL JSON persistence | Fails after canonical credential status is saved; delivery row remains unchanged. |
| 4,300-digit integer | Parsed and retained without a JavaScript-number precision limit. |
| 4,301-digit integer | JSON parsing falls back to the bounded original-text excerpt. |

There are nine validation HTTP 500 observations. Of the 198 full credential
routes, 69 return plain HTTP 500 after canonical persistence and preserve the
entire delivery row; 129 return HTTP 200 and save delivery state. The reference
retains complete before/after rows, exact changed credential columns, publication
and provider/save ordering, request bodies, and event-row equality. No published
route adds issuance events in these cases. Newer native success events must not
be deleted merely because the old implementation lacked them.

These are observations of the actual published app. They do not establish a
single universal JSON rendering policy: top-level typed dictionary keys, nested
values, provider metadata and PostgreSQL storage visibly differ. The next Rust
implementation must preserve those boundaries instead of normalizing values
during parsing or globally rejecting every exceptional value.

## Lossless diagnostic encoding

`scripts/canvas_observation_values.py` runs only after actual consumer execution.
It encodes surrogate text as `python_codepoints`, non-finite/signed-zero floats
as `python_float`, and integers outside the JavaScript-safe range as decimal
`python_integer` strings. Objects with non-scalar or reserved marker keys become
ordered `python_object` entry pairs. Thus literal application objects cannot be
mistaken for generated markers. Eighteen unit cases cover collision safety,
nesting, unchanged inputs, surrogate pairs versus scalar text, numeric boundaries,
and signed zero. Ordinary finite float literals remain JSON numbers.

Validation diagnostics also retain actual response text, normalizing only the
fixture-generated validation timestamp. This prevents reparsing a response from
hiding key collisions or numeric rendering. Large numeric literals must not pass
through JavaScript parse/stringify while authoring the reference. The retained raw
captures and a whitespace-only formatter preserve the numeric tokens; configured
regeneration compares the complete artifact using the Rust JSON owner.

The UTF-7 observer reuses this encoder without changing its frozen artifact.
Existing validation observers retain their expected-exception assertions by
default. Only the new diagnostic mode records actual exceptions and wire bodies;
the configured JSON gate then freezes and compares those observations in full.

## Reproduction and remaining work

Capture with the existing example:
`capture_canvas_published_oracle json-consumer`.
The required configured image/schema gate is
`json_consumer_diagnostic_matches_published_boundaries`, with
`MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1`. An unset variable does not qualify the gate.

Native response JSON parsing still uses scalar serde values. The next work is
lossless parsing of values and keys, exact numeric acceptance/fallback, separate
validation rendering and persistence policies, then native replay of this matrix.
Recursion/depth, other exceptional codecs and whole-worker/every-consumer adoption
remain open; this finite reference must not be presented as proof of those scopes.
