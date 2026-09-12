# Signing response adoption reference

This is reference discovery, not production Rust adoption or deployment proof.
The original 45-vector signing diagnostic corpus remains unchanged.

## Reproduction and ownership

`scripts/capture_signing_response_reference.py <credentials-checkout> --check
--summary` reads Git objects at credentials revision
`d418ac0df283625f43b0c011fb1c72fd7d3013a9`, verifies all four source blobs, and
executes the complete unchanged signing module. Exact AST-selected original
LTI signing, organization proof-policy, and readiness callers execute with
controlled configuration and HTTPX MockTransport. All remote requests use one
synthetic origin and direct synthetic service keys; the capture environment is
cleared, preventing operator secret-file fallback. Socket connections are denied.
No repository, crypto, deployment, or production configuration is changed.

The FastAPI wrapper tests actual default exception handling/JSON serialization,
but is not the published service's route graph or gateway. The artifact records
the actual local dependency versions: Python 3.12.10, HTTPX 0.28.1, FastAPI
0.135.3, Starlette 1.0.0, Pydantic 2.13.0, recursion limit 1000. Those versions
are evidence boundaries, not a claim of equivalence to every published image.
Pinned `main.py` installs CORS and request-ID middleware, with no custom exception
handler or debug override. Its request-ID middleware resets context in `finally`
without swallowing exceptions. Eight additive `outward_http_responses` entries
use `raise_app_exceptions=False` to observe actual controlled HTTP status/body:
unhandled decoder errors and LTI surrogate-rendering failures return plain-text
500 `Internal Server Error`; handled RuntimeError paths retain JSON 503. The
original exception-propagating observations remain unchanged. This confirms
controlled response behavior, not the entire published service middleware graph.

`contracts/signing-response-python-reference.json` contains 35 explicit inputs,
16 helper observations, 105 remote operation observations, and 102 caller
observations. Each caller observation executes both directly and through the
controlled ASGI wrapper. LTI signing first performs real source-level identity
validation on synthetic public fixture data; no actual signing/verification is
performed. The readiness slice controls only pre-resolution configuration and
observes the unchanged failure catch; it is not successful readiness acceptance.

The source identities and complete SHA256 hashes are embedded in the artifact.
The signing helper blob is `5e84cfdcbdf289ec0059eb39dd54c4a5c79c5b3a`; its source
SHA256 is `c412284956f3cb41a9dbd8840a1f67ff4df97f3db1990109499d5b37b704d253`.
Deep inputs are represented by explicit nested-object depths, avoiding repeated
large encoded strings; the capture constructs those exact bytes before HTTPX.

## Findings that constrain Rust adoption

- JSON parsing precedes text decoding, even when JSON supplies the selected
  diagnostic. Valid JSON with `charset=utf-16` and no BOM still raises
  `UnicodeError` while decoding text. UTF-16 JSON byte detection remains separate
  from the declared response-text charset.
- Selected unpaired surrogates survive Python diagnostic selection. Nested
  dictionary representations escape them; discarded fields do not poison a
  valid selected diagnostic. Truncation retains exactly 500 Python codepoints,
  without an ellipsis. A surrogate beyond that boundary disappears legitimately.
- Both original LTI resolve/sign callers put a retained surrogate in their
  HTTPException detail; the real controlled JSON renderer raises
  `UnicodeEncodeError`. This must not be mistaken for successful 503 JSON output
  or silently replaced by Rust scalar conversion.
- The proof-policy fixed 503 catches `RuntimeError`, including `RecursionError`,
  and masks remote diagnostics. It does **not** catch `UnicodeError` or malformed
  redirect-response `JSONDecodeError`. Those escape the original caller and
  controlled renderer. Readiness catches all these failures and returns false.
  Any intentional native normalization needs separate review, not a parity claim.
- Dictionary insertion order, last duplicate value at its original key position,
  lowercase `nan`/`inf`/`-inf`, and negative integer zero normalization matter.
  `to_scalar().ok()` and validation JSON conversion cannot preserve these inputs.
- Depth 2048 parses and formats successfully on the recorded runtime. Depth
  10000 raises `RecursionError` during JSON parsing, before text decoding.
  These are observations at two depths, not an inferred universal depth limit.
- 301/302/303/307/308/399 responses follow the normal successful-response parser
  without following `Location`: exactly one request per remote operation.
  Malformed/empty/non-object/false/missing `ok` cases differ. Signer DID,
  algorithm, verification method, private-selector, and nonempty signature checks
  still execute. Native `!is_success()` checks currently reject 3xx earlier.
  Two additional valid public-profile/JWK inputs prove actual LTI success and
  required/default proof-policy output on 302, not just helper continuation.
  The direct LTI tuple's return type is recorded alongside its JSON-array form.

Operation identity comes from the caller, not its URL. Credential context and
proof-policy use Context even with `/resolve-issuer-did`; original LTI/readiness
callers use Resolve. The Rust resolver is shared, so adoption should select the
operation at those existing caller seams without creating another HTTP/crypto
implementation.

## Required next review

Keep lossless JsonTree/PythonText through selection, formatting, and truncation.
The existing Rust `IssuerUnavailable(String)`/`SigningUnavailable(String)` and
LTI stringification boundaries cannot represent a raw surrogate; agree the
actual outward serialization policy before changing production adapters.
Preserve all existing success/crypto validation and proof-policy/readiness
privacy. The six original 401/503 helper vectors still require real native HTTP
adapter and caller qualification; these Python mock requests do not satisfy it.

Local guards: `python -m pytest tests/test_signing_response_reference.py`
(nine tests), capture `--check`, Ruff and
formatting. No Cargo lease was used and no production Rust was edited.
The guards are collected by root CI's `pytest tests`; they extract inert source
identity literals with the standard-library AST reader and do not import the
capture runtime, FastAPI, or HTTPX.
