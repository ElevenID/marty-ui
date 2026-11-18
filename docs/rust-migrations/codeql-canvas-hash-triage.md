# Canvas hashing alert review

Reviewed source: `f7ab5f908`, with the flagged lines unchanged from PR #814's
pushed `98e78b8d036b3beaf7537fb09280b4f04ecbb16b`.

CI run `34718953669` completed successfully. The separate CodeQL result
`103621230629` reports two high-severity password-hashing findings. Successful
tests do not resolve those alerts. Root and an independent reviewer inspected
the reported inputs, sinks, callers, and persistence path. Both confirmed the
narrow false-positive classifications below; alert disposition is recorded
separately in GitHub.

## Alert 137: OAuth authorization state

`rust/services/issuance/src/canvas_oauth.rs` creates authorization state using
`secure_token(32)`: 32 random bytes from `rand::rng().fill_bytes`, encoded as
unpadded URL-safe Base64. It persists the SHA-256 digest, not the bearer state,
alongside the authorization expiry. Callback handling hashes the supplied state
and asks the repository to consume the matching authorization at the current time.
The submitted state is a lookup candidate, not a password chosen by a user.

The flagged source is the HTTP callback input (`http.rs:1579`), and the sink is
`hash_state` (`canvas_oauth.rs:1735`). Both calls to that helper were inspected:
authorization creation and callback lookup. No password-verification call to it
was found. Existing behavior tests check non-plaintext persistence; PostgreSQL
contract tests cover one-time consumption. The frozen lifecycle contract specifies
`sha256-only` state persistence.

Reviewed classification: false positive for password hashing. A password KDF is
not a substitute for this high-entropy bearer-state lookup and would change the
frozen storage/lookup contract. This does not excuse low-entropy passwords hashed
with SHA-256 elsewhere, or establish that every OAuth behavior is correct.

## Alert 139: public behavioral-contract fingerprint

`rust/services/issuance/src/contract.rs:872` hashes canonical LF-normalized bytes
from the compile-time `include_bytes!` of
`contracts/issuance-canvas-oauth-lifecycle.json`. The digest is compared with the
recorded behavioral-contract provenance. The input is a checked-in public
specification, not credentials, callback input, or a stored password.

Reviewed classification: false positive. SHA-256 fingerprints these public bytes;
replacing it with a password KDF would break provenance rather than repair a
password store.

## Boundaries

Independent review additionally verified the PostgreSQL consume operation marks
the authorization consumed only if unused and unexpired, with a 600-second
authorization lifetime. The review was source-based; it did not rerun tests or
claim a comprehensive OAuth audit.

No cryptography, frozen fixture, workflow query, branch protection, or CodeQL rule
was changed or disabled by this review. Only alerts 137 and 139 are approved for
false-positive disposition as maintainer `burdettadam`. Other alerts, including
organization alert 138 and existing findings
outside these two locations, are not covered by these classifications. Final-head
checks and all consumer/deployment gates remain required.
