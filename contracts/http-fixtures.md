# Shared HTTP compatibility fixtures

The Issuance HTTP response codecs, outbound timeout/retry policy, JSON syntax
error diagnostics and signing-error projection are platform utilities. They do
not import a Canvas provider, worker or connector runtime.

The `http-*codec*`, `http-charset-*`, `http-unicode-text-oracle.json`,
`http-utf7-boundary-oracle.json`, `http-json-diagnostic-*`,
`http-retry-after-scenarios.json` and `signing-error-privacy-reference.json` inputs
were copied byte-for-byte from their historical frozen captures in the parent
revision `3f8c7b8ae3116408e2de743320be3627e52f18bb`. Original schema identifiers,
source digests and historical provider names remain provenance; they are not
supported platform routes or an integration contract. In particular, the signing
privacy corpus retains the exact original digest and all 63 recorded cases.

Two fixtures isolate only the generic data actually consumed by the platform:

- `http-timeout-scalar-scenarios.json` preserves all 19 timeout scalar cases.
- `http-retry-after-reference.json` preserves all five fixed-time Retry-After cases.

Both record the exact parent Git blob and selected JSON field. Selected values,
order and case counts are unchanged; unrelated provider configuration and worker
behavior are not part of the projected fixtures.

Provider-specific oracle scripts and their old Rust capture fixtures are removed.
Original frozen inputs remain historical evidence during the remaining contract
inventory cleanup. Generic offline capture utilities use `http_*_codec_oracle.py`;
JSON structural/value observers have independent neutral modules and tests.
Platform Rust modules consume neutral fixture paths. The generic database fixture
`platform_test_database.rs` invokes current schema owners directly.

Canvas protocol and administration belong in the independent connector, whose
only platform integration point is the public Common Gateway. Production connector
adapters and cutover are deferred and do not justify restoring provider code here.
