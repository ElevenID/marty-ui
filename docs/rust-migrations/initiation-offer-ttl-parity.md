# Initiation offer expiry configuration parity

Python Credentials `services/issuance/domain/entities.py` reads
`ISSUANCE_OFFER_TTL_MINUTES` at module import and applies it when constructing a
new transaction. The native shared initiation owner previously hardcoded 10080
minutes. This change preserves the configurable value for both HTTP and gRPC
consumers without changing consumer selection or delivery behavior.

`contracts/initiation-offer-ttl-python-reference.json` contains 18 executed
observations from unchanged entity source blob
`1b5e2eba90c1ec13c1a38135f4da92813f1d1073`, Credentials commit
`87eae30788924921a42848425d315e2f33f7ae41`. Only environment and `datetime.now`
are controlled; the entity module and dataclass default factories execute intact.
Reproduce explicitly with:

`python scripts/capture_initiation_offer_ttl_reference.py <credentials-checkout> --check`

Default CI tests use repository fixtures only; the explicit replay needs the old
checkout but no native binding. This is not HTTP/gRPC admission, database,
gateway, fresh automatic delivery or deployment acceptance.

Observed compatibility preserved:

- Unset defaults to 10080; custom values, zero and negative values are accepted.
- Python integer grammar includes surrounding whitespace, signs, separators and
  Unicode decimal digits. Empty, fractional and malformed values fail startup.
- Large valid integers are retained at startup. Values outside the Python
  datetime calendar fail during new transaction construction, before issuer
  resolution or reservation, rather than being clamped or causing a Rust panic.
- Existing idempotent reservation recovery precedes new expiry construction.
  Changing TTL, even to an oversized valid integer, does not rewrite stored expiry.

The implementation reuses MMF `PythonConfigInteger`, the existing layered
configuration, and one shared `InitiationService`. The structured setting is
`MARTY_ISSUANCE__INITIATION__OFFER_TTL_MINUTES`; the legacy environment variable
maps into that layer. Overflow becomes a sanitized typed internal error; this
corpus does not claim frozen whole-HTTP error formatting for misconfiguration.

Deployment integration now forwards `ISSUANCE_OFFER_TTL_MINUTES` into beta
`issuance-native` using the exact legacy base expression and default. The
read-only Compose gate checks default, custom Python integer spelling, zero
and negative bindings without clamping. Automatic initiation routing is still
unchanged; this setting does not itself qualify that consumer cutover. No
release pins, Core crypto, KMS configuration or deployed services were changed.
