# Public CSCA lifecycle vectors

These synthetic, self-signed P-256 CA certificates were generated once on
2026-10-07. The transient signing keys were kept only in the fixture-generation
process; this directory contains certificates, not private keys. The fixed
validity window is 2026-10-07 through 2026-11-06. Tests use the certificate's
`not_before` as a synthetic clock so the vectors remain usable after expiry.
The `http-*` pair is valid from 2025-01-01 through 2045-01-01 so the live HTTP
route test can use its real service clock during that interval.

Each `original`/`renewed` pair has the same subject and public key but a
different certificate serial. Each `other-key` certificate keeps that subject
and changes the public key. The lifecycle tests use these distinctions to
exercise explicit key reuse, key rotation, and rejection of inconsistent
renewal requests without generating or loading issuer private keys.

These vectors are test-only and are not deployment trust anchors.
