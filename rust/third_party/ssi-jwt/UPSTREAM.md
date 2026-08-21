# Vendored ssi-jwt

This directory contains the exact Rust source published as `ssi-jwt 0.6.0`
from the Apache-2.0 licensed `spruceid/ssi` project (crates.io checksum
`98f953e271857faddebb077cae34e4f514664038f9177471528ce921e6b28297`).

The only source-package change is the compatible `serde_with` dependency bound:
`2.3.2` was replaced by `3.21.0`. The crate does not import or use
`serde_with::KeyValueMap`; this removes the vulnerable 2.x package identified by
GHSA-7gcf-g7xr-8hxj without changing the SSI JWT implementation or public API.

Remove this patch when the canonical SSI release consumed by `marty-core`
depends on `serde_with 3.21.0` or newer.
