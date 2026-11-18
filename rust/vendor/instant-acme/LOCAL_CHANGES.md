# Local changes to instant-acme 0.8.5

This directory contains the runtime source, license and README from the published
`instant-acme` 0.8.5 crate, with the explicit changes below. The maintained client
continues to own ACME protocol behavior. Marty supplies the bounded network and
nonexportable signing adapters in `crates/acme-client`.

`UPSTREAM.json` records the published archive checksum, upstream revision,
original/vendored file checksums and patch checksums. The crate archive checksum
was independently checked against the crates.io index. The original Apache-2.0
license is retained without modification.

The patches use zero context so they contain no whitespace-only context lines.
Apply the signer patch, response-metadata patch, prepared-account patch, and
manifest patch in that order to the verified original archive with
`git apply --unidiff-zero`. This sequence
reproduces every retained runtime file and the normalized manifest exactly.

## Account signing extension

`patches/nonexportable-account-signer.patch` is the complete change to
`src/account.rs`, `src/types.rs`, and `src/lib.rs`:

- Add an async external ES256 account signer with a public P-256 SEC1 point.
- Add account creation/restoration methods that never request private key bytes.
- Snapshot the public point and verify every external signature before CA POST.
- Await signing inside the existing JWS and nonce/retry path.
- Keep local account creation and HMAC External Account Binding behavior intact.
- Refuse the existing local-key rollover API for an externally held account key.

The signer patch does not change order/challenge handling, external CSR
finalization, polling, profiles, IP identifiers or ARI. Upstream main at revision
`1cbc35cca446e6d6813b3c13ac843d50948facd0` was also inspected. Its public crypto
provider still has synchronous signing and PKCS#8-based load/generation APIs,
so it does not replace this explicit asynchronous external-key boundary.

## Durable response metadata

`patches/durable-response-metadata.patch` is a separate, subsequent patch:

- Retain optional order/authorization `expires` text and the exact order
  identifier list. Missing values stay distinguishable; the installation owner
  must require and validate them before scheduling or resuming an order.
- Retain observed HTTP status and parsed absolute `Retry-After` on order and
  authorization responses and API problems. JSON cannot supply these fields.
- Add `set_ready_with_response` for a challenge readiness result with the same
  request as the existing `set_ready` method.
- Preserve the existing nonce and retry loop. Invalid or overflowing numeric
  `Retry-After` values return no hint rather than panicking on time overflow.

This patch exposes response information; it does not add a scheduler, durable
state, automatic order retry or certificate activation. The existing internal
polling policy is unchanged. Callers must persist deadlines themselves.

## Explicit account preparation

`patches/prepared-account-registration.patch` adds a directory-GET-only
`PreparedExternalAccount` boundary. It exposes the advertised terms URL and
profiles so the installer can check its immutable selection before recording
registration intent. Its explicit `register` call checks the same fetched
directory again, including for same-key `onlyReturnExisting` recovery, and
requires explicit agreement. It never registers implicitly during preparation.
Existing `create_with_signer` and local account behavior are preserved.

## Manifest normalization

`patches/vendor-manifest.patch` removes unused example and network-test targets
and all upstream development dependencies from the published normalized
manifest. Runtime dependencies, feature declarations, package identity and
license are retained. The original normalized-manifest checksum is in
`UPSTREAM.json` so the transformation can be reproduced from the pinned archive.

The upstream lockfile, example programs, development fixtures and tooling are
not vendored. The enclosing Marty workspace owns dependency resolution and its
lockfile; this directory is excluded from workspace membership. Marty tests the
adapter and external signer protocol through its own crate.

## Verification boundary

The local signer extension and adapters have passed in-memory ACME protocol
tests and a disposable, loopback TLS test against the official OpenBao 2.5.5
binary. Those tests do not create a public CA account or qualify the shipped
container image, certificate renewal, installation journals or reboot recovery.
See `docs/installer-acme-client.md` for the installation-owned integration
requirements.
