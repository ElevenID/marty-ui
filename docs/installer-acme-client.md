# ACME client and nonexportable account signing

`marty-acme-client` supplies bounded HTTPS transports for the pinned
`instant-acme` 0.8.5 protocol client and an asynchronous OpenBao account signer.
The installation-owned enrolment module uses this library through an explicit
provisioning entry point. It produces an admitted certificate candidate; live
hosting activation and recurring renewal are separate integration work. It
grants no installation readiness or public certificate claim. See
[the enrolment contract](installer-acme-enrolment.md) for persistence and
interruption behavior.

## Account and certificate keys

The account signer uses one installation-owned Transit key name, explicit
positive version, and public P-256 SEC1 point. The installation owner must first
verify the key's type, nonexportable settings, version and public identity.
Construction alone is not evidence of those custody settings.

The adapter sends the exact ACME JWS input to OpenBao with SHA-256, JWS
marshaling and its pinned key version. It never calls export or backup APIs.
Only the matching `vault:vN:` response with canonical Base64URL encoding of a
64-byte signature is accepted. The client verifies that signature locally
against its immutable public-key snapshot before sending the corresponding CA
request. Transit rotation therefore cannot silently change the ACME account.

The certificate key remains separate. The owner constructs and validates the
exact DNS/IP CSR for its retained nonexportable certificate key, then passes
the admitted DER bytes to the client's existing `Order::finalize_csr`. The
client does not need certificate private material. External Account Binding
is an unrelated HMAC mechanism and is not used as an account-signing substitute.

## Transport and credentials

Both the signing input and response are limited to 64 KiB. A ten-second deadline
covers the complete signing call, including workload credential obtainment and
response consumption. The credential provider is invoked for each signature;
it must supply fresh, narrowly scoped authority and implement the actual
authentication/renewal lifecycle. Headers containing credentials are marked
sensitive, and transport errors do not include tokens or response bodies.

OpenBao requests use the existing `marty-openbao-http` verified HTTPS policy.
The ACME adapter separately permits only the selected Let's Encrypt staging or
production origin, requires normal HTTPS verification, disables redirects and
environment proxies, and bounds request/response size and time. Restored server
URLs cannot send ACME requests to another origin. Account state must keep the
selected directory bound to the same installation and key reference.

The maintained protocol is available through `marty_acme_client::protocol`.
Use `prepare_with_signer` with the bounded adapters to fetch the directory
without registration. Check its terms URL and profile against the saved
selection, persist registration intent, then call its explicit `register`.
That method rechecks the same fetched directory even for same-key
`onlyReturnExisting` lookup after an interruption. A saved account URL can be
reattached with `restore` after the same directory check. The original
`create_with_signer`/`from_signer` APIs remain compatible; the installation owner
uses the preparation boundary. The legacy local-key rollover API refuses a
remote account; an explicit remote-key rollover operation is separate work.

A separate vendor patch retains the server's order and authorization expiry
text, the order identifier list, and HTTP status/`Retry-After` hints. Missing
fields remain absent; the installation owner must validate returned identities
and parse deadlines before persisting them. Header metadata cannot be injected
through the JSON response. `set_ready_with_response` exposes readiness-response
hints without an additional request. The client's existing retry loop is
unchanged; none of these fields supplies durable scheduling by itself.

## Durable operations belong to the installation owner

The adapter owns no installation directory, journal, scheduling loop or service
manager. The installation owner must provide:

1. A durable account intent containing directory, key name/version and public
   fingerprint before registration, followed by the returned account URL.
2. An installation lock and durable order intent containing exact identifiers,
   profile, certificate-key version and CSR bytes/hash. The returned order URL
   must be recorded before challenge completion or finalization proceeds.
3. Reconciliation of a known order URL after interruption. A crash after the CA
   accepts `newOrder` but before its URL is persisted remains uncertain. The
   client has no new-order idempotency key or account-order listing API; blind
   retry of that mutation is not supported.
4. Exact CSR SAN/SPKI/signature validation before finalization and public-chain,
   SAN, SPKI, validity and selected-profile validation before atomic certificate
   activation. Staging trust must never become production trust.
5. Persisted ARI renewal scheduling, bounded retries and expiry fallback,
   credential re-authentication, challenge cleanup and installed recovery tests.

The existing protocol client supports IP identifiers, profiles, ARI and
external CSR finalization. IP certificates require Let's Encrypt's `shortlived`
profile; the current published validity is 160 hours. These features make expiry
and interruption handling part of the installation lifecycle, not a one-time
certificate download. Official references:

- <https://docs.rs/instant-acme/0.8.5/instant_acme/struct.Account.html>
- <https://docs.rs/instant-acme/0.8.5/instant_acme/struct.Order.html>
- <https://docs.rs/instant-acme/0.8.5/instant_acme/struct.NewOrder.html>
- <https://openbao.org/docs/2.5.x/api/secret/transit/>
- <https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/>

## Verification

The crate's ordinary tests use in-memory ACME responses and real ES256
verification. They cover remote JWK/thumbprint, IP/profile/ARI requests,
known-order recovery, exact CSR pass-through, nonce retry signing, invalid
signature refusal, remote rollover refusal and preserved EAB behavior. Adapter
tests cover origin/method/size rejection before network access, strict signature
decoding and a pending credential provider inside the signing deadline.
Response-metadata tests cover order creation/restoration/finalization/refresh,
authorization expiry, challenge readiness hints, rate-limit responses, missing
fields, header/JSON separation, and invalid or overflowing retry deadlines.
Prepared-account regressions verify that preparation sends only a directory
GET and that terms/profile/agreement mismatch makes no registration POST,
including a resumed same-key account lookup.

The opt-in `official_openbao_255_signs_nonexportable_account_and_pins_key_version`
test requires `MARTY_TEST_OPENBAO_EXECUTABLE` to identify a separately verified
official OpenBao 2.5.5 binary. It starts an ephemeral loopback TLS server, verifies
its TLS certificate, suppresses secret-bearing server output and kills the child
on unwind. Its scoped token cannot read/export keys or sign using the separate
certificate key. Even the fixture root cannot export the account key. The test
proves explicit version pinning after rotation, wrong-public-key refusal, and
replacement of a revoked token without changing account identity.

An OpenBao CSR is independently verified with OpenSSL and passed through the
client to an in-memory CA fixture. That fixture CSR has no SANs; exact product
identity admission is tested separately by the certificate owner. The test is
official-binary protocol evidence, not public CA issuance, shipped-image
qualification, persistent storage, renewal, expiry or reboot evidence.

The upstream runtime source, license, original checksums and exact local patches
are retained under `rust/vendor/instant-acme`. The workspace lockfile owns
dependency resolution. No upstream development lockfile or executable tool is
included.
