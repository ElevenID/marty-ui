# Delegated-use client candidate

`marty-delegated-use-client` is an independent Rust client for the explicitly
selected public caller routes of `marty-delegated-use`. It depends on ordinary
transport and serialization libraries, not Marty Core, owner services or their
databases. The crate is currently a workspace candidate (`publish = false`).
The selected profile remains one managed organization, full-machine identity,
KEY grant binding, exact operation and a nested machine JWT-VC/DCQL response.

## Explicit transport trust

Construct `ClientConfig` with a canonical HTTPS origin **without a trailing
slash**, a non-nil organization UUID, a nonzero whole-request timeout of at most
300 seconds, and `MtlsConfig` containing:

- A nonempty `rustls::RootCertStore` containing the explicitly configured CA
  certificates. The client adds no operating-system or public Web PKI roots.
- An `Arc<dyn rustls::client::ResolvesClientCert>` with a client certificate.
  This resolver can use remote key custody; the client does not request or
  export private key material.

The client constructs its own TLS verifier from those roots. It rejects URL
credentials, paths, query strings, fragments, noncanonical origins and missing
client certificates. Redirects, automatic retries, environment proxies and
automatic decompression are disabled. Connections use HTTP/1.1 with no idle
connection reuse; connect time is limited to the smaller of ten seconds and
the configured whole-request timeout. All response bodies have streaming size
limits, and success responses must carry the selected media type plus
`Cache-Control: no-store`, `Pragma: no-cache` and `X-Content-Type-Options: nosniff`.

```rust
use std::{sync::Arc, time::Duration};
use marty_delegated_use_client::{ClientConfig, DelegatedUseClient, MtlsConfig};
use rustls::{client::ResolvesClientCert, RootCertStore};
use uuid::Uuid;

fn connect(
    roots: RootCertStore,
    client_certificate: Arc<dyn ResolvesClientCert>,
    organization: Uuid,
) -> Result<DelegatedUseClient, marty_delegated_use_client::ClientError> {
    DelegatedUseClient::new(ClientConfig {
        origin: "https://use.example.test".into(),
        organization,
        tls: MtlsConfig { roots, client_certificate },
        timeout: Duration::from_secs(20),
    })
}
```

Origin and certificate configuration belong to trusted application setup.
Neither a command result nor a request JWT can change them. Authentication to
the transport remains separate from machine proof, current component rights,
grant authority and the consumer application's business permission.

## Prepare and retain each command before I/O

Use `PreparedStart::new(command_id, grant, operation)` and
`PreparedFinalize::new(command_id, challenge_id, proof_submission_id)`. Each
validates the closed command schema, constructs canonical bytes and computes
the SHA-256 digest locally. The application must durably retain its original
inputs and exact command UUID **before calling the network**. Reconstructing
the object from those inputs preserves its bytes and digest. The crate itself
does not provide durable storage or a business-operation journal.

`start` and `finalize` make one request each. A repeated explicit call retains
the caller's same identity; the library does not create a new one. Recovery is
an explicit read using the independently retained command:

```rust
use marty_delegated_use_client::{DelegatedUseClient, PreparedFinalize};

async fn recover_original(
    client: &DelegatedUseClient,
    retained: &PreparedFinalize,
) -> Result<(), marty_delegated_use_client::ClientError> {
    let result = client.recover_final(retained).await?;
    let evidence = client.recover_receipt(retained).await?;
    assert_eq!(result.response().original_command_id, retained.command_id());
    assert_eq!(evidence.original_response().command_digest, retained.command_digest());
    // Pass evidence and independently retained context/trust to the receipt
    // consumer before using any signed assertions from it.
    Ok(())
}
```

`recover_start`, `recover_final` and `recover_receipt` construct their
`RECOVER_RESULT` request from that original UUID and locally computed digest.
Server-returned IDs and digests never replace recovery expectations.

A timeout, disconnected response, pending result, HTTP error or absent result
does **not** establish that the original operation did no work. The application
must retain that uncertainty and its existing command identity. The client
never retries automatically, treats a missing result as permission to reissue,
or creates a replacement command.

## Follow the bound request and verify it independently

`start`/`recover_start` return a sealed `StartedUse` only after checking the
response profile, original command UUID and digest, exact original grant and
operation, challenge and lifetime shape. Its returned `Link` must identify
exactly that challenge's request URL on the configured origin. The client
rejects duplicated links, another host or challenge, additional query or
fragment data, and alternate URL encodings.

`fetch_request(&started)` follows the retained advertised URL. Its
`UnverifiedRequestArtifact` contains the original compact bytes. Transport and
JWS-shaped syntax do not verify the signature or any request claims.

Before constructing a `CallerVerifiedRequest`, the caller must independently
verify the signed authorization request against its configured signing trust
and original operation context. This includes signing identity and allowed
algorithm, audience/client identity, nonce, lifetime, selected securing profile,
state, response mode and the complete frozen DCQL query. The type is explicitly
a **caller assertion**, not a verification result supplied by this crate.

After that verification, set `response_uri`, `state` and `query_id` from the
verified request and call
`submit_direct_post(&started, &verified_request, &compact_vp)`. Before sending
any proof, the client requires the exact configured-origin submit URL and the
original challenge state. It sends a form containing only `state` and a
`vp_token` JSON map with the selected query ID and one compact VP. It then checks
the returned challenge, exact original proof digest and retained receipt time
against the original challenge interval. The host independently associates
the response against its frozen query and later verifies machine proof.

## Original receipt evidence remains separate from authorization

`recover_receipt` checks that its original result matches the independently
retained finalization, that its reference and digest agree with the result,
and that the exact compact bytes have that digest. The outer and inner result
must retain `EVIDENCE_ONLY` semantics. `PERMIT` and `DENY` are accepted as
evidence outcomes; neither causes business execution.

The returned `ReceiptArtifact` remains cryptographically unverified. Pass its
exact `compact_jws()` bytes to `marty-delegated-receipt-consumer` with separate
issuer/key trust, original request context and an explicit freshness policy.
Transport success, a digest match or the name `ReceiptArtifact` does not supply
that verification. Historical recovery preserves the original timestamps; it
does not renew expired or revoked authority. Rifare continues to own current
business authorization, reservations, budgets, provider calls and outcomes.

## Selected routes

| Operation | Route |
| --- | --- |
| Start, finalize, recover command | `POST /v1/organizations/{organization}/delegated-use-commands` |
| Original receipt recovery | `POST /v1/organizations/{organization}/delegated-use/receipts/recover` |
| Fetch advertised signed request | `GET /v1/flows/instances/{challenge}/request` |
| Submit verified request's response | `POST /v1/flows/instances/{challenge}/submit` |

These are the opt-in host's machine-caller surfaces. This crate does not enable
public Gateway routing, human lifecycle commands, arbitrary wallets, production
certificate issuance or business execution.

## Local qualification

From the workspace's `rust` directory, with the pinned dependencies available:

```sh
cargo test --locked --offline -p marty-delegated-use-client
```

The synthetic network suite uses a real HTTPS server requiring a client
certificate. It covers explicit trust failure, wrong client certificate,
retained command reconstruction, one-attempt failures and explicit recovery,
response correlation, destination refusal before proof dispatch, duplicate-safe
wire decoding, protected response headers, size limits and preservation of
original historical receipt evidence. Its JWS-shaped fixtures do not claim
cryptographic request or receipt verification. The host's separate managed
lifecycle acceptance performs those checks with actual selected owner services
and remote signing custody.
