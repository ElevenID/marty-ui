# Authenticated internal delegated-use transport

`use_http::delegated_use_command_router` exposes the retained P03 command service
through an explicitly assembled internal HTTP router. No executable or public
Gateway installs it. The existing human command host continues rejecting
`START_USE` and `FINALIZE_USE`; public discovery and MIP support are unchanged.

The sole application route is:

```text
POST /internal/v1/organizations/{organization_id}/delegated-use-commands
```

It accepts the original `START_USE`, `FINALIZE_USE` or `RECOVER_RESULT` JSON
document. It uses the existing closed P03 decoder and passes the original bytes
to `DelegationUseCommandService`; it does not normalize intent, create replacement
command IDs, retry work or supply successful proof/authorization flags.

## Authenticated forwarding contract

The deployment configures one organization and one dedicated service credential
of 32–1,024 visible ASCII bytes. `ServiceTokenAuthenticator` authenticates that
credential before the router trusts any forwarded actor metadata. There is no
anonymous mode or fallback to a user session/API key.

Every required header must appear exactly once, with no surrounding whitespace:

| Header | Meaning |
| --- | --- |
| `x-service-token` | Credential of the independently authenticated forwarding workload |
| `x-marty-use-organization-id` | Canonical UUID, equal to the configured organization and path |
| `x-marty-use-principal-type` | Exactly `SERVICE_ACCOUNT` or `MACHINE_IDENTITY` |
| `x-marty-use-principal-id` | Complete authenticated principal identifier |
| `x-marty-use-observed-at` | Original authentication observation, RFC 3339 UTC with `Z` |
| `x-marty-use-valid-until` | Original authentication expiry, at most 30 seconds after observation |
| `content-type` | `application/json`, with optional media-type parameters |

The forwarding workload is trusted to authenticate and bind the complete actor;
possession of a header or principal URI is not machine proof. A deployment must
protect the service hop with its selected authenticated TLS/network controls,
strip caller-authored trusted headers at ingress and use a distinct credential.
Those deployment controls and the authoritative workload-authentication source
are not installed by this router.

The resulting `AuthenticatedDelegationUseContext` has private fields, no public
constructor and no deserialization implementation. It carries only caller
identity and the bounded service-hop observation. The application still requires
its independent current actor authorization, exact grant/operation evaluation
and selected cryptographic proof path.

Human `Authorization`, `Cookie`, user/API-key identity headers and the separate
command/approval metadata families are rejected. Query strings, duplicate
metadata, foreign organizations, unsupported actor types and malformed time or
command values fail before application dispatch. Request bodies use the existing
grant-wire size bound and a five-second read timeout. Authentication is checked
again after the body arrives, including for a slow real HTTP stream.

## Deadline propagation and original work

The concrete application invokes `execute_before` with the original observation
and hop expiry, preserving both clock bounds after dispatch and source reads.
Its scoped authorizer first validates the original current-source observation,
including the source's own 30-second maximum. Only then does it shorten that
observation to the earlier hop expiry. A short hop cannot qualify an invalid
overlong source record, and a later source read cannot renew the original hop.

The bound reaches admission, current permission rechecks after lock waits,
prepared finalization, the ledger commit deadline and the existing deferred
PostgreSQL COMMIT guard. The service rechecks before starting signing after
awaited proof resolution and Flow preparation. If authentication expires during
an already-started signing invocation, final persistence fails closed and leaves
the original command claim unresolved. Signing and COMMIT are not wrapped in a
cancellation timeout or automatically retried.

Fresh authenticated requests may recover completed historical results after
independent current read authorization. Recovery preserves original bytes,
decision and timestamps; it supplies no renewed authority. Repeating an
unresolved command returns `PreparationPending`, even with a new authentication
observation, without repeating preparation or signing.

## Response behavior

All responses are marked `Cache-Control: no-store`, `Pragma: no-cache` and
`X-Content-Type-Options: nosniff`. Errors use stable sanitized `detail` codes:

| HTTP status | Condition |
| --- | --- |
| 400 | Invalid/unsupported closed command or malformed transport metadata |
| 401 | Missing, duplicate or invalid service credential |
| 403 | Forbidden actor/context, expired transport observation, or denied current source access |
| 404 | No retained original result |
| 408 / 413 / 415 | Body timeout, excessive body, or wrong media type |
| 409 | Original-intent conflict, unresolved preparation, or application evidence expiry |
| 503 | Unavailable evidence, preparation, persistence or signing dependency |

The router does not expose raw proofs, machine audit documents, source failure
details or custody credentials. `FINAL_USE` remains evidence of Marty's identity
and authority decision; it does not execute a Rifare operation.

## Qualification and next host work

Local tests cover authenticated typed forwarding, exact original bytes, strict
metadata/wire rejection, real HTTP body-read expiry, actual PostgreSQL completion
and recovery, source access loss, invalid source observations and expiry across
preparation/signing waits. Current actor, consent and domain-policy sources in
these integration tests are explicitly synthetic trusted fixtures.

The next host must compose independently owned full-machine/MAP and credential
status sources, required attestation and active policy sources, the audited
machine verifier, reviewed database roles and qualified managed custody. It
must separately authenticate wallet request retrieval and immutable proof
submission. This candidate supplies neither those owner contracts nor a public
host. See [retained commands](USE_COMMANDS.md), [machine audit](MACHINE_AUTH.md),
[credential verification](MACHINE_CREDENTIALS.md) and [receipt custody](RECEIPT_SIGNING.md).
