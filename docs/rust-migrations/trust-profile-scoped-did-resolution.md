# Trust profiles and retained issuer identity

Trust-profile hydration resolves an organization-owned DID from the signing
service's existing scoped public-document store before using the configured DID
resolver. The lookup uses the issuer entity's stored organization ID and exact
DID, through `POST /internal/documents/{organization_id}/did/load` with only the
`did_id` field. It uses the existing `SIGNING_KEYS_SERVICE_URL` origin and
`SIGNING_KEYS_INTERNAL_API_KEY`; it does not contact the DID's authority or invoke
signing, document publication, registration, or key creation.

An authenticated response with `found: true` must contain that exact DID and
usable public assertion keys bound to it. Private key or custody metadata,
foreign controllers or method IDs, conflicting key material, malformed replies,
redirects, and authorization or transport failures are refused. Requests use the
configured dependency timeout and a 1 MiB response limit. Only an explicit
`found: false` permits the existing configured resolver path. Its public-host,
IPv4, and SSRF policies are unchanged. Global issuer entities continue to use
that resolver directly, and already pinned verification keys are preserved.

This separates an issuer's registered identity from the deployment's current
public transport address. For example, moving a development server can make its
ordinary gateway DID route project the new address, while the signing store
still publishes the intentionally retained DID. Trust hydration must not replace
that issuer ID with the new address. Successful hydration persists public keys
and resolution provenance using the existing issuer metadata path; it is not a
strictly read-only trust-profile request.

The scoped lookup does not prove that an external wallet can resolve the retained
DID over the public network. Test that separately. An unregistered or incorrect
credential-template issuer reference is also a separate configuration error:
this lookup neither repairs it nor creates a replacement issuer.
