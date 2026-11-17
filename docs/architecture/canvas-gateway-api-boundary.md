# External connector: Common Gateway boundary

The public Common Gateway is the only integration point between the external Canvas connector and Marty. Core owns canonical identity, learner association, evidence, policy, approval, signing, status and audit. Canvas-specific protocol and provider behavior belongs in [canvas-integration](https://github.com/ElevenID/canvas-integration).

## Requests and authority

The connector uses a server-side client with a fixed public Gateway HTTPS origin, an organization-scoped API key in `X-API-Key`, explicit organization context, TLS verification, no redirects and bounded response sizes/deadlines. Keys never enter a browser bundle, URL, Canvas launch claim or log. Provider credentials cannot be sent as platform credentials.

Authorization derives from the authenticated principal and canonical resource ownership. A request body, provider identity, email or course membership cannot establish tenant or learner ownership. Read permission cannot authorize writes. The connector cannot call Core/private service URLs, access Marty PostgreSQL/Redis or use internal service credentials and signing grants.

Use each generic public contract's declared permission and DTO. Missing generic APIs are owner-scoped TODOs, and affected connector operations remain disabled. Do not preserve Canvas-specific platform endpoints as a second implementation or invent an internal adapter to bridge a gap. Routine connector credentials do not grant application approval or signing authority.

## Migration evidence and availability

The route matrix in [frozen pre-removal route inventory](https://github.com/ElevenID/marty-ui/blob/2fb4db3b40a77caf71a09c8c1a8057780711ae7a/contracts/canvas-integration-gateway-boundary.json) and the [administration migration inventory](canvas-administration-api-migration.md) describe the original Marty API baseline. They are historical evidence, not the current supported API or proof that a connector workflow is enabled. The removal candidate retires the provider routes and their authentication exceptions. A compatibility client referencing them requires explicit retirement or disabling in the connector.

The supported boundary is defined by current generic Gateway routing, request schemas, authorization mappings and tests. A disabled connector workflow needs no substitute production adapter to complete source retirement. Production deployment and cutover remain separate work.

## Verification requirements

For each enabled connector operation, verify valid-key/correct-organization success, missing/expired/revoked-key rejection, wrong-organization rejection, insufficient-scope rejection, schema bounds, ownership, canonical audit and defined idempotency behavior. Unknown write outcomes require reconciliation before retry; a transport failure is not evidence of rollback.

Canvas protocol callbacks terminate at the connector and independently validate protocol proofs. Runtime network policy must isolate connector storage and deny private Marty destinations. Static source checks do not establish deployed isolation.

See [extraction and ownership](canvas-integration-extraction.md) for the current scope and remaining owners. Local checks drive development; required protected integration checks and review remain in force.
