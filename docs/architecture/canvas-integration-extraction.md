# External Canvas connector and platform boundary

The Canvas LMS adapter belongs to [ElevenID/canvas-integration](https://github.com/ElevenID/canvas-integration). Marty is a provider-neutral platform. The removal branch retires Canvas pages, routes, worker binaries, provider modules, schema objects, signing origins and deployment wiring from Marty; it is not a production connector release. This is the current architecture decision and supersedes the original extraction-before-cutover sequence.

## Ownership and integration

| Owner | Responsibilities |
| --- | --- |
| Connector | Canvas LTI/OIDC callbacks, OAuth tokens, REST/AGS/NRPS clients, provider resource mappings, observation capture, scheduling, retries, delivery projection and connector administration UI |
| Public Common Gateway | Sole connector entry point to Marty; API-key authentication, organization ownership, scoped authorization, request validation and canonical operation forwarding |
| Core | Canonical identity and learner ownership, evidence persistence, policy, approval, application lifecycle, credential templates, issuer DID and keys, signing, credential status and audit |

Canvas calls the connector's own protocol edge. The connector validates signatures, issuer, audience/client, deployment, nonce/state, replay, redirect and origin constraints. Any subsequent platform operation uses the public Gateway with a dedicated organization-scoped API key over HTTPS. Protocol callbacks do not create an authentication exception for calls to Marty.

Connector-owned storage may hold provider tokens, launch/session state, cursors, mappings and jobs. It cannot write canonical EvidenceFact, policy, application, credential, status or audit persistence. An external observation is not identity proof, ownership, approval or signing authority. Email, provider subject IDs and course membership do not establish canonical learner association.

The connector must not:

- import private Marty crates, packages or application modules;
- connect to a Marty database, schema, shared Redis queue or internal service network;
- call private Core, issuance, signing, identity or organization endpoints;
- receive Core service keys, signing grants, issuer signing material or private recovery records;
- place Gateway API keys or provider tokens in browser bundles, URLs or logs;
- retry writes automatically when the platform's idempotency contract is absent or the outcome is unknown.

Canvas-facing tool signing material remains connector-owned. Canonical issuer credential signing remains Core-owned. The connector needs its own deployment, database, secret custody, identity and rotation procedure, without a local Marty checkout. Its permitted Marty network destination is the public Gateway origin only. Keep beta and production environments separate; source retirement does not authorize changing running deployments or migrating existing data.

## Public contract and disabled gaps

Use the generic public Gateway contract for the operation being performed. Every enabled operation needs a method/path, stable request/response DTO, minimum permission, authenticated organization binding, ownership rules, audit behavior and defined retry/idempotency semantics. Neither a route name nor a caller-supplied organization identifier proves authority.

The original provider route matrix in `contracts/canvas-integration-gateway-boundary.json` is frozen migration evidence. It is not a supported route list or a compatibility promise. Retired `/v1/integrations/canvas` and provider delivery routes must not be reintroduced as a hidden platform adapter. A historical connector compatibility client cannot make those operations available in the removal candidate.

If a generic Gateway capability or connector adapter is missing, keep that workflow disabled and document the gap. Do not add a private endpoint or direct persistence path to make it work. Core controls approval and issuance even when the connector submits valid observations. Preserve own-session proof, tenant and Origin checks, service authentication and no-retry behavior for canonical association.

## Enforcement and verification

Connector checks must reject private dependencies, internal URLs, database destinations belonging to Marty, service credentials, alternate transports, browser secret exports and requests bypassing the organization-bound Gateway client. Static checks complement deployed network isolation; they do not prove it.

Platform tests retain API-key authentication, wrong-organization rejection, read/write permission separation, ownership enforcement, canonical policy and signing guards, bounded validation and audit. Keep frozen evidence for provenance while removing retired executable consumers. Preserve upstream license and copyright notices when moving reviewed source; publish no credentials, customer data, private artifacts or unrelated source history.

Development uses large cohesive PRs and focused local tests. Required protected CI/security checks, review and merge queues remain integration gates. Production connector adapters, end-to-end cloud qualification and cutover are not removal gates.

## Remaining work by owner

- **Platform cleanup owner:** finish deployment generators, installer/acceptance fixtures, CI/source inventories and current documentation; integrate the removal through protected paths and reconcile eligible worktrees.
- **Connector owner:** retire or explicitly disable compatibility operations targeting removed provider APIs; finish generic Gateway adapters, connector-owned storage/deployment and administration UI as needed. No incomplete workflow should appear as an active Marty UI feature.
- **Gateway/Core contract owner:** document and test any missing generic operation before an adapter is enabled; retain canonical identity, ownership, approval, signing and audit authority.
- **Deployment operator:** plan any future data upgrade, operational qualification and cutover separately. See [issuance schema boundary](issuance-schema-boundary.md) for baseline v2 and the explicit legacy-ledger TODO. No automatic drop, rewrite or relabel of existing data is authorized.
