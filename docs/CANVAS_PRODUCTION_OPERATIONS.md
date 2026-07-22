# Canvas Production Operations and Rollout

## Scope and production invariant

The portable integration is an external LTI 1.3/Advantage tool against an
unmodified hosted Canvas tenant. Canvas supplies a signed launch and the native
services it advertises. Marty owns evidence normalization, policy, canonical
Open Badge issuance, DID resolution, status, and signing through the configured
identity/KMS abstraction.

LTI tool signing and credential signing are separate key purposes. Canvas must
never receive a canonical credential private key, cloud-KMS credential, or a
general Marty service key. A Canvas Credentials assertion is an optional mirror
with canonical Marty provenance; it is not the source credential.

Production portability acceptance excludes all of the following:

- Canvas source patches or a custom Canvas plugin
- `rails runner`, Rails console, or direct Canvas database access
- the local Canvas container's seed scripts as evidence of hosted compatibility
- custom webhook, custom AGS-event, or custom NRPS-event ingestion
- an institution-specific event that stock hosted Canvas does not emit

Canvas supports LTI 1.3 external tools, Deep Linking, a sessionless-launch API,
AGS, and NRPS through supported product interfaces. The relevant hosted-product
references are the [External Tools API](https://developerdocs.instructure.com/services/canvas/resources/external_tools),
[Deep Linking documentation](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.content_item),
[grading/AGS documentation](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.assignment_tools),
and [NRPS provisioning guidance](https://developerdocs.instructure.com/services/canvas/external-tools/lti/file.provisioning).

All Canvas metadata, OAuth, REST, AGS, NRPS, and optional Canvas Credentials
requests use HTTPS, no redirects or environment proxies, endpoint-specific
origin checks, and a DNS-pinned transport that connects to the address validated
for that request while preserving the original Host header and TLS SNI. Hosted
Canvas's issuer and SSO authorization/JWKS endpoints are global and therefore
need not share the institution Canvas origin. Institution OAuth/token endpoints
are pinned to the registered institution origin; launch-advertised AGS/NRPS
services are trusted from the verified JWT and their pagination may not change
origin.

## Feature controls and emergency stop

The production defaults are fail-closed:

| Control | Production default | Purpose |
|---|---:|---|
| `CANVAS_PORTABLE_INTEGRATION_ENABLED` | `false` | Global runtime kill switch |
| `CANVAS_PILOT_ORGANIZATION_IDS` | empty | Exact organization IDs admitted to the pilot; no wildcard |
| `CANVAS_LEGACY_EVENT_INGEST_ENABLED` | `false` | Keeps compatibility-only inbound events unavailable |
| Canvas sync worker deployment | stopped until pilot | Prevents unattended evidence and roster work |
| `CANVAS_ALLOW_PRIVATE_BASE_URLS` | `false` | Rejects private/internal Canvas origins |
| `CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS` | `false` | Rejects non-HTTPS origins outside isolated test profiles |
| `CANVAS_PRIVATE_ORIGIN_ALLOWLIST` | empty | Exact operator approval for private self-managed Canvas origins |
| `CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST` | empty | Exact extra public origins for the optional secondary projection |
| `CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS` | `900` | Denies Canvas-bound signing when the current authoritative evidence is older than 15 minutes |
| `CANVAS_BINDING_READINESS_MAX_AGE_SECONDS` | `900` | Denies activation, approval, and signing when the persisted KMS/DID readiness challenge is older than 15 minutes |
| `CANVAS_BACKGROUND_ROSTER_BATCH_SIZE` | `500` | Bounds each worker roster page/batch |
| `CANVAS_BACKGROUND_ROSTER_MAX_SIZE` | `5000` | Bounds one background roster evaluation job |

Portable Canvas requires a dedicated RS256 issuer profile and DID identity in
both the issuance API and `canvas-sync-worker`. Application code selects only
that profile and DID verification method. The profile owns the private KMS key
binding, which is never accepted from an issuance or LTI request:

| Setting | Requirement |
|---|---|
| `CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID` | Organization that owns the issuer profile |
| `CANVAS_LTI_TOOL_ISSUER_PROFILE_ID` | Active issuer profile selected for LTI tool assertions |
| `CANVAS_LTI_TOOL_ISSUER_DID` | DID controlled by that issuer profile |
| `CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS` | Required comma-separated inventory of credential issuer profiles; the dedicated LTI profile must not overlap |
| `CANVAS_LTI_TOOL_ACTIVE_KID` | DID verification method (`<issuer DID>#<fragment>`) used in every RS256 client assertion |
| `CANVAS_LTI_TOOL_PUBLIC_JWKS` | Compact public RSA/RS256 JWKS; retiring keys include `retired_at` and remain published for seven days |
| `SIGNING_KEYS_INTERNAL_URL` and API-key secret | Internal signing gateway used by the API and worker; production Compose mounts the key from a secret file and Kubernetes uses a Secret key |

The production preflight rejects missing signer settings, credential/LTI profile
overlap, a non-DID issuer, a `kid` outside that DID, non-RSA/RS256
keys, duplicate key IDs, and every RSA private parameter (`d`, `p`, `q`, `dp`,
`dq`, `qi`, or `oth`). Never place a private JWK in an environment variable,
ConfigMap, Compose secret, or deployment artifact.

For a preexisting external KMS key, bind it to the LTI issuer profile before
enabling Canvas. Only the profile layer may contain the underlying
`signing_service_id` and `signing_key_reference`; its signing-key configuration contains
`key_reference_purposes.<service_id>.<key_reference> = ["lti_tool_signing"]`.
The same KMS service may contain other keys with credential purposes, but the LTI
profile's reference may have no second purpose. Signing, issuer-profile creation/update,
and issuer resolution all fail closed if this binding is absent or conflicts.

Enabling the global flag is insufficient by itself. The organization must also
be in `CANVAS_PILOT_ORGANIZATION_IDS`, the Canvas platform and binding must be
enabled and ready, and the binding's deployment-profile snapshot must permit
the requested Canvas capability. The allowlist is evaluated on every runtime
launch, bootstrap, evidence read, and delivery operation; it is not only a UI
filter.

When the global or organization gate is closed, the management boundary is:

| Still available | Blocked before provider access or mutation |
|---|---|
| Draft create/update/read, registration JSON/JWKS reads, metadata/JWKS setup probes, readiness inspection, archive/deactivate, OAuth disconnect/revocation, job/review reads | Binding activation, LTI login/launch/bootstrap/Deep Linking, OAuth start or callback token exchange, Canvas catalog/evidence/roster reads, sync processing, Canvas application approval, and Canvas Credentials publish/status sync |

An OAuth callback received after an emergency stop consumes its one-time state
but performs no token exchange, preventing later replay if the rollout is
re-enabled.

The emergency-stop sequence is:

1. Set `CANVAS_PORTABLE_INTEGRATION_ENABLED=false` and roll/restart the issuance
   runtime that consumes the setting.
2. Stop the standalone `canvas-sync-worker` deployment. The worker also checks
   the global/pilot gate before any Canvas network read.
3. Disable affected program bindings. Preserve platform records and audit data.
4. If compromise is suspected, disconnect Canvas OAuth, revoke the Canvas token,
   and rotate the LTI tool-signing key.
5. Verify that new LTI launch/bootstrap, evidence synchronization, automatic
   approval, and mirror-delivery attempts fail closed. Administrative reads,
   disconnect/revoke operations, and canonical credential lifecycle operations
   must remain available for recovery.

The kill switch does not revoke an already issued credential. Use the canonical
Marty suspension/revocation lifecycle and allow the optional Canvas mirror to
converge from that state.

Platform and program-binding `DELETE` operations are archival lifecycle
transitions. They disable the record and retain launches, evidence, jobs,
applications, credentials, and audit history. The issuance repositories do not
expose Canvas platform or binding hard-delete operations; recovery and support
procedures must never remove these rows to clear a readiness or rollout error.

## Rollout gates

Rollout is one-way only after the previous mode has produced reviewable hosted
tenant evidence. A failed gate returns the pilot to the preceding mode.

| Mode | Allowed behavior | Promotion gate | Rollback |
|---|---|---|---|
| `shadow` | Verify launches, read negotiated services, normalize evidence, and record the policy result. No approval, issuance, or mirror publish. | Full hosted acceptance run; seven consecutive nightly read-only contract passes; at least 20 distinct learner/instructor launches; zero cross-org, replay, or secret-exposure findings. | Global kill switch or disable the binding. |
| `admin_approved` | An administrator reviews facts and policy output before canonical issuance. Background mirror work remains off. | At least 20 reviewed decisions with recorded reason codes, including permit and deny cases; no unexplained divergence between evidence, policy, and the administrator decision. | Return the binding to shadow/manual review. |
| `learner_claim` | A policy permit may automatically prepare the wallet offer after learner launch. Holder binding and KMS signing still occur only when the learner claims. | At least 25 automatic decisions with 100% expected-policy concordance, replay-safe claim issuance, successful wrong-org denial, and a completed OAuth/key-rotation recovery drill. | Disable auto-approval and return to `admin_approved`. |
| `background` | Roster evaluation and drift reconciliation may run unattended and may create unsigned `pending_claim` candidates. | Job leasing, idempotent retry, rate-limit handling, dead-letter replay, backlog alerts, and kill-switch drain all pass in the hosted pilot. | Stop the sync worker first, then return to `learner_claim` or `admin_approved`. |

No mode promotion is inferred from a green readiness response. Promotion is an
explicit operator decision recorded with the deployed release SHA, Marty/Canvas
platform IDs in protected records, acceptance case IDs, and the rollback owner.

## RS256 LTI tool-key rotation

Canvas LTI tool-signing uses an RSA key with `alg=RS256`, `use=sig`, and a unique
`kid`. Configure the external key service with purpose `lti_tool_signing`; do not
reuse a credential issuer or organization JWKS key.

The retiring public key remains in the Canvas LTI JWKS for at least seven full
days after the last token signed with it. Seven days is the minimum overlap,
even when the configured JWKS cache is shorter.

Rotation procedure:

1. Create the replacement RSA signing key through the configured KMS adapter.
   Confirm only public `kty`, `kid`, `alg`, `use`, `n`, and `e` material can reach
   `/v1/integrations/canvas/lti/jwks`.
2. Publish the replacement public JWK alongside the active public JWK. Do not
   switch signing yet.
3. Set `HOSTED_CANVAS_EXPECTED_ACTIVE_KID` to the current key and
   `HOSTED_CANVAS_EXPECTED_RETIRING_KID` only when testing an overlap. Run the
   hosted contract and confirm both public keys are visible from outside Marty.
4. Switch new LTI service tokens to the replacement `kid`. Record the exact
   last-signature timestamp for the old key.
5. Exercise learner launch, Deep Linking, AGS, and NRPS on hosted Canvas. Keep
   the old key published and verification-only for at least seven full days.
6. After seven days plus the maximum observed JWKS-cache interval, confirm no
   new signatures use the old `kid`, remove its public JWK, then destroy or
   disable its KMS version according to retention policy.

During the overlap, rollback means switching the active signer back to the old
key while both keys remain published. If either public key disappears early,
stop automatic Canvas work and republish before continuing.

## Canvas OAuth recovery and revoke

Canvas REST access is optional and must not be used when launch-advertised AGS
satisfies the requirement. OAuth access and refresh tokens are stored as
separate encrypted, organization-scoped integration secrets; API responses and
artifacts contain only secret references, status, and granted scopes. NRPS is a
roster/identity source, not issuance evidence.

Recovery procedure:

1. On `invalid_grant`, repeated `401`, refresh failure, or scope drift, stop the
   REST-dependent binding from automatic approval. Do not retry refresh in an
   unbounded loop.
2. Preserve the failed job and audit correlation, but never copy the token,
   authorization code, callback query, or response body into a ticket or log.
3. Disconnect with
   `DELETE /v1/integrations/canvas/platforms/{platform_id}/oauth`. The service
   attempts Canvas's supported [`DELETE /login/oauth2/token`](https://developerdocs.instructure.com/services/canvas/oauth2/file.oauth_endpoints)
   revocation. If Canvas is unavailable, Marty keeps only the encrypted local
   material needed by the leased revocation retry and deletes it after remote
   revocation succeeds.
4. Start a new authorization with
   `POST /v1/integrations/canvas/platforms/{platform_id}/oauth/authorizations`.
   OAuth
   state is high-entropy, short-lived, bound to organization/platform and
   callback URI, and accepted only once.
5. Verify the exact least-privilege scopes, rerun platform/binding readiness,
   then replay one quarantined job. Resume automatic work only after that job is
   idempotently successful.

An administrator can also revoke the token in Canvas. Marty must treat a token
missing remotely as disconnected rather than recreating it from cached state.

## Worker and dead-letter operations

The standalone `canvas-sync-worker` is disabled through the shadow and manual
pilot stages. It uses PostgreSQL targets/jobs, `FOR UPDATE SKIP LOCKED`, expiring
leases, and one active job per target, so multiple replicas may run safely.
Configure `CANVAS_SYNC_PROCESSOR`, batch/lease limits, and the heartbeat polling
interval from the checked-in environment examples. The complete processing of
one target, including all paginated reads, has a 600-second absolute deadline
(`CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS`); per-request network timeouts do not
replace that bound. Roster evaluation defaults
to batches of 500 and a maximum of 5,000 learners per job. The issuance API
requires evidence observed within the previous 900 seconds before it signs a
Canvas-bound credential. The issuance web process must not run an in-process
synchronization loop.

Pending applications/candidates run every 15 minutes. Issued-credential drift
checks run every six hours for 90 days. A job gets eight attempts with
exponential jitter, honors Canvas `Retry-After`, and then remains in
`dead_letter` with its target disabled until an organization administrator
explicitly retries it. Retry atomically re-enables the target and resets the
eight-attempt budget. An administrator can instead acknowledge the stopped
record with `POST /v1/integrations/canvas/canvas-sync-jobs/{job_id}/resolve`;
Resolve marks the job cancelled and deliberately leaves its target stopped. A
background roster job can create only an unsigned `pending_claim` candidate;
it cannot invoke approval, holder binding, KMS signing, or issuance.

Dead-letter runbook:

1. Stop failed-record retries without stopping canonical issuance.
2. Export only record IDs, attempt counts, fixed error categories, and audit
   correlation IDs. Do not export assertion payloads, subject data, or tokens.
3. Classify the cause: OAuth revoked/scope drift, Canvas rate limit, provider
   outage, invalid evidence mapping, identity link, or poison data.
4. Fix the cause and retry one job through
   `POST /v1/integrations/canvas/canvas-sync-jobs/{job_id}/retry`. Verify that
   immutable revisions are reused rather than duplicated.
   If the target must be retired instead, use Resolve in the Operations console
   and verify the target remains stopped.
5. Replay a bounded batch, observe error/rate metrics, then drain the remainder.
6. Retain the original attempts and operator action in audit history; never
   delete a failed record to make health appear green.

Use small batches during recovery. A worker heartbeat older than the readiness
threshold, a backlog above two normal intervals, any dead-letter job,
cross-organization lookup, duplicate issuance, or canonical status mismatch
pages the integration owner and blocks rollout promotion. Optional Canvas
Credentials projection has a separate delivery outbox and is enabled only after
the canonical hosted-Canvas gate passes.

## Schema migration gate

The unreleased portable-Canvas revision must pass a real PostgreSQL upgrade and
exact downgrade before it can enter a deployment. The required contract lives
in `marty-credentials/docker-compose.canvas-migration-contract.yml`; it starts
only an isolated, digest-pinned PostgreSQL container and a read-only one-shot
migration runner. It seeds representative legacy platform, binding, and
evidence rows, verifies quarantine and tenant constraints after upgrade, then
verifies the original JSON, flags, evidence, defaults, and schema after
downgrade.

Run it from the `marty-credentials` repository with:

```bash
docker compose --file docker-compose.canvas-migration-contract.yml \
  up --build --force-recreate --abort-on-container-exit \
  --exit-code-from migration-contract migration-contract
docker compose --file docker-compose.canvas-migration-contract.yml \
  down --volumes --remove-orphans
```

The credentials CI job and the marty-ui deployment workflow both require this
contract. The deployment workflow checks out the exact 40-character
`MARTY_CREDENTIALS_REF` and binds that SHA into the sanitized contract result;
there is no native host PostgreSQL fallback and no beta or self-host database is
used by this gate.

## Legacy ingest remains disabled

`CANVAS_LEGACY_EVENT_INGEST_ENABLED=false` is a permanent portability gate for
new deployments. These compatibility routes do not count as hosted acceptance:

- `POST /v1/integrations/canvas/evidence-events`
- `POST /v1/integrations/canvas/ags/score-events`
- `POST /v1/integrations/canvas/nrps/membership-events`

The supported model reads AGS and NRPS services advertised by the verified LTI
launch. A legacy route must be unavailable when the flag is false, and no legacy
shared signing secret should be configured. Historical receipts remain
read-only for audit/migration.

## Hosted Canvas acceptance

Acceptance uses a real hosted Canvas tenant or its institution custom domain,
stock root-account administration, public Canvas APIs, and LTI Advantage. Local
containers and Canvas internals are useful developer fixtures but cannot promote
a release.

| Case | Required result |
|---|---|
| Root-admin installation | Registration configuration creates a standard LTI 1.3 Developer Key and scoped account/course installation without a plugin or source change. |
| OIDC/LTI launch | Learner and instructor launches validate issuer, audience, deployment, nonce, state, and role/context; state replay is rejected. |
| Deep Linking | An instructor places an ElevenID activity with Canvas's standard Deep Linking placement and a later learner launch preserves the binding. |
| AGS | Marty reads the launch-advertised AGS result with the granted read scope, normalizes one immutable fact, and does not require a custom inbound score event. |
| Native activity scores | Existing assignments and Classic Quizzes expose the authoritative score through Assignment Submissions. New Quiz support passes only if the hosted tenant's assignment submission exposes the authoritative score. |
| Course/module completion | A module-based course with at least one requirement is verified through learner/bulk Course Progress; module completion is verified with the learner `student_id`. |
| Roster pending award | NRPS/native roster reads enforce course/context and identity boundaries, create only an unsigned `pending_claim`, and do not require custom inbound membership events. |
| OAuth | Connect, refresh, revoke in Canvas, detect failure, disconnect locally, and reconnect with least privilege. No token appears in evidence. |
| Canonical badge | A permit/admin approval issues exactly one Open Badge signed by the organization's external KMS key; the issuer DID/status verifies outside Canvas. |
| Corrections | A pre-issuance downgrade changes the current policy decision; a post-issuance downgrade creates one review without automatically changing credential status, and recovery resolves an untouched review. |
| Optional Canvas Credentials mirror | When enabled, Canvas displays the secondary assertion, provenance resolves to the canonical badge, and canonical status changes converge without duplicate awards. |
| Rotation | Fresh LTI service JWTs use the new RS256 `kid`; the retiring public key remains visible for the seven-day overlap. |
| Isolation | A user/API key from another organization cannot read or mutate the platform, binding, secret, evidence, or delivery record. |
| Operations | Kill switch, pilot removal, OAuth failure, transient worker retry, poison-record dead letter, replay, and worker drain behave as documented. |
| Legacy negative | Compatibility event ingest is unavailable and no test uses Rails, a Canvas plugin, database access, or a custom event sender. |

## Manual/nightly contract workflow

`.github/workflows/hosted-canvas-contract.yml` runs nightly and on manual
dispatch. It uses the `hosted-canvas-contract` GitHub environment and the
checked-in contract at
`deploy-config/catalog/hosted-canvas-acceptance.json`.

Environment variables:

| Kind | Name |
|---|---|
| Secret | `HOSTED_CANVAS_MARTY_API_KEY` with only integration-read permission |
| Secret | `HOSTED_CANVAS_API_TOKEN` scoped to read the pilot course and external tool |
| Variable | `HOSTED_CANVAS_MARTY_ORIGIN` |
| Variable | `HOSTED_CANVAS_PLATFORM_ID` |
| Variable | `HOSTED_CANVAS_ORIGIN` |
| Variable | `HOSTED_CANVAS_COURSE_ID` |
| Variable | `HOSTED_CANVAS_EXTERNAL_TOOL_ID` |
| Optional variable | `HOSTED_CANVAS_LTI_CLIENT_ID` |
| Optional rotation variable | `HOSTED_CANVAS_EXPECTED_ACTIVE_KID` |
| Optional rotation variable | `HOSTED_CANVAS_EXPECTED_RETIRING_KID` |

If any required tenant value is absent, the workflow performs no network calls,
writes an explicit `skipped` result, and succeeds. A skip is safe automation
behavior, not production acceptance or a rollout-promotion pass.

The automated lane is non-mutating. It checks the gateway authentication
default, public RS256 JWKS, public registration shape, authenticated readiness,
hosted course/tool reads, and Canvas generation of a sessionless launch URL. It
discards all response bodies and the launch URL after in-memory validation. The
full OIDC launch and stateful cases remain operator acceptance cases.

The uploaded artifact is only
`tests/artifacts/hosted-canvas-contract/result.json`. A second verifier enforces
a fixed field set, fixed reason codes, absence of tenant configuration values,
and the prohibition on response bodies, headers, URLs, tenant identifiers,
screenshots, videos, and traces. Workflow logs print only case IDs, status, and
fixed reason codes. Store any richer hosted-tenant evidence in a separately
protected evidence system and attach only its content hash and approval record
to a release decision.
