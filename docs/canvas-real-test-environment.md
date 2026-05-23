# Real Canvas LMS test environment (Docker)

This workspace includes an optional profile to run a real Canvas LMS container for development.

## Why this profile exists

For production-like integration testing (LTI/OIDC/JWKS behavior), a real Canvas runtime is often better than a simulator.

## Image choice

Default image:

- `readystack/canvas:v5.14.2-CE-ubuntu24.04-r1`

Alternatives you can switch to via `CANVAS_REAL_IMAGE`:

- `cbbm142/canvas` (older, local LTI-dev focused)

## Start / stop

From `marty-ui/`:

- `make canvas-real-up`
- `make canvas-real-status`
- `make canvas-real-logs`
- `make canvas-real-down`

Seed the Canvas platform/program binding (and optionally Canvas test data):

- `make canvas-real-seed`
- `make canvas-real-bootstrap` (up + seed)

For the public beta experiment deployment, use the dedicated experiments stack:

- `make beta-experiments-plan`
- `make beta-experiments-up`
- `make beta-canvas-experiments-bootstrap`

That stack runs with `MARTY_MIGRATION_PROFILE=experiments`, includes the real
Canvas LMS compose profile, and exposes Canvas at
`https://canvas-test.elevenidllc.com` while ElevenID stays at
`https://beta.elevenidllc.com`.

### Seeder behavior

The seeder script lives at:

- `scripts/seed_canvas_real.py`

By default it will:

1. Upsert an ElevenID Canvas platform via `http://localhost:8005/v1/integrations/canvas/platforms`
2. Sync Canvas's real LTI `client_id` and `deployment_id` back onto the platform.
3. Refresh platform JWKS/OIDC metadata via `POST /v1/integrations/canvas/platforms/{id}/jwks-refresh`
4. Upsert a Canvas program binding for the Marty organization when `CANVAS_PROGRAM_BINDING_SEED_ENABLED=true`
5. Bootstrap Canvas initial data/admin login when needed
6. Create/update the Canvas developer key + external tool through a local Rails-runner fallback inside `marty-canvas-real`
7. Force both the developer key owner/site-admin binding and the target account binding to workflow state `on`
8. Mint a Canvas admin API token when `CANVAS_ADMIN_ACCESS_TOKEN` is missing or stale
9. Create/update a test course, learner, enrollment, launch module item, and launch assignment
10. Seed the Interoperable Credentials Foundations Open Badge demo scenario by default, including a quiz, MIP policy, public badge metadata/image, remote DID issuer context metadata, and wallet + Canvas mirror delivery mode
11. When demo evidence is enabled, claim the credential through the OID4VCI wallet endpoint and run one Canvas mirror automation cycle
12. Print Canvas Credentials display and employer verification URLs when the mirror publish succeeds

Minimum env vars for Canvas platform/binding seeding:

- `ISSUANCE_API_KEY` (required)
- `CANVAS_ORGANIZATION_ID` (default: Marty org)
- `CANVAS_CREDENTIAL_TEMPLATE_ID` (default: Interoperable Credentials Foundations Badge when `CANVAS_OPEN_BADGE_SCENARIO_ENABLED=true`; otherwise Verified Member Badge)
- `CANVAS_APPLICATION_TEMPLATE_ID` (default: Interoperable Credentials Foundations Application when `CANVAS_OPEN_BADGE_SCENARIO_ENABLED=true`; otherwise Verified Member Badge application template)
- `CANVAS_CONNECTOR_BASE_URL` (historical env name; used as the Canvas platform base URL, default: `http://localhost:8088` for the local real-Canvas profile)
- `CANVAS_LTI_EXPERIENCE_BASE_URL` (default: `UI_BASE_URL`, then `ISSUER_BASE_URL`)
- `CANVAS_LTI_CLIENT_ID` (default: `canvas-real-client-id`; used as the local developer key label before the platform is synced to Canvas's real launch `client_id`)
- `CANVAS_LTI_DEPLOYMENT_ID` (default: `canvas-real-deployment-id`; fallback only until the platform is synced to the tool's real `deployment_id`)

Optional program binding env vars:

- `CANVAS_OPEN_BADGE_SCENARIO_ENABLED` (default: `true`)
- `CANVAS_PROGRAM_BINDING_SEED_ENABLED` (default: `true`)
- `CANVAS_PROGRAM_BINDING_DISPLAY_NAME`
- `CANVAS_PROGRAM_BINDING_EVIDENCE_TYPE` (default: `canvas.quiz_score` for the Open Badge scenario)
- `CANVAS_PROGRAM_BINDING_DELIVERY_MODE` (default: `wallet_plus_canvas_mirror` for the Open Badge scenario)
- `CANVAS_PROGRAM_BINDING_AUTO_APPROVE` (default: `true`)
- `CANVAS_PROGRAM_BINDING_DIRECT_ISSUE` (default: `false`)
- `CANVAS_PROGRAM_BINDING_SCORE_THRESHOLD` (default: `80`)
- `CANVAS_DEMO_APPLICATION_SEED_ENABLED` (default: `true`)
- `CANVAS_DEMO_EVIDENCE_EVENT_ENABLED` (default: `false`; set true only when `CANVAS_CREDENTIALS_SHARED_SECRET` is configured in the issuance service environment)
- `CANVAS_DEMO_WALLET_CLAIM_ENABLED` (default: `true`; after demo evidence approval, exercise the OID4VCI token/proof/credential endpoints as a wallet)
- `CANVAS_DEMO_MIRROR_PUBLISH_ENABLED` (default: `true`; after demo wallet claim, run one Canvas mirror automation cycle)
- `CANVAS_CREDENTIALS_SHARED_SECRET` signs demo Canvas evidence events; keep the value in the beta env/secret layer and do not place issuer signing keys in Canvas
- `CANVAS_CREDENTIALS_PUBLISH_URL` and `CANVAS_CREDENTIALS_STATUS_SYNC_URL` point the issuance service at the Canvas Credentials mirror API. In beta experiments, the Canvas sandbox profile supplies a guarded receiver for this contract.
- `CANVAS_CREDENTIALS_API_TOKEN` is an optional bearer token shared by issuance and the beta Canvas Credentials receiver. It protects the publish/status endpoints but is not issuer key material.
- `CANVAS_CREDENTIALS_PUBLIC_BASE_URL` optionally overrides the public Canvas Credentials demo display base URL printed by the seeder and returned by the sandbox mirror receiver.

### Real Canvas Credentials API mode

The mirror path now supports two provider modes:

- `CANVAS_CREDENTIALS_PROVIDER=bridge` posts the existing ElevenID bridge payload to the sandbox/beta receiver.
- `CANVAS_CREDENTIALS_PROVIDER=badgr_api` publishes a real Canvas Credentials assertion through the Canvas Credentials API.

For real API mode, configure issuance with:

- `CANVAS_CREDENTIALS_API_BASE_URL` (default: `https://api.badgr.io`)
- `CANVAS_CREDENTIALS_API_TOKEN`
- `CANVAS_CREDENTIALS_ISSUER_ID`
- `CANVAS_CREDENTIALS_BADGECLASS_ID`
- `CANVAS_CREDENTIALS_ASSERTION_SCOPE` (default: `badgeclasses`)
- `CANVAS_CREDENTIALS_PROVENANCE_BASE_URL` (for example, `https://beta.elevenidllc.com`)

Real API mode issues the Canvas Credentials assertion only after the canonical ElevenID credential exists. The assertion includes a public ElevenID provenance URL so verifiers can resolve the canonical issuer DID, status-list metadata, delivery record, and revocation state. Revocation sync uses the Canvas Credentials assertion revoke endpoint; suspend/reinstate are not first-class Canvas Credentials operations and remain represented by the ElevenID canonical status/provenance layer.

Optional Canvas LMS seeding env vars:

- `CANVAS_ADMIN_ACCESS_TOKEN` (optional; the seeder mints one through the local Canvas container when missing or stale)
- `CANVAS_ADMIN_EMAIL` (default: `admin@example.com`)
- `CANVAS_ADMIN_PASSWORD` (default: `readystack123`, used only for first-boot Canvas initial data)
- `CANVAS_API_BASE_URL` (default: `http://localhost:8088`)
- `CANVAS_BROWSER_BASE_URL` (optional; defaults to `https://$CANVAS_REAL_PUBLIC_HOST` when set, otherwise `CANVAS_API_BASE_URL`)
- `CANVAS_REAL_CONTAINER_NAME` (default: `marty-canvas-real`)
- `CANVAS_REAL_LTI_ISS` (optional override; default local issuer is `http://localhost:8088`)
- `CANVAS_ROOT_ACCOUNT_ID` (default: `1`)
- `CANVAS_TEST_COURSE_NAME`, `CANVAS_TEST_COURSE_CODE`, `CANVAS_TEST_COURSE_SIS_ID`
- `CANVAS_TEST_LEARNER_NAME`, `CANVAS_TEST_LEARNER_EMAIL`, `CANVAS_TEST_LEARNER_PASSWORD`
- `CANVAS_LAUNCH_SEED_ENABLED` (default: `true`)
- `CANVAS_TEST_MODULE_NAME` (default: `ElevenID Credential Launch`)
- `CANVAS_TEST_MODULE_ITEM_TITLE` (default: `Launch ElevenID Credential Issuance`)
- `CANVAS_TEST_ASSIGNMENT_NAME` (default: `ElevenID Credential Issuance`)
- `CANVAS_TEST_QUIZ_SEED_ENABLED` (default: follows `CANVAS_OPEN_BADGE_SCENARIO_ENABLED`)
- `CANVAS_TEST_QUIZ_TITLE` (default: `Interoperable Credentials Foundations Quiz`)
- `CANVAS_TEST_QUIZ_PASSING_SCORE_PERCENT` (default: `92`)

### Open Badge demonstration flow

The default beta experiment demonstrates:

```text
Canvas quiz score -> signed AGS score event -> MIP EvidenceFact -> policy permit -> issuance transaction -> OID4VCI wallet claim -> Canvas mirror publish
```

The badge type metadata and image are public at `https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge`, so Open Badge packs/backpacks and Canvas mirror surfaces can resolve a real achievement, criteria, image, result, and status-list-backed credential.

The Marty issuer DID is `did:web:beta.elevenidllc.com:orgs:marty`. The issuer private key stays outside Canvas and outside the beta web host; issuance resolves the active issuer context through the gateway signing-key registry and signs via the remote OpenBao transit service.

When `CANVAS_DEMO_EVIDENCE_EVENT_ENABLED=true`, the seeder prints a verification summary showing the evidence fact type, verification method, policy result, issuance transaction, resolved issuer DID, remote signing service, delivery mode, issued credential, wallet delivery record, Canvas mirror delivery record, external Canvas mirror ID, Canvas Credentials display URL, and employer verification URL when publish succeeds.

The employer demo route is:

- `https://beta.elevenidllc.com/verify/canvas-credentials?external_credential_id=...`

That page resolves the Canvas mirror through the public provenance endpoint and shows why the badge has value outside Canvas: an employer can verify the canonical issuer DID, issuance record, Canvas distribution channel, active status, and subject hash without trusting a Canvas-only database lookup.

## Compose wiring

Profile file:

- `docker-compose.profile.canvas-real.yml`

When active:

- Container name: `marty-canvas-real`
- Internal URL: `http://canvas-real:3000`
- Host URL: `http://localhost:${CANVAS_REAL_HOST_PORT:-8088}`
- Tunnel URL: `https://${CANVAS_REAL_PUBLIC_HOST}` (for beta experiments: `https://canvas-test.elevenidllc.com`)
- Sidecar bridge: `marty-issuance-canvas-localhost-bridge`
- Canvas local overrides mounted for this profile:
	- `config/canvas/production-local.rb` → enables static file serving and seeds `Canvas::Security.config['lti_iss']` for local LTI launches when blank
	- `config/canvas/dynamic_settings.local.yml` → production LTI key store / JWKS
	- `config/canvas/session_store.local.yml` → browser-login cookie fix

## Tunnel hostname (Cloudflare)

Add a public hostname in your Cloudflare tunnel config:

- Hostname: `${CANVAS_REAL_PUBLIC_HOST:-canvas-test.${PUBLIC_DOMAIN}}`
- Service URL: `http://tunnel-nginx-proxy:80`

Nginx tunnel route is already added in:

- `nginx-tunnel.conf.template`

## Resource expectations

The default all-in-one Canvas image is heavy.

Recommended minimum local resources:

- RAM: 8 GB available to Docker
- Disk: 10+ GB free

## Notes for ElevenID integration

- Use this profile when you need realistic Canvas behavior.
- For quick iteration/unit tests, keep using the lightweight sandbox profile (`canvas-sandbox-*` targets).
- In local real-Canvas mode, use `http://localhost:8088` as the Canvas platform `canvas_base_url`; the issuance-side localhost bridge synthesizes `/.well-known/openid-configuration` and proxies other requests to the host Canvas instance.
- Real Canvas exposes `/api/lti/security/jwks`, but its `/api/lti/security/openid-configuration` path is gated by `registration_token`; the bridge exists specifically to provide a standards-style discovery document for localhost testing.
- Use `CANVAS_LTI_EXPERIENCE_BASE_URL` for the public ElevenID launch/redirect URLs that Canvas stores on the developer key and external tool.
- If `CANVAS_LTI_EXPERIENCE_BASE_URL` is unset, the issuance service now falls back to `UI_BASE_URL` instead of hard-coding `http://localhost:3000`; this keeps tunnel/profile launches on the public ElevenID hostname.
- The local production override also backfills Canvas `lti_iss` to `http://localhost:8088` when the image-generated `config/security.yml` omits it; without that, real assignment/tool launches fail before the ElevenID redirect is created.
- Canvas does **not** launch with the friendly developer key label; it launches with the developer key `global_id`, and the external tool emits its own `deployment_id`. The local seeder now writes those real values back into the ElevenID Canvas platform after Canvas objects are created.
- For site-admin developer keys, Canvas checks the owner/site-admin binding first during OIDC authorization. If that binding is left `off`, Canvas returns `unauthorized_client` even when the course/root-account binding is `on`.
- In hardened mode, use an HTTPS `canvas_base_url` (for example `https://canvas-test.${PUBLIC_DOMAIN}`) rather than HTTP/localhost values.
