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
- `CANVAS_CREDENTIALS_API_TOKEN` is only used by the beta sandbox receiver and the standalone read-only contract checker. Real institution Canvas Credentials API tokens are saved by organization admins as managed integration secrets.
- `CANVAS_CREDENTIALS_PUBLIC_BASE_URL` optionally overrides the public Canvas Credentials demo display base URL printed by the seeder and returned by the sandbox mirror receiver.

### Real Canvas Credentials API mode

The mirror path now supports two provider modes on each organization-managed Canvas Program Binding:

- `bridge` posts the existing ElevenID bridge payload to the sandbox/beta receiver.
- `badgr_api` publishes a real Canvas Credentials assertion through the Canvas Credentials API.

For real API mode, an organization administrator should configure the Canvas Credentials provider in the Canvas integration wizard. The binding stores non-secret provider settings such as:

- provider (`badgr_api`)
- API base URL
- issuer ID
- badgeclass ID
- assertion scope
- API token secret reference

The API token itself should live in the managed integration secret store. Issuance copies the binding's `api_token_secret_id` into each Canvas mirror delivery record, so publish/revoke/status sync use the organization-specific provider settings rather than a global Canvas Credentials environment.

For self-service setup, organization admins can save the Canvas Credentials API token as a managed integration secret from the Canvas binding wizard. Issuance encrypts that value with `INTEGRATION_SECRET_MASTER_KEY` and stores only an `org_secret://...` reference on the binding. The binding then carries `api_token_secret_id` instead of a raw token, env var, or file path.

`CANVAS_CREDENTIALS_*` environment values are only an ops fallback for local/smoke tests and legacy bridge deployments. They should not be treated as the production source of truth for multi-organization Canvas Credentials setup.

Real API mode issues the Canvas Credentials assertion only after the canonical ElevenID credential exists. The assertion includes a public ElevenID provenance URL so verifiers can resolve the canonical issuer DID, status-list metadata, delivery record, and revocation state. Revocation sync uses the Canvas Credentials assertion revoke endpoint; suspend/reinstate are not first-class Canvas Credentials operations and remain represented by the ElevenID canonical status/provenance layer.

Before enabling publish in a shared sandbox, prefer the Canvas integration wizard's **Validate provider** action. It validates the provider configuration saved on the organization binding without publishing a credential. For operator-only secret smoke tests, the read-only CLI check can still be pointed at an env file:

```powershell
python scripts/check-canvas-credentials-contract.py --env-file .env --list-assertions
```

The CLI check validates a token, base URL, assertion scope, and issuer or badgeclass ID without creating or revoking an assertion. Use it only when validating deployment-level secret wiring outside the admin UI.

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

When `CANVAS_DEMO_EVIDENCE_EVENT_ENABLED=true`, the seeder prints a verification summary showing the evidence fact type, verification method, policy result, issuance transaction, resolved issuer DID, remote signing service, delivery mode, issued credential, wallet delivery record, Canvas mirror delivery record, external Canvas mirror ID, Canvas Credentials display URL, and Canvas mirror provenance lookup URL when publish succeeds.

The expanded console-native demo path is:

1. Launch the credential activity from Canvas.
2. Continue from the LTI launch into the normal ElevenID credential application surface, with the Canvas course/activity context already bound.
3. Explain the MIP transition: Canvas AGS score event -> `EvidenceFact` -> Cedar policy permit -> issuance transaction -> OID4VCI claim -> Canvas mirror publish.
4. Open **My Identity** and review the issued Interoperable Credentials Foundations Badge, including its badge artwork, claim state, Canvas course source, and Canvas Credentials mirror delivery metadata.
5. As an issuer admin, open the credential template **Destinations** tab to review Canvas Credentials readiness, badgeclass mapping, mirror health, projection policy, and per-template destination controls.
6. As an issuer admin, open **Canvas** setup to review Canvas platforms, program bindings, LTI launch binding, feature gates, AGS/NRPS/Deep Linking coverage, Canvas Credentials provider settings, managed token references, and provider validation.
7. Show the Canvas Credentials sandbox display as an external destination appendix only.
8. In the organization console, open **Credential Verification** with the Canvas mirror lookup params to resolve the mirror to the canonical ElevenID issuance, issuer DID, delivery record, and revocation status.
9. As a verifier organization, start a saved verification flow or presentation policy, generate the OID4VP request, and review the Open Badge verification result. The result view shows badge name/image/issuer, trust result, revocation/status result, selected claims, and Canvas mirror provenance when present.

The org-console portions of the recording use a dedicated demo administrator:

- Email: `canvas.admin@marty.demo`
- Password: `CanvasAdmin123!`

Fresh dev realm imports include this user. For an existing dev/beta realm, rerun the Keycloak setup step so `scripts/setup-keycloak.sh` creates the user and grants the `administrator` role. Self-host production startup removes this demo account by default.

The Canvas mirror provenance route is now console-native:

- `https://beta.elevenidllc.com/console/org/operate/verify?external_credential_id=...`

Legacy public Canvas verification routes are not supported. Canvas mirror resolution is a support/admin workflow inside the organization console, while employer-facing verification should use the normal OID4VP console flow whenever the holder can present from a wallet.

UX alignment note: the Canvas Credentials display page in the beta sandbox is a handcrafted external-destination simulator, not a real Canvas Credentials product page. Treat the sandbox display page as an appendix to the product demo.

To record the browser demo after seeding:

```powershell
cd ..\marty-demo-recorder
npm install
npm run record:canvas
```

The shared demo recorder lives in `marty-demo-recorder/`. The Canvas demo story and overlay notes are configured in `marty-demo-recorder/demos/canvas-employer-demo.json`; Canvas-specific Playwright helpers live in `marty-demo-recorder/demos/hooks/canvasEmployerHooks.js`.

The recorder reads the latest `canvas_display` and `console_provenance` URLs from `canvas-seed-latest.log` or from `CANVAS_DEMO_CANVAS_DISPLAY_URL` and `CANVAS_DEMO_CONSOLE_PROVENANCE_URL`. It attempts the full expanded path: Canvas LTI, normal application bootstrap, learner **My Identity**, credential template **Destinations**, Canvas admin setup, sandbox destination appendix, Canvas provenance inside **Credential Verification**, and OID4VP verification. After the learner checkpoint, it switches to `canvas.admin@marty.demo` for organization-console screens.

Useful recorder overrides:

- `CANVAS_DEMO_APPLICANT_IDENTITY_URL` (default: `https://beta.elevenidllc.com/console/applicant/identity`)
- `CANVAS_DEMO_CREDENTIAL_TEMPLATE_URL` (default: Interoperable Credentials Foundations Badge template detail)
- `CANVAS_DEMO_CANVAS_ADMIN_URL` (default: `https://beta.elevenidllc.com/console/org/deploy/canvas`)
- `CANVAS_DEMO_CONSOLE_PROVENANCE_URL` (default: seeded `/console/org/operate/verify?...` Canvas provenance lookup)
- `CANVAS_DEMO_CONSOLE_VERIFY_URL` (default: `https://beta.elevenidllc.com/console/org/operate/verify`)
- `CANVAS_DEMO_ADMIN_EMAIL` (default: `canvas.admin@marty.demo`)
- `CANVAS_DEMO_ADMIN_PASSWORD` (default: `CanvasAdmin123!`)

It writes:

- `marty-demo-recorder/artifacts/canvas-employer-demo/canvas-employer-demo.webm`
- `marty-demo-recorder/artifacts/canvas-employer-demo/canvas-employer-demo-steps.json`

If you intentionally want a placeholder recording with built-in sandbox URLs, set `CANVAS_DEMO_ALLOW_FALLBACK_URLS=1`.

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
