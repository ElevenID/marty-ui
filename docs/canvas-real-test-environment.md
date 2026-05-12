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

Seed the connector (and optionally Canvas test data):

- `make canvas-real-seed`
- `make canvas-real-bootstrap` (up + seed)

### Seeder behavior

The seeder script lives at:

- `scripts/seed_canvas_real.py`

By default it will:

1. Upsert an ElevenID Canvas connector via `http://localhost:8005/v1/integrations/canvas/connectors`
2. Refresh connector JWKS/OIDC metadata via `POST /v1/integrations/canvas/connectors/{id}/jwks-refresh`
3. Attempt Canvas LMS test-data seeding **only if** `CANVAS_ADMIN_ACCESS_TOKEN` is set
4. Create/update the Canvas developer key + external tool through a local Rails-runner fallback inside `marty-canvas-real`
5. Sync the connector `lti_client_id` and `lti_deployment_id` to the actual Canvas launch values (`DeveloperKey.global_id` and `ContextExternalTool.deployment_id`)
6. Force both the developer key owner/site-admin binding and the target account binding to workflow state `on`

Minimum env vars for connector seeding:

- `ISSUANCE_API_KEY` (required)
- `CANVAS_ORGANIZATION_ID` (default: Marty org)
- `CANVAS_CREDENTIAL_TEMPLATE_ID` (default: Verified Member Badge template)
- `CANVAS_CONNECTOR_BASE_URL` (default: `http://localhost:8088` for the local real-Canvas profile)
- `CANVAS_LTI_EXPERIENCE_BASE_URL` (default: `UI_BASE_URL`, then `ISSUER_BASE_URL`)
- `CANVAS_LTI_CLIENT_ID` (default: `canvas-real-client-id`; used as the local developer key label before the connector is synced to Canvas's real launch `client_id`)
- `CANVAS_LTI_DEPLOYMENT_ID` (default: `canvas-real-deployment-id`; fallback only until the connector is synced to the tool's real `deployment_id`)

Optional Canvas LMS seeding env vars:

- `CANVAS_ADMIN_ACCESS_TOKEN`
- `CANVAS_API_BASE_URL` (default: `http://localhost:8088`)
- `CANVAS_REAL_CONTAINER_NAME` (default: `marty-canvas-real`)
- `CANVAS_REAL_LTI_ISS` (optional override; default local issuer is `http://localhost:8088`)
- `CANVAS_ROOT_ACCOUNT_ID` (default: `1`)
- `CANVAS_TEST_COURSE_NAME`, `CANVAS_TEST_COURSE_CODE`, `CANVAS_TEST_COURSE_SIS_ID`
- `CANVAS_TEST_LEARNER_NAME`, `CANVAS_TEST_LEARNER_EMAIL`, `CANVAS_TEST_LEARNER_PASSWORD`

## Compose wiring

Profile file:

- `docker-compose.profile.canvas-real.yml`

When active:

- Container name: `marty-canvas-real`
- Internal URL: `http://canvas-real:3000`
- Host URL: `http://localhost:${CANVAS_REAL_HOST_PORT:-8088}`
- Tunnel URL: `https://canvas-test.${PUBLIC_DOMAIN}`
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
- In local real-Canvas mode, use `http://localhost:8088` as the connector `canvas_base_url`; the issuance-side localhost bridge synthesizes `/.well-known/openid-configuration` and proxies other requests to the host Canvas instance.
- Real Canvas exposes `/api/lti/security/jwks`, but its `/api/lti/security/openid-configuration` path is gated by `registration_token`; the bridge exists specifically to provide a standards-style discovery document for localhost testing.
- Use `CANVAS_LTI_EXPERIENCE_BASE_URL` for the public ElevenID launch/redirect URLs that Canvas stores on the developer key and external tool.
- If `CANVAS_LTI_EXPERIENCE_BASE_URL` is unset, the issuance service now falls back to `UI_BASE_URL` instead of hard-coding `http://localhost:3000`; this keeps tunnel/profile launches on the public ElevenID hostname.
- The local production override also backfills Canvas `lti_iss` to `http://localhost:8088` when the image-generated `config/security.yml` omits it; without that, real assignment/tool launches fail before the ElevenID redirect is created.
- Canvas does **not** launch with the friendly developer key label; it launches with the developer key `global_id`, and the external tool emits its own `deployment_id`. The local seeder now writes those real values back into the ElevenID connector after Canvas objects are created.
- For site-admin developer keys, Canvas checks the owner/site-admin binding first during OIDC authorization. If that binding is left `off`, Canvas returns `unauthorized_client` even when the course/root-account binding is `on`.
- In hardened mode, use an HTTPS `canvas_base_url` (for example `https://canvas-test.${PUBLIC_DOMAIN}`) rather than HTTP/localhost values.
