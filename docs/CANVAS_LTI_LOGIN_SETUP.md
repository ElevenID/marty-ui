# Canvas LTI Login Setup & Testing Guide

## Current Status

The seed script creates the **ElevenID Canvas connector** and (with admin token) the **Canvas-side LTI infrastructure**. Here's the current state:

### What's Working
- ✅ ElevenID issuance service is running
- ✅ Canvas connector is created in ElevenID database (id: `67f60f26-67aa-405f-9e04-b48165d49c61`)
- ✅ Canvas instance is running (`http://localhost:8088`)
- ✅ Canvas admin user created (admin@example.com / readystack123)
- ✅ Canvas admin API token generated (in `.env.tunnel.beta.local`)
- ✅ Canvas LTI developer key is created/updated with the correct ElevenID redirect URI
- ✅ Canvas test course seeded ("ElevenID LTI Test Course")
- ✅ Canvas external tool is installed/updated ("Canvas Real LMS")
- ✅ Canvas test learner enrolled (learner+elevenid@example.edu)
- ✅ Canvas browser login works locally with the cookie/session fix
- ✅ Local Canvas production override now seeds `Canvas::Security.config['lti_iss']` for real LTI launches
- ✅ Seeder now syncs connector `lti_client_id` / `lti_deployment_id` to Canvas's real launch values
- ✅ Seeder now forces the developer key owner/site-admin binding `on` so Canvas OIDC authorization accepts the client
- ✅ Real Canvas JWKS endpoint returns 3 RSA signing keys
- ✅ Connector trust metadata auto-refreshes after each seed run
- ✅ Localhost OIDC discovery works inside issuance via `issuance-canvas-localhost-bridge`

### Known Limitations
- ℹ️ The readystack Canvas image does not expose a normal root `/.well-known/openid-configuration` document on the host URL.
- ℹ️ For local `http://localhost:8088` mode, issuance relies on the compose sidecar bridge to synthesize that discovery document inside the issuance network namespace.
- ℹ️ The local seeder uses a Rails-runner fallback for Canvas developer-key and external-tool updates because the image's public developer-key API endpoints are unreliable for this flow.

### Local Browser Login Fix Applied
- File: `config/canvas/session_store.local.yml`
- Mounted by: `docker-compose.profile.canvas-real.yml` to `/usr/src/app/config/session_store.yml`
- Effective production override:
  - `same_site: Lax`
  - `secure: false`
- Apply/re-apply with container recreate:
  - `docker compose ... up -d --force-recreate canvas-real`

### Local Canvas LTI Issuer Fix Applied
- File: `config/canvas/production-local.rb`
- Effective production override:
  - if `Canvas::Security.config['lti_iss']` is blank, set it to `http://localhost:8088`
  - optional override via `CANVAS_REAL_LTI_ISS`
- Why:
  - the local Canvas image can generate `config/security.yml` without `lti_iss`
  - blank `iss` causes assignment/tool launches to fail with `Validation failed: Iss can't be blank`
- Apply/re-apply with container recreate:
  - `docker compose ... up -d --force-recreate canvas-real`

---

## Manual Testing Checklist

### Feature 1: ElevenID Canvas Connector (API)

Verify the ElevenID-side connector CRUD.

```bash
# List connectors for the Marty org
curl -s -H "X-API-Key: dev-issuance-api-key" \
  "http://localhost:8005/v1/integrations/canvas/connectors?organization_id=00000000-0000-0000-0000-000000000001" | jq

# Expected: array with one connector showing lti_client_id, lti_deployment_id, canvas_base_url
```

**Test steps:**
1. List connectors → expect 1 result with `canvas_real_client_id`
2. Get connector by ID → expect full config with LTI fields
3. Try sandbox-probe → expect probe of Canvas metadata

**What to verify:**
- `lti_client_id` = the Canvas developer key **global_id** used in launches (for example `10000000000001`)
- `lti_deployment_id` = the Canvas external tool deployment id emitted in launches
- `canvas_base_url` = `http://localhost:8088`
- `lti_issuer` = `http://localhost:8088`
- `lti_jwks_url` = `http://localhost:8088/api/lti/security/jwks`
- `lti_jwks_json.keys` contains 3 RSA keys
- `enabled` = `true`

---

### Feature 2: Canvas Admin Login

Verify you can access Canvas admin and manage settings.

**Test steps:**
1. Open `http://localhost:8088/login/canvas` in a browser
2. Sign in with `admin@example.com` / `readystack123`
3. Verify dashboard loads

**What to verify:**
- Login succeeds (no error message)
- Admin dashboard is visible with navigation sidebar
- Admin menu shows: Accounts, Courses, Developer Keys

---

### Feature 3: Canvas LTI Developer Key

Verify Canvas has an LTI 1.3 developer key configured.

```bash
# Check via Rails
docker exec marty-canvas-real bash -c "cd /usr/src/app && bin/rails runner -e production 'puts DeveloperKey.where(is_lti_key: true).pluck(:id, :name, :workflow_state).inspect'" 2>&1 | grep -v warning | grep -v deprecated

# Check via curl (if JWKS populated)
curl -s http://localhost:8088/api/lti/security/jwks
```

**Test steps (via browser once logged in):**
1. Go to Admin → Developer Keys
2. Verify "canvas-real-client-id" key exists and is shown
3. Check the key has LTI 1.3 scopes configured

**What to verify:**
- Key name = `canvas-real-client-id`
- Actual launch client_id = the developer key `global_id` (Canvas submits this in the LTI login form)
- The developer key owner/site-admin binding and the requested root-account binding are both `on`
- Workflow state = `active`  
- Redirect URI = `https://beta.elevenidllc.com/v1/integrations/canvas/lti/experience/67f60f26-67aa-405f-9e04-b48165d49c61`
- Scopes include: `lineitem`, `lineitem.readonly`, `result.readonly`, `contextmembership.readonly`

---

### Feature 4: Canvas External Tool

Verify the LTI external tool is installed in the test course.

```bash
# List external tools in the test course
curl -s -H "Authorization: Bearer ZX4KPKvXCDaP2AWVGLRkGzKvrHPQU6KK6KrVU7WZzc6t8yyL24fBkYPv8GxrQtmh" \
  "http://localhost:8088/api/v1/courses/1/external_tools" | jq
```

**Test steps (via browser once logged in):**
1. Go to Courses → ElevenID LTI Test Course
2. Settings → Apps
3. Look for "Canvas Real LMS" in installed apps

**What to verify:**
- Tool name = "Canvas Real LMS"
- Launch URL = `https://beta.elevenidllc.com/v1/integrations/canvas/lti/experience-login/67f60f26-67aa-405f-9e04-b48165d49c61`
- LTI version = 1.3
- Deployment ID = the tool's Canvas-generated `deployment_id` value, and the ElevenID connector stores the same value after seeding

---

### Feature 5: Canvas API Access

Verify the admin API token works for programmatic management.

```bash
# List courses via API
curl -s -H "Authorization: Bearer ZX4KPKvXCDaP2AWVGLRkGzKvrHPQU6KK6KrVU7WZzc6t8yyL24fBkYPv8GxrQtmh" \
  "http://localhost:8088/api/v1/accounts/1/courses"

# Verify test course exists
curl -s -H "Authorization: Bearer ZX4KPKvXCDaP2AWVGLRkGzKvrHPQU6KK6KrVU7WZzc6t8yyL24fBkYPv8GxrQtmh" \
  "http://localhost:8088/api/v1/courses/1"

# Check users
curl -s -H "Authorization: Bearer ZX4KPKvXCDaP2AWVGLRkGzKvrHPQU6KK6KrVU7WZzc6t8yyL24fBkYPv8GxrQtmh" \
  "http://localhost:8088/api/v1/accounts/1/users"
```

**What to verify:**
- Courses list includes "ElevenID LTI Test Course" (id=1)
- Users list includes admin + test learner
- API returns 200 and valid JSON

---

### Feature 6: LTI 1.3 OIDC Login Flow (End-to-End)

This is the primary integration test — verifying the complete OIDC flow from Canvas to ElevenID and back.

**Prerequisites:**
- Canvas JWKS endpoint populated (`/api/lti/security/jwks` returns 3 keys)
- Connector trust refreshed (`lti_issuer`, `lti_jwks_url`, `lti_openid_configuration` populated)
- Localhost discovery bridge running for issuance (`/.well-known/openid-configuration` inside the issuance namespace)
- Canvas developer key enabled
- Canvas external tool installed in course
- ElevenID connector configured

**Test steps (via browser):**

1. Log into Canvas as test learner (`learner+elevenid@example.edu` / `ChangeMe123!`)
2. Go to "ElevenID LTI Test Course"
3. Create an assignment with External Tool submission type:
   - Click Assignments → + Assignment
   - Submission Type: "External Tool"
   - Find "Canvas Real LMS" in tool list
   - Save & publish
4. Click the assignment → click "Load External Tool" in a new tab
5. Expected flow:
   - Canvas sends OIDC login request to ElevenID
   - ElevenID validates the login hint
   - ElevenID redirects to Canvas authorization endpoint
   - Canvas presents user authentication (SSO or login)
   - Canvas sends id_token back to ElevenID
   - ElevenID verifies the id_token signature (using JWKS)
   - ElevenID creates a credential issuance session
   - User sees ElevenID credential issuance UI
   - User claims credential → redirect back to Canvas

**What to verify:**
- Login hint from Canvas reaches ElevenID
- ElevenID responds with OIDC auth redirect
- Canvas returns id_token (signed JWT)
- ElevenID successfully verifies the id_token signature
- Credential issuance flow completes
- User redirected back to Canvas with LTI launch success

---

### Feature 7: Evidence Flow (ElevenID-Planned)

Verify the ElevenID-orchestrated Canvas evidence flow.

```bash
# Create an evidence flow plan
curl -s -X POST \
  -H "X-API-Key: dev-issuance-api-key" \
  -H "Content-Type: application/json" \
  -d '{"canvas_course_id": "1", "evidence_requirements": ["canvas.course_completion"]}' \
  "http://localhost:8005/v1/integrations/canvas/connectors/67f60f26-67aa-405f-9e04-b48165d49c61/evidence-flow" | jq
```

**Test steps:**
1. Create evidence flow with course ID and requirements
2. Verify the flow plan includes MIP primitives
3. Check the flow has canvas_course_id set correctly

**What to verify:**
- Response includes `flow` with plan details
- Evidence requirements match request
- Canvas course ID is set in the plan

---

### Feature 8: Canvas Evidence Events

Verify signed Canvas evidence can be processed.

```bash
# This requires a signed Canvas-compatible evidence payload
# Usually triggered by Canvas when a course event occurs
curl -s -X POST \
  -H "Content-Type: application/vnd.canvas.evidence+json" \
  -d '{"canvas_course_id": "1", "canvas_user_id": "2", "completion_status": "complete"}' \
  "http://localhost:8005/v1/integrations/canvas/evidence-events" | jq
```

**What to verify:**
- Evidence is accepted and validated
- Response confirms event processed
- Evidence is attached to the correct application

---

### Feature 9: Canvas Credential Events

Verify Canvas completion events can trigger wallet credential issuance.

```bash
# Test credential event processing
curl -s -X POST \
  -H "Content-Type: application/vnd.canvas.credential+json" \
  -d '{"canvas_course_id": "1", "canvas_user_id": "2", "event": "course_complete"}' \
  "http://localhost:8005/v1/integrations/canvas/credential-events" | jq
```

**What to verify:**
- Credential event triggers issuance flow
- Response includes credential/issuance details
- Wallet receives the issued credential

---

### Feature 10: Seed Script Idempotency

Verify the seed script can be safely re-run without errors.

```bash
# Run twice to verify idempotency
python scripts/seed_canvas_real.py
python scripts/seed_canvas_real.py
```

**What to verify:**
- Both runs succeed with exit code 0
- Second run reports "updated" not "created"
- No duplicate connectors, developer keys, or courses
- All resources remain in valid state

---

## Quick Reference: API Endpoints

### ElevenID Issuance (port 8005)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/integrations/canvas/connectors` | GET | List connectors |
| `/v1/integrations/canvas/connectors` | POST | Create connector |
| `/v1/integrations/canvas/connectors/{id}` | GET | Get connector |
| `/v1/integrations/canvas/connectors/{id}` | PUT | Update connector |
| `/v1/integrations/canvas/connectors/{id}` | DELETE | Delete connector |
| `/v1/integrations/canvas/connectors/{id}/sandbox-probe` | POST | Probe Canvas metadata |
| `/v1/integrations/canvas/connectors/{id}/jwks-refresh` | POST | Refresh JWKS |
| `/v1/integrations/canvas/connectors/{id}/evidence-flow` | POST | Plan evidence flow |
| `/v1/integrations/canvas/lti/experience-login/{id}` | POST | Initiate the ElevenID experience from Canvas |
| `/v1/integrations/canvas/lti/experience/{id}` | POST | Complete the Canvas LTI launch into ElevenID |
| `/v1/integrations/canvas/evidence-events` | POST | Process evidence event |
| `/v1/integrations/canvas/credential-events` | POST | Process credential event |

### Canvas LMS (port 8088)

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/login/canvas` | POST | — | Admin login form |
| `/api/v1/accounts/1/courses` | GET | Bearer token | List courses |
| `/api/v1/courses/{id}` | GET | Bearer token | Get course |
| `/api/v1/accounts/1/users` | GET | Bearer token | List users |
| `/api/v1/courses/{id}/enrollments` | GET | Bearer token | List enrollments |
| `/api/v1/courses/{id}/external_tools` | GET | Bearer token | List tools |
| `/api/lti/security/jwks` | GET | — | LTI signing keys |
| `/.well-known/openid-configuration` | GET | — | Synthetic discovery doc exposed inside issuance by the localhost bridge |

## Getting a Canvas Admin Token

### Option 1: Use Generated Token (Already Available)

The admin token has been generated and saved to `.env.tunnel.beta.local`:
```
CANVAS_ADMIN_ACCESS_TOKEN=ZX4KPKvXCDaP2AWVGLRkGzKvrHPQU6KK6KrVU7WZzc6t8yyL24fBkYPv8GxrQtmh
```

### Option 2: Generate New Token via Rails Runner

```bash
docker exec marty-canvas-real bash -c "cd /usr/src/app && bin/rails runner -e production \
  'u=User.find(1); t=u.access_tokens.create!(purpose: \"elevenid\"); puts t.full_token'"
```

### Option 3: Manual Token via Browser

1. Open `http://localhost:8088`
2. Log in with `admin@example.com` / `readystack123`
3. Click profile → Settings → Access Tokens → New Token
4. Copy the generated token

---

## Environment Variables Reference

| Variable | Current Value | Purpose |
|----------|--------------|---------|
| `ISSUANCE_API_KEY` | `dev-issuance-api-key` | ElevenID API authentication |
| `CANVAS_ORGANIZATION_ID` | `00000000-0000-0000-0000-000000000001` | ElevenID org for connector |
| `CANVAS_ACCOUNT_ID` | `canvas-real-account-1` | Canvas account identifier |
| `CANVAS_LTI_CLIENT_ID` | `canvas-real-client-id` | Seed-time developer key label; after seeding the connector is synced to Canvas's real launch `client_id` (`DeveloperKey.global_id`) |
| `CANVAS_LTI_DEPLOYMENT_ID` | `canvas-real-deployment-id` | Seed-time fallback; after seeding the connector is synced to the Canvas tool `deployment_id` emitted at launch |
| `CANVAS_CONNECTOR_BASE_URL` | `http://localhost:8088` | Canvas platform base URL used by the connector |
| `CANVAS_LTI_EXPERIENCE_BASE_URL` | `https://beta.elevenidllc.com` | Public ElevenID base URL used for Canvas launch + redirect URLs |
| `CANVAS_ADMIN_ACCESS_TOKEN` | `ZX4KPKvXCDaP2AWVGLRkGzKvrHPQU6KK6KrVU7WZzc6t8yyL24fBkYPv8GxrQtmh` | Canvas API admin token |
| `CANVAS_API_BASE_URL` | `http://localhost:8088` | Canvas API endpoint |
| `CANVAS_REAL_CONTAINER_NAME` | `marty-canvas-real` | Local Canvas container used by the Rails-runner fallback |
| `CANVAS_ROOT_ACCOUNT_ID` | `1` | Canvas account ID for API |
| `CANVAS_TEST_COURSE_NAME` | `ElevenID LTI Test Course` | Test course name |
| `CANVAS_TEST_LEARNER_EMAIL` | `learner+elevenid@example.edu` | Test learner email |

