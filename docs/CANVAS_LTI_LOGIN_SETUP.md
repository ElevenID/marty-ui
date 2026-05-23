# Canvas LTI Login Setup & Testing Guide

## Current Status

Canvas is configured through the platform + program-binding model. Older pre-platform Canvas configuration APIs and direct Canvas credential events are no longer exposed.

The active demo path is:

```text
Canvas LTI launch -> CanvasPlatform -> CanvasProgramBinding -> application flow
Canvas AGS/evidence event -> MIP EvidenceFact -> policy approval -> issuance -> wallet + Canvas mirror
```

## What Is Working

- ElevenID issuance service exposes Canvas platform and program-binding APIs.
- Canvas LMS can launch ElevenID through LTI 1.3 OIDC.
- LTI launch state is tied to the Canvas platform and resolved to an enabled program binding.
- Canvas evidence is accepted through `/evidence-events`, `/ags/score-events`, and `/nrps/membership-events`.
- Direct credential-event issuance is no longer supported.
- The real Canvas seeder creates or updates the Canvas developer key, external tool, test course, learner, quiz, platform, and program binding.
- The demo can auto-approve and issue after policy accepts the Canvas evidence fact.

## Manual Testing Checklist

### Feature 1: ElevenID Canvas Platform

Verify the ElevenID-side Canvas platform.

```bash
curl -s -H "X-API-Key: dev-issuance-api-key" \
  "http://localhost:8005/v1/integrations/canvas/platforms?organization_id=00000000-0000-0000-0000-000000000001" | jq
```

Check:

- `canvas_base_url` points to the Canvas host.
- `lti_issuer` matches the issuer Canvas places in the LTI `id_token`.
- `lti_client_id` is Canvas developer key `global_id`.
- `lti_deployment_id` is the external tool deployment id.
- `lti_jwks_json.keys` is populated after JWKS refresh.
- `enabled` is `true`.

Refresh platform metadata:

```bash
curl -s -X POST -H "X-API-Key: dev-issuance-api-key" \
  "http://localhost:8005/v1/integrations/canvas/platforms/{platform_id}/jwks-refresh" | jq
```

### Feature 2: Canvas Program Binding

Verify at least one enabled binding maps the platform/course activity to an ElevenID credential flow.

```bash
curl -s -H "X-API-Key: dev-issuance-api-key" \
  "http://localhost:8005/v1/integrations/canvas/program-bindings?organization_id=00000000-0000-0000-0000-000000000001" | jq
```

Check:

- `canvas_platform_id` matches the platform from Feature 1.
- `application_template_id` and `credential_template_id` are present.
- `evidence_requirements` describe the Canvas completion/score requirement.
- `auto_approve_on_evidence` is `true` for the demo.
- `delivery_mode` is `wallet_plus_canvas_mirror` for the full mirror demo.

### Feature 3: Canvas Admin Login

1. Open `http://localhost:8088/login/canvas` locally, or `https://canvas-test.elevenidllc.com/login/canvas` for beta experiments.
2. Sign in with the configured Canvas admin user.
3. Verify the course, developer key, and external tool exist.

### Feature 4: Canvas LTI Developer Key

```bash
docker exec marty-canvas-real bash -c "cd /usr/src/app && bin/rails runner -e production 'puts DeveloperKey.where(is_lti_key: true).pluck(:id, :global_id, :name, :workflow_state).inspect'" 2>&1 | grep -v warning | grep -v deprecated
```

Check:

- Workflow state is `active`.
- Redirect URI uses the platform route:
  `https://beta.elevenidllc.com/v1/integrations/canvas/lti/platforms/{platform_id}/experience`
- Scopes include line-item, result, and membership read permissions when AGS/NRPS evidence is enabled.

### Feature 5: Canvas External Tool

```bash
curl -s -H "Authorization: Bearer $CANVAS_ADMIN_ACCESS_TOKEN" \
  "http://localhost:8088/api/v1/courses/1/external_tools" | jq
```

Check:

- Launch URL uses:
  `https://beta.elevenidllc.com/v1/integrations/canvas/lti/platforms/{platform_id}/experience-login`
- Tool deployment id matches the platform `lti_deployment_id`.

### Feature 6: LTI Launch

1. Log into Canvas as the test learner.
2. Open the ElevenID external-tool assignment or module item.
3. Canvas sends OIDC login to ElevenID.
4. ElevenID verifies the Canvas `id_token`.
5. ElevenID signs in the LTI learner and opens the matching credential application.

Expected:

- The embedded page is served from `beta.elevenidllc.com`, not localhost.
- The learner does not receive org-console access.
- Re-launching resumes or resolves the existing application instead of creating a broken duplicate.

### Feature 7: Canvas Evidence Event

The preferred demo evidence path is AGS quiz score evidence.

```bash
curl -s -X POST \
  -H "Content-Type: application/vnd.canvas.evidence+json" \
  -d '{"application_id":"{application_id}","canvas_course_id":"1","canvas_user_id":"2","score_percent":92,"evidence_type":"canvas.quiz_score"}' \
  "http://localhost:8005/v1/integrations/canvas/ags/score-events" | jq
```

Check:

- A `MipEvidenceReceipt` is created.
- An immutable `EvidenceFact` is stored.
- The approval policy permits the application when scope and score match.
- Issuance transaction is created or reused.

### Feature 8: Wallet Claim + Canvas Mirror

After the application is approved:

1. Claim the credential through the wallet flow.
2. Confirm the issuer DID is the Marty remote-key DID.
3. Confirm the revocation registry is set.
4. Confirm the Canvas mirror delivery record is queued/published.

## Seeder

Run the real Canvas seeder:

```bash
cd marty-ui
PYTHONIOENCODING=utf-8 python scripts/seed_canvas_real.py --env-file .env.tunnel.beta.local
```

The seeder is idempotent and now creates:

- CanvasPlatform
- CanvasProgramBinding
- Canvas developer key
- Canvas external tool
- Canvas test course/learner/quiz/assignment
- Open Badge credential template and application template
- demo application/evidence/claim/mirror steps when enabled

## Quick Reference: ElevenID Canvas Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/integrations/canvas/platforms` | GET/POST | List or create Canvas platforms |
| `/v1/integrations/canvas/platforms/{id}` | GET/PUT/DELETE | Manage one Canvas platform |
| `/v1/integrations/canvas/platforms/{id}/sandbox-probe` | POST | Probe Canvas metadata |
| `/v1/integrations/canvas/platforms/{id}/jwks-refresh` | POST | Refresh OIDC/JWKS metadata |
| `/v1/integrations/canvas/program-bindings` | GET/POST | List or create Canvas program bindings |
| `/v1/integrations/canvas/program-bindings/{id}` | GET/PUT/DELETE | Manage one binding |
| `/v1/integrations/canvas/lti/platforms/{id}/experience-login` | POST | Initiate Canvas LTI experience login |
| `/v1/integrations/canvas/lti/platforms/{id}/experience` | POST | Complete Canvas LTI launch |
| `/v1/integrations/canvas/evidence-events` | POST | Process generic signed Canvas evidence |
| `/v1/integrations/canvas/ags/score-events` | POST | Process Canvas AGS score evidence |
| `/v1/integrations/canvas/nrps/membership-events` | POST | Process Canvas NRPS membership evidence |
## Environment Variables

Minimum ElevenID values:

- `ISSUANCE_API_KEY`
- `CANVAS_ORGANIZATION_ID`
- `CANVAS_CREDENTIAL_TEMPLATE_ID`
- `CANVAS_APPLICATION_TEMPLATE_ID`
- `CANVAS_CONNECTOR_BASE_URL` (historical name; used as the Canvas platform base URL)
- `CANVAS_LTI_EXPERIENCE_BASE_URL`
- `CANVAS_LTI_CLIENT_ID`
- `CANVAS_LTI_DEPLOYMENT_ID`

Demo values:

- `CANVAS_OPEN_BADGE_SCENARIO_ENABLED=true`
- `CANVAS_PROGRAM_BINDING_SEED_ENABLED=true`
- `CANVAS_PROGRAM_BINDING_EVIDENCE_TYPE=canvas.quiz_score`
- `CANVAS_PROGRAM_BINDING_DELIVERY_MODE=wallet_plus_canvas_mirror`
- `CANVAS_PROGRAM_BINDING_AUTO_APPROVE=true`
- `CANVAS_DEMO_EVIDENCE_EVENT_ENABLED=true`
- `CANVAS_DEMO_WALLET_CLAIM_ENABLED=true`
- `CANVAS_DEMO_MIRROR_PUBLISH_ENABLED=true`

Canvas LMS values:

- `CANVAS_ADMIN_ACCESS_TOKEN`
- `CANVAS_ADMIN_EMAIL`
- `CANVAS_ADMIN_PASSWORD`
- `CANVAS_API_BASE_URL`
- `CANVAS_BROWSER_BASE_URL`
- `CANVAS_REAL_CONTAINER_NAME`
- `CANVAS_REAL_LTI_ISS`
- `CANVAS_ROOT_ACCOUNT_ID`

## Retired Surfaces

These are intentionally unsupported:

- Older pre-platform Canvas configuration CRUD
- Connector evidence-flow planning
- Direct Canvas credential events
- LTI routes that use connector ids instead of platform ids

Use platform + program binding APIs for all new Canvas work.
