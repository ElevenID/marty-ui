import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import {
  createCanvasIntegrationSecret,
  createCanvasPlatform,
  createCanvasProgramBinding,
  finalizeCanvasLtiInstallation,
  listCanvasAwardCandidates,
  listCanvasEvidencePolicyReviews,
  listCanvasSyncJobs,
  resolveCanvasSyncJob,
  startCanvasOAuthConnection,
  updateCanvasPlatform,
  updateCanvasProgramBinding,
} from '../canvasIntegrationsApi'

describe('canvasIntegrationsApi', () => {
  it('acknowledges a Canvas synchronization dead letter', async () => {
    let body: unknown;
    server.use(
      http.post('http://localhost:8000/v1/integrations/canvas/canvas-sync-jobs/job%2F1/resolve', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ id: 'job/1', status: 'cancelled' });
      }),
    );

    const response = await resolveCanvasSyncJob('job/1');

    expect(body).toEqual({});
    expect(response).toEqual({ id: 'job/1', status: 'cancelled' });
  });

  it('creates Canvas artifacts with trusted org context and strict request bodies', async () => {
    const seen: Array<{
      path: string
      queryOrganizationId: string | null
      body: Record<string, unknown>
      idempotencyKey: string | null
    }> = []

    server.use(
      http.post('http://localhost:8000/v1/integrations/canvas/platforms', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({
          path: '/platforms',
          queryOrganizationId: new URL(request.url).searchParams.get('organization_id'),
          body,
          idempotencyKey: request.headers.get('Idempotency-Key'),
        })
        return HttpResponse.json({ id: 'platform-1', ...body }, { status: 201 })
      }),
      http.post('http://localhost:8000/v1/integrations/canvas/platforms/platform-1/program-bindings', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({
          path: '/program-bindings',
          queryOrganizationId: new URL(request.url).searchParams.get('organization_id'),
          body,
          idempotencyKey: request.headers.get('Idempotency-Key'),
        })
        return HttpResponse.json({ id: 'binding-1', ...body }, { status: 201 })
      }),
      http.post('http://localhost:8000/v1/integrations/canvas/integration-secrets', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({
          path: '/integration-secrets',
          queryOrganizationId: new URL(request.url).searchParams.get('organization_id'),
          body,
          idempotencyKey: request.headers.get('Idempotency-Key'),
        })
        return HttpResponse.json({ id: 'secret-1', ...body }, { status: 201 })
      }),
    )

    await createCanvasPlatform({
      display_name: 'Canvas',
      canvas_base_url: 'https://canvas.example.edu',
      organization_id: 'should-not-be-forwarded',
      status: 'active',
    }, { organizationId: ' org-123 ' })
    await createCanvasProgramBinding('platform-1', {
      display_name: 'Course',
      application_template_id: 'application-template-1',
      credential_template_id: 'credential-template-1',
      evidence_requirements: [],
      canvas_scope: { course_id: 'course-1' },
      flow_mode: 'legacy-forbidden-field',
      direct_issue_enabled: true,
      enabled: true,
    }, { organizationId: ' org-123 ' })
    await createCanvasIntegrationSecret({
      organization_id: ' org-123 ',
      provider: 'canvas_credentials',
      secret_name: 'CANVAS_TOKEN',
    })

    expect(seen).toEqual([
      expect.objectContaining({
        path: '/platforms',
        queryOrganizationId: 'org-123',
        body: {
          display_name: 'Canvas',
          canvas_base_url: 'https://canvas.example.edu',
        },
        idempotencyKey: expect.stringContaining('v1-integrations-canvas-platforms'),
      }),
      expect.objectContaining({
        path: '/program-bindings',
        queryOrganizationId: 'org-123',
        body: {
          display_name: 'Course',
          application_template_id: 'application-template-1',
          credential_template_id: 'credential-template-1',
          evidence_requirements: [],
          canvas_scope: { course_id: 'course-1' },
        },
        idempotencyKey: expect.stringContaining('v1-integrations-canvas-platforms-platform-1-program-bindings'),
      }),
      expect.objectContaining({
        path: '/integration-secrets',
        queryOrganizationId: null,
        body: expect.objectContaining({ organization_id: 'org-123' }),
        idempotencyKey: expect.stringContaining('v1-integrations-canvas-integration-secrets'),
      }),
    ])
  })

  it('sanitizes update bodies and finalizes LTI installation through the dedicated endpoint', async () => {
    const seen: Array<{ path: string; body: Record<string, unknown> }> = []

    server.use(
      http.put('http://localhost:8000/v1/integrations/canvas/platforms/platform-1', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({ path: '/platforms/platform-1', body })
        return HttpResponse.json({ id: 'platform-1', ...body })
      }),
      http.put('http://localhost:8000/v1/integrations/canvas/platforms/platform-1/lti-installation', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({ path: '/platforms/platform-1/lti-installation', body })
        return HttpResponse.json({ platform_id: 'platform-1' })
      }),
      http.put('http://localhost:8000/v1/integrations/canvas/program-bindings/binding-1', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({ path: '/program-bindings/binding-1', body })
        return HttpResponse.json({ id: 'binding-1', ...body })
      }),
    )

    await updateCanvasPlatform('platform-1', {
      display_name: 'Canvas',
      canvas_base_url: 'https://canvas.example.edu',
      organization_id: 'org-forbidden',
      registration_status: 'verified',
    })
    await finalizeCanvasLtiInstallation('platform-1', {
      lti_client_id: 'client-1',
      lti_deployment_id: 'deployment-1',
      organization_id: 'org-forbidden',
      status: 'verified',
    })
    await updateCanvasProgramBinding('binding-1', {
      application_template_id: 'application-template-1',
      credential_template_id: 'credential-template-1',
      evidence_requirements: [],
      canvas_scope: { course_id: 'course-1' },
      organization_id: 'org-forbidden',
      flow_mode: 'legacy-forbidden-field',
      direct_issue_enabled: true,
      enabled: true,
    })

    expect(seen).toEqual([
      {
        path: '/platforms/platform-1',
        body: {
          display_name: 'Canvas',
          canvas_base_url: 'https://canvas.example.edu',
        },
      },
      {
        path: '/platforms/platform-1/lti-installation',
        body: {
          lti_client_id: 'client-1',
          lti_deployment_id: 'deployment-1',
        },
      },
      {
        path: '/program-bindings/binding-1',
        body: {
          application_template_id: 'application-template-1',
          credential_template_id: 'credential-template-1',
          evidence_requirements: [],
          canvas_scope: { course_id: 'course-1' },
        },
      },
    ])
  })

  it('uses capability-derived OAuth and organization-scoped operations APIs', async () => {
    const seen: Array<{ path: string; value: unknown }> = []

    server.use(
      http.post('http://localhost:8000/v1/integrations/canvas/platforms/platform-1/oauth/authorizations', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({ path: '/oauth/authorizations', value: body })
        return HttpResponse.json({ authorization_url: 'https://canvas.example.edu/login/oauth2/auth' })
      }),
      http.get('http://localhost:8000/v1/integrations/canvas/canvas-sync-jobs', ({ request }) => {
        seen.push({ path: '/canvas-sync-jobs', value: new URL(request.url).searchParams.get('organization_id') })
        return HttpResponse.json({ items: [] })
      }),
      http.get('http://localhost:8000/v1/integrations/canvas/canvas-award-candidates', ({ request }) => {
        seen.push({ path: '/canvas-award-candidates', value: new URL(request.url).searchParams.get('organization_id') })
        return HttpResponse.json([])
      }),
      http.get('http://localhost:8000/v1/integrations/canvas/evidence-policy-reviews', ({ request }) => {
        seen.push({ path: '/evidence-policy-reviews', value: new URL(request.url).searchParams.get('organization_id') })
        return HttpResponse.json([])
      }),
    )

    await startCanvasOAuthConnection('platform-1', {
      client_id: 'client-1',
      capabilities: ['catalog', 'native_activity_scores'],
    })
    await listCanvasSyncJobs({ organizationId: ' org-123 ' })
    await listCanvasAwardCandidates({ organizationId: ' org-123 ' })
    await listCanvasEvidencePolicyReviews({ organizationId: ' org-123 ' })

    expect(seen[0]).toEqual({
      path: '/oauth/authorizations',
      value: {
        client_id: 'client-1',
        capabilities: ['catalog', 'native_activity_scores'],
      },
    })
    expect(seen.slice(1)).toEqual([
      { path: '/canvas-sync-jobs', value: 'org-123' },
      { path: '/canvas-award-candidates', value: 'org-123' },
      { path: '/evidence-policy-reviews', value: 'org-123' },
    ])
  })
})
