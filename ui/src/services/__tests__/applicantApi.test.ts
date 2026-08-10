import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import {
  deleteApplicationEvidence,
  getMyApplications,
  getMyCredentials,
  listApplicationEvidence,
  listOrganizationApplicationEvidence,
  revokeOrganizationApplicationEvidence,
  submitApplicationEvidence,
} from '../applicantApi'

describe('applicantApi', () => {
  it('loads current applicant applications from the canonical self-service route', async () => {
    const requestedPaths: string[] = []

    server.use(
      http.get('http://localhost:8000/v1/me/applications', ({ request }) => {
        requestedPaths.push(new URL(request.url).pathname)
        return HttpResponse.json({
          items: [
            { id: 'application-1', status: 'offered' },
          ],
        })
      }),
    )

    await expect(getMyApplications()).resolves.toMatchObject({
      items: [{ id: 'application-1', status: 'offered' }],
      total: 1,
    })
    expect(requestedPaths).toEqual(['/v1/me/applications'])
  })

  it('normalizes holder inventory to the same page contract', async () => {
    server.use(
      http.get('http://localhost:8000/v1/issued-credentials/mine', () => (
        HttpResponse.json({ items: [{ id: 'credential-1' }], total: 1, limit: 25, offset: 0 })
      )),
    )

    await expect(getMyCredentials({ limit: 25 })).resolves.toEqual({
      items: [{ id: 'credential-1' }],
      total: 1,
      limit: 25,
      offset: 0,
    })
  })

  it('fails closed to an empty page for malformed list payloads', async () => {
    server.use(
      http.get('http://localhost:8000/v1/me/applications', () => (
        HttpResponse.json({ items: { id: 'not-an-array' }, total: 99 })
      )),
    )

    await expect(getMyApplications({ limit: 10, offset: 20 })).resolves.toEqual({
      items: [],
      total: 0,
      limit: 10,
      offset: 20,
    })
  })

  it('uses only the current self-service evidence routes', async () => {
    const requests: Array<{ method: string; path: string; body?: unknown }> = []
    server.use(
      http.post('http://localhost:8000/v1/me/applications/:applicationId/evidence', async ({ request }) => {
        requests.push({
          method: request.method,
          path: new URL(request.url).pathname,
          body: await request.json(),
        })
        return HttpResponse.json({ id: 'evidence-1', status: 'ACTIVE' })
      }),
      http.get('http://localhost:8000/v1/me/applications/:applicationId/evidence', ({ request }) => {
        requests.push({ method: request.method, path: new URL(request.url).pathname })
        return HttpResponse.json([{ id: 'evidence-1', status: 'ACTIVE' }])
      }),
      http.delete('http://localhost:8000/v1/me/applications/:applicationId/evidence/:evidenceId', ({ request }) => {
        requests.push({ method: request.method, path: new URL(request.url).pathname })
        return HttpResponse.json({ deleted: true })
      }),
    )

    await submitApplicationEvidence('application/1', {
      evidence_requirement_id: 'identity-scan',
      media_type: 'image/png',
      filename: 'identity.png',
      content_base64: 'aWRlbnRpdHk=',
    })
    await listApplicationEvidence('application/1')
    await deleteApplicationEvidence('application/1', 'evidence/1')

    expect(requests).toEqual([
      {
        method: 'POST',
        path: '/v1/me/applications/application%2F1/evidence',
        body: expect.objectContaining({ evidence_requirement_id: 'identity-scan' }),
      },
      { method: 'GET', path: '/v1/me/applications/application%2F1/evidence' },
      { method: 'DELETE', path: '/v1/me/applications/application%2F1/evidence/evidence%2F1' },
    ])
    expect(requests.every(({ path }) => !path.startsWith('/v1/applications/'))).toBe(true)
  })

  it('binds reviewer evidence access to the organization-scoped route', async () => {
    const requests: Array<{ method: string; path: string; body?: unknown }> = []
    server.use(
      http.get('http://localhost:8000/v1/organizations/:organizationId/applicants/:applicationId/evidence', ({ request }) => {
        requests.push({ method: request.method, path: new URL(request.url).pathname })
        return HttpResponse.json([{ id: 'evidence-1', status: 'ACTIVE' }])
      }),
      http.post('http://localhost:8000/v1/organizations/:organizationId/applicants/:applicationId/evidence/:evidenceId/revoke', async ({ request }) => {
        requests.push({ method: request.method, path: new URL(request.url).pathname, body: await request.json() })
        return HttpResponse.json({ id: 'evidence-1', status: 'REVOKED' })
      }),
    )

    await listOrganizationApplicationEvidence('org/1', 'application/1')
    await revokeOrganizationApplicationEvidence('org/1', 'application/1', 'evidence/1', 'invalid image')

    expect(requests).toEqual([
      { method: 'GET', path: '/v1/organizations/org%2F1/applicants/application%2F1/evidence' },
      {
        method: 'POST',
        path: '/v1/organizations/org%2F1/applicants/application%2F1/evidence/evidence%2F1/revoke',
        body: { reason: 'invalid image' },
      },
    ])
  })
})
