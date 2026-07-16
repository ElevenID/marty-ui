import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { getMyApplications, getMyCredentials } from '../applicantApi'

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
})
