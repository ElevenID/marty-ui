import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { getMyApplications } from '../applicantApi'

describe('applicantApi', () => {
  it('loads current applicant applications from the profile-scoped route first', async () => {
    const requestedPaths: string[] = []

    server.use(
      http.get('http://localhost:8000/v1/auth/me', () => HttpResponse.json({
        authenticated: true,
        user: {
          user_id: 'user-1',
          applicant_id: 'app-1',
        },
      })),
      http.get('http://localhost:8000/v1/applicants/by-user/user-1', () => HttpResponse.json({
        id: 'app-1',
      })),
      http.get('http://localhost:8000/v1/applicants/profiles/app-1/applications', ({ request }) => {
        requestedPaths.push(new URL(request.url).pathname)
        return HttpResponse.json({
          applications: [
            { id: 'application-1', status: 'offered' },
          ],
        })
      }),
      http.get('http://localhost:8000/v1/applicants/app-1/applications', ({ request }) => {
        requestedPaths.push(new URL(request.url).pathname)
        return HttpResponse.json({ detail: 'legacy route should not be called' }, { status: 404 })
      }),
    )

    await expect(getMyApplications()).resolves.toMatchObject({
      applications: [{ id: 'application-1', status: 'offered' }],
      total: 1,
    })
    expect(requestedPaths).toEqual(['/v1/applicants/profiles/app-1/applications'])
  })
})
