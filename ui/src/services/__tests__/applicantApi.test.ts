import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { getMyApplications } from '../applicantApi'

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
      applications: [{ id: 'application-1', status: 'offered' }],
      total: 1,
    })
    expect(requestedPaths).toEqual(['/v1/me/applications'])
  })
})
