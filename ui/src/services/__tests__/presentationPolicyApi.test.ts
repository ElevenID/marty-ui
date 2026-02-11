/**
 * API Contract Tests for Presentation Policy Service
 * 
 * Validates request/response shapes for policies, templates, and trust profiles.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import {
  createPresentationPolicy,
  listPresentationPolicies,
  getPresentationPolicy,
  updatePresentationPolicy,
  deletePresentationPolicy,
  createCredentialTemplate,
  listCredentialTemplates,
  createTrustProfile,
  listTrustProfiles,
} from '../presentationPolicyApi'
import {
  mockPolicies,
  mockTemplates,
} from '@test/mocks/fixtures'

describe('presentationPolicyApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('Presentation Policies', () => {
    it('should create policy with correct payload', async () => {
      const newPolicy = {
        name: 'Age Verification',
        description: 'Verify age over 21',
        credential_requirements: [{ field: 'age', condition: 'gt', value: 21 }],
      }

      let receivedData: any
      server.use(
        http.post('http://localhost:8000/v1/presentation-policies', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json(
            { ...mockPolicies.valid, ...newPolicy },
            { status: 201 }
          )
        })
      )

      const result = await createPresentationPolicy(newPolicy)

      expect(receivedData).toEqual(newPolicy)
      expect(result.name).toBe(newPolicy.name)
    })

    it('should list policies', async () => {
      const policies = await listPresentationPolicies()

      expect(Array.isArray(policies)).toBe(true)
      expect(policies[0]).toHaveProperty('id')
      expect(policies[0]).toHaveProperty('name')
      expect(policies[0]).toHaveProperty('status')
    })

    it('should get policy by id', async () => {
      const policy = await getPresentationPolicy(1)

      expect(policy.id).toBe(mockPolicies.valid.id)
      expect(policy.name).toBe(mockPolicies.valid.name)
    })

    it('should update policy', async () => {
      const updates = { name: 'Updated Policy Name' }

      let receivedData: any
      server.use(
        http.put('http://localhost:8000/v1/presentation-policies/:id', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({ ...mockPolicies.valid, ...receivedData })
        })
      )

      const result = await updatePresentationPolicy(1, updates)

      expect(receivedData).toEqual(updates)
      expect(result.name).toBe(updates.name)
    })

    it('should delete policy', async () => {
      let deletedId: string | undefined
      server.use(
        http.delete('http://localhost:8000/v1/presentation-policies/:id', ({ params }) => {
          deletedId = params.id as string
          return HttpResponse.json({ message: 'Deleted successfully' })
        })
      )

      await deletePresentationPolicy(1)

      expect(deletedId).toBe('1')
    })

    it('should handle API errors', async () => {
      server.use(
        http.post('http://localhost:8000/v1/presentation-policies', () => {
          return HttpResponse.json(
            { error: { code: 'VALIDATION_ERROR', message: 'Invalid data' } },
            { status: 400 }
          )
        })
      )

      await expect(createPresentationPolicy({})).rejects.toThrow()
    })
  })

  describe('Credential Templates', () => {
    it('should create template with correct shape', async () => {
      const newTemplate = {
        name: 'mDL Template',
        doctype: 'org.iso.18013.5.1.mDL',
        namespace: 'org.iso.18013.5.1',
        fields: [],
      }

      let receivedData: any
      server.use(
        http.post('http://localhost:8000/v1/credential-templates', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json(
            { ...mockTemplates.valid, ...newTemplate },
            { status: 201 }
          )
        })
      )

      const result = await createCredentialTemplate(newTemplate)

      expect(receivedData.name).toBe(newTemplate.name)
      expect(result.doctype).toBe(newTemplate.doctype)
    })

    it('should list templates', async () => {
      const templates = await listCredentialTemplates()

      expect(Array.isArray(templates)).toBe(true)
      expect(templates[0]).toHaveProperty('id')
      expect(templates[0]).toHaveProperty('doctype')
    })

    it('should pass query params', async () => {
      let queryParams: URLSearchParams | undefined
      server.use(
        http.get('http://localhost:8000/v1/credential-templates', ({ request }) => {
          queryParams = new URL(request.url).searchParams
          return HttpResponse.json([mockTemplates.valid])
        })
      )

      await listCredentialTemplates({ status: 'active' })

      expect(queryParams?.toString()).toContain('status=active')
    })
  })

  describe('Trust Profiles', () => {
    it('should create trust profile', async () => {
      const newProfile = {
        name: 'Production Trust',
        trust_list_url: 'https://example.com/trust-list',
        status: 'active',
      }

      const result = await createTrustProfile(newProfile)

      expect(result.name).toBeDefined()
      expect(result).toHaveProperty('id')
    })

    it('should list trust profiles', async () => {
      const profiles = await listTrustProfiles()

      expect(Array.isArray(profiles)).toBe(true)
      expect(profiles[0]).toHaveProperty('id')
      expect(profiles[0]).toHaveProperty('status')
    })

    it('should validate response structure', async () => {
      const profile = await listTrustProfiles().then((list: any[]) => list[0])

      // Validate expected fields exist
      expect(profile).toHaveProperty('id')
      expect(profile).toHaveProperty('name')
      expect(profile).toHaveProperty('status')
      expect(profile).toHaveProperty('trust_list_url')
    })
  })

  describe('HTTP method correctness', () => {
    it('should use POST for create operations', async () => {
      let method: string | undefined
      server.use(
        http.post('http://localhost:8000/v1/presentation-policies', ({ request }) => {
          method = request.method
          return HttpResponse.json({ id: 1 })
        })
      )

      await createPresentationPolicy({ name: 'Test' })

      expect(method).toBe('POST')
    })

    it('should use PATCH for updates', async () => {
      let method: string | undefined
      server.use(
        http.patch('http://localhost:8000/v1/presentation-policies/:id', ({ request }) => {
          method = request.method
          return HttpResponse.json({ id: 1 })
        })
      )

      await updatePresentationPolicy(1, { name: 'Updated' })

      expect(method).toBe('PATCH')
    })

    it('should use DELETE for delete operations', async () => {
      let method: string | undefined
      server.use(
        http.delete('http://localhost:8000/v1/presentation-policies/:id', ({ request }) => {
          method = request.method
          return HttpResponse.json({ message: 'Deleted' })
        })
      )

      await deletePresentationPolicy(1)

      expect(method).toBe('DELETE')
    })
  })
})
