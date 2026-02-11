/**
 * API Contract Tests for Credentials Service
 * 
 * Validates request/response contracts for credential lifecycle operations:
 * - Issuance
 * - Verification
 * - Revocation (single and batch)
 * - Metadata retrieval
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import {
  issueCredential,
  verifyCredential,
  getCredentialMetadata,
  revokeCredential,
  batchRevokeCredentials,
  listCredentials,
  listRevocationBatches,
} from '../credentialsApi'

describe('credentialsApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('issueCredential', () => {
    it('should issue credential with correct payload', async () => {
      const issuanceRequest = {
        credential_template_id: 'template_123',
        flow_execution_id: 'flow_456',
        subject_claims: {
          given_name: 'Alice',
          family_name: 'Smith',
          birth_date: '1985-01-15',
        },
        holder_identifier: 'did:example:alice123',
        application_data: {
          document_number: 'D123456',
        },
      }

      let receivedData: any
      server.use(
        http.post('http://localhost:8000/v1/credentials/issue', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json(
            {
              credential: { id: 'cred_789', ...receivedData },
              status: 'issued',
            },
            { status: 201 }
          )
        })
      )

      const result = await issueCredential(issuanceRequest)

      expect(receivedData).toEqual(issuanceRequest)
      expect(result).toHaveProperty('credential')
      expect(result).toHaveProperty('status')
    })

    it('should handle validation errors', async () => {
      server.use(
        http.post('http://localhost:8000/v1/credentials/issue', () => {
          return HttpResponse.json(
            {
              error: {
                code: 'VALIDATION_ERROR',
                message: 'Missing subject_claims',
              },
            },
            { status: 400 }
          )
        })
      )

      await expect(issueCredential({})).rejects.toThrow()
    })
  })

  describe('verifyCredential', () => {
    it('should verify credential', async () => {
      const verifyRequest = {
        credential: { id: 'cred_123', proof: {} },
        presentation_policy_id: 'policy_456',
        trust_profile_id: 'trust_789',
      }

      let receivedData: any
      server.use(
        http.post('http://localhost:8000/v1/credentials/verify', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({
            valid: true,
            verification_result: {
              signature_valid: true,
              not_expired: true,
              not_revoked: true,
            },
          })
        })
      )

      const result = await verifyCredential(verifyRequest)

      expect(receivedData).toEqual(verifyRequest)
      expect(result.valid).toBe(true)
      expect(result.verification_result).toHaveProperty('signature_valid')
    })

    it('should return validation failures', async () => {
      server.use(
        http.post('http://localhost:8000/v1/credentials/verify', () => {
          return HttpResponse.json({
            valid: false,
            verification_result: {
              signature_valid: false,
              not_expired: true,
              not_revoked: true,
              errors: ['Invalid signature'],
            },
          })
        })
      )

      const result = await verifyCredential({ credential: {} })

      expect(result.valid).toBe(false)
      expect(result.verification_result.errors).toContain('Invalid signature')
    })
  })

  describe('getCredentialMetadata', () => {
    it('should fetch credential metadata', async () => {
      const credentialId = 'cred_123'

      server.use(
        http.get(`http://localhost:8000/v1/credentials/${credentialId}`, () => {
          return HttpResponse.json({
            id: credentialId,
            status: 'issued',
            template_id: 'template_456',
            issued_at: '2024-01-15T10:00:00Z',
          })
        })
      )

      const metadata = await getCredentialMetadata(credentialId)

      expect(metadata.id).toBe(credentialId)
      expect(metadata).toHaveProperty('status')
      expect(metadata).toHaveProperty('issued_at')
    })

    it('should handle 404 for non-existent credential', async () => {
      server.use(
        http.get('http://localhost:8000/v1/credentials/:id', () => {
          return HttpResponse.json(
            { error: { message: 'Credential not found' } },
            { status: 404 }
          )
        })
      )

      await expect(getCredentialMetadata('invalid_id')).rejects.toThrow()
    })
  })

  describe('revokeCredential', () => {
    it('should revoke single credential with defaults', async () => {
      const credentialId = 'cred_123'

      let receivedData: any
      server.use(
        http.patch(`http://localhost:8000/v1/credentials/${credentialId}/revoke`, async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({
            id: credentialId,
            status: 'revoked',
            revocation_strategy: 'scheduled',
          })
        })
      )

      const result = await revokeCredential(credentialId)

      expect(receivedData.revocation_strategy).toBe('scheduled')
      expect(result.status).toBe('revoked')
    })

    it('should support immediate revocation', async () => {
      const credentialId = 'cred_123'

      let receivedData: any
      server.use(
        http.patch('http://localhost:8000/v1/credentials/:id/revoke', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({
            id: credentialId,
            status: 'revoked',
            revocation_strategy: 'immediate',
          })
        })
      )

      await revokeCredential(credentialId, { revocation_strategy: 'immediate' })

      expect(receivedData.revocation_strategy).toBe('immediate')
    })

    it('should include revocation reason', async () => {
      const credentialId = 'cred_123'
      const reason = 'Lost document'

      let receivedData: any
      server.use(
        http.patch('http://localhost:8000/v1/credentials/:id/revoke', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({ id: credentialId, status: 'revoked' })
        })
      )

      await revokeCredential(credentialId, { revocation_reason: reason })

      expect(receivedData.revocation_reason).toBe(reason)
    })
  })

  describe('batchRevokeCredentials', () => {
    it('should revoke multiple credentials', async () => {
      const credentialIds = ['cred_1', 'cred_2', 'cred_3']

      let receivedData: any
      server.use(
        http.post('http://localhost:8000/v1/credentials/revoke/batch', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({
            batch_id: 'batch_789',
            status: 'pending',
            credential_count: credentialIds.length,
          })
        })
      )

      const result = await batchRevokeCredentials(credentialIds)

      expect(receivedData.credential_ids).toEqual(credentialIds)
      expect(result.batch_id).toBe('batch_789')
      expect(result.credential_count).toBe(3)
    })

    it('should use scheduled strategy by default', async () => {
      let receivedData: any
      server.use(
        http.post('http://localhost:8000/v1/credentials/revoke/batch', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({ batch_id: 'batch_123' })
        })
      )

      await batchRevokeCredentials(['cred_1'])

      expect(receivedData.revocation_strategy).toBe('scheduled')
    })
  })

  describe('listCredentials', () => {
    it('should list credentials without filters', async () => {
      server.use(
        http.get('http://localhost:8000/v1/credentials', () => {
          return HttpResponse.json([
            { id: 'cred_1', status: 'issued' },
            { id: 'cred_2', status: 'revoked' },
          ])
        })
      )

      const credentials = await listCredentials()

      expect(Array.isArray(credentials)).toBe(true)
      expect(credentials).toHaveLength(2)
    })

    it('should apply query filters', async () => {
      let queryParams: URLSearchParams | undefined
      server.use(
        http.get('http://localhost:8000/v1/credentials', ({ request }) => {
          queryParams = new URL(request.url).searchParams
          return HttpResponse.json([])
        })
      )

      await listCredentials({
        flow_id: 'flow_123',
        status: 'issued',
        limit: 10,
        offset: 20,
      })

      expect(queryParams?.get('flow_id')).toBe('flow_123')
      expect(queryParams?.get('status')).toBe('issued')
      expect(queryParams?.get('limit')).toBe('10')
      expect(queryParams?.get('offset')).toBe('20')
    })
  })

  describe('listRevocationBatches', () => {
    it('should list revocation batches', async () => {
      server.use(
        http.get('http://localhost:8000/v1/credentials/revocation-batches', () => {
          return HttpResponse.json([
            {
              batch_id: 'batch_1',
              status: 'completed',
              credential_count: 5,
            },
            {
              batch_id: 'batch_2',
              status: 'processing',
              credential_count: 10,
            },
          ])
        })
      )

      const batches = await listRevocationBatches()

      expect(Array.isArray(batches)).toBe(true)
      expect(batches[0]).toHaveProperty('batch_id')
      expect(batches[0]).toHaveProperty('status')
    })

    it('should filter by status', async () => {
      let queryParams: URLSearchParams | undefined
      server.use(
        http.get('http://localhost:8000/v1/credentials/revocation-batches', ({ request }) => {
          queryParams = new URL(request.url).searchParams
          return HttpResponse.json([])
        })
      )

      await listRevocationBatches({ status: 'completed' })

      expect(queryParams?.get('status')).toBe('completed')
    })
  })
})
