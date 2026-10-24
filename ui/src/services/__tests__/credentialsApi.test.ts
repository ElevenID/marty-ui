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
        organization_id: 'org_123',
        credential_template_id: 'template_123',
        issuer_did: 'did:web:issuer.example',
        credential: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiableCredential'],
          issuer: 'did:web:issuer.example',
          credentialSubject: { id: 'did:example:alice123' },
        },
      }

      let receivedData: any
      let receivedUrl: URL
      server.use(
        http.post('http://localhost:8000/v1/vc-api/credentials/issue', async ({ request }) => {
          receivedUrl = new URL(request.url)
          receivedData = await request.json()
          return HttpResponse.json(
            {
              verifiableCredential: { ...receivedData.credential, proof: { cryptosuite: 'eddsa-rdfc-2022' } },
            },
            { status: 200 }
          )
        })
      )

      const result = await issueCredential(issuanceRequest)

      expect(receivedUrl!.searchParams.get('organization_id')).toBe(issuanceRequest.organization_id)
      expect(receivedUrl!.searchParams.get('credential_template_id')).toBe(issuanceRequest.credential_template_id)
      expect(receivedUrl!.searchParams.get('issuer_did')).toBe(issuanceRequest.issuer_did)
      expect(receivedData).toEqual({ credential: issuanceRequest.credential })
      expect(result.verifiableCredential.proof.cryptosuite).toBe('eddsa-rdfc-2022')
    })

    it('should handle validation errors', async () => {
      server.use(
        http.post('http://localhost:8000/v1/vc-api/credentials/issue', () => {
          return HttpResponse.json(
            {
              error: {
                code: 'VALIDATION_ERROR',
                message: 'Missing credential',
              },
            },
            { status: 400 }
          )
        })
      )

      await expect(issueCredential({ organization_id: 'org_123', credential_template_id: 'template_123', issuer_did: 'did:web:issuer.example', credential: {} })).rejects.toThrow()
    })
  })

  describe('verifyCredential', () => {
    it('should verify credential', async () => {
      const verifyRequest = {
        organization_id: 'org_123',
        presentation_policy_id: 'policy_456',
        verifiableCredential: 'header.payload.signature',
        options: { challenge: 'n', domain: 'aud' },
      }

      let receivedData: any
      let receivedUrl: URL
      server.use(
        http.post('http://localhost:8000/v1/vc-api/credentials/verify', async ({ request }) => {
          receivedUrl = new URL(request.url)
          receivedData = await request.json()
          return HttpResponse.json({
            verified: true,
            results: { decision: 'allow' },
          })
        })
      )

      const result = await verifyCredential(verifyRequest)

      expect(receivedUrl!.searchParams.get('organization_id')).toBe(verifyRequest.organization_id)
      expect(receivedUrl!.searchParams.get('presentation_policy_id')).toBe(verifyRequest.presentation_policy_id)
      expect(receivedData).toEqual({ verifiableCredential: verifyRequest.verifiableCredential, options: verifyRequest.options })
      expect(result.verified).toBe(true)
      expect(result.results.decision).toBe('allow')
    })

    it('should return validation failures', async () => {
      server.use(
        http.post('http://localhost:8000/v1/vc-api/credentials/verify', () => {
          return HttpResponse.json({
            verified: false,
            results: { decision: 'deny', errors: ['Invalid signature'] },
          })
        })
      )

      const result = await verifyCredential({ organization_id: 'org_123', presentation_policy_id: 'policy_456', verifiableCredential: 'invalid.jwt' })

      expect(result.verified).toBe(false)
      expect(result.results.errors).toContain('Invalid signature')
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
