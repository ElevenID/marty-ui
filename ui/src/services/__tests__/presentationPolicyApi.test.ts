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
  activateCredentialTemplate,
  listCredentialTemplates,
  getCredentialTemplate,
  activateTrustProfile,
  createTrustProfile,
  synchronizeTrustProfileRegistries,
  listTrustProfiles,
  addTrustProfileIssuer,
  listTrustProfileIssuers,
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
        organization_id: 'org-1',
        name: 'Age Verification',
        description: 'Verify age over 21',
        purpose: 'Verify employee eligibility',
        accepted_credential_types: ['EmployeeBadge'],
        required_claims: [
          {
            claim_name: 'age',
            credential_type: 'EmployeeBadge',
            required_value: 21,
            accept_predicate: true,
          },
        ],
        holder_binding: 'device_key',
        freshness_requirements: {
          max_credential_age_seconds: 86400,
          require_revocation_check: true,
        },
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

      expect(receivedData).toMatchObject({
        organization_id: 'org-1',
        name: 'Age Verification',
        description: 'Verify age over 21',
        purpose: 'Verify employee eligibility',
        accepted_credential_types: ['EmployeeBadge'],
        required_claims: [
          {
            claim_name: 'age',
            credential_type: 'EmployeeBadge',
            value_constraint: 21,
            predicate_spec: null,
          },
        ],
        holder_binding: {
          required: true,
          binding_methods: ['DEVICE_KEY'],
          proof_profiles: ['OID4VP_VERIFIABLE_PRESENTATION', 'MDOC_DEVICE_AUTHENTICATION'],
          proof_freshness: {
            challenge_required: true,
            audience_binding_required: true,
            replay_detection_required: true,
          },
        },
        freshness: {
          max_age_seconds: 86400,
          require_not_revoked: true,
        },
      })
      expect(result.name).toBe(newPolicy.name)
    })

    it('activates a newly-created presentation policy when requested', async () => {
      let activatedPolicyId: string | undefined
      server.use(
        http.post('http://localhost:8000/v1/presentation-policies', async ({ request }) => {
          const body = await request.json() as any
          return HttpResponse.json({
            ...mockPolicies.valid,
            id: 'policy-activate',
            organization_id: body.organization_id,
            name: body.name,
            status: 'DRAFT',
          })
        }),
        http.post('http://localhost:8000/v1/presentation-policies/:id/activate', ({ params }) => {
          activatedPolicyId = params.id as string
          return HttpResponse.json({
            ...mockPolicies.valid,
            id: params.id,
            organization_id: 'org-1',
            status: 'ACTIVE',
          })
        }),
      )

      const result = await createPresentationPolicy({
        organization_id: 'org-1',
        name: 'Active Policy',
        required_claims: [{ claim_name: 'employee_id' }],
        activate_immediately: true,
      })

      expect(activatedPolicyId).toBe('policy-activate')
      expect(result.status).toBe('active')
    })

    it('retries presentation policy creation once with the same idempotency key after an aborted response', async () => {
      let activatedPolicyId: string | undefined
      const idempotencyKeys: string[] = []
      let createAttempts = 0
      server.use(
        http.post('http://localhost:8000/v1/presentation-policies', async ({ request }) => {
          idempotencyKeys.push(String(request.headers.get('Idempotency-Key')))
          createAttempts += 1
          if (createAttempts === 1) {
            return HttpResponse.error()
          }
          const body = await request.json() as any
          return HttpResponse.json({
            ...mockPolicies.valid,
            id: 'policy-create-retried',
            organization_id: body.organization_id,
            name: body.name,
            status: 'draft',
            required_claims: body.required_claims,
          })
        }),
        http.post('http://localhost:8000/v1/presentation-policies/:id/activate', ({ params }) => {
          activatedPolicyId = params.id as string
          return HttpResponse.json({
            ...mockPolicies.valid,
            id: params.id,
            organization_id: 'org-1',
            name: 'Recovered Policy',
            status: 'active',
          })
        }),
      )

      const result = await createPresentationPolicy({
        organization_id: 'org-1',
        name: 'Recovered Policy',
        required_claims: [{ claim_name: 'employee_id' }],
        activate_immediately: true,
      })

      expect(createAttempts).toBe(2)
      expect(idempotencyKeys[0]).toBe(idempotencyKeys[1])
      expect(activatedPolicyId).toBe('policy-create-retried')
      expect(result.id).toBe('policy-create-retried')
      expect(result.status).toBe('active')
    })

    it('should list policies', async () => {
      const policies = await listPresentationPolicies({ organization_id: 'org-1' })

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
      const updates = { organization_id: 'org-1', name: 'Updated Policy Name' }

      let receivedData: any
      server.use(
        http.patch('http://localhost:8000/v1/presentation-policies/:id', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({ ...mockPolicies.valid, ...receivedData })
        })
      )

      const result = await updatePresentationPolicy(1, updates)

      expect(receivedData).toMatchObject({
        organization_id: 'org-1',
        name: 'Updated Policy Name',
        required_claims: [],
        accepted_credential_types: [],
      })
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

      await expect(createPresentationPolicy({
        organization_id: 'org-1',
        name: 'Bad Policy',
        required_claims: [{ claim_name: 'employee_id' }],
      })).rejects.toThrow()
    })
  })

  describe('Credential Templates', () => {
    it('should create template with correct shape', async () => {
      const newTemplate = {
        organization_id: 'org-1',
        name: 'mDL Template',
        doctype: 'org.iso.18013.5.1.mDL',
        namespace: 'org.iso.18013.5.1',
        issuer_did: 'did:web:issuer.example.com',
        issuer_profile_id: 'ip-1',
        compliance_profile_id: 'compliance-1',
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
      expect(receivedData.organization_id).toBe('org-1')
      expect(receivedData.issuer_did).toBe('did:web:issuer.example.com')
      expect(receivedData).not.toHaveProperty('issuer_profile_id')
      expect(result.doctype).toBe(newTemplate.doctype)
    })

    it('fails locally instead of creating a credential template without an issuer DID', async () => {
      let requested = false
      server.use(
        http.post('http://localhost:8000/v1/credential-templates', () => {
          requested = true
          return HttpResponse.json({})
        })
      )

      await expect(createCredentialTemplate({
        organization_id: 'org-1',
        name: 'Missing Issuer DID',
        credential_type: 'EmployeeBadge',
      })).rejects.toMatchObject({
        code: 'ISSUER_DID_REQUIRED',
        status: 400,
      })
      expect(requested).toBe(false)
    })

    it('normalizes wizard claims before creating a template', async () => {
      let receivedData: any
      server.use(
        http.post('http://localhost:8000/v1/credential-templates', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json(
            {
              ...mockTemplates.valid,
              id: 'ct-claims',
              organization_id: receivedData.organization_id,
              name: receivedData.name,
              credential_type: receivedData.credential_type,
              claims: receivedData.claims,
              validity_rules: {},
            },
            { status: 201 }
          )
        })
      )

      await createCredentialTemplate({
        organization_id: 'org-1',
        name: 'Wizard Payload',
        credential_type: 'EmployeeBadge',
        issuer_did: 'did:web:issuer.example.com',
        issuer_profile_id: 'ip-1',
        compliance_profile_id: 'compliance-1',
        vct: 'com.example.employee',
        claims: [
          { name: 'employee_id', type: 'string', required: true },
          { name: 'score', type: 'number', required: false },
        ],
      })

      expect(receivedData.organization_id).toBe('org-1')
      expect(receivedData.claims).toEqual([
        {
          name: 'employee_id',
          display_name: 'Employee Id',
          claim_type: 'string',
          required: true,
          selectively_disclosable: true,
        },
        {
          name: 'score',
          display_name: 'Score',
          claim_type: 'integer',
          required: false,
          selectively_disclosable: true,
        },
      ])
      expect(receivedData.claims[0]).not.toHaveProperty('type')
      expect(receivedData.vct).toBe(`${window.location.origin}/vct/com.example.employee`)
      expect(receivedData.compliance_profile_id).toBe('compliance-1')
      expect(receivedData).not.toHaveProperty('compliance_profile')
    })

    it('activates a newly-created template when requested', async () => {
      let activatedTemplateId: string | undefined
      server.use(
        http.post('http://localhost:8000/v1/credential-templates', async ({ request }) => {
          const body = (await request.json()) as any
          return HttpResponse.json({
            ...mockTemplates.valid,
            id: 'ct-activate',
            organization_id: body.organization_id,
            name: body.name,
            credential_type: body.credential_type,
            claims: body.claims,
            status: 'DRAFT',
            validity_rules: {},
          })
        }),
        http.post('http://localhost:8000/v1/credential-templates/:id/activate', ({ params }) => {
          activatedTemplateId = params.id as string
          return HttpResponse.json({
            ...mockTemplates.valid,
            id: params.id,
            organization_id: 'org-1',
            status: 'ACTIVE',
            claims: [],
            validity_rules: {},
          })
        })
      )

      const result = await createCredentialTemplate({
        organization_id: 'org-1',
        name: 'Active Template',
        credential_type: 'EmployeeBadge',
        issuer_did: 'did:web:issuer.example.com',
        issuer_profile_id: 'ip-1',
        compliance_profile_id: 'compliance-1',
        vct: 'com.example.employee',
        activate_immediately: true,
        claims: [{ name: 'employee_id', type: 'string', required: true }],
      })

      expect(activatedTemplateId).toBe('ct-activate')
      expect(result.status).toBe('active')
    })

    it('recovers when template activation is applied but the activation response is aborted', async () => {
      server.use(
        http.post('http://localhost:8000/v1/credential-templates', async ({ request }) => {
          const body = (await request.json()) as any
          return HttpResponse.json({
            ...mockTemplates.valid,
            id: 'ct-activation-aborted',
            organization_id: body.organization_id,
            name: body.name,
            credential_type: body.credential_type,
            claims: body.claims,
            status: 'DRAFT',
            validity_rules: {},
          })
        }),
        http.post('http://localhost:8000/v1/credential-templates/:id/activate', () => {
          return HttpResponse.error()
        }),
        http.get('http://localhost:8000/v1/credential-templates/:id', ({ params }) => {
          return HttpResponse.json({
            ...mockTemplates.valid,
            id: params.id,
            organization_id: 'org-1',
            status: 'ACTIVE',
            claims: [],
            validity_rules: {},
          })
        })
      )

      const result = await createCredentialTemplate({
        organization_id: 'org-1',
        name: 'Active Template',
        credential_type: 'EmployeeBadge',
        issuer_did: 'did:web:issuer.example.com',
        issuer_profile_id: 'ip-1',
        compliance_profile_id: 'compliance-1',
        vct: 'com.example.employee',
        activate_immediately: true,
        claims: [{ name: 'employee_id', type: 'string', required: true }],
      })

      expect(result.id).toBe('ct-activation-aborted')
      expect(result.status).toBe('active')
    })

    it('retries template creation once with the same idempotency key after an aborted response', async () => {
      let activatedTemplateId: string | undefined
      const idempotencyKeys: string[] = []
      let createAttempts = 0
      server.use(
        http.post('http://localhost:8000/v1/credential-templates', async ({ request }) => {
          idempotencyKeys.push(String(request.headers.get('Idempotency-Key')))
          createAttempts += 1
          if (createAttempts === 1) {
            return HttpResponse.error()
          }
          const body = await request.json() as any
          return HttpResponse.json({
            ...mockTemplates.valid,
            id: 'ct-create-retried',
            organization_id: body.organization_id,
            name: body.name,
            status: 'DRAFT',
            vct: body.vct,
            claims: body.claims,
            validity_rules: {},
          })
        }),
        http.post('http://localhost:8000/v1/credential-templates/:id/activate', ({ params }) => {
          activatedTemplateId = params.id as string
          return HttpResponse.json({
            ...mockTemplates.valid,
            id: params.id,
            organization_id: 'org-1',
            name: 'Recovered Created Template',
            status: 'ACTIVE',
            claims: [],
            validity_rules: {},
          })
        })
      )

      const result = await createCredentialTemplate({
        organization_id: 'org-1',
        name: 'Recovered Created Template',
        credential_type: 'EmployeeBadge',
        issuer_did: 'did:web:issuer.example.com',
        issuer_profile_id: 'ip-1',
        compliance_profile_id: 'compliance-1',
        vct: 'com.example.recovered',
        activate_immediately: true,
        claims: [{ name: 'employee_id', type: 'string', required: true }],
      })

      expect(createAttempts).toBe(2)
      expect(idempotencyKeys[0]).toBe(idempotencyKeys[1])
      expect(activatedTemplateId).toBe('ct-create-retried')
      expect(result.id).toBe('ct-create-retried')
      expect(result.status).toBe('active')
    })

    it('activates an existing template through the template activation endpoint', async () => {
      let activatedTemplateId: string | undefined
      server.use(
        http.post('http://localhost:8000/v1/credential-templates/:id/activate', ({ params }) => {
          activatedTemplateId = params.id as string
          return HttpResponse.json({
            ...mockTemplates.valid,
            id: params.id,
            organization_id: 'org-1',
            status: 'ACTIVE',
            claims: [],
            validity_rules: {},
          })
        })
      )

      const result = await activateCredentialTemplate('ct-existing')

      expect(activatedTemplateId).toBe('ct-existing')
      expect(result.status).toBe('active')
    })

    it('recovers when trust profile activation is applied but the activation response is aborted', async () => {
      server.use(
        http.post('http://localhost:8000/v1/trust-profiles/:id/activate', () => {
          return HttpResponse.error()
        }),
        http.get('http://localhost:8000/v1/trust-profiles/:id', ({ params }) => {
          return HttpResponse.json({
            id: params.id,
            organization_id: 'org-1',
            name: 'Recovered Trust Profile',
            status: 'ACTIVE',
            trust_sources: [],
            validation_rules: {},
          })
        })
      )

      const result = await activateTrustProfile('trust-activation-aborted')

      expect(result.id).toBe('trust-activation-aborted')
      expect(result.status).toBe('active')
    })

    it('retries trust profile creation once with the same idempotency key after an aborted response', async () => {
      const idempotencyKeys: string[] = []
      let createAttempts = 0
      server.use(
        http.post('http://localhost:8000/v1/trust-profiles', async ({ request }) => {
          idempotencyKeys.push(String(request.headers.get('Idempotency-Key')))
          createAttempts += 1
          if (createAttempts === 1) {
            return HttpResponse.error()
          }
          const body = await request.json() as any
          return HttpResponse.json({
            id: 'trust-create-retried',
            organization_id: 'org-1',
            name: body.name,
            status: 'DRAFT',
            trust_sources: [],
            validation_rules: {},
          })
        })
      )

      const result = await createTrustProfile({
        organization_id: 'org-1',
        name: 'Recovered Trust Profile',
        status: 'draft',
      })

      expect(createAttempts).toBe(2)
      expect(idempotencyKeys[0]).toBe(idempotencyKeys[1])
      expect(result.id).toBe('trust-create-retried')
      expect(result.status).toBe('draft')
    })

    it('should list templates', async () => {
      const templates = await listCredentialTemplates({ organization_id: 'org-1' })

      expect(Array.isArray(templates)).toBe(true)
      expect(templates[0]).toHaveProperty('id')
      expect(templates[0]).toHaveProperty('doctype')
    })

    it('fails locally instead of listing templates without an active organization', async () => {
      await expect(listCredentialTemplates()).rejects.toMatchObject({
        code: 'ORG_REQUIRED',
        status: 400,
      })
    })

    it('should pass query params', async () => {
      let queryParams: URLSearchParams | undefined
      server.use(
        http.get('http://localhost:8000/v1/credential-templates', ({ request }) => {
          queryParams = new URL(request.url).searchParams
          return HttpResponse.json([mockTemplates.valid])
        })
      )

      await listCredentialTemplates({ organization_id: 'org-1', status: 'active' })

      expect(queryParams?.toString()).toContain('status=active')
    })

    it('should normalize credential template responses for UI consumers', async () => {
      server.use(
        http.get('http://localhost:8000/v1/credential-templates/:id', () => {
          return HttpResponse.json({
            id: 'ct-1',
            organization_id: 'org-1',
            name: 'Canonical Template',
            status: 'ACTIVE',
            credential_type: 'EmployeeBadge',
            compliance_profile_id: '123e4567-e89b-12d3-a456-426614174000',
            claims: [
              {
                name: 'given_name',
                type: 'STRING',
                required: true,
                display: { label: 'Given Name' },
              },
            ],
            validity_rules: {
              ttl_seconds: 30 * 86400,
              renewable: true,
              reissue_within_seconds: 7 * 86400,
              not_before_offset_seconds: 300,
            },
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-02T00:00:00Z',
          })
        })
      )

      const template = await getCredentialTemplate('ct-1')

      expect(template.status).toBe('active')
      expect(template.claims[0].display_name).toBe('Given Name')
      expect(template.validity_rules).toMatchObject({
        ttl_seconds: 30 * 86400,
        default_validity_days: 30,
        reissue_within_seconds: 7 * 86400,
        renewal_window_days: 7,
        not_before_offset_seconds: 300,
        not_before_offset: 300,
      })
    })

    it('should build credential template payloads from canonical validity fields', async () => {
      let receivedData: any
      server.use(
        http.post('http://localhost:8000/v1/credential-templates', async ({ request }) => {
          receivedData = await request.json()
          return HttpResponse.json({
            id: 'ct-2',
            organization_id: 'org-1',
            name: 'Canonical Payload',
            status: 'DRAFT',
            credential_type: 'EmployeeBadge',
            compliance_profile_id: '123e4567-e89b-12d3-a456-426614174000',
            claims: [],
            validity_rules: {
              ttl_seconds: 14 * 86400,
              renewable: false,
              reissue_within_seconds: 3 * 86400,
              not_before_offset_seconds: 900,
            },
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          })
        })
      )

      await createCredentialTemplate({
        organization_id: 'org-1',
        name: 'Canonical Payload',
        credential_type: 'EmployeeBadge',
        issuer_did: 'did:web:issuer.example.com',
        issuer_profile_id: 'ip-1',
        compliance_profile_id: '123e4567-e89b-12d3-a456-426614174000',
        supported_wallet_ids: ['removed-wallet-selection'],
        issuance_protocol: 'oid4vci',
        wallet_configs: [{ wallet_id: 'removed-wallet-config' }],
        claims: [],
        validity_rules: {
          ttl_seconds: 14 * 86400,
          renewable: false,
          reissue_within_seconds: 3 * 86400,
          not_before_offset: 900,
        },
      })

      expect(receivedData.validity_rules).toMatchObject({
        default_validity_days: 14,
        renewable: false,
        renewal_window_days: 3,
        not_before_offset_seconds: 900,
      })
      expect(receivedData).not.toHaveProperty('supported_wallet_ids')
      expect(receivedData).not.toHaveProperty('issuance_protocol')
      expect(receivedData).not.toHaveProperty('wallet_configs')
    })

    it('should normalize listed credential templates', async () => {
      server.use(
        http.get('http://localhost:8000/v1/credential-templates', () => {
          return HttpResponse.json([
            {
              id: 'ct-3',
              organization_id: 'org-1',
              name: 'Listed Template',
              status: 'ACTIVE',
              credential_type: 'EmployeeBadge',
              compliance_profile_id: '123e4567-e89b-12d3-a456-426614174000',
              claims: [],
              validity_rules: { ttl_seconds: 86400 },
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          ])
        })
      )

      const templates = await listCredentialTemplates({ organization_id: 'org-1' })

      expect(templates[0].status).toBe('active')
      expect(templates[0].validity_rules.default_validity_days).toBe(1)
    })
  })

  describe('Trust Profiles', () => {
    it('creates only the public trust-profile contract and preserves registry sync configuration', async () => {
      let requestBody: any
      server.use(
        http.post('http://localhost:8000/v1/trust-profiles', async ({ request }) => {
          requestBody = await request.json()
          return HttpResponse.json({
            id: 'trust-profile-1',
            status: 'DRAFT',
            ...requestBody,
          })
        })
      )
      const newProfile = {
        organization_id: 'org-1',
        name: 'Production Trust',
        status: 'active',
        registry_imports: [{ registry_type: 'EU_TRUST_LIST' }],
        supported_wallet_ids: ['ui-only-wallet'],
        trust_sources: [{
          source_type: 'TRUST_LIST',
          url: 'https://registry.example/sync',
          registry_sync: {
            protocol: 'MARTY_TRUST_REGISTRY_SYNC_V1',
            refresh_interval_hours: 24,
          },
          metadata: { ui_only: true },
        }],
      }

      const result = await createTrustProfile(newProfile)

      expect(result.name).toBeDefined()
      expect(result).toHaveProperty('id')
      expect(requestBody).not.toHaveProperty('status')
      expect(requestBody).not.toHaveProperty('registry_imports')
      expect(requestBody).not.toHaveProperty('supported_wallet_ids')
      expect(requestBody.trust_sources).toEqual([{
        source_type: 'TRUST_LIST',
        url: 'https://registry.example/sync',
        registry_sync: {
          protocol: 'MARTY_TRUST_REGISTRY_SYNC_V1',
          refresh_interval_hours: 24,
        },
      }])
    })

    it('synchronizes registries through the trust-profile production API', async () => {
      let synchronizedId: string | undefined
      server.use(
        http.post('http://localhost:8000/v1/trust-profiles/:id/registry-sync', ({ params }) => {
          synchronizedId = params.id as string
          return HttpResponse.json({
            trust_profile_id: params.id,
            sources: [{
              url: 'https://registry.example/sync',
              protocol: 'MARTY_TRUST_REGISTRY_SYNC_V1',
              sequence: 2,
              csca_entries: 1,
              dsc_entries: 0,
              synchronized_at: '2026-08-07T12:00:00Z',
            }],
            synchronized_at: '2026-08-07T12:00:00Z',
          })
        })
      )

      const result = await synchronizeTrustProfileRegistries('trust-profile-1')

      expect(synchronizedId).toBe('trust-profile-1')
      expect(result.sources[0].sequence).toBe(2)
    })

    it('fails locally instead of creating trust profiles without an active organization', async () => {
      let requested = false
      server.use(
        http.post('http://localhost:8000/v1/trust-profiles', () => {
          requested = true
          return HttpResponse.json({ id: 'unexpected' })
        })
      )

      await expect(createTrustProfile({
        name: 'Missing Org Trust',
      })).rejects.toMatchObject({
        code: 'ORG_REQUIRED',
        status: 400,
      })

      expect(requested).toBe(false)
    })

    it('should activate trust profile with the service activation route', async () => {
      let activatedId: string | undefined
      server.use(
        http.post('http://localhost:8000/v1/trust-profiles/:id/activate', ({ params }) => {
          activatedId = params.id as string
          return HttpResponse.json({
            id: params.id,
            name: 'Production Trust',
            status: 'ACTIVE',
          })
        })
      )

      const result = await activateTrustProfile('trust-profile-1')

      expect(activatedId).toBe('trust-profile-1')
      expect(result.status).toBe('active')
    })

    it('should list trust profiles', async () => {
      const profiles = await listTrustProfiles({ organization_id: 'org-1' })

      expect(Array.isArray(profiles)).toBe(true)
      expect(profiles[0]).toHaveProperty('id')
      expect(profiles[0]).toHaveProperty('status')
    })

    it('should validate response structure', async () => {
      const profile = await listTrustProfiles({ organization_id: 'org-1' }).then((list: any[]) => list[0])

      // Validate expected fields exist
      expect(profile).toHaveProperty('id')
      expect(profile).toHaveProperty('name')
      expect(profile).toHaveProperty('status')
      expect(profile).toHaveProperty('trust_list_url')
    })

    it('composes trust-profile issuer relationships with organization-scoped issuer entities', async () => {
      server.use(
        http.get('http://localhost:8000/v1/issuer-entities', ({ request }) => {
          expect(new URL(request.url).searchParams.get('organization_id')).toBe('org-1')
          return HttpResponse.json([{
            id: '10000000-0000-4000-8000-000000000001',
            organization_id: 'org-1',
            issuer_id: 'did:web:issuer.example.com',
            issuer_type: 'ORGANIZATION',
            display_name: 'Example Issuer',
            description: 'Resolved issuer identity',
            compliance_status: 'COMPLIANT',
            accreditation_body: 'National Identity Authority',
            accreditations: ['ISO27001', 'FIPS140-2'],
            metadata: { issuer_url: 'https://issuer.example.com' },
          }])
        }),
        http.get('http://localhost:8000/v1/trust-profiles/:id/issuers', () => HttpResponse.json([{
          id: '20000000-0000-4000-8000-000000000001',
          trust_profile_id: '30000000-0000-4000-8000-000000000001',
          issuer_id: '10000000-0000-4000-8000-000000000001',
          trust_level: 100,
          relationship_status: 'TRUSTED',
          cascade_revocation_policy: 'NOTIFY_ONLY',
          metadata: { credential_template_ids: [] },
        }])),
      )

      const issuers = await listTrustProfileIssuers(
        '30000000-0000-4000-8000-000000000001',
        'org-1',
      )

      expect(issuers).toHaveLength(1)
      expect(issuers[0]).toMatchObject({
        issuer_id: '10000000-0000-4000-8000-000000000001',
        issuer_did: 'did:web:issuer.example.com',
        did: 'did:web:issuer.example.com',
        name: 'Example Issuer',
        accreditation_body: 'National Identity Authority',
        accreditations: ['ISO27001', 'FIPS140-2'],
      })
    })

    it('creates an issuer entity and links only its public relationship fields', async () => {
      let entityPayload: any
      let relationshipPayload: any
      server.use(
        http.get('http://localhost:8000/v1/issuer-entities', () => HttpResponse.json([])),
        http.post('http://localhost:8000/v1/issuer-entities', async ({ request }) => {
          entityPayload = await request.json()
          return HttpResponse.json({
            id: '10000000-0000-4000-8000-000000000002',
            compliance_status: 'PENDING',
            ...entityPayload,
          }, { status: 201 })
        }),
        http.post('http://localhost:8000/v1/trust-profiles/:id/issuers', async ({ request }) => {
          relationshipPayload = await request.json()
          return HttpResponse.json({
            id: '20000000-0000-4000-8000-000000000002',
            trust_profile_id: '30000000-0000-4000-8000-000000000002',
            ...relationshipPayload,
          }, { status: 201 })
        }),
      )

      await addTrustProfileIssuer(
        '30000000-0000-4000-8000-000000000002',
        'org-1',
        {
          issuer_did: 'did:web:new.example.com',
          name: 'New Issuer',
          accreditation_body: 'National Identity Authority',
          accreditations: ['ISO27001', 'FIPS140-2'],
          issuer_profile_id: 'must-not-cross-the-public-boundary',
          signing_service_id: 'must-not-cross-the-public-boundary',
          signing_key_reference: 'must-not-cross-the-public-boundary',
          kms_provider: 'must-not-cross-the-public-boundary',
          verification_keys: [{ kty: 'EC', d: 'private-key-material' }],
        },
      )

      expect(entityPayload).toEqual({
        organization_id: 'org-1',
        issuer_id: 'did:web:new.example.com',
        issuer_type: 'ORGANIZATION',
        display_name: 'New Issuer',
        description: null,
        accreditation_body: 'National Identity Authority',
        accreditations: ['ISO27001', 'FIPS140-2'],
        metadata: {},
      })
      expect(relationshipPayload).toEqual({
        issuer_id: '10000000-0000-4000-8000-000000000002',
        trust_level: 100,
        relationship_status: 'TRUSTED',
        cascade_revocation_policy: 'NOTIFY_ONLY',
        metadata: { credential_template_ids: [] },
      })
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

      await createPresentationPolicy({ organization_id: 'org-1', name: 'Test' })

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

      await updatePresentationPolicy(1, { organization_id: 'org-1', name: 'Updated' })

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
