import { describe, expect, it } from 'vitest'

import {
  buildCredentialTemplatePayload,
  normalizeCredentialTemplate,
} from '../presentationPolicyApi'

describe('credential template normalization', () => {
  it('normalizes canonical protocol response fields for UI consumers', () => {
    const template = normalizeCredentialTemplate({
      id: 'ct-1',
      organization_id: 'org-1',
      name: 'Canonical Template',
      status: 'ACTIVE',
      credential_type: 'EmployeeBadge',
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
    expect(template.createdAt).toBe('2024-01-01T00:00:00Z')
    expect(template.updatedAt).toBe('2024-01-02T00:00:00Z')
  })

  it('builds backend-compatible payloads from canonical validity fields', () => {
    const payload = buildCredentialTemplatePayload({
      organization_id: 'org-1',
      name: 'Canonical Payload',
      credential_type: 'EmployeeBadge',
      issuer_profile_id: 'ip-1',
      vct: 'com.example.employee',
      claims: [
        { name: 'given_name', type: 'string', required: true },
        { name: 'score', type: 'number', display_name: 'Score', required: false },
      ],
      validity_rules: {
        ttl_seconds: 14 * 86400,
        renewable: false,
        reissue_within_seconds: 3 * 86400,
        not_before_offset: 900,
      },
    })

    expect(payload.validity_rules).toEqual({
      default_validity_days: 14,
      max_validity_days: undefined,
      renewable: false,
      renewal_window_days: 3,
      not_before_offset_seconds: 900,
    })
    expect(payload.vct).toBe('https://credentials.elevenidllc.com/vct/com.example.employee')
    expect(payload.issuer_profile_id).toBe('ip-1')
    expect(payload.compliance_profile).toEqual({
      compliance_code: 'CUSTOM',
      credential_format: 'sd_jwt_vc',
    })
    expect(payload.claims).toEqual([
      {
        name: 'given_name',
        display_name: 'Given Name',
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
    expect(payload.claims[0]).not.toHaveProperty('type')
  })

  it('preserves explicit compliance and absolute VCT values', () => {
    const payload = buildCredentialTemplatePayload({
      organization_id: 'org-1',
      name: 'EUDI Payload',
      credential_type: 'PersonIdentificationData',
      issuer_profile_id: 'ip-1',
      vct: 'https://credentials.example.com/pid',
      compliance_profile: { compliance_code: 'EUDI_PID', credential_format: 'sd_jwt_vc' },
      claims: [{ name: 'given_name', claim_type: 'string', display_name: 'Given Name' }],
    })

    expect(payload.vct).toBe('https://credentials.example.com/pid')
    expect(payload.compliance_profile).toEqual({
      compliance_code: 'EUDI_PID',
      credential_format: 'sd_jwt_vc',
    })
  })

  it('rejects payloads without an active issuer profile id', () => {
    expect(() => buildCredentialTemplatePayload({
      organization_id: 'org-1',
      name: 'Missing Issuer',
      credential_type: 'EmployeeBadge',
    })).toThrow('active issuer profile')
  })
})
