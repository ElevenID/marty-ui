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
  })
})
