import { describe, expect, it, vi } from 'vitest'
import {
  buildApplicantProfileData,
  buildAutoApplyContext,
  buildStandardApplicationPayload,
  getCredentialKindFlags,
  getOneClickSummaryFields,
  groupFieldsIntoSteps,
  normalizeApplicationTemplateToFormConfig,
  normalizeCredentialConfigInput,
  normalizeTemplateToFormConfig,
  validateApplicationStep,
} from './applicationFlow'

describe('applicationFlow helpers', () => {
  const t = vi.fn((key: string) => key)

  it('normalizes credential configs from mixed field shapes', () => {
    expect(normalizeCredentialConfigInput({
      id: 'cfg-1',
      credentialType: 'ExampleCredential',
      name: 'Example',
      requiredFields: ['first_name'],
      optionalFields: ['email'],
      customFields: [{ name: 'custom_field' }],
    })).toEqual({
      id: 'cfg-1',
      credentialType: 'ExampleCredential',
      credential_type: 'ExampleCredential',
      name: 'Example',
      display_name: 'Example',
      requiredFields: ['first_name'],
      optionalFields: ['email'],
      customFields: [{ name: 'custom_field' }],
      required_fields: ['first_name'],
      optional_fields: ['email'],
      custom_fields: [{ name: 'custom_field' }],
      field_validation_rules: {},
    })
  })

  it('normalizes template responses into form config shape', () => {
    expect(normalizeTemplateToFormConfig({
      id: 'tpl-1',
      credential_type: 'ExampleCredential',
      name: 'Example',
      claims: [{ name: 'first_name', required: true }, { name: 'email', required: false }],
    })).toMatchObject({
      id: 'tpl-1',
      credential_type: 'ExampleCredential',
      display_name: 'Example',
      required_fields: ['first_name'],
      optional_fields: ['email'],
    })
  })

  it('merges application template form fields into the dynamic form config', () => {
    expect(normalizeApplicationTemplateToFormConfig({
      id: 'app-template-1',
      name: 'Canvas Quiz Application',
      description: 'Complete the course quiz.',
      credential_template_id: 'credential-template-1',
      form_fields: [
        { name: 'email', label: 'Email', type: 'email', required: true },
        { name: 'course_name', label: 'Canvas course', type: 'string', required: true },
        { name: 'score_percent', label: 'Score percent', type: 'integer', required: true },
      ],
      evidence_requirements: [{ evidence_type: 'canvas.quiz_score' }],
      ui_config: { submission_instructions: 'Review your course details.' },
    }, {
      id: 'credential-template-1',
      credential_type: 'open_badge',
      name: 'Quiz Badge',
      required_fields: ['email'],
      optional_fields: ['family_name'],
    })).toMatchObject({
      id: 'credential-template-1',
      credential_type: 'open_badge',
      display_name: 'Canvas Quiz Application',
      required_fields: [
        { name: 'email', label: 'Email', type: 'email', required: true },
        { name: 'course_name', label: 'Canvas course', type: 'text', required: true },
        { name: 'score_percent', label: 'Score percent', type: 'number', required: true },
      ],
      optional_fields: [
        { name: 'family_name', label: 'Family Name', type: 'text', required: false },
      ],
      submission_instructions: 'Review your course details.',
      evidence_requirements: [{ evidence_type: 'canvas.quiz_score' }],
    })
  })

  it('groups form fields into logical steps', () => {
    const steps = groupFieldsIntoSteps(['first_name', 'email'], ['street'], [{ name: 'portrait' }], t)
    expect(steps.map((step) => step.label)).toEqual([
      'applicationForm.steps.personalInfo',
      'applicationForm.steps.address',
      'applicationForm.steps.photos',
      'applicationForm.steps.review',
    ])
  })

  it('derives one-click credential flags', () => {
    expect(getCredentialKindFlags({ credential_type: 'MemberCredential' })).toEqual({
      isMemberCredential: true,
      isMdlCredential: false,
      isMdocMemberCredential: false,
      isOpenBadgeCredential: false,
      isAccessBadgeCredential: false,
      isOneClickCredential: true,
    })
  })

  it('builds applicant profile payloads including address information', () => {
    expect(buildApplicantProfileData({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com' },
      formData: {
        first_name: 'Ada',
        last_name: 'Lovelace',
        city: 'London',
      },
    })).toEqual({
      organization_id: 'org-1',
      user_id: 'user-1',
      given_name: 'Ada',
      family_name: 'Lovelace',
      email: 'user@example.com',
      date_of_birth: undefined,
      nationality: 'USA',
      address: {
        city: 'London',
        country: 'USA',
      },
    })
  })

  it('builds standard application payloads', () => {
    expect(buildStandardApplicationPayload({
      applicantId: 'app-1',
      credentialConfig: { id: 'cfg-1', credential_type: 'ExampleCredential', display_name: 'Example' },
      credentialConfigId: 'cfg-fallback',
      formData: { documentNumber: '1234' },
    })).toMatchObject({
      applicant_id: 'app-1',
      credential_configuration_id: 'cfg-1',
      issuing_authority: 'ElevenID LLC',
      requested_validity_years: 10,
      metadata: {
        document_number: '1234',
        credential_type: 'ExampleCredential',
        credential_display_name: 'Example',
      },
    })
  })

  it('marks Canvas LTI applications for demo auto-approval', () => {
    expect(buildStandardApplicationPayload({
      applicantId: 'app-1',
      credentialConfig: { id: 'cfg-1', credential_type: 'open_badge', display_name: 'Canvas Badge' },
      credentialConfigId: 'cfg-fallback',
      formData: {},
      canvasLtiContext: {
        state: 'state-1',
        canvas_account_id: 'canvas-real-account-1',
      },
    })).toMatchObject({
      applicant_id: 'app-1',
      credential_configuration_id: 'cfg-1',
      metadata: {
        credential_type: 'open_badge',
        credential_display_name: 'Canvas Badge',
        canvas_lti: {
          state: 'state-1',
          canvas_account_id: 'canvas-real-account-1',
        },
        auto_approve: true,
      },
    })
  })

  it('builds auto-apply context for mDL credentials', () => {
    const result = buildAutoApplyContext({
      credentialConfig: { credential_type: 'org.iso.18013.5.1.mDL', name: 'mDL' },
      user: { user_id: 'abcdef12', family_name: 'Doe', given_name: 'Jane' },
      organizationId: 'org-1',
      nowIso: '2026-03-16T10:00:00.000Z',
    })

    expect(result.requested_validity_years).toBe(5)
    expect(result.metadata.document_number).toBe('MDL-ABCDEF12')
  })

  it('builds auto-apply context for open badge membership credentials', () => {
    const result = buildAutoApplyContext({
      credentialConfig: { credential_type: 'open_badge', name: 'Verified Member Badge' },
      user: {
        user_id: 'abcdef12',
        family_name: 'Doe',
        given_name: 'Jane',
        email: 'jane@example.com',
        organization_name: 'Acme Org',
        roles: ['vendor'],
      },
      organizationId: 'org-1',
      nowIso: '2026-03-16T10:00:00.000Z',
    })

    expect(result).toMatchObject({
      requested_validity_years: 1,
      metadata: {
        credential_type: 'open_badge',
        credential_display_name: 'Verified Member Badge',
        member_id: 'abcdef12',
        email: 'jane@example.com',
        organization_id: 'org-1',
        organization_name: 'Acme Org',
        role: 'vendor',
        achievement_name: 'Verified Member Badge',
        achievement_description: 'Verifiable proof of active membership in the issuing organization.',
        issued_at: '2026-03-16T10:00:00.000Z',
        auto_approve: true,
      },
    })
  })

  it('builds one-click summary fields for member credentials', () => {
    expect(getOneClickSummaryFields({
      credentialConfig: { credential_type: 'MemberCredential' },
      user: { given_name: 'Jane', family_name: 'Doe', email: 'jane@example.com', roles: ['vendor'], organization_name: 'Acme' },
      organizationId: 'org-1',
    })).toEqual([
      { label: 'Name', value: 'Jane Doe' },
      { label: 'Email', value: 'jane@example.com' },
      { label: 'Role', value: 'Vendor' },
      { label: 'Organization', value: 'Acme' },
    ])
  })

  it('builds one-click summary fields for open badge membership credentials', () => {
    expect(getOneClickSummaryFields({
      credentialConfig: { credential_type: 'open_badge', name: 'Verified Member Badge' },
      user: { given_name: 'Jane', family_name: 'Doe', email: 'jane@example.com', roles: ['vendor'] },
      organizationId: 'org-1',
    })).toEqual([
      { label: 'Name', value: 'Jane Doe' },
      { label: 'Email', value: 'jane@example.com' },
      { label: 'Role', value: 'Vendor' },
      { label: 'Badge', value: 'Verified Member Badge' },
    ])
  })

  it('validates review step terms acceptance', () => {
    expect(validateApplicationStep({
      stepIndex: 1,
      steps: [{ label: 'step', fields: [] }, { label: 'review', fields: [] }],
      formData: { acceptTerms: false },
    })).toEqual({
      valid: false,
      errors: { acceptTerms: 'You must accept the terms' },
    })
  })

  it('validates required fields and rules', () => {
    expect(validateApplicationStep({
      stepIndex: 0,
      steps: [{ label: 'step', fields: [{ name: 'first_name', required: true }] }, { label: 'review', fields: [] }],
      formData: {},
      validationRules: {},
    })).toEqual({
      valid: false,
      errors: { first_name: 'first name is required' },
    })

    expect(validateApplicationStep({
      stepIndex: 0,
      steps: [{ label: 'step', fields: [{ name: 'code', required: false }] }, { label: 'review', fields: [] }],
      formData: { code: '12' },
      validationRules: { code: { min_length: 3 } },
    })).toEqual({
      valid: false,
      errors: { code: 'Minimum length is 3' },
    })
  })
})
