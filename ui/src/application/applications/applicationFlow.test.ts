import { describe, expect, it, vi } from 'vitest'
import {
  buildApplicantProfileData,
  buildAutoApplyFormData,
  canAutoApplyApplicationTemplate,
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
      application_template_id: 'app-template-1',
      credential_type: 'ExampleCredential',
      name: 'Example',
      claims: [{ name: 'first_name', required: true }, { name: 'email', required: false }],
    })).toMatchObject({
      id: 'tpl-1',
      credential_type: 'ExampleCredential',
      display_name: 'Example',
      required_fields: [expect.objectContaining({ name: 'first_name', required: true })],
      optional_fields: [expect.objectContaining({ name: 'email', required: false })],
      application_template_id: 'app-template-1',
    })
  })

  it('merges application template form fields into the dynamic form config', () => {
    expect(normalizeApplicationTemplateToFormConfig({
      id: 'app-template-1',
      name: 'Canvas Quiz Application',
      description: 'Complete the course quiz.',
      credential_template_id: 'credential-template-1',
      form_fields: [
        { field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true },
        { field_id: 'course_name', label: 'Canvas course', field_type: 'TEXT', required: true },
        { field_id: 'score_percent', label: 'Score percent', field_type: 'INTEGER', required: true },
      ],
      evidence_requirements: [{
        evidence_id: 'canvas_quiz_score',
        evidence_type: 'EXTERNAL_FACT',
        description: 'Verified Canvas quiz score',
        required: true,
      }],
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
          { name: 'score_percent', label: 'Score percent', type: 'integer', required: true },
      ],
      optional_fields: [
        { name: 'family_name', label: 'Family Name', type: 'text', required: false },
      ],
      submission_instructions: 'Review your course details.',
      evidence_requirements: [expect.objectContaining({ evidence_id: 'canvas_quiz_score', evidence_type: 'EXTERNAL_FACT' })],
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

  it('builds applicant profile payloads without caller-controlled identity fields', () => {
    expect(buildApplicantProfileData({
      user: { user_id: 'user-1', email: 'user@example.com' },
      formData: {
        first_name: 'Ada',
        last_name: 'Lovelace',
        city: 'London',
      },
    })).toEqual({
      given_name: 'Ada',
      family_name: 'Lovelace',
      email: 'user@example.com',
    })
  })

  it('builds standard application payloads', () => {
    expect(buildStandardApplicationPayload({
      organizationId: 'org-1',
      credentialConfig: { id: 'cfg-1', application_template_id: 'app-template-1' },
      formData: { documentNumber: '1234' },
    })).toEqual({
      organization_id: 'org-1',
      application_template_id: 'app-template-1',
      form_data: { documentNumber: '1234' },
      integration_context: {},
    })
  })

  it('marks Canvas LTI applications for demo auto-approval', () => {
    expect(buildStandardApplicationPayload({
      organizationId: 'org-1',
      credentialConfig: { id: 'cfg-1', application_template_id: 'app-template-1' },
      formData: {},
      canvasLtiContext: {
        state: 'state-1',
        canvas_account_id: 'canvas-real-account-1',
      },
    })).toEqual({
      organization_id: 'org-1',
      application_template_id: 'app-template-1',
      form_data: {},
      integration_context: {
        canvas_lti: {
          state: 'state-1',
          canvas_account_id: 'canvas-real-account-1',
        },
      },
    })
  })

  it('builds auto-apply form data only from canonical template fields', () => {
    const applicationTemplate = {
      id: 'application-template-1',
      form_fields: [
        { field_id: 'given_name', label: 'Given name', field_type: 'TEXT', required: true },
        { field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true },
      ],
    }
    const result = buildAutoApplyFormData({
      applicationTemplate,
      user: {
        user_id: 'abcdef12',
        family_name: 'Doe',
        given_name: 'Jane',
        email: 'jane@example.com',
      },
    })

    expect(result).toEqual({ given_name: 'Jane', email: 'jane@example.com' })
    expect(canAutoApplyApplicationTemplate({ applicationTemplate, user: { given_name: 'Jane' } })).toBe(false)
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

  it('validates typed template fields before submission', () => {
    const result = validateApplicationStep({
      stepIndex: 0,
      steps: [{ label: 'step', fields: [
        { name: 'birth_date', type: 'date' },
        { name: 'score', type: 'integer', minimum: 1, maximum: 10 },
        { name: 'consent', type: 'boolean' },
        { name: 'level', type: 'select', enum: ['basic', 'advanced'] },
        { name: 'code', type: 'text', pattern: '[A-Z]{3}' },
      ] }, { label: 'review', fields: [] }],
      formData: {
        birth_date: '03/12/2026',
        score: 1.5,
        consent: 'yes',
        level: 'unknown',
        code: 'ab',
      },
    })

    expect(result).toEqual({
      valid: false,
      errors: {
        birth_date: 'Use a date in YYYY-MM-DD format',
        score: 'Enter a whole number',
        consent: 'Choose true or false',
        level: 'Choose one of the allowed values',
        code: 'Invalid format',
      },
    })
  })
})
