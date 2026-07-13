import { describe, expect, it, vi } from 'vitest';

import {
  autoApplyForCredential,
  ensureApplicantProfileForApplication,
  findActiveApplicationForCredential,
  loadCredentialApplicationConfig,
  resolveApplicantIdForApplication,
  submitCredentialApplication,
} from './applicationFormUseCases';

describe('applicationForm use cases', () => {
  it('loads and normalizes credential config', async () => {
    await expect(loadCredentialApplicationConfig({
      credentialConfigId: 'tpl-1',
      credentialConfig: null,
      organizationId: 'org-1',
      getCredentialTemplate: vi.fn().mockResolvedValue({
        id: 'tpl-1',
        credential_type: 'ExampleCredential',
        name: 'Example',
        claims: [{ name: 'first_name', required: true }],
      }),
    })).resolves.toMatchObject({
      credentialConfig: {
        id: 'tpl-1',
        credential_type: 'ExampleCredential',
        display_name: 'Example',
        required_fields: [expect.objectContaining({ name: 'first_name', required: true })],
      },
      error: null,
    });

    await expect(loadCredentialApplicationConfig({
      credentialConfigId: 'tpl-1',
      credentialConfig: null,
      organizationId: null,
      getCredentialTemplate: vi.fn(),
    })).resolves.toEqual({
      credentialConfig: null,
      applicationTemplate: null,
      error: 'Organization context missing for credential configuration.',
    });
  });

  it('loads an application template and reuses the dynamic form model', async () => {
    await expect(loadCredentialApplicationConfig({
      credentialConfigId: 'credential-template-1',
      credentialConfig: null,
      organizationId: 'org-1',
      getCredentialTemplate: vi.fn().mockResolvedValue({
        id: 'credential-template-1',
        credential_type: 'open_badge',
        name: 'Canvas Quiz Badge',
        claims: [{ name: 'email', required: true }],
      }),
      applicationTemplateId: 'application-template-1',
      getApplicationTemplate: vi.fn().mockResolvedValue({
        id: 'application-template-1',
        name: 'Canvas Quiz Application',
        credential_template_id: 'credential-template-1',
        form_fields: [
          { field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true },
          { field_id: 'course_name', label: 'Canvas course', field_type: 'TEXT', required: true },
        ],
        evidence_requirements: [{ evidence_id: 'canvas_quiz_score', evidence_type: 'EXTERNAL_FACT', description: 'Verified score', required: true }],
      }),
    })).resolves.toMatchObject({
      credentialConfig: {
        id: 'credential-template-1',
        credential_type: 'open_badge',
        display_name: 'Canvas Quiz Application',
        required_fields: [
          { name: 'email', label: 'Email', type: 'email', required: true },
          { name: 'course_name', label: 'Canvas course', type: 'text', required: true },
        ],
        evidence_requirements: [expect.objectContaining({ evidence_id: 'canvas_quiz_score', evidence_type: 'EXTERNAL_FACT' })],
      },
      applicationTemplate: {
        id: 'application-template-1',
      },
      error: null,
    });
  });

  it('resolves the active linked application template for a direct credential URL', async () => {
    const listApplicationTemplates = vi.fn().mockResolvedValue([
      {
        id: 'draft-application-template',
        credential_template_id: 'credential-template-1',
        status: 'DRAFT',
      },
      {
        id: 'active-application-template',
        name: 'Active Application',
        credential_template_id: 'credential-template-1',
        status: 'ACTIVE',
        form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true }],
      },
    ]);

    await expect(loadCredentialApplicationConfig({
      credentialConfigId: 'credential-template-1',
      credentialConfig: null,
      organizationId: 'org-1',
      getCredentialTemplate: vi.fn().mockResolvedValue({
        id: 'credential-template-1',
        credential_type: 'ExampleCredential',
        name: 'Example Credential',
        claims: [],
      }),
      listApplicationTemplates,
    })).resolves.toMatchObject({
      credentialConfig: {
        id: 'credential-template-1',
        application_template_id: 'active-application-template',
        required_fields: [expect.objectContaining({ name: 'email', required: true })],
      },
      applicationTemplate: { id: 'active-application-template' },
    });
    expect(listApplicationTemplates).toHaveBeenCalledWith('org-1');
  });

  it('resolves applicant ids by direct id then user lookup', async () => {
    await expect(resolveApplicantIdForApplication({
      user: { applicant_id: 'app-1', user_id: 'user-1' },
      getApplicant: vi.fn().mockResolvedValue({ id: 'app-1' }),
      getApplicantByUser: vi.fn(),
    })).resolves.toBe('app-1');

    await expect(resolveApplicantIdForApplication({
      user: { applicant_id: 'missing', user_id: 'user-1' },
      getApplicant: vi.fn().mockRejectedValue(new Error('not found')),
      getApplicantByUser: vi.fn().mockResolvedValue({ id: 'app-2' }),
    })).resolves.toBe('app-2');
  });

  it('skips direct profile lookup when auth exposes the user id as applicant id', async () => {
    const getApplicant = vi.fn();
    const getApplicantByUser = vi.fn().mockResolvedValue({ id: 'real-applicant-id' });

    await expect(resolveApplicantIdForApplication({
      user: { applicant_id: 'user-1', user_id: 'user-1' },
      getApplicant,
      getApplicantByUser,
    })).resolves.toBe('real-applicant-id');

    expect(getApplicant).not.toHaveBeenCalled();
    expect(getApplicantByUser).toHaveBeenCalledWith('user-1');
  });

  it('ensures applicant profile and recovers from update 404s', async () => {
    const createApplicant = vi.fn().mockResolvedValue({ id: 'app-2' });

    await expect(ensureApplicantProfileForApplication({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com' },
      formData: { first_name: 'Ada' },
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant,
      updateApplicantProfile: vi.fn().mockRejectedValue(Object.assign(new Error('missing'), { status: 404 })),
      getApplicantByUser: vi.fn().mockResolvedValue(null),
    })).resolves.toMatchObject({
      applicantId: 'app-2',
      applicantCreated: true,
      applicantData: {
        given_name: 'Ada',
        family_name: '',
        email: 'user@example.com',
      },
    });
  });

  it('auto-applies and returns wallet offer data', async () => {
    await expect(autoApplyForCredential({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com', roles: ['applicant'] },
      credentialConfig: { id: 'cfg-1', credential_type: 'MemberCredential', name: 'Member Login Credential' },
      applicationTemplate: { id: 'app-template-1', form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true }] },
      credentialConfigId: 'cfg-fallback',
      hasRegisteredWallet: true,
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      createApplication: vi.fn().mockResolvedValue({ id: 'application-1' }),
      submitApplication: vi.fn().mockResolvedValue({
        id: 'application-1',
        reference_number: 'APP-20260317-SUBMITTED',
      }),
      generateIssuanceOffer: vi.fn().mockResolvedValue({
        id: 'issued-1',
        reference_number: 'APP-20260317-ISSUED',
        credential_offer_uri: 'openid-credential-offer://offer',
        credential_offer_uris: { apple: 'apple://offer' },
        offer_expires_at: '2026-03-17T00:00:00.000Z',
      }),
    })).resolves.toEqual({
      applicationId: 'issued-1',
      applicationReference: 'APP-20260317-ISSUED',
      offerData: {
        offer_url: 'openid-credential-offer://offer',
        credential_offer_uris: { apple: 'apple://offer' },
        expires_at: '2026-03-17T00:00:00.000Z',
      },
    });
  });

  it('submits the application but waits for wallet selection before minting an offer', async () => {
    const submitApplication = vi.fn().mockResolvedValue({
      id: 'application-1',
      reference_number: 'APP-20260317-SUBMITTED',
    });
    const generateIssuanceOffer = vi.fn();

    await expect(autoApplyForCredential({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com', roles: ['applicant'] },
      credentialConfig: { id: 'cfg-1', application_template_id: 'app-template-1', credential_type: 'open_badge', name: 'Verified Member Badge' },
      applicationTemplate: { id: 'app-template-1', form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true }] },
      credentialConfigId: 'cfg-fallback',
      hasRegisteredWallet: false,
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      createApplication: vi.fn().mockResolvedValue({ id: 'application-1' }),
      submitApplication,
      generateIssuanceOffer,
      listApplications: vi.fn().mockResolvedValue({ items: [] }),
    })).resolves.toEqual({
      applicationId: 'application-1',
      applicationReference: 'APP-20260317-SUBMITTED',
      offerData: {
        offer_url: null,
        credential_offer_uris: {},
        expires_at: null,
      },
      requiresWalletSelection: true,
    });

    expect(submitApplication).toHaveBeenCalledWith('application-1');
    expect(generateIssuanceOffer).not.toHaveBeenCalled();
  });

  it('reissues a fresh offer for an existing issued login badge', async () => {
    const generateIssuanceOffer = vi.fn().mockResolvedValue({
      id: 'existing-1',
      credential_offer_uri: 'openid-credential-offer://fresh-offer',
      credential_offer_uris: { spruce: 'spruce://fresh-offer' },
      offer_expires_at: '2026-03-18T00:00:00.000Z',
    });

    await expect(autoApplyForCredential({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com', roles: ['applicant'] },
      credentialConfig: { id: 'cfg-1', credential_type: 'open_badge', name: 'Verified Member Badge' },
      credentialConfigId: 'cfg-fallback',
      hasRegisteredWallet: true,
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      createApplication: vi.fn(),
      generateIssuanceOffer,
      listApplications: vi.fn().mockResolvedValue({
        items: [
          {
            id: 'existing-1',
            credential_template_id: 'cfg-1',
            status: 'CREDENTIALED',
            reference_number: 'APP-EXISTING',
          },
        ],
      }),
    })).resolves.toEqual({
      applicationId: 'existing-1',
      applicationReference: 'APP-EXISTING',
      offerData: {
        offer_url: 'openid-credential-offer://fresh-offer',
        credential_offer_uris: { spruce: 'spruce://fresh-offer' },
        expires_at: '2026-03-18T00:00:00.000Z',
      },
      existingApplication: true,
    });

    expect(generateIssuanceOffer).toHaveBeenCalledWith('existing-1');
  });

  it('submits applications and uploads biometrics when a portrait is provided', async () => {
    const createApplication = vi.fn().mockResolvedValue({ id: 'application-1', reference_number: 'APP-20260317-CREATED' });
    const submitApplication = vi.fn().mockResolvedValue({ id: 'submitted-1', reference_number: 'APP-20260317-SUBMIT' });
    const enrollBiometric = vi.fn().mockResolvedValue({ id: 'bio-1' });
    const file = { name: 'portrait.png' };

    await expect(submitCredentialApplication({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com' },
      formData: { first_name: 'Ada', documentNumber: '1234', portrait: file },
      credentialConfig: { id: 'cfg-1', application_template_id: 'app-template-1', credential_type: 'ExampleCredential', display_name: 'Example' },
      credentialConfigId: 'cfg-fallback',
      allFields: [{ name: 'portrait', type: 'file' }],
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      updateApplicantProfile: vi.fn().mockResolvedValue({ id: 'app-1' }),
      getApplicantByUser: vi.fn(),
      createApplication,
      submitApplication,
      enrollBiometric,
      readFileAsBase64: vi.fn().mockResolvedValue('image-base64'),
    })).resolves.toEqual({
      applicationId: 'submitted-1',
      applicationReference: 'APP-20260317-SUBMIT',
      submitted: true,
    });

    expect(createApplication).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: 'org-1',
      application_template_id: 'app-template-1',
      form_data: expect.objectContaining({ documentNumber: '1234' }),
    }));
    expect(submitApplication).toHaveBeenCalledWith('application-1');
    expect(enrollBiometric).toHaveBeenCalledWith('app-1', expect.objectContaining({
      biometric_type: 'FACIAL',
      image_data_base64: 'image-base64',
      template_data_base64: 'image-base64',
    }));
  });

  it('detects active duplicate applications for the same credential', () => {
    expect(findActiveApplicationForCredential([
      { id: 'old-rejected', credential_template_id: 'cfg-1', status: 'REJECTED', updated_at: '2026-01-01T00:00:00.000Z' },
      { id: 'active', credential_template_id: 'cfg-1', status: 'APPROVED', updated_at: '2026-01-02T00:00:00.000Z' },
      { id: 'other', credential_template_id: 'cfg-2', status: 'SUBMITTED', updated_at: '2026-01-03T00:00:00.000Z' },
    ], 'cfg-1')).toMatchObject({ id: 'active' });
  });

  it('returns a duplicate conflict before creating another application', async () => {
    const createApplication = vi.fn();

    await expect(submitCredentialApplication({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com' },
      formData: { first_name: 'Ada' },
      credentialConfig: { id: 'cfg-1', application_template_id: 'app-template-1', credential_type: 'open_badge', display_name: 'Canvas Badge' },
      credentialConfigId: 'cfg-fallback',
      allFields: [],
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      updateApplicantProfile: vi.fn().mockResolvedValue({ id: 'app-1' }),
      getApplicantByUser: vi.fn(),
      listApplicantApplications: vi.fn().mockResolvedValue([
        { id: 'application-existing', credential_template_id: 'cfg-1', status: 'APPROVED', reference_number: 'APP-EXISTING' },
      ]),
      createApplication,
      submitApplication: vi.fn(),
      enrollBiometric: vi.fn(),
      readFileAsBase64: vi.fn(),
    })).resolves.toMatchObject({
      duplicateApplicationConflict: {
        existingApplication: {
          id: 'application-existing',
          reference_number: 'APP-EXISTING',
        },
        credentialConfigId: 'cfg-1',
      },
      submitted: false,
    });

    expect(createApplication).not.toHaveBeenCalled();
  });

  it('supersedes an existing application before replacing it', async () => {
    const supersedeApplication = vi.fn().mockResolvedValue({ id: 'application-existing', status: 'WITHDRAWN' });
    const createApplication = vi.fn().mockResolvedValue({ id: 'application-new', reference_number: 'APP-NEW' });
    const submitApplication = vi.fn().mockResolvedValue({ id: 'application-new', reference_number: 'APP-NEW-SUBMITTED' });

    await expect(submitCredentialApplication({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com' },
      formData: { first_name: 'Ada' },
      credentialConfig: { id: 'cfg-1', application_template_id: 'app-template-1', credential_type: 'open_badge', display_name: 'Canvas Badge' },
      credentialConfigId: 'cfg-fallback',
      canvasLtiContext: { state: 'state-1' },
      allFields: [],
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      updateApplicantProfile: vi.fn().mockResolvedValue({ id: 'app-1' }),
      getApplicantByUser: vi.fn(),
      listApplicantApplications: vi.fn().mockResolvedValue([
        { id: 'application-existing', credential_template_id: 'cfg-1', status: 'APPROVED', reference_number: 'APP-EXISTING' },
      ]),
      supersedeApplication,
      duplicateApplicationAction: 'replace',
      createApplication,
      submitApplication,
      enrollBiometric: vi.fn(),
      readFileAsBase64: vi.fn(),
    })).resolves.toEqual({
      applicationId: 'application-new',
      applicationReference: 'APP-NEW-SUBMITTED',
      submitted: true,
    });

    expect(supersedeApplication).toHaveBeenCalledWith('application-existing', expect.objectContaining({
      reason: 'superseded_by_reapplication',
    }));
    expect(createApplication).toHaveBeenCalled();
    expect(submitApplication).toHaveBeenCalledWith('application-new');
  });
});
