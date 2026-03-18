import { describe, expect, it, vi } from 'vitest';

import {
  autoApplyForCredential,
  ensureApplicantProfileForApplication,
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
        required_fields: ['first_name'],
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
      error: 'Organization context missing for credential configuration.',
    });
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
      applicantData: expect.objectContaining({
        organization_id: 'org-1',
        user_id: 'user-1',
      }),
    });
  });

  it('auto-applies and returns wallet offer data', async () => {
    await expect(autoApplyForCredential({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com', roles: ['applicant'] },
      credentialConfig: { id: 'cfg-1', credential_type: 'MemberCredential', name: 'Member Login Credential' },
      credentialConfigId: 'cfg-fallback',
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      createApplication: vi.fn().mockResolvedValue({ id: 'application-1' }),
      autoIssueApplication: vi.fn().mockResolvedValue({
        id: 'issued-1',
        credential_offer_uri: 'openid-credential-offer://offer',
        credential_offer_uris: { apple: 'apple://offer' },
        offer_expires_at: '2026-03-17T00:00:00.000Z',
      }),
    })).resolves.toEqual({
      applicationId: 'issued-1',
      offerData: {
        offer_url: 'openid-credential-offer://offer',
        credential_offer_uris: { apple: 'apple://offer' },
        expires_at: '2026-03-17T00:00:00.000Z',
      },
    });
  });

  it('submits applications and uploads biometrics when a portrait is provided', async () => {
    const createApplication = vi.fn().mockResolvedValue({ id: 'application-1' });
    const submitApplication = vi.fn().mockResolvedValue({ id: 'submitted-1' });
    const enrollBiometric = vi.fn().mockResolvedValue({ id: 'bio-1' });
    const file = { name: 'portrait.png' };

    await expect(submitCredentialApplication({
      organizationId: 'org-1',
      user: { user_id: 'user-1', email: 'user@example.com' },
      formData: { first_name: 'Ada', documentNumber: '1234', portrait: file },
      credentialConfig: { id: 'cfg-1', credential_type: 'ExampleCredential', display_name: 'Example' },
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
      submitted: true,
    });

    expect(createApplication).toHaveBeenCalledWith(expect.objectContaining({
      applicant_id: 'app-1',
      credential_configuration_id: 'cfg-1',
    }));
    expect(submitApplication).toHaveBeenCalledWith('application-1');
    expect(enrollBiometric).toHaveBeenCalledWith('app-1', expect.objectContaining({
      biometric_type: 'FACIAL',
      image_data_base64: 'image-base64',
      template_data_base64: 'image-base64',
    }));
  });
});
