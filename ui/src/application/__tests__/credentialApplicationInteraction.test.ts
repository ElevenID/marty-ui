/**
 * Interaction tests: Credential Application Journey
 *
 * Exercises the multi-step flow that a user follows when applying
 * for a credential through the headless UI layer:
 *
 *   1. Browse credential catalog → pick a credential
 *   2. Load application form config
 *   3. Ensure applicant profile
 *   4. Submit the application (with biometric)
 *   5. Auto-apply fast path (one-click issuance)
 */

import { describe, expect, it, vi } from 'vitest';

import {
  loadCredentialCatalogItems,
  loadExistingCredentialApplications,
  filterCredentialCatalogItems,
  buildCredentialApplicationNavigationState,
  extractApplicationStatusInfo,
} from '../applications/credentialCatalog';
import {
  loadCredentialApplicationConfig,
  ensureApplicantProfileForApplication,
  submitCredentialApplication,
  autoApplyForCredential,
  resolveApplicantIdForApplication,
} from '../applications/applicationFormUseCases';

describe('Credential Application — end-to-end interaction', () => {
  const USER = {
    user_id: 'user-42',
    applicant_id: null,
    given_name: 'Alice',
    family_name: 'Smith',
    email: 'alice@example.com',
  };

  const ORG = { id: 'org-1', name: 'Acme Credentials' };

  const MDL_TEMPLATE = {
    id: 'tpl-mdl',
    credential_type: 'org.iso.18013.5.1.mDL',
    name: "Mobile Driver's License",
    description: 'ISO 18013-5 mDL',
    claims: [
      { name: 'given_name', required: true },
      { name: 'family_name', required: true },
      { name: 'birth_date', required: true },
      { name: 'portrait', required: false },
    ],
  };

  it('catalog → select → configure → submit: complete journey', async () => {
    // ── Step 1: Load catalog ────────────────────────────────
    const { credentials } = await loadCredentialCatalogItems({
      organizationId: ORG.id,
      organizationName: ORG.name,
      listCredentialTemplates: vi.fn().mockResolvedValue([MDL_TEMPLATE]),
    });
    expect(credentials.length).toBe(1);
    expect(credentials[0]).toMatchObject({
      id: 'tpl-mdl',
      name: "Mobile Driver's License",
    });

    // ── Step 2: Filter & pick ───────────────────────────────
    const filtered = filterCredentialCatalogItems(credentials, {
      searchTerm: 'driver',
      categoryFilter: 'all',
    });
    expect(filtered.length).toBe(1);

    const navState = buildCredentialApplicationNavigationState(filtered[0]);
    expect(navState).toMatchObject({
      path: '/apply/tpl-mdl',
      state: { credential: expect.objectContaining({ id: 'tpl-mdl' }) },
    });

    // ── Step 3: Load form config ────────────────────────────
    const { credentialConfig, error: configError } = await loadCredentialApplicationConfig({
      credentialConfigId: navState.state.credential.id,
      credentialConfig: null,
      organizationId: ORG.id,
      getCredentialTemplate: vi.fn().mockResolvedValue(MDL_TEMPLATE),
    });
    expect(configError).toBeNull();
    expect(credentialConfig).toMatchObject({
      id: 'tpl-mdl',
      credential_type: 'org.iso.18013.5.1.mDL',
      required_fields: ['given_name', 'family_name', 'birth_date'],
      optional_fields: ['portrait'],
    });

    // ── Step 4: Resolve/create applicant ────────────────────
    const createApplicant = vi.fn().mockResolvedValue({ id: 'app-new' });
    const { applicantId, applicantCreated } = await ensureApplicantProfileForApplication({
      organizationId: ORG.id,
      user: USER,
      formData: { given_name: 'Alice', family_name: 'Smith', birth_date: '1990-05-15' },
      resolveApplicantId: vi.fn().mockResolvedValue(null),
      createApplicant,
      updateApplicantProfile: vi.fn(),
      getApplicantByUser: vi.fn().mockResolvedValue(null),
    });
    expect(applicantCreated).toBe(true);
    expect(applicantId).toBe('app-new');

    // ── Step 5: Submit application ──────────────────────────
    const result = await submitCredentialApplication({
      organizationId: ORG.id,
      user: USER,
      formData: { given_name: 'Alice', family_name: 'Smith', birth_date: '1990-05-15' },
      credentialConfig,
      credentialConfigId: credentialConfig.id,
      allFields: credentialConfig.claims || [],
      resolveApplicantId: vi.fn().mockResolvedValue('app-new'),
      createApplicant: vi.fn(),
      updateApplicantProfile: vi.fn().mockResolvedValue(undefined),
      getApplicantByUser: vi.fn(),
      createApplication: vi.fn().mockResolvedValue({ id: 'appl-1' }),
      submitApplication: vi.fn().mockResolvedValue({ id: 'appl-1' }),
      enrollBiometric: vi.fn(),
      readFileAsBase64: vi.fn(),
    });

    expect(result).toEqual({ applicationId: 'appl-1', submitted: true });
  });

  it('auto-apply fast path returns wallet offer in one step', async () => {
    const result = await autoApplyForCredential({
      organizationId: ORG.id,
      user: { ...USER, user_id: 'user-42' },
      credentialConfig: { id: 'tpl-mdl' },
      credentialConfigId: 'tpl-mdl',
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      createApplication: vi.fn().mockResolvedValue({ id: 'appl-2' }),
      autoIssueApplication: vi.fn().mockResolvedValue({
        id: 'appl-2',
        credential_offer_uri: 'openid-credential-offer://example.com/offer?id=abc',
        credential_offer_uris: { marty: 'openid-credential-offer://marty/offer?id=abc' },
        offer_expires_at: '2026-04-10T00:00:00Z',
      }),
      listApplications: vi.fn().mockResolvedValue({ applications: [] }),
    });

    expect(result).toMatchObject({
      applicationId: 'appl-2',
      offerData: {
        offer_url: 'openid-credential-offer://example.com/offer?id=abc',
        credential_offer_uris: { marty: 'openid-credential-offer://marty/offer?id=abc' },
      },
    });
  });

  it('auto-apply returns existing application when duplicate detected', async () => {
    const result = await autoApplyForCredential({
      organizationId: ORG.id,
      user: USER,
      credentialConfig: { id: 'tpl-mdl' },
      credentialConfigId: 'tpl-mdl',
      resolveApplicantId: vi.fn().mockResolvedValue('app-1'),
      createApplicant: vi.fn(),
      createApplication: vi.fn(),
      autoIssueApplication: vi.fn(),
      listApplications: vi.fn().mockResolvedValue({
        applications: [
          {
            id: 'existing-appl',
            credential_configuration_id: 'tpl-mdl',
            status: 'APPROVED',
            credential_offer_uri: 'openid-credential-offer://existing',
            credential_offer_uris: {},
          },
        ],
      }),
    });

    expect(result).toMatchObject({
      applicationId: 'existing-appl',
      existingApplication: true,
    });
  });

  it('catalog load with existing applications yields status info', async () => {
    const existingAppIds = await loadExistingCredentialApplications({
      organizationId: ORG.id,
      userId: 'user-42',
      getApplicantByUser: vi.fn().mockResolvedValue({ id: 'app-1' }),
      listApplicantApplications: vi.fn().mockResolvedValue([
        { id: 'appl-1', credential_configuration_id: 'tpl-mdl', status: 'approved' },
        { id: 'appl-2', credential_configuration_id: 'tpl-badge', status: 'pending' },
      ]),
    });

    expect(existingAppIds).toContain('tpl-mdl');
    expect(existingAppIds).toContain('tpl-badge');
  });

  it('applicant resolution falls back to user lookup when direct id fails', async () => {
    const applicantId = await resolveApplicantIdForApplication({
      user: { applicant_id: 'stale-id', user_id: 'user-42' },
      getApplicant: vi.fn().mockRejectedValue(new Error('404')),
      getApplicantByUser: vi.fn().mockResolvedValue({ id: 'real-app-id' }),
    });

    expect(applicantId).toBe('real-app-id');
  });
});
