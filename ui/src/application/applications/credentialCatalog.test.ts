import { describe, expect, it, vi } from 'vitest';

import {
  buildCredentialApplicationNavigationState,
  extractExistingApplicationIds,
  filterCredentialCatalogItems,
  getCredentialCatalogCategories,
  loadCredentialCatalogItems,
  loadExistingCredentialApplications,
  mapCredentialTemplateToCatalogItem,
  resolveCredentialApplicationPath,
  scopeCredentialCatalogItemsForCanvasLaunch,
} from './credentialCatalog';

describe('credentialCatalog helpers', () => {
  it('builds translated categories', () => {
    const t = vi.fn((key) => key);
    expect(getCredentialCatalogCategories(t)).toEqual([
      { value: 'all', label: 'catalog.categories.all' },
      { value: 'travel', label: 'catalog.categories.travel' },
      { value: 'identity', label: 'catalog.categories.identity' },
      { value: 'enterprise', label: 'catalog.categories.enterprise' },
      { value: 'education', label: 'catalog.categories.education' },
    ]);
  });

  it('maps templates into catalog cards', () => {
    expect(mapCredentialTemplateToCatalogItem({
      id: 'tpl-1',
      credential_type: 'MemberCredential',
      name: 'Member Login Credential',
      claims: [{ name: 'email', required: true }],
      status: 'ACTIVE',
      version: '1.0.0',
    }, 'Acme')).toMatchObject({
      id: 'tpl-1',
      credentialType: 'MemberCredential',
      category: 'identity',
      requirements: ['email'],
      vendorName: 'Acme',
      available: true,
    });
  });

  it('maps open badge templates as identity membership credentials', () => {
    const catalogItem = mapCredentialTemplateToCatalogItem({
      id: 'tpl-ob',
      credential_type: 'open_badge',
      name: 'Marty Verified Member Badge',
      description: 'Open Badge 3.0 membership badge for passwordless login/sign-in with your wallet.',
      claims: [{ name: 'email', required: true }, { name: 'role', required: true }],
      status: 'ACTIVE',
    }, 'Acme');

    expect(catalogItem).toMatchObject({
      id: 'tpl-ob',
      name: 'Marty Verified Member Badge',
      credentialType: 'open_badge',
      category: 'identity',
      requirements: ['email', 'role'],
      format: 'vc+sd-jwt',
      standard: '1EdTech Open Badges 3.0',
      worksWithLabel: 'Web & VC wallets',
      available: true,
      searchAliases: expect.arrayContaining(['open badge login', 'achievement credential']),
    });

    expect(filterCredentialCatalogItems([catalogItem], {
      searchTerm: 'open badge login',
      categoryFilter: 'all',
    })).toEqual([catalogItem]);
  });

  it('extracts existing application ids and filters credentials', () => {
    expect(extractExistingApplicationIds([
      { credential_configuration_id: 'cfg-1' },
      { credential_configuration_id: null },
      { credential_configuration_id: 'cfg-2' },
    ])).toEqual(['cfg-1', 'cfg-2']);

    expect(filterCredentialCatalogItems([
      { name: 'Passport', description: 'Travel credential', category: 'travel' },
      { name: 'Member Login Credential', description: 'Identity', category: 'identity' },
    ], {
      searchTerm: 'pass',
      categoryFilter: 'travel',
    })).toEqual([
      { name: 'Passport', description: 'Travel credential', category: 'travel' },
    ]);
  });

  it('scopes catalog items to Canvas launch credential templates when present', () => {
    const credentials = [
      { id: 'cfg-1', name: 'Canvas Credential' },
      { id: 'cfg-2', name: 'General Credential' },
    ];

    expect(scopeCredentialCatalogItemsForCanvasLaunch(credentials, {
      credentialTemplateIds: ['cfg-1'],
    })).toEqual([
      { id: 'cfg-1', name: 'Canvas Credential' },
    ]);

    expect(scopeCredentialCatalogItemsForCanvasLaunch(credentials)).toEqual(credentials);
  });

  it('builds serializable navigation payloads', () => {
    const payload = buildCredentialApplicationNavigationState({
      id: 'cfg-1',
      name: 'Passport',
      icon: () => null,
      processingFee: 0,
    });

    expect(payload).toEqual({
      path: '/apply/cfg-1',
      state: {
        credential: {
          id: 'cfg-1',
          name: 'Passport',
          processingFee: 0,
        },
      },
    });
  });

  it('preserves Canvas launch context when navigating from the scoped catalog', () => {
    const payload = buildCredentialApplicationNavigationState({
      id: 'cfg-1',
      name: 'Canvas Credential',
      icon: () => null,
    }, {
      currentPathname: '/console/applicant/catalog',
      canvasLtiContext: {
        state: 'state-1',
        canvas_program_binding_id: 'binding-1',
        canvas_platform_id: 'platform-1',
        application_template_id: 'app-tpl-1',
        credential_template_id: 'cfg-1',
      },
      canvasLtiSession: { state: 'state-1' },
    });

    expect(payload).toEqual({
      path: '/console/applicant/apply/cfg-1?canvas_lti_state=state-1&canvas_program_binding_id=binding-1&canvas_platform_id=platform-1&application_template_id=app-tpl-1&credential_template_id=cfg-1',
      state: {
        credential: {
          id: 'cfg-1',
          name: 'Canvas Credential',
        },
        canvasLtiSession: { state: 'state-1' },
      },
    });
  });

  it('resolves direct application paths for console and preview contexts', () => {
    expect(resolveCredentialApplicationPath({
      credentialId: 'cfg-1',
      currentPathname: '/console/applicant/catalog',
    })).toBe('/console/applicant/apply/cfg-1');

    expect(resolveCredentialApplicationPath({
      credentialId: 'cfg-1',
      currentPathname: '/applicant/preview/catalog',
      isPreview: true,
    })).toBe('/applicant/preview/applications/cfg-1');

    expect(resolveCredentialApplicationPath({
      credentialId: 'cfg-1',
      currentPathname: '/catalog',
    })).toBe('/apply/cfg-1');
  });

  it('loads catalog items and existing application ids safely', async () => {
    await expect(loadCredentialCatalogItems({
      organizationId: 'org-1',
      organizationName: 'Acme',
      listCredentialTemplates: vi.fn().mockResolvedValue([
        { id: 'tpl-1', credential_type: 'MemberCredential', name: 'Member Login Credential', claims: [], status: 'active' },
      ]),
    })).resolves.toMatchObject({
      credentials: [expect.objectContaining({ id: 'tpl-1', vendorName: 'Acme' })],
      error: null,
    });

    await expect(loadExistingCredentialApplications({
      organizationId: 'org-1',
      userId: 'user-1',
      getApplicantByUser: vi.fn().mockResolvedValue({ id: 'app-1' }),
      listApplicantApplications: vi.fn().mockResolvedValue([
        { credential_configuration_id: 'cfg-1' },
      ]),
    })).resolves.toEqual(['cfg-1']);

    await expect(loadExistingCredentialApplications({
      organizationId: null,
      userId: 'user-1',
      getApplicantByUser: vi.fn(),
      listApplicantApplications: vi.fn(),
    })).resolves.toEqual([]);
  });

  it('does not call the template API without a real organization id', async () => {
    const listCredentialTemplates = vi.fn();

    const result = await loadCredentialCatalogItems({
      organizationId: '   ',
      organizationName: 'Acme',
      listCredentialTemplates,
    });

    expect(listCredentialTemplates).not.toHaveBeenCalled();
    expect(result.credentials).toEqual([]);
    expect(result.missingOrganization).toBe(true);
    expect(result.error).toBeInstanceOf(Error);
    expect(result.error?.message).toMatch(/organization/i);
  });

  it('preserves template API failures for callers to display', async () => {
    const error = new Error('Gateway unavailable');
    const listCredentialTemplates = vi.fn().mockRejectedValue(error);

    const result = await loadCredentialCatalogItems({
      organizationId: 'org-1',
      organizationName: 'Acme',
      listCredentialTemplates,
    });

    expect(listCredentialTemplates).toHaveBeenCalledWith('org-1');
    expect(result.credentials).toEqual([]);
    expect(result.missingOrganization).toBe(false);
    expect(result.error).toBe(error);
  });
});
