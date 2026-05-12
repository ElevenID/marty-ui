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
      status: 'active',
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
    expect(mapCredentialTemplateToCatalogItem({
      id: 'tpl-ob',
      credential_type: 'open_badge',
      name: 'Verified Member Badge',
      claims: [{ name: 'email', required: true }, { name: 'role', required: true }],
      status: 'active',
    }, 'Acme')).toMatchObject({
      id: 'tpl-ob',
      credentialType: 'open_badge',
      category: 'identity',
      requirements: ['email', 'role'],
      format: 'vc+sd-jwt',
      standard: '1EdTech Open Badges 3.0',
      worksWithLabel: 'Web & VC wallets',
    });
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
});
