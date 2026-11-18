import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@test/utils';

import CredentialCatalog from '../applicant/CredentialCatalog';

const { mockNavigate, mockGet, mockGetApplicantByUser, mockAuthState, mockPreview } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockGet: vi.fn(),
  mockGetApplicantByUser: vi.fn(),
  mockPreview: { isPreview: false },
  mockAuthState: {
    organizationId: 'org-1' as string | null,
    organizationName: 'Acme Org' as string | null,
    user: { user_id: 'user-1' } as any,
  },
}));

let mockPathname = '/';
let mockSearch = '';
let mockLocationState: any = null;

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string, options?: any) => options?.count !== undefined ? `${key}:${options.count}` : key }),
}));

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: () => ({ pathname: mockPathname, search: mockSearch, state: mockLocationState }),
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockAuthState,
}));

vi.mock('../../contexts/PreviewContext', () => ({
  usePreview: () => mockPreview,
}));

vi.mock('../../services/api', () => ({
  get: mockGet,
}));

vi.mock('../../services/applicantApi', () => ({
  listApplications: async () => {
    const result = await mockGet('/v1/me/applications');
    return { items: result?.items || [], total: result?.total || result?.items?.length || 0 };
  },
}));

describe('CredentialCatalog', () => {
  it('shows API wallet requirements and credential validity without inventing interoperability or processing promises', async () => {
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/v1/credential-templates')) return Promise.resolve([{
        id: 'actual', name: 'Tenant membership', credential_type: 'org.iso.18013.5.1.mDL', status: 'ACTIVE',
        revocation_profile_id: 'revocation-1', credential_payload_format: 'SD_JWT_VC', issuance_protocol: 'OID4VCI_PRE_AUTH',
        claims: [{ name: 'member_id', required: true, display: { label: 'Member ID' } }], validity_rules: { ttl_seconds: 86400 },
      }]);
      if (endpoint.includes('/v1/application-templates')) return Promise.resolve([
        { id: 'application-actual', credential_template_id: 'actual', organization_id: 'org-1', status: 'ACTIVE' },
      ]);
      return Promise.resolve({ items: [] });
    });
    const { user } = render(<CredentialCatalog />);
    const card = await screen.findByTestId('credential-card-actual');
    expect(card).toHaveTextContent('Wallet support required: SD-JWT VC with OID4VCI_PRE_AUTH.');
    expect(card).not.toHaveTextContent(/Apple|Google|Instant|business days|Works with/);
    await user.click(within(card).getByTestId('credential-details-btn'));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('SD-JWT VC');
    expect(dialog).toHaveTextContent('OID4VCI_PRE_AUTH');
    expect(dialog).toHaveTextContent('catalog.detailsDialog.validity');
    expect(dialog).toHaveTextContent('1 day');
    expect(dialog).toHaveTextContent('Member ID');
    expect(dialog).not.toHaveTextContent(/Apple|Google|Instant|business days|processingTime|Works with/);
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mockPreview.isPreview = false;
    sessionStorage.clear();
    mockPathname = '/';
    mockSearch = '';
    mockLocationState = null;
    mockAuthState.organizationId = 'org-1';
    mockAuthState.organizationName = 'Acme Org';
    mockAuthState.user = { user_id: 'user-1' };
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/v1/credential-templates')) {
        return Promise.resolve([
          {
            id: 'cfg-1',
            credential_type: 'MemberCredential',
            name: 'Member Login Credential',
            description: 'Platform login credential',
            claims: [],
            status: 'active',
            revocation_profile_id: 'rp-1',
          },
          {
            id: 'cfg-2',
            credential_type: 'passport',
            name: 'Digital Passport',
            description: 'Travel credential',
            claims: [],
            status: 'active',
            revocation_profile_id: 'rp-2',
          },
          {
            id: 'cfg-incomplete',
            credential_type: 'MemberCredential',
            name: 'Incomplete Credential',
            claims: [],
            status: 'active',
          },
        ]);
      }

      if (endpoint.includes('/v1/application-templates')) {
        const organization_id = new URL(endpoint, 'https://fixture.invalid').searchParams.get('organization_id');
        return Promise.resolve([
          { id: 'app-tpl-1', organization_id, credential_template_id: 'cfg-1', status: 'ACTIVE' },
          { id: 'app-tpl-2', organization_id, credential_template_id: 'cfg-2', status: 'ACTIVE' },
          { id: 'app-tpl-incomplete', organization_id, credential_template_id: 'cfg-incomplete', status: 'ACTIVE' },
        ]);
      }

      if (endpoint.includes('/v1/me/applications')) {
        return Promise.resolve({ items: [
          { credential_template_id: 'cfg-2' },
        ] });
      }

      return Promise.resolve([]);
    });
    mockGetApplicantByUser.mockResolvedValue({ id: 'app-1' });
  });

  it('shows an actionable alert and skips template requests when organization context is missing', async () => {
    mockAuthState.organizationId = null;
    mockAuthState.organizationName = null;
    mockAuthState.user = { user_id: 'user-1' };

    render(<CredentialCatalog />);

    const alert = await screen.findByTestId('catalog-load-alert');
    expect(alert).toHaveTextContent(/organization/i);
    expect(alert).toHaveTextContent(/refresh|choose|join/i);
    expect(screen.queryByTestId('credentials-count')).not.toBeInTheDocument();
    expect(mockGet.mock.calls.some(([endpoint]) => String(endpoint).includes('/v1/credential-templates'))).toBe(false);
    expect(mockGet.mock.calls.some(([endpoint]) => String(endpoint).includes('organization_id=null'))).toBe(false);
  });

  it('uses and encodes a safe fallback organization id from the authenticated user', async () => {
    mockAuthState.organizationId = null;
    mockAuthState.user = {
      user_id: 'user-1',
      current_organization_id: 'fallback org/1',
    };

    render(<CredentialCatalog />);

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
    });

    expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates?organization_id=fallback%20org%2F1&status=active');
  });

  it('opens a preview using the resolved Application Template ID instead of the Credential Template ID', async () => {
    mockPreview.isPreview = true;
    mockPathname = '/applicant/preview/catalog';
    const { user } = render(<CredentialCatalog />);
    const card = await screen.findByTestId('credential-card-cfg-1');
    await user.click(within(card).getByTestId('apply-btn'));
    expect(mockNavigate).toHaveBeenCalledWith('/applicant/preview/applications/app-tpl-1?organization_id=org-1', {
      state: expect.objectContaining({ applicationTemplate: expect.objectContaining({ id: 'app-tpl-1', credential_template_id: 'cfg-1', organization_id: 'org-1' }) }),
    });
  });

  it('uses the explicit preview organization without labeling it as the authenticated organization', async () => {
    mockPreview.isPreview = true;
    mockPathname = '/applicant/preview/catalog';
    mockSearch = '?organization_id=selected%20org%2F2';
    const { user } = render(<CredentialCatalog />);
    const card = await screen.findByTestId('credential-card-cfg-1');

    expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates?organization_id=selected%20org%2F2&status=active');
    expect(mockGet.mock.calls.some(([endpoint]) => String(endpoint).includes('organization_id=org-1'))).toBe(false);
    expect(screen.queryByRole('heading', { name: 'Acme Org' })).not.toBeInTheDocument();
    expect(card).not.toHaveTextContent('Acme Org');
    await user.click(within(card).getByTestId('apply-btn'));
    expect(mockNavigate).toHaveBeenCalledTimes(1);
    const [destination, options] = mockNavigate.mock.calls[0];
    const target = new URL(destination, 'https://preview.invalid');
    expect(target.pathname).toBe('/applicant/preview/applications/app-tpl-1');
    expect(target.searchParams.get('organization_id')).toBe('selected org/2');
    expect(options).toEqual({
      state: expect.objectContaining({ applicationTemplate: expect.objectContaining({ organization_id: 'selected org/2' }) }),
    });
  });

  it.each(['?organization_id=', '?organization_id=%20%09', '?organization_id=org-2&organization_id=org-3',
    '?organization_id=org-2&organization_id=org-2', '?organization_id=org-2%09'])('refuses an empty or ambiguous explicit preview scope: %s', async (query) => {
    mockPreview.isPreview = true;
    mockPathname = '/applicant/preview/catalog';
    mockSearch = query;
    render(<CredentialCatalog />);

    const alert = await screen.findByTestId('catalog-load-alert');
    expect(alert).toHaveTextContent(/preview|organization/i);
    expect(mockGet.mock.calls.some(([endpoint]) => String(endpoint).includes('/v1/credential-templates')
      || String(endpoint).includes('/v1/application-templates'))).toBe(false);
    expect(screen.queryByTestId('credential-card-cfg-1')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Acme Org' })).not.toBeInTheDocument();
  });

  it('preserves the known organization name for a matching explicit preview', async () => {
    mockPreview.isPreview = true;
    mockPathname = '/applicant/preview/catalog';
    mockSearch = '?organization_id=org-1';
    render(<CredentialCatalog />);
    await screen.findByTestId('credential-card-cfg-1');
    expect(screen.getByRole('heading', { name: 'Acme Org' })).toBeInTheDocument();
  });

  it('ignores the preview organization query in the ordinary applicant catalog', async () => {
    mockPathname = '/console/applicant/catalog';
    mockSearch = '?organization_id=another-org';
    render(<CredentialCatalog />);
    await screen.findByTestId('credential-card-cfg-1');
    expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates?organization_id=org-1&status=active');
    expect(mockGet.mock.calls.some(([endpoint]) => String(endpoint).includes('organization_id=another-org'))).toBe(false);
  });



  it('discards an old explicit organization catalog after the preview query changes', async () => {
    mockPreview.isPreview = true;
    mockPathname = '/applicant/preview/catalog';
    mockSearch = '?organization_id=old-org';
    const oldCatalog = deferred<any[]>();
    const baseGet = mockGet.getMockImplementation()!;
    mockGet.mockImplementation((endpoint: string) => endpoint.includes('/v1/credential-templates?organization_id=old-org')
      ? oldCatalog.promise : baseGet(endpoint));
    const { rerender } = render(<CredentialCatalog />);
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates?organization_id=old-org&status=active'));
    mockSearch = '?organization_id=current-org';
    rerender(<CredentialCatalog />);
    expect(await screen.findByTestId('credential-card-cfg-1')).toHaveTextContent('Member Login Credential');
    await act(async () => { oldCatalog.resolve([{
      id: 'cfg-1', name: 'Obsolete organization credential', claims: [], status: 'ACTIVE', revocation_profile_id: 'rp-old',
    }]); });
    expect(screen.queryByText('Obsolete organization credential')).not.toBeInTheDocument();
    expect(screen.getByTestId('credential-card-cfg-1')).toHaveTextContent('Member Login Credential');
  });

  it('loads credentials, marks existing applications, filters, and navigates with serializable state', async () => {
    const { user } = render(<CredentialCatalog />);

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
      expect(screen.getByTestId('credential-card-cfg-2')).toBeInTheDocument();
      expect(screen.queryByTestId('credential-card-cfg-incomplete')).not.toBeInTheDocument();
    });

    expect(screen.getByTestId('credential-card-cfg-2')).toHaveAttribute('data-credential-status', 'applied');

    await user.type(within(screen.getByTestId('credential-search')).getByRole('textbox'), 'member');

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
      expect(screen.queryByTestId('credential-card-cfg-2')).not.toBeInTheDocument();
    });

    const memberCard = screen.getByTestId('credential-card-cfg-1');
    await user.click(within(memberCard).getByTestId('apply-btn'));

    expect(mockNavigate).toHaveBeenCalledWith('/apply/cfg-1', {
      state: {
        credential: expect.objectContaining({
          id: 'cfg-1',
          name: 'Member Login Credential',
        }),
        applicationTemplate: expect.objectContaining({
          id: 'app-tpl-1',
          credential_template_id: 'cfg-1',
        }),
      },
    });
  });





  it('navigates directly to the applicant application route from the console catalog', async () => {
    mockPathname = '/console/applicant/catalog';
    const { user } = render(<CredentialCatalog />);

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
    });

    await user.click(within(screen.getByTestId('credential-card-cfg-1')).getByTestId('apply-btn'));

    expect(mockNavigate).toHaveBeenCalledWith('/console/applicant/apply/cfg-1', {
      state: {
        credential: expect.objectContaining({
          id: 'cfg-1',
          name: 'Member Login Credential',
        }),
        applicationTemplate: expect.objectContaining({
          id: 'app-tpl-1',
          credential_template_id: 'cfg-1',
        }),
      },
    });
  });

  it.each(['/v1/credential-templates', '/v1/application-templates'])('explains an empty available catalog when %s returns no entries', async (emptyEndpoint) => {
    const defaultGet = mockGet.getMockImplementation()!;
    mockGet.mockImplementation((endpoint: string) => endpoint.includes(emptyEndpoint)
      ? Promise.resolve([])
      : defaultGet(endpoint));
    const { user } = render(<CredentialCatalog />);

    expect(await screen.findByText('catalog.empty.description')).toBeInTheDocument();
    expect(screen.getByText('catalog.empty.title')).toBeInTheDocument();
    expect(screen.getByTestId('credentials-count')).toHaveTextContent('catalog.resultsCount:0');
    expect(screen.queryByText('catalog.empty.message')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'catalog.filters.clear' })).not.toBeInTheDocument();

    await user.type(screen.getByRole('textbox', { name: 'catalog.searchLabel' }), 'member');

    expect(screen.getByText('catalog.empty.description')).toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.message')).not.toBeInTheDocument();
  });

  it('labels the search and category controls and clears filters when they hide available credentials', async () => {
    const { user } = render(<CredentialCatalog />);
    await screen.findByTestId('credential-card-cfg-1');
    const search = screen.getByRole('textbox', { name: 'catalog.searchLabel' });
    const category = screen.getByRole('combobox', { name: 'catalog.filters.category' });

    await user.click(category);
    await user.click(screen.getByRole('option', { name: 'catalog.categories.travel' }));
    await user.type(search, 'member');

    expect(await screen.findByText('catalog.empty.message')).toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.description')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'catalog.filters.clear' }));

    expect(await screen.findByTestId('credential-card-cfg-1')).toBeInTheDocument();
    expect(screen.getByTestId('credential-card-cfg-2')).toBeInTheDocument();
    expect(search).toHaveValue('');
    expect(category).toHaveTextContent('catalog.categories.all');
    expect(screen.queryByText('catalog.empty.message')).not.toBeInTheDocument();
    expect(screen.getByTestId('credentials-count')).toHaveTextContent('catalog.resultsCount:2');
  });

  it('does not report zero results while loading or failed and retries the catalog in place', async () => {
    let rejectCatalog!: (error: Error) => void;
    let catalogRequests = 0;
    const defaultGet = mockGet.getMockImplementation()!;
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/v1/credential-templates') && catalogRequests++ === 0) {
        return new Promise((_, reject) => { rejectCatalog = reject; });
      }
      return defaultGet(endpoint);
    });
    const { user } = render(<CredentialCatalog />);
    expect(screen.queryByTestId('credentials-count')).not.toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.description')).not.toBeInTheDocument();

    await act(async () => rejectCatalog(new Error('Catalog temporarily unavailable')));

    expect(await screen.findByTestId('catalog-load-alert')).toHaveTextContent('catalog.errorLoading');
    expect(screen.queryByTestId('credentials-count')).not.toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.description')).not.toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.message')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'actions.retry' }));

    expect(await screen.findByTestId('credential-card-cfg-1')).toBeInTheDocument();
    expect(screen.queryByTestId('catalog-load-alert')).not.toBeInTheDocument();
    expect(screen.getByTestId('credentials-count')).toHaveTextContent('catalog.resultsCount:2');
    expect(catalogRequests).toBe(2);
  });







  it.each(['success', 'failure'])('ignores stale catalog and application %s after switching accounts in the same organization', async (outcome) => {
    const previousCredentials = deferred<any[]>();
    const previousApplications = deferred<any>();
    const defaultGet = mockGet.getMockImplementation()!;
    let catalogRequests = 0;
    let applicationRequests = 0;
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/v1/credential-templates') && catalogRequests++ === 0) return previousCredentials.promise;
      if (endpoint.includes('/v1/me/applications')) {
        if (applicationRequests++ === 0) return previousApplications.promise;
        return Promise.resolve({ items: [{ credential_template_id: 'cfg-1', status: 'approved' }] });
      }
      return defaultGet(endpoint);
    });
    const { rerender } = render(<CredentialCatalog />);
    mockAuthState.user = { user_id: 'user-2' };
    rerender(<CredentialCatalog />);

    expect(await screen.findByTestId('credential-card-cfg-1')).toHaveAttribute('data-credential-status', 'applied');
    expect(screen.getByText('Approved (1)')).toBeInTheDocument();

    await act(async () => {
      if (outcome === 'success') {
        previousCredentials.resolve([]);
        previousApplications.resolve({ items: [{ credential_template_id: 'cfg-2', status: 'rejected' }] });
      } else {
        previousCredentials.reject(new Error('Previous account catalog failed'));
        previousApplications.reject(new Error('Previous account applications failed'));
      }
      await Promise.allSettled([previousCredentials.promise, previousApplications.promise]);
    });

    expect(screen.getByTestId('credential-card-cfg-1')).toHaveAttribute('data-credential-status', 'applied');
    expect(screen.getByTestId('credential-card-cfg-2')).toHaveAttribute('data-credential-status', 'available');
    expect(screen.getByText('Approved (1)')).toBeInTheDocument();
    expect(screen.queryByText('Rejected (1)')).not.toBeInTheDocument();
    expect(screen.queryByTestId('catalog-load-alert')).not.toBeInTheDocument();
    expect(screen.getByTestId('credentials-count')).toHaveTextContent('catalog.resultsCount:2');
  });

  it('clears the previous account application badges and counts while the new account loads', async () => {
    const currentApplications = deferred<any>();
    const defaultGet = mockGet.getMockImplementation()!;
    let applicationRequests = 0;
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/v1/me/applications')) {
        return applicationRequests++ === 0
          ? Promise.resolve({ items: [{ credential_template_id: 'cfg-1', status: 'approved' }] })
          : currentApplications.promise;
      }
      return defaultGet(endpoint);
    });
    const { rerender } = render(<CredentialCatalog />);
    expect(await screen.findByText('Approved (1)')).toBeInTheDocument();
    mockAuthState.user = { user_id: 'user-2' };
    rerender(<CredentialCatalog />);

    expect(screen.queryByText('Approved (1)')).not.toBeInTheDocument();
    expect(screen.queryByText('Application Status')).not.toBeInTheDocument();
    expect(await screen.findByTestId('credential-card-cfg-1')).toHaveAttribute('data-credential-status', 'available');

    await act(async () => currentApplications.resolve({ items: [] }));

    expect(screen.getByTestId('credential-card-cfg-1')).toHaveAttribute('data-credential-status', 'available');
    expect(screen.queryByText('Application Status')).not.toBeInTheDocument();
  });

  it.each(['organization', 'account'])('closes credential details when the %s scope changes', async (scope) => {
    const { user, rerender } = render(<CredentialCatalog />);
    const originalCard = await screen.findByTestId('credential-card-cfg-1');
    await user.click(within(originalCard).getByTestId('credential-details-btn'));
    expect(await screen.findByRole('dialog')).toHaveTextContent('Member Login Credential');

    if (scope === 'organization') {
      mockAuthState.organizationId = 'org-2';
    } else if (scope === 'account') {
      mockAuthState.user = { user_id: 'user-2' };
    }
    rerender(<CredentialCatalog />);

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(mockNavigate).not.toHaveBeenCalled();
    const currentCard = await screen.findByTestId('credential-card-cfg-1');
    await user.click(within(currentCard).getByTestId('credential-details-btn'));
    const currentDialog = await screen.findByRole('dialog');
    expect(currentDialog).toHaveTextContent('Member Login Credential');
    {
      await user.click(within(currentDialog).getByRole('button', { name: 'catalog.card.actions.apply' }));
      expect(mockNavigate).toHaveBeenCalledWith('/apply/cfg-1', {
        state: expect.objectContaining({ applicationTemplate: expect.objectContaining({
          organization_id: scope === 'organization' ? 'org-2' : 'org-1',
        }) }),
      });
    }
  });


  it('ignores legacy launch state and uses the authenticated organization', async () => {
    mockSearch = '?canvas_lti_state=retired';
    mockLocationState = { canvasLtiSession: { organization_id: 'foreign-org', credential_template_id: 'cfg-2' } };
    const { user } = render(<CredentialCatalog />);
    const card = await screen.findByTestId('credential-card-cfg-1');
    expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates?organization_id=org-1&status=active');
    expect(mockGet.mock.calls.some(([url]) => String(url).includes('/integrations/'))).toBe(false);
    await user.click(within(card).getByTestId('apply-btn'));
    expect(mockNavigate).toHaveBeenCalledWith('/apply/cfg-1', {
      state: expect.not.objectContaining({ canvasLtiSession: expect.anything() }),
    });
  });

});
