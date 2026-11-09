import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@test/utils';

import CredentialCatalog from '../applicant/CredentialCatalog';
import { storeCanvasLtiSession } from '../../services/canvasLtiExperience';

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
    storeCanvasLtiSession({
      session_token: 'canvas-session-token',
      expires_at: '2099-01-01T00:00:00.000Z',
    });
    mockPathname = '/';
    mockSearch = '';
    mockLocationState = null;
    mockAuthState.organizationId = 'org-1';
    mockAuthState.organizationName = 'Acme Org';
    mockAuthState.user = { user_id: 'user-1' };
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/v1/integrations/canvas/lti/experience-sessions/current')) {
        return Promise.resolve({
          organization_id: 'marty-canvas-org',
          canvas_platform_id: 'platform-1',
          canvas_program_binding_id: 'binding-1',
          application_template_id: 'app-tpl-1',
          credential_template_id: 'cfg-1',
          canvas_context: { course_id: 'course-1', title: 'Canvas Course' },
          learner_display_name: 'Canvas Learner',
          identity_mapping_status: 'linked',
          roles: ['Learner'],
        });
      }

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

  it('scopes Canvas-launched catalog choices and preserves launch context into apply', async () => {
    mockPathname = '/console/applicant/catalog';
    mockSearch = '?canvas_lti_state=state-1';

    const { user } = render(<CredentialCatalog />);

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
      expect(screen.queryByTestId('credential-card-cfg-2')).not.toBeInTheDocument();
    });

    await user.click(within(screen.getByTestId('credential-card-cfg-1')).getByTestId('apply-btn'));

    expect(mockNavigate).toHaveBeenCalledWith(
      '/console/applicant/apply/cfg-1?canvas_lti_state=state-1&canvas_program_binding_id=binding-1&canvas_platform_id=platform-1&application_template_id=app-tpl-1&credential_template_id=cfg-1',
      {
        state: {
          credential: expect.objectContaining({
            id: 'cfg-1',
            name: 'Member Login Credential',
          }),
          applicationTemplate: expect.objectContaining({
            id: 'app-tpl-1',
            credential_template_id: 'cfg-1',
          }),
          canvasLtiSession: expect.objectContaining({
            credential_template_id: 'cfg-1',
            canvas_program_binding_id: 'binding-1',
            canvas_context: { course_id: 'course-1', title: 'Canvas Course' },
            identity_mapping_status: 'linked',
          }),
        },
      },
    );
  });

  it('uses the Canvas launch organization when the learner has no org context', async () => {
    mockPathname = '/console/applicant/catalog';
    mockSearch = '?canvas_lti_state=state-1';
    mockAuthState.organizationId = null;
    mockAuthState.organizationName = null;
    mockAuthState.user = { user_id: 'canvas-learner-1', roles: ['canvas_lti_learner'] };

    render(<CredentialCatalog />);

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
    });

    expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates?organization_id=marty-canvas-org&status=active');
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

  it('explains an unavailable Canvas launch credential without offering to clear its scope', async () => {
    mockPathname = '/console/applicant/catalog';
    mockSearch = '?canvas_lti_state=state-1';
    mockLocationState = {
      canvasLtiSession: {
        organization_id: 'org-1',
        credential_template_id: 'cfg-unpublished',
      },
    };

    render(<CredentialCatalog />);

    expect(await screen.findByText('catalog.empty.launchUnavailable')).toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.description')).not.toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.message')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'catalog.filters.clear' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('credential-card-cfg-1')).not.toBeInTheDocument();
    expect(screen.queryByTestId('credential-card-cfg-2')).not.toBeInTheDocument();
  });

  it.each(['success', 'credential error', 'application template error'])('ignores a late initial-organization %s after the Canvas catalog loads', async (outcome) => {
    mockSearch = '?canvas_lti_state=state-1';
    const canvasSession = deferred<any>();
    const initialCredentials = deferred<any[]>();
    const initialApplicationTemplates = deferred<any[]>();
    const defaultGet = mockGet.getMockImplementation()!;
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/experience-sessions/current')) return canvasSession.promise;
      if (endpoint.includes('organization_id=org-1')) {
        if (endpoint.includes('/v1/credential-templates')) return initialCredentials.promise;
        if (endpoint.includes('/v1/application-templates')) return initialApplicationTemplates.promise;
      }
      return defaultGet(endpoint);
    });
    render(<CredentialCatalog />);

    await act(async () => canvasSession.resolve({
      organization_id: 'marty-canvas-org',
      credential_template_id: 'cfg-1',
    }));
    expect(await screen.findByTestId('credential-card-cfg-1')).toBeInTheDocument();
    expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates?organization_id=marty-canvas-org&status=active');

    await act(async () => {
      if (outcome === 'credential error') initialCredentials.reject(new Error('Old catalog failed'));
      else initialCredentials.resolve([]);
      if (outcome === 'application template error') initialApplicationTemplates.reject(new Error('Old application templates failed'));
      else initialApplicationTemplates.resolve([]);
      await Promise.allSettled([initialCredentials.promise, initialApplicationTemplates.promise]);
    });

    expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-card-cfg-2')).not.toBeInTheDocument();
    expect(screen.queryByTestId('catalog-load-alert')).not.toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.launchUnavailable')).not.toBeInTheDocument();
    expect(screen.getByTestId('credentials-count')).toHaveTextContent('catalog.resultsCount:1');
  });

  it('keeps the Canvas catalog loading when the initial-organization request finishes first', async () => {
    mockSearch = '?canvas_lti_state=state-1';
    const canvasSession = deferred<any>();
    const initialCredentials = deferred<any[]>();
    const currentCredentials = deferred<any[]>();
    const defaultGet = mockGet.getMockImplementation()!;
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/experience-sessions/current')) return canvasSession.promise;
      if (endpoint.includes('/v1/credential-templates')) {
        return endpoint.includes('organization_id=org-1')
          ? initialCredentials.promise
          : currentCredentials.promise;
      }
      return defaultGet(endpoint);
    });
    render(<CredentialCatalog />);
    await act(async () => canvasSession.resolve({
      organization_id: 'marty-canvas-org',
      credential_template_id: 'cfg-1',
    }));
    expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates?organization_id=marty-canvas-org&status=active');

    await act(async () => initialCredentials.resolve([]));

    expect(screen.queryByTestId('credentials-count')).not.toBeInTheDocument();
    expect(screen.queryByText('catalog.empty.launchUnavailable')).not.toBeInTheDocument();
    expect(screen.queryByTestId('catalog-load-alert')).not.toBeInTheDocument();

    await act(async () => currentCredentials.resolve(await defaultGet('/v1/credential-templates')));

    expect(await screen.findByTestId('credential-card-cfg-1')).toBeInTheDocument();
    expect(screen.getByTestId('credentials-count')).toHaveTextContent('catalog.resultsCount:1');
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

  it.each(['organization', 'account', 'Canvas launch'])('closes credential details when the %s scope changes', async (scope) => {
    const { user, rerender } = render(<CredentialCatalog />);
    const originalCard = await screen.findByTestId('credential-card-cfg-1');
    await user.click(within(originalCard).getByTestId('credential-details-btn'));
    expect(await screen.findByRole('dialog')).toHaveTextContent('Member Login Credential');

    if (scope === 'organization') {
      mockAuthState.organizationId = 'org-2';
    } else if (scope === 'account') {
      mockAuthState.user = { user_id: 'user-2' };
    } else {
      mockSearch = '?canvas_lti_state=another-course';
      mockLocationState = { canvasLtiSession: {
        organization_id: 'org-1',
        credential_template_id: 'cfg-2',
        application_template_id: 'app-tpl-2',
      } };
    }
    rerender(<CredentialCatalog />);

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(mockNavigate).not.toHaveBeenCalled();
    const currentCard = await screen.findByTestId(`credential-card-${scope === 'Canvas launch' ? 'cfg-2' : 'cfg-1'}`);
    await user.click(within(currentCard).getByTestId('credential-details-btn'));
    const currentDialog = await screen.findByRole('dialog');
    expect(currentDialog).toHaveTextContent(scope === 'Canvas launch' ? 'Digital Passport' : 'Member Login Credential');
    if (scope !== 'Canvas launch') {
      await user.click(within(currentDialog).getByRole('button', { name: 'catalog.card.actions.apply' }));
      expect(mockNavigate).toHaveBeenCalledWith('/apply/cfg-1', {
        state: expect.objectContaining({ applicationTemplate: expect.objectContaining({
          organization_id: scope === 'organization' ? 'org-2' : 'org-1',
        }) }),
      });
    }
  });

  it('uses new route-provided Canvas context while a previous lookup is still pending', async () => {
    const previousLaunch = deferred<any>();
    const defaultGet = mockGet.getMockImplementation()!;
    mockSearch = '?canvas_lti_state=previous-course';
    mockGet.mockImplementation((endpoint: string) => endpoint.includes('/v1/integrations/canvas/lti/experience-sessions/current')
      ? previousLaunch.promise
      : defaultGet(endpoint));
    const { rerender } = render(<CredentialCatalog />);
    await waitFor(() => expect(mockGet.mock.calls.some(([endpoint]) => endpoint === '/v1/integrations/canvas/lti/experience-sessions/current')).toBe(true));

    mockSearch = '?canvas_lti_state=current-course';
    mockLocationState = { canvasLtiSession: {
      organization_id: 'org-1',
      credential_template_id: 'cfg-2',
      application_template_id: 'app-tpl-2',
    } };
    rerender(<CredentialCatalog />);

    expect(await screen.findByTestId('credential-card-cfg-2')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-card-cfg-1')).not.toBeInTheDocument();
    expect(screen.getByTestId('credentials-count')).toHaveTextContent('catalog.resultsCount:1');
    await act(async () => previousLaunch.resolve({
      organization_id: 'previous-org', credential_template_id: 'cfg-1', application_template_id: 'app-tpl-1',
    }));

    expect(screen.getByTestId('credential-card-cfg-2')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-card-cfg-1')).not.toBeInTheDocument();
    expect(mockGet.mock.calls.filter(([endpoint]) => String(endpoint).includes('/v1/integrations/canvas/lti/experience-sessions/current'))).toHaveLength(1);
    expect(mockGet).not.toHaveBeenCalledWith('/v1/credential-templates?organization_id=previous-org&status=active');
  });
});
