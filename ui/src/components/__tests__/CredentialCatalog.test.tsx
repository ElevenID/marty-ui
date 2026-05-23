import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@test/utils';

import CredentialCatalog from '../applicant/CredentialCatalog';

const { mockNavigate, mockGet, mockGetApplicantByUser, mockAuthState } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockGet: vi.fn(),
  mockGetApplicantByUser: vi.fn(),
  mockAuthState: {
    organizationId: 'org-1' as string | null,
    organizationName: 'Acme Org' as string | null,
    user: { user_id: 'user-1' } as any,
  },
}));

let mockPathname = '/';
let mockSearch = '';
let mockLocationState: any = null;

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string, options?: any) => options?.count !== undefined ? `${key}:${options.count}` : key }),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
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
  usePreview: () => ({ isPreview: false }),
}));

vi.mock('../../services/api', () => ({
  get: mockGet,
}));

vi.mock('../../services/applicantApi', () => ({
  getApplicantByUser: mockGetApplicantByUser,
}));

describe('CredentialCatalog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPathname = '/';
    mockSearch = '';
    mockLocationState = null;
    mockAuthState.organizationId = 'org-1';
    mockAuthState.organizationName = 'Acme Org';
    mockAuthState.user = { user_id: 'user-1' };
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/v1/integrations/canvas/lti/experience-sessions/state-1')) {
        return Promise.resolve({
          state: 'state-1',
          organization_id: 'marty-canvas-org',
          canvas_platform_id: 'platform-1',
          canvas_program_binding_id: 'binding-1',
          application_template_id: 'app-tpl-1',
          credential_template_id: 'cfg-1',
          verified_launch: {
            subject: 'learner-1',
          },
          mip_primitives: {
            context: {
              organization_id: 'marty-canvas-org',
              canvas_platform_id: 'platform-1',
              canvas_program_binding_id: 'binding-1',
              application_template_id: 'app-tpl-1',
              credential_template_id: 'cfg-1',
            },
          },
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
          },
          {
            id: 'cfg-2',
            credential_type: 'passport',
            name: 'Digital Passport',
            description: 'Travel credential',
            claims: [],
            status: 'active',
          },
        ]);
      }

      if (endpoint.includes('/v1/applicants/profiles/app-1/applications')) {
        return Promise.resolve([
          { credential_configuration_id: 'cfg-2' },
        ]);
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

  it('loads credentials, marks existing applications, filters, and navigates with serializable state', async () => {
    const { user } = render(<CredentialCatalog />);

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
      expect(screen.getByTestId('credential-card-cfg-2')).toBeInTheDocument();
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
          canvasLtiSession: expect.objectContaining({
            state: 'state-1',
            credential_template_id: 'cfg-1',
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
      },
    });
  });
});
