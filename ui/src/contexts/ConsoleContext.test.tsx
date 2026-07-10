import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import { AuthContext } from './AuthContext';
import { ConsoleProvider, useConsole } from './ConsoleContext';
import { getPreferences, updatePreferences } from '../services/preferencesApi';
import { getMyOrganizations } from '../services/organizationsApi';

vi.mock('../services/preferencesApi', () => ({
  getPreferences: vi.fn(),
  updatePreferences: vi.fn(),
}));

vi.mock('../services/organizationsApi', () => ({
  getMyOrganizations: vi.fn(),
}));

function Probe() {
  const {
    mode,
    activeOrgId,
    memberships,
    membershipsLoaded,
    membershipLoadError,
    isOrgBootstrapRequired,
    isLoading,
  } = useConsole();

  return (
    <div>
      <div data-testid="mode">{mode}</div>
      <div data-testid="active-org">{activeOrgId || ''}</div>
      <div data-testid="loading">{isLoading ? 'loading' : 'ready'}</div>
      <div data-testid="loaded">{membershipsLoaded ? 'loaded' : 'not-loaded'}</div>
      <div data-testid="memberships">{memberships.length}</div>
      <div data-testid="bootstrap">{isOrgBootstrapRequired ? 'required' : 'optional'}</div>
      <div data-testid="error">{membershipLoadError?.message || ''}</div>
      <div data-testid="message-id">{membershipLoadError?.messageId || ''}</div>
    </div>
  );
}

function renderProvider(userOverrides = {}) {
  const setActiveOrganizationId = vi.fn();
  const authValue = {
    user: {
      user_id: 'user-1',
      email: 'vendor@example.com',
      roles: ['vendor'],
      capabilities: { 'org:view': true },
      organizations: [],
      ...userOverrides,
    },
    isAuthenticated: true,
    isLoading: false,
    setActiveOrganizationId,
  };

  return {
    setActiveOrganizationId,
    ...renderWithRouter(
    <AuthContext.Provider value={authValue as any}>
      <ConsoleProvider>
        <Probe />
      </ConsoleProvider>
    </AuthContext.Provider>
    ),
  };
}

describe('ConsoleContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    vi.mocked(getPreferences).mockResolvedValue({
      last_view_mode: 'org',
      last_active_org_id: 'org-1',
    });
    vi.mocked(updatePreferences).mockResolvedValue({
      last_view_mode: 'org',
      last_active_org_id: 'org-1',
    });
  });

  it('treats organization membership load failures as errors, not loaded empty memberships', async () => {
    const error = new Error('Service unavailable') as Error & {
      status?: number;
      response?: { message_id?: string; error_description?: string };
    };
    error.status = 503;
    error.response = {
      message_id: 'msg-503',
      error_description: 'Organization service unavailable',
    };
    vi.mocked(getMyOrganizations).mockRejectedValue(error);

    renderProvider();

    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('ready');
    });

    expect(vi.mocked(getMyOrganizations)).toHaveBeenCalledWith({ retryConfig: { maxRetries: 0 } });
    expect(screen.getByTestId('loaded')).toHaveTextContent('not-loaded');
    expect(screen.getByTestId('memberships')).toHaveTextContent('0');
    expect(screen.getByTestId('bootstrap')).toHaveTextContent('required');
    expect(screen.getByTestId('error')).toHaveTextContent('Organization service unavailable');
    expect(screen.getByTestId('message-id')).toHaveTextContent('msg-503');
  });

  it('preserves the selected fallback org while memberships refresh after org creation', async () => {
    window.localStorage.setItem('activeOrgId', 'org-new');
    vi.mocked(getMyOrganizations).mockResolvedValue([
      {
        id: 'org-old',
        name: 'Old Org',
        membership: {
          roles: [{ name: 'owner' }],
          has_org_console_access: true,
        },
      },
    ]);

    renderProvider({
      organization_id: 'org-new',
      organization_name: 'New Org',
      organizations: [
        {
          id: 'org-new',
          name: 'new-org',
          display_name: 'New Org',
          membership: {
            roles: [{ name: 'owner' }],
            has_org_console_access: true,
          },
        },
      ],
    });

    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('ready');
    });

    expect(screen.getByTestId('loaded')).toHaveTextContent('loaded');
    expect(screen.getByTestId('memberships')).toHaveTextContent('2');
    expect(screen.getByTestId('mode')).toHaveTextContent('org');
    expect(screen.getByTestId('active-org')).toHaveTextContent('org-new');
  });

  it('syncs back to the configured default Marty org when no org-console membership is available', async () => {
    window.localStorage.setItem('activeOrgId', 'org-stale');
    vi.mocked(getPreferences).mockResolvedValue({
      last_view_mode: 'org',
      last_active_org_id: 'org-stale',
    });
    vi.mocked(getMyOrganizations).mockResolvedValue([
      {
        id: '00000000-0000-0000-0000-000000000001',
        name: 'Marty',
        display_name: 'Marty Identity Platform',
        membership: {
          roles: [{ name: 'applicant' }],
          has_org_console_access: false,
        },
      },
    ]);

    const { setActiveOrganizationId } = renderProvider({
      organization_id: 'org-stale',
      default_organization_id: '00000000-0000-0000-0000-000000000001',
    });

    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('ready');
    });

    expect(screen.getByTestId('loaded')).toHaveTextContent('loaded');
    expect(screen.getByTestId('memberships')).toHaveTextContent('0');
    expect(screen.getByTestId('mode')).toHaveTextContent('applicant');
    expect(screen.getByTestId('active-org')).toHaveTextContent('');
    expect(setActiveOrganizationId).toHaveBeenCalledWith('00000000-0000-0000-0000-000000000001');
    expect(vi.mocked(updatePreferences)).toHaveBeenCalledWith({
      last_view_mode: 'applicant',
      last_active_org_id: null,
    });
  });
});
