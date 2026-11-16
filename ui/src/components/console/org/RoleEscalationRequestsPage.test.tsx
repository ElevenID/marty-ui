import { beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { useLocation } from 'react-router';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import RoleEscalationRequestsPage from './RoleEscalationRequestsPage';

const { scope, getMyPermissions, unsupportedRequest } = vi.hoisted(() => ({
  scope: { organizationId: 'org-a', principalId: 'user-a', authenticated: true },
  getMyPermissions: vi.fn(),
  unsupportedRequest: vi.fn(),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    activeOrgId: scope.organizationId,
    memberships: scope.organizationId ? [{ id: scope.organizationId }] : [],
    membershipsLoaded: true,
    mode: 'org',
  }),
}));
vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ user: { user_id: scope.principalId }, isAuthenticated: scope.authenticated }),
}));
vi.mock('../../../services/rbacApi', () => ({ getMyPermissions }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

function CurrentPath() {
  const { pathname, search, hash } = useLocation();
  return <span data-testid="current-path">{pathname}{search}{hash}</span>;
}

beforeEach(() => {
  vi.clearAllMocks();
  scope.organizationId = 'org-a';
  scope.principalId = 'user-a';
  scope.authenticated = true;
  getMyPermissions.mockResolvedValue({ permissions: ['team:view', 'role:view'], roles: [] });
  server.use(http.all(/\/api\/roles(?:\/|$)/, ({ request }) => {
    unsupportedRequest(request.method, request.url);
    return HttpResponse.json({ requests: [] });
  }));
});

describe('Role Requests compatibility page', () => {
  it('explains the unavailable workflow at the old URL without loading or offering request actions', async () => {
    renderWithRouter(<><RoleEscalationRequestsPage /><CurrentPath /></>, {
      initialEntries: ['/console/org/role-requests?source=bookmark#requests'],
    });

    expect(await screen.findByRole('alert')).toHaveTextContent('Role change requests are not available in this console.');
    expect(await screen.findByRole('link', { name: 'View team' })).toHaveAttribute('href', '/console/org/team');
    expect(screen.getByRole('link', { name: 'View roles' })).toHaveAttribute('href', '/console/org/roles');
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/role-requests?source=bookmark#requests');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /approve|reject|retry|refresh/i })).not.toBeInTheDocument();
    expect(screen.queryByText('No pending role escalation requests')).not.toBeInTheDocument();
    expect(unsupportedRequest).not.toHaveBeenCalled();
  });

  it.each([
    { permissions: ['team:view'], team: true, roles: false },
    { permissions: ['role:view'], team: false, roles: true },
    { permissions: ['team:view', 'role:view'], team: true, roles: true },
    { permissions: ['role:assign'], team: false, roles: false },
    { permissions: [], team: false, roles: false },
  ])('gates destination links independently for $permissions', async ({ permissions, team, roles }) => {
    getMyPermissions.mockResolvedValue({ permissions, roles: [] });
    renderWithRouter(<RoleEscalationRequestsPage />);
    await act(async () => {});

    expect(getMyPermissions).toHaveBeenCalledWith('org-a');
    expect(Boolean(screen.queryByRole('link', { name: 'View team' }))).toBe(team);
    expect(Boolean(screen.queryByRole('link', { name: 'View roles' }))).toBe(roles);
    expect(unsupportedRequest).not.toHaveBeenCalled();
  });

  it('keeps the explanation available but hides links until current permissions resolve', async () => {
    const permissions = deferred<{ permissions: string[]; roles: unknown[] }>();
    getMyPermissions.mockReturnValue(permissions.promise);
    renderWithRouter(<RoleEscalationRequestsPage />);

    expect(screen.getByRole('alert')).toHaveTextContent('Role change requests are not available');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    await act(async () => permissions.resolve({ permissions: ['role:view'], roles: [] }));
    expect(await screen.findByRole('link', { name: 'View roles' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'View team' })).not.toBeInTheDocument();
    expect(unsupportedRequest).not.toHaveBeenCalled();
  });

  it.each(['organization', 'account'])('withdraws old destination access immediately on an %s change', async changed => {
    const view = renderWithRouter(<RoleEscalationRequestsPage />);
    await screen.findByRole('link', { name: 'View team' });
    const permissions = deferred<{ permissions: string[]; roles: unknown[] }>();
    getMyPermissions.mockReturnValueOnce(permissions.promise);
    if (changed === 'organization') scope.organizationId = 'org-b';
    else scope.principalId = 'user-b';
    view.rerender(<RoleEscalationRequestsPage />);

    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    await waitFor(() => expect(getMyPermissions).toHaveBeenCalledTimes(2));
    await act(async () => permissions.resolve({ permissions: ['role:view'], roles: [] }));
    expect(await screen.findByRole('link', { name: 'View roles' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'View team' })).not.toBeInTheDocument();
    expect(unsupportedRequest).not.toHaveBeenCalled();
  });

  it.each(['signed-out', 'no-organization'])('offers no scoped destinations for %s state', async state => {
    if (state === 'signed-out') scope.authenticated = false;
    else scope.organizationId = '';
    renderWithRouter(<RoleEscalationRequestsPage />);
    await act(async () => {});

    expect(screen.getByRole('alert')).toHaveTextContent('Role change requests are not available');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(getMyPermissions).not.toHaveBeenCalled();
    expect(unsupportedRequest).not.toHaveBeenCalled();
  });
});
