import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { AuthContext } from '../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../contexts/ConsoleContext';
import NotificationBell from './NotificationBell';

const api = vi.hoisted(() => ({
  getPreferences: vi.fn(), updatePreferences: vi.fn(), getMyOrganizations: vi.fn(),
  getMyPermissions: vi.fn(), getUnreadCount: vi.fn(), dropdown: vi.fn(),
}));
vi.mock('../../services/preferencesApi', () => ({ getPreferences: api.getPreferences, updatePreferences: api.updatePreferences }));
vi.mock('../../services/organizationsApi', () => ({ getMyOrganizations: api.getMyOrganizations }));
vi.mock('../../services/rbacApi', () => ({ getMyPermissions: api.getMyPermissions }));
vi.mock('../../services/notificationsApi', () => ({ default: { getUnreadCount: api.getUnreadCount } }));
vi.mock('./NotificationDropdown', () => ({ default: (props: Record<string, unknown>) => {
  api.dropdown(props);
  return props.open ? <div role="dialog" aria-label="Notification inbox" /> : null;
} }));

const organizations = ['org-a', 'org-b'].map(id => ({
  id, name: id, membership: { status: 'active', roles: [{ name: 'admin' }], has_org_console_access: true },
}));
const auth = {
  user: { user_id: 'user-a', sub: 'user-a', roles: ['admin'], organizations },
  isAuthenticated: true, isLoading: false, isVendor: true, isApplicant: false, isAdministrator: false,
  organizationId: 'org-a', hasCapability: () => true,
};

function ScopeControls() {
  const { setActiveOrgId } = useConsole();
  return <button onClick={() => setActiveOrgId('org-b', null, { navigate: false })}>Switch organization</button>;
}
function App({ account = 'user-a', controls = false }: { account?: string; controls?: boolean }) {
  return <AuthContext.Provider value={{ ...auth, user: { ...auth.user, user_id: account, sub: account } } as any}>
    <ConsoleProvider>
      {controls && <ScopeControls />}
      <NotificationBell />
    </ConsoleProvider>
  </AuthContext.Provider>;
}
function deferred() {
  let resolve!: (value: { permissions: string[]; roles: any[] }) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<{ permissions: string[]; roles: any[] }>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

describe('notification permission recovery with the real scoped hook', () => {
  beforeEach(() => {
    Object.values(api).forEach(mock => mock.mockReset());
    window.localStorage.clear();
    api.getPreferences.mockResolvedValue({ last_view_mode: 'org', last_active_org_id: 'org-a' });
    api.updatePreferences.mockResolvedValue({});
    api.getMyOrganizations.mockResolvedValue(organizations);
    api.getUnreadCount.mockResolvedValue({ count: 2 });
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());

  it.each(['503', 'network'])('offers keyboard Retry after a %s failure and mounts notification loaders only after recovery', async failure => {
    const initial = deferred();
    api.getMyPermissions.mockReturnValue(initial.promise);
    const { user } = renderWithRouter(<App />);
    await waitFor(() => expect(api.getMyPermissions).toHaveBeenCalledWith('org-a'));
    expect(screen.queryByRole('button', { name: 'notifications', exact: true })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry notifications' })).not.toBeInTheDocument();
    expect(api.getUnreadCount).not.toHaveBeenCalled();
    expect(api.dropdown).not.toHaveBeenCalled();

    await act(async () => initial.reject(failure === '503'
      ? Object.assign(new Error('Permissions temporarily unavailable'), { status: 503 })
      : new TypeError('Failed to fetch')));
    const retry = await screen.findByRole('button', { name: 'Retry notifications' });
    await user.hover(retry);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Notifications could not be loaded.');
    expect(retry).toHaveAccessibleDescription('Notifications could not be loaded.');
    expect(api.getUnreadCount).not.toHaveBeenCalled();
    expect(api.dropdown).not.toHaveBeenCalled();
    const pending = deferred();
    api.getMyPermissions.mockReturnValue(pending.promise);
    retry.focus();
    await user.keyboard('{Enter}');
    expect(screen.queryByRole('button', { name: 'Retry notifications' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'notifications', exact: true })).not.toBeInTheDocument();
    expect(api.getUnreadCount).not.toHaveBeenCalled();
    expect(api.dropdown).not.toHaveBeenCalled();

    await act(async () => pending.resolve({ permissions: ['notification:view'], roles: [] }));
    const bell = await screen.findByRole('button', { name: 'notifications', exact: true });
    expect(api.getUnreadCount).toHaveBeenCalledExactlyOnceWith('org-a', 'user-a');
    await user.click(bell);
    expect(await screen.findByRole('dialog', { name: 'Notification inbox' })).toBeInTheDocument();
    expect(api.dropdown).toHaveBeenLastCalledWith(expect.objectContaining({ organizationId: 'org-a', recipientId: 'user-a', open: true }));
  });

  it.each(['403', 'empty grants'])('keeps a confirmed %s denial hidden without mounting notification loaders', async denial => {
    const pending = deferred();
    api.getMyPermissions.mockReturnValue(pending.promise);
    renderWithRouter(<App />);
    await waitFor(() => expect(api.getMyPermissions).toHaveBeenCalledWith('org-a'));
    await act(async () => denial === '403'
      ? pending.reject(Object.assign(new Error('Permission denied'), { status: 403 }))
      : pending.resolve({ permissions: [], roles: [] }));
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(api.getUnreadCount).not.toHaveBeenCalled();
    expect(api.dropdown).not.toHaveBeenCalled();
  });

  it.each(['organization', 'account'].flatMap(owner => ['success', 'failure'].map(outcome => ({ owner, outcome }))))(
    'discards an old Retry $outcome after changing $owner', async ({ owner, outcome }) => {
      api.getMyPermissions.mockRejectedValue(new Error('Permissions temporarily unavailable'));
      const { user, rerender } = renderWithRouter(<App controls />);
      const retry = await screen.findByRole('button', { name: 'Retry notifications' });
      const old = deferred();
      api.getMyPermissions.mockResolvedValue({ permissions: [], roles: [] }).mockReturnValueOnce(old.promise);
      const reads = api.getMyPermissions.mock.calls.length;
      await user.click(retry);
      if (owner === 'organization') await user.click(screen.getByRole('button', { name: 'Switch organization' }));
      else rerender(<App account="user-b" controls />);
      await waitFor(() => expect(api.getMyPermissions).toHaveBeenCalledTimes(reads + 2));
      await act(async () => outcome === 'success'
        ? old.resolve({ permissions: ['notification:view'], roles: [] })
        : old.reject(new Error('Old permission request failed')));
      expect(screen.queryByRole('button', { name: 'Retry notifications' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'notifications', exact: true })).not.toBeInTheDocument();
      expect(api.getUnreadCount).not.toHaveBeenCalled();
      expect(api.dropdown).not.toHaveBeenCalled();
      expect(api.getMyPermissions).toHaveBeenLastCalledWith(owner === 'organization' ? 'org-b' : 'org-a');
    },
  );

  it('does not mount notification loaders when a Retry finishes after unmount', async () => {
    api.getMyPermissions.mockRejectedValue(new Error('Permissions temporarily unavailable'));
    const { user, unmount } = renderWithRouter(<App />);
    const retry = await screen.findByRole('button', { name: 'Retry notifications' });
    const pending = deferred();
    api.getMyPermissions.mockReturnValue(pending.promise);
    await user.click(retry);
    unmount();
    await act(async () => pending.resolve({ permissions: ['notification:view'], roles: [] }));
    expect(api.getUnreadCount).not.toHaveBeenCalled();
    expect(api.dropdown).not.toHaveBeenCalled();
  });
});
