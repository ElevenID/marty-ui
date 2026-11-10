import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { ConsoleHeaderBar } from '../navigation/ConsoleHeaderBar';
import { OrgSwitcher } from '../navigation/OrgSwitcher';
import SidebarNavigation from '../navigation/SidebarNavigation';
import MyOrganizationsPage from '../pages/MyOrganizationsPage';
import OrgSetupPage from '../console/org/OrgSetupPage';
import OrganizationMembershipHub from '../organizations/OrganizationMembershipHub';

const state = vi.hoisted(() => ({
  activeOrgId: 'org-a' as string | null,
  mobile: false,
  setActiveOrgId: vi.fn(), setMode: vi.fn(), showError: vi.fn(), navigate: vi.fn(),
  memberships: [] as any[],
}));
vi.mock('../../contexts/ConsoleContext', () => ({ useConsole: () => ({
  ...state, mode: 'org', membershipsLoaded: true, membershipLoadError: null,
  isOrgBootstrapRequired: false, isOrgBlocked: false,
  isOrgConsoleAvailable: true, isApplicantConsoleAvailable: true,
}) }));
vi.mock('../../hooks/useAuth', () => ({ useAuth: () => ({
  user: { user_id: 'user-a', name: 'Current User' }, isAuthenticated: true,
  isAdministrator: false, isVendor: true, isApplicant: true, logout: vi.fn(),
  organizationId: 'org-a', organizationName: 'Marty Org',
}) }));
vi.mock('../../hooks/usePermissions', () => ({ usePermissions: () => ({ can: () => true }) }));
vi.mock('../../hooks/useNotifications', () => ({ useNotifications: () => ({ showError: state.showError }) }));
vi.mock('../../hooks/useBranding', () => ({ useBranding: () => ({
  branding: { appName: 'Marty', shortName: 'Marty', logoUrl: null },
}) }));
vi.mock('../../services/organizationsApi', () => ({ getMyOrganizations: async () => state.memberships }));
vi.mock('react-router', async () => ({
  ...await vi.importActual<typeof import('react-router')>('react-router'),
  useNavigate: () => state.navigate,
}));
vi.mock('@mui/material', async () => ({
  ...await vi.importActual<typeof import('@mui/material')>('@mui/material'),
  useMediaQuery: (query: string) => {
    // Header lifecycle callers use the inline switcher on wider mobile screens.
    const viewportWidth = state.mobile ? 768 : 1280;
    const maximum = query.match(/max-width:\s*([\d.]+)px/)?.[1];
    return maximum !== undefined && viewportWidth <= Number(maximum);
  },
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

type Caller = 'header organization' | 'header mode' | 'switcher' | 'sidebar expanded'
  | 'sidebar collapsed' | 'profile hub' | 'my organizations' | 'setup';
const callers: Caller[] = ['header organization', 'header mode', 'switcher', 'sidebar expanded',
  'sidebar collapsed', 'profile hub', 'my organizations', 'setup'];

function renderCaller(caller: Caller, initialEntry = '/console/org') {
  state.mobile = caller.startsWith('header');
  if (caller === 'sidebar collapsed') localStorage.setItem('sidebar-collapsed', 'true');
  if (caller === 'setup') state.activeOrgId = null;
  const component = caller.startsWith('header') ? <ConsoleHeaderBar onMobileMenuToggle={vi.fn()} />
    : caller === 'switcher' ? <OrgSwitcher collapsed={false} variant="header" />
    : caller.startsWith('sidebar') ? <SidebarNavigation mobileOpen={false} onMobileClose={vi.fn()} />
    : caller === 'profile hub' ? <OrganizationMembershipHub organizations={state.memberships}
      activeOrgId="org-a" onSwitchToOrg={state.setActiveOrgId} />
    : caller === 'my organizations' ? <MyOrganizationsPage /> : <OrgSetupPage />;
  const view = renderWithRouter(component, { initialEntries: [initialEntry] });
  const trigger = async () => {
    if (caller === 'header organization') {
      await view.user.click(screen.getByRole('button', { name: 'MO' }));
      await view.user.click(screen.getByRole('menuitem', { name: /Beta Org/ }));
    } else if (caller === 'header mode') {
      await view.user.click(screen.getByRole('button', { name: 'Me' }));
    } else if (caller === 'switcher') {
      await view.user.click(screen.getByRole('combobox'));
      await view.user.click(screen.getByRole('option', { name: 'Beta Org' }));
    } else if (caller.startsWith('sidebar')) {
      await view.user.click(screen.getByRole('button', {
        name: caller === 'sidebar collapsed' ? 'Applicant Console' : 'Applicant',
      }));
    } else {
      await view.user.click((await screen.findAllByRole('button', { name: 'Open Org Console' }))[0]);
    }
  };
  return { ...view, trigger };
}

describe('console selection caller lifetimes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    state.activeOrgId = 'org-a';
    state.mobile = false;
    state.setActiveOrgId.mockReset().mockResolvedValue(undefined);
    state.setMode.mockReset().mockResolvedValue(undefined);
    state.memberships = [
      { id: 'org-a', name: 'Marty Org', membership: { status: 'active', has_org_console_access: true, roles: [{ name: 'owner' }] } },
      { id: 'org-b', name: 'Beta Org', membership: { status: 'active', has_org_console_access: true, roles: [{ name: 'owner' }] } },
    ];
  });
  afterEach(() => vi.restoreAllMocks());

  it.each(callers)('%s handles provider cancellation without reporting an error', async caller => {
    const canceled = Object.assign(new Error('The console session or selection changed.'), { name: 'AbortError' });
    state.setActiveOrgId.mockRejectedValue(canceled);
    state.setMode.mockRejectedValue(canceled);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const view = renderCaller(caller);
    await view.trigger();
    await act(async () => {});
    expect(state.setActiveOrgId.mock.calls.length + state.setMode.mock.calls.length).toBe(1);
    expect(logged.mock.calls.flat()).not.toContain(canceled);
    expect(state.showError).not.toHaveBeenCalled();
    expect(state.navigate).not.toHaveBeenCalled();
  });

  it.each(callers.filter(caller => caller !== 'setup'))('%s still reports a current genuine failure', async caller => {
    const error = new Error('Organization switch unavailable');
    state.setActiveOrgId.mockRejectedValue(error);
    state.setMode.mockRejectedValue(error);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const view = renderCaller(caller);
    await view.trigger();
    await waitFor(() => expect(logged.mock.calls.flat()).toContain(error));
    if (caller === 'my organizations') expect(state.showError).toHaveBeenCalledTimes(1);
  });

  it('setup preserves its own returnTo query and hash after a current selection', async () => {
    const target = '/console/org/settings?tab=trust#keys';
    const view = renderCaller('setup', '/console/org/setup?returnTo=' + encodeURIComponent(target));
    await view.trigger();
    expect(state.setActiveOrgId).toHaveBeenCalledWith('org-a', null, { navigate: false });
    expect(state.navigate).toHaveBeenCalledExactlyOnceWith(target);
  });

  it('setup cannot navigate back after leaving during a selection', async () => {
    const result = deferred<void>();
    state.setActiveOrgId.mockReturnValue(result.promise);
    const view = renderCaller('setup');
    await view.trigger();
    view.unmount();
    await act(async () => result.resolve());
    expect(state.navigate).not.toHaveBeenCalled();
  });

  it('my organizations cannot show a late failure toast after leaving the page', async () => {
    const result = deferred<void>();
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    state.setActiveOrgId.mockReturnValue(result.promise);
    const view = renderCaller('my organizations');
    await view.trigger();
    view.unmount();
    const error = new Error('Late request failure');
    await act(async () => result.reject(error));
    expect(state.showError).not.toHaveBeenCalled();
    expect(logged.mock.calls.flat()).not.toContain(error);
  });

  it('my organizations ignores a prior selection failure after a newer choice', async () => {
    const result = deferred<void>();
    state.setActiveOrgId.mockReturnValueOnce(result.promise).mockResolvedValue(undefined);
    state.memberships.push({ id: 'org-c', name: 'Gamma Org', membership: {
      status: 'active', has_org_console_access: true, roles: [{ name: 'owner' }],
    } });
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const view = renderCaller('my organizations');
    const buttons = await screen.findAllByRole('button', { name: 'Open Org Console' });
    await view.user.click(buttons[0]);
    await view.user.click(buttons[1]);
    const error = new Error('Previous selection failure');
    await act(async () => result.reject(error));
    expect(state.setActiveOrgId).toHaveBeenCalledTimes(2);
    expect(state.showError).not.toHaveBeenCalled();
    expect(logged.mock.calls.flat()).not.toContain(error);
  });
});
