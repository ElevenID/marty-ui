import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router';
import { act, renderWithRouter, screen, waitFor, within } from '@test/utils';
import RevocationProfilesPage from '../RevocationProfilesPage';

const { context, permissions, grants, listProfiles } = vi.hoisted(() => ({
  context: { activeOrgId: 'org-1' as string | null },
  permissions: { isLoading: false },
  grants: new Set<string>(),
  listProfiles: vi.fn(),
}));

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({
    ...permissions,
    can: (resource: string, action: string) => grants.has(`${resource}:${action}`),
  }),
}));
vi.mock('../../../../services/presentationPolicyApi', () => ({
  listRevocationProfiles: listProfiles,
}));

// Keep the actual ResourcePage, BuildButton, EmptyState and translations. The
// older catalog tests replace ResourcePage with a mock that omits its actions.
const LIST_PATH = '/console/org/trust/revocation';
const CREATE_PATH = `${LIST_PATH}/new`;
const BUILD_NAME = 'Build Revocation Profile';
const profile = {
  id: 'profile-1', organization_id: 'org-1', name: 'Existing revocation profile',
  status: 'DRAFT', check_mode: 'ALWAYS', revocation_mechanism: ['STATUS_LIST_2021'],
  status_list_url: 'https://status.example.test/current', updated_at: '2026-11-09T12:00:00Z',
};

function page() {
  return <Routes>
    <Route path={LIST_PATH} element={<RevocationProfilesPage />} />
    <Route path={CREATE_PATH} element={<h1>Revocation creation entry</h1>} />
  </Routes>;
}

function renderPage() { return renderWithRouter(page(), { initialEntries: [LIST_PATH] }); }
function grantCreate() { grants.add('revocation-profile:create'); }
function expectNoCreationEntry() {
  expect(screen.queryByRole('button', { name: BUILD_NAME })).not.toBeInTheDocument();
  expect(screen.queryByRole('group', { name: BUILD_NAME })).not.toBeInTheDocument();
  expect(screen.queryByRole('menuitem', { name: /new \(advanced\)/i })).not.toBeInTheDocument();
  expect(screen.queryAllByRole('link').filter(link => link.getAttribute('href') === CREATE_PATH)).toHaveLength(0);
}

beforeEach(() => {
  context.activeOrgId = 'org-1';
  permissions.isLoading = false;
  grants.clear(); grants.add('revocation-profile:view');
  listProfiles.mockReset().mockResolvedValue([]);
});

describe('Revocation catalog creation access with real shared controls', () => {
  it.each(['empty', 'populated'])('keeps a %s catalog available to a view-only user without offering creation', async (kind) => {
    if (kind === 'populated') listProfiles.mockResolvedValue([profile]);
    renderPage();
    if (kind === 'populated') {
      expect(await screen.findByText(profile.name)).toBeInTheDocument();
      expect(screen.getByRole('link', { name: 'View' })).toHaveAttribute('href', `${LIST_PATH}/${profile.id}`);
    } else {
      expect(await screen.findByText('No revocation profiles configured.')).toBeInTheDocument();
    }
    expectNoCreationEntry();
    expect(listProfiles).toHaveBeenCalledWith(
      { organization_id: 'org-1', limit: 100, offset: 0 }, { retryConfig: { maxRetries: 0 } },
    );
  });

  it('does not treat an edit grant as create permission', async () => {
    grants.add('revocation-profile:edit');
    renderPage();
    await screen.findByText('No revocation profiles configured.');
    expectNoCreationEntry();
  });

  it('opens the existing creation route for a create-capable user with an empty catalog', async () => {
    grantCreate();
    const { user } = renderPage();
    await screen.findByText('No revocation profiles configured.');
    expect(screen.getByRole('button', { name: BUILD_NAME })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: BUILD_NAME }));
    expect(screen.getByRole('heading', { name: 'Revocation creation entry' })).toBeInTheDocument();
  });

  it('admits the native create grant independently of a list-view denial', async () => {
    grants.clear(); grantCreate();
    listProfiles.mockRejectedValue(Object.assign(new Error('List view permission denied'), { status: 403 }));
    const { user } = renderPage();
    await screen.findByText('List view permission denied');
    await user.click(screen.getByRole('button', { name: BUILD_NAME }));
    expect(screen.getByRole('heading', { name: 'Revocation creation entry' })).toBeInTheDocument();
  });

  it.each([null, '', '   '])('requires a selected nonempty organization despite an available grant: %s', async (organization) => {
    context.activeOrgId = organization; grantCreate();
    renderPage();
    await act(async () => {});
    expectNoCreationEntry();
  });

  it('waits for current permissions and withdraws creation during a permission reload', async () => {
    grantCreate(); permissions.isLoading = true;
    const view = renderPage();
    await screen.findByText('No revocation profiles configured.');
    expectNoCreationEntry();
    permissions.isLoading = false; view.rerender(page());
    expect(screen.getByRole('button', { name: BUILD_NAME })).toBeEnabled();
    permissions.isLoading = true; view.rerender(page());
    expectNoCreationEntry();
    permissions.isLoading = false; view.rerender(page());
    expect(screen.getByRole('button', { name: BUILD_NAME })).toBeEnabled();
  });

  it('removes an open creation menu when the create grant is withdrawn, then restores the current entry', async () => {
    grantCreate();
    const view = renderPage();
    await screen.findByText('No revocation profiles configured.');
    const group = screen.getByRole('group', { name: BUILD_NAME });
    await view.user.click(within(group).getByRole('button', { name: '' }));
    expect(screen.getByRole('menuitem', { name: /new \(advanced\)/i })).toBeInTheDocument();
    grants.delete('revocation-profile:create'); view.rerender(page());
    expectNoCreationEntry();
    grantCreate(); view.rerender(page());
    expect(screen.getByRole('button', { name: BUILD_NAME })).toBeEnabled();
    expect(screen.queryByRole('menuitem', { name: /new \(advanced\)/i })).not.toBeInTheDocument();
  });

  it('uses the new organization and its settled create permission after a selection change', async () => {
    grantCreate();
    const view = renderPage();
    await screen.findByText('No revocation profiles configured.');
    expect(screen.getByRole('button', { name: BUILD_NAME })).toBeEnabled();
    context.activeOrgId = 'org-2'; permissions.isLoading = true; view.rerender(page());
    expectNoCreationEntry();
    await waitFor(() => expect(listProfiles).toHaveBeenCalledWith(
      { organization_id: 'org-2', limit: 100, offset: 0 }, { retryConfig: { maxRetries: 0 } },
    ));
    permissions.isLoading = false; grants.delete('revocation-profile:create'); view.rerender(page());
    expectNoCreationEntry();
    grantCreate(); view.rerender(page());
    expect(screen.getByRole('button', { name: BUILD_NAME })).toBeEnabled();
  });

  it('keeps authorized creation available while the catalog request is pending', async () => {
    grantCreate();
    let resolve!: (value: unknown[]) => void;
    listProfiles.mockReturnValue(new Promise<unknown[]>(done => { resolve = done; }));
    const { user } = renderPage();
    await waitFor(() => expect(listProfiles).toHaveBeenCalledTimes(1));
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: BUILD_NAME })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: BUILD_NAME }));
    expect(screen.getByRole('heading', { name: 'Revocation creation entry' })).toBeInTheDocument();
    await act(async () => { resolve([]); });
  });

  it('opens the existing advanced creation entry only when creation is allowed', async () => {
    grantCreate();
    const { user } = renderPage();
    await screen.findByText('No revocation profiles configured.');
    const group = screen.getByRole('group', { name: BUILD_NAME });
    await user.click(within(group).getByRole('button', { name: '' }));
    await user.click(screen.getByRole('menuitem', { name: /new \(advanced\)/i }));
    expect(screen.getByRole('heading', { name: 'Revocation creation entry' })).toBeInTheDocument();
  });
});
