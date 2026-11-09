import { beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { renderWithRouter, screen, waitFor, within } from '@test/utils';
import { server } from '@test/mocks/server';
import RolesPage from './RolesPage';

const state = vi.hoisted(() => ({
  grants: new Set(['role:view', 'role:create', 'role:edit', 'role:delete']),
  notify: vi.fn(), refreshPermissions: vi.fn(),
}));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: 'org-current' }) }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({ organizationId: 'org-login' }) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({
  can: (resource: string, action: string) => state.grants.has(`${resource}:${action}`),
  refresh: state.refreshPermissions,
}) }));
vi.mock('../../../hooks/useNotifications', () => ({ useNotifications: () => ({ showNotification: state.notify }) }));

// Native PermissionCatalogGroup[]: resource groups have no permission id/action.
const teamPermissions = [
  { id: '3cf8e000-26c5-4d2a-a880-000000000001', resource: 'team', action: 'invite', description: 'Invite team members' },
  { id: '3cf8e000-26c5-4d2a-a880-000000000002', resource: 'team', action: 'manage', description: 'Change member roles and remove members' },
  { id: '3cf8e000-26c5-4d2a-a880-000000000003', resource: 'team', action: 'view', description: 'View team members' },
];
const roleView = { id: '3cf8e000-26c5-4d2a-a880-000000000004', resource: 'role', action: 'view' };
const catalog = [
  { resource: 'team', permissions: teamPermissions },
  { resource: 'role', permissions: [roleView] },
];
const supportRole = {
  id: '3cf8e000-26c5-4d2a-a880-000000000100', organization_id: 'org-current', name: 'support',
  display_name: 'Support agents', description: 'Customer support', is_system_role: false,
  is_default_for_new_members: false, member_count: 0, permissions: [teamPermissions[2]],
};
const ownerRole = {
  ...supportRole, id: '3cf8e000-26c5-4d2a-a880-000000000101', name: 'owner', display_name: 'Owner',
  is_system_role: true, permissions: [...teamPermissions, roleView],
};

describe('Roles native permission catalog', () => {
  let creates: Record<string, unknown>[];
  let updates: Record<string, unknown>[];
  beforeEach(() => {
    state.grants = new Set(['role:view', 'role:create', 'role:edit', 'role:delete']);
    state.notify.mockReset();
    state.refreshPermissions.mockReset().mockResolvedValue(undefined);
    creates = []; updates = [];
    server.use(
      http.get('*/v1/organizations/:org/roles', ({ params }) => {
        expect(params.org).toBe('org-current');
        return HttpResponse.json([supportRole, ownerRole]);
      }),
      http.get('*/v1/organizations/:org/permissions', ({ params }) => {
        expect(params.org).toBe('org-current');
        return HttpResponse.json(catalog);
      }),
      http.post('*/v1/organizations/:org/roles', async ({ params, request }) => {
        expect(params.org).toBe('org-current');
        const body = await request.json() as Record<string, unknown>;
        creates.push(body);
        return HttpResponse.json({ ...supportRole, ...body }, { status: 201 });
      }),
      http.patch('*/v1/organizations/:org/roles/:id', async ({ params, request }) => {
        expect(params).toMatchObject({ org: 'org-current', id: supportRole.id });
        const body = await request.json() as Record<string, unknown>;
        updates.push(body);
        // UpdateRoleRequest denies unknown fields; unlike create, it has no name.
        return 'name' in body
          ? HttpResponse.json({ detail: 'unknown field name' }, { status: 422 })
          : HttpResponse.json({ ...supportRole, ...body });
      }),
    );
  });

  async function openCreate() {
    const view = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
    await screen.findByText('Support agents');
    await view.user.click(screen.getByRole('button', { name: 'Create Role' }));
    return { ...view, dialog: within(screen.getByRole('dialog')) };
  }

  it('renders every native group action with its label and the real group count', async () => {
    const { user, dialog } = await openCreate();
    expect(dialog.getByText('0/3')).toBeInTheDocument();
    expect(dialog.getByText('0/1')).toBeInTheDocument();
    await user.click(dialog.getByRole('button', { name: /Team Management/ }));
    expect(dialog.getByRole('checkbox', { name: 'invite Invite team members' })).not.toBeChecked();
    expect(dialog.getByRole('checkbox', { name: 'manage Change member roles and remove members' })).not.toBeChecked();
    expect(dialog.getByRole('checkbox', { name: 'view View team members' })).not.toBeChecked();
    for (const checkbox of dialog.getAllByRole('checkbox')) expect(checkbox).toHaveAccessibleName();
  });

  it('selects groups and individual actions then creates using only the selected native UUIDs', async () => {
    const { user, dialog } = await openCreate();
    const selectTeam = dialog.getByRole('checkbox', { name: 'Select all Team Management permissions' });
    await user.click(selectTeam);
    expect(dialog.getByText('3/3')).toBeInTheDocument();
    await user.click(selectTeam);
    expect(dialog.getByText('0/3')).toBeInTheDocument();
    await user.click(selectTeam);
    await user.click(dialog.getByRole('button', { name: /Team Management/ }));
    await user.click(dialog.getByRole('checkbox', { name: 'manage Change member roles and remove members' }));
    expect(dialog.getByText('2/3')).toBeInTheDocument();
    await user.click(dialog.getByRole('checkbox', { name: 'Select all Role Management permissions' }));
    await user.type(dialog.getByRole('textbox', { name: /^Name/ }), 'reviewer');
    await user.type(dialog.getByRole('textbox', { name: 'Display Name' }), 'Reviewers');
    await user.click(dialog.getByRole('button', { name: 'Create Role' }));
    await waitFor(() => expect(state.notify).toHaveBeenCalledWith('Role "Reviewers" created', 'success'));
    expect(creates).toEqual([{
      name: 'reviewer', display_name: 'Reviewers', description: null,
      permission_ids: [teamPermissions[0].id, teamPermissions[2].id, roleView.id],
      is_default_for_new_members: false,
    }]);
    expect(state.refreshPermissions).toHaveBeenCalledOnce();
  });

  it('preselects an existing role and updates native editable fields without a create-only name', async () => {
    const { user } = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
    await user.click(await screen.findByRole('button', { name: 'Edit role Support agents' }));
    const dialog = within(screen.getByRole('dialog'));
    expect(dialog.getByRole('textbox', { name: /^Name/ })).toBeDisabled();
    expect(dialog.getByText('1/3')).toBeInTheDocument();
    await user.click(dialog.getByRole('button', { name: /Team Management/ }));
    expect(dialog.getByRole('checkbox', { name: 'view View team members' })).toBeChecked();
    await user.click(dialog.getByRole('checkbox', { name: 'invite Invite team members' }));
    await user.click(dialog.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(state.notify).toHaveBeenCalledWith('Role "Support agents" updated', 'success'));
    expect(updates).toEqual([{
      display_name: 'Support agents', description: 'Customer support',
      permission_ids: [teamPermissions[2].id, teamPermissions[0].id],
      is_default_for_new_members: false,
    }]);
    expect(creates).toHaveLength(0);
  });

  it('names each row action and keeps native system roles read-only', async () => {
    renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
    const edit = await screen.findByRole('button', { name: 'Edit role Support agents' });
    expect(edit).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Delete role Support agents' })).toBeEnabled();
    const systemRow = screen.getByText('Owner').closest('tr')!;
    expect(within(systemRow).getByText('System')).toBeInTheDocument();
    expect(within(systemRow).getByRole('button', { name: 'System role Owner is read-only' })).toBeDisabled();
    expect(within(systemRow).queryByRole('button', { name: /Edit role|Delete role/ })).not.toBeInTheDocument();
    for (const button of screen.getAllByRole('button')) expect(button).toHaveAccessibleName();
  });

  it.each(['role:edit', 'role:delete'])('keeps row operations limited to the %s grant', async grant => {
    state.grants = new Set(['role:view', grant]);
    renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
    const edit = await screen.findByRole('button', { name: 'Edit role Support agents' });
    const remove = screen.getByRole('button', { name: 'Delete role Support agents' });
    expect(edit.disabled).toBe(grant !== 'role:edit');
    expect(remove.disabled).toBe(grant !== 'role:delete');
    expect(screen.queryByRole('button', { name: 'Create Role' })).not.toBeInTheDocument();
  });

  it('blocks creation when a catalog is malformed and recovers through Retry', async () => {
    server.use(http.get('*/v1/organizations/:org/permissions', () => HttpResponse.json([
      { resource: 'team', permissions: [{ resource: 'team', action: 'invite' }] },
    ])));
    const { user } = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
    expect(await screen.findByText('Failed to load roles. Please try again.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create Role' })).toBeDisabled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    server.use(http.get('*/v1/organizations/:org/permissions', () => HttpResponse.json(catalog)));
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    await screen.findByText('Support agents');
    await user.click(screen.getByRole('button', { name: 'Create Role' }));
    expect(within(screen.getByRole('dialog')).getByText('0/3')).toBeInTheDocument();
    expect(creates).toHaveLength(0);
  });
});
