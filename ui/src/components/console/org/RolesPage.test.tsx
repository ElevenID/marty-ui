import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { act, renderWithRouter, screen, waitFor, within } from '@test/utils';
import { server } from '@test/mocks/server';
import RolesPage from './RolesPage';
import * as rbacApi from '../../../services/rbacApi';

const state = vi.hoisted(() => ({
  grants: new Set(['role:view', 'role:create', 'role:edit', 'role:delete']),
  orgId: 'org-current', permissionsLoading: false,
  notify: vi.fn(), refreshPermissions: vi.fn(),
}));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: state.orgId }) }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({ organizationId: 'org-login' }) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({
  can: (resource: string, action: string) => state.grants.has(`${resource}:${action}`),
  refresh: state.refreshPermissions,
  isLoading: state.permissionsLoading,
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
const adminRole = { ...ownerRole, name: 'admin', display_name: 'Admin' };
const viewerRole = {
  ...supportRole, id: '3cf8e000-26c5-4d2a-a880-000000000102', name: 'viewer', display_name: 'Viewer',
  is_default_for_new_members: true,
};

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

describe('Roles native permission catalog', () => {
  let creates: Record<string, unknown>[];
  let updates: Record<string, unknown>[];
  let inventory = [supportRole, ownerRole];
  let deletes: Array<{ id: string; replacement: string | null }>;
  beforeEach(() => {
    state.orgId = 'org-current'; state.permissionsLoading = false;
    state.grants = new Set(['role:view', 'role:create', 'role:edit', 'role:delete']);
    state.notify.mockReset();
    state.refreshPermissions.mockReset().mockResolvedValue(undefined);
    creates = []; updates = [];
    deletes = []; inventory = [supportRole, ownerRole];
    server.use(
      http.get('*/v1/organizations/:org/roles', ({ params }) => {
        expect(params.org).toBe('org-current');
        return HttpResponse.json(inventory);
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
      http.delete('*/v1/organizations/:org/roles/:id', ({ params, request }) => {
        expect(params.org).toBe('org-current');
        deletes.push({ id: String(params.id), replacement: new URL(request.url).searchParams.get('replacement_role_id') });
        inventory = inventory.filter(role => role.id !== params.id);
        return new HttpResponse(null, { status: 204 });
      }),
    );
  });
  afterEach(() => vi.restoreAllMocks());

  async function openCreate() {
    const view = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
    await screen.findByText('Support agents');
    await view.user.click(screen.getByRole('button', { name: 'Create Role' }));
    return { ...view, dialog: within(screen.getByRole('dialog')) };
  }

  function mockNativeOptionalFieldReadback() {
    let storedRole = { ...supportRole };
    server.use(
      http.get('*/v1/organizations/:org/roles', () => HttpResponse.json([storedRole, ownerRole])),
      http.patch('*/v1/organizations/:org/roles/:id', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>;
        updates.push(body);
        if ('name' in body) return HttpResponse.json({ detail: 'unknown field name' }, { status: 422 });
        // Native Option<String> ignores null/omitted fields. Only an explicit
        // description string clears text; a display name must remain nonempty.
        if (typeof body.display_name === 'string') {
          if (!body.display_name.trim()) {
            return HttpResponse.json({ detail: 'display_name must not be empty' }, { status: 400 });
          }
          storedRole = { ...storedRole, display_name: body.display_name };
        }
        if (typeof body.description === 'string') {
          storedRole = { ...storedRole, description: body.description };
        }
        return HttpResponse.json(storedRole);
      }),
    );
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

  it('clears an existing description with an explicit empty string and confirms the saved readback', async () => {
    mockNativeOptionalFieldReadback();
    const { user } = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
    await user.click(await screen.findByRole('button', { name: 'Edit role Support agents' }));
    const dialog = within(screen.getByRole('dialog'));
    await user.clear(dialog.getByRole('textbox', { name: 'Description' }));
    await user.click(dialog.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    const edit = await screen.findByRole('button', { name: 'Edit role Support agents' });
    const row = within(edit.closest('tr')!);
    expect(row.queryByText('Customer support')).not.toBeInTheDocument();
    expect(updates).toEqual([expect.objectContaining({ description: '' })]);
    expect(updates[0]).not.toHaveProperty('name');
    await user.click(edit);
    expect(within(screen.getByRole('dialog')).getByRole('textbox', { name: 'Description' })).toHaveValue('');
  });

  it.each(['', '   '])('resets a blank display name %j to the immutable role name and confirms readback', async blank => {
    mockNativeOptionalFieldReadback();
    const { user } = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
    await user.click(await screen.findByRole('button', { name: 'Edit role Support agents' }));
    const dialog = within(screen.getByRole('dialog'));
    const displayName = dialog.getByRole('textbox', { name: 'Display Name' });
    await user.clear(displayName);
    if (blank) await user.type(displayName, blank);
    await user.click(dialog.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    const edit = await screen.findByRole('button', { name: 'Edit role support' });
    expect(updates).toEqual([expect.objectContaining({ display_name: 'support' })]);
    expect(updates[0]).not.toHaveProperty('name');
    expect(state.notify).toHaveBeenCalledWith('Role "support" updated', 'success');
    expect(state.notify).not.toHaveBeenCalledWith(expect.anything(), 'error');
    await user.click(edit);
    const reopened = within(screen.getByRole('dialog'));
    expect(reopened.getByRole('textbox', { name: 'Display Name' })).toHaveValue('support');
    expect(reopened.getByText('Leave blank to use the role name.')).toBeInTheDocument();
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
    expect((edit as HTMLButtonElement).disabled).toBe(grant !== 'role:edit');
    expect((remove as HTMLButtonElement).disabled).toBe(grant !== 'role:delete');
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

  it('keeps a genuine current save failure visible and retryable', async () => {
    let attempts = 0;
    server.use(http.post('*/v1/organizations/:org/roles', () => {
      attempts += 1;
      return attempts === 1 ? HttpResponse.json({ detail: 'That role name is taken' }, { status: 409 })
        : HttpResponse.json(supportRole, { status: 201 });
    }));
    const { user, dialog } = await openCreate();
    await user.type(dialog.getByRole('textbox', { name: /^Name/ }), 'support');
    await user.click(dialog.getByRole('button', { name: 'Create Role' }));
    await waitFor(() => expect(state.notify).toHaveBeenCalledWith('That role name is taken', 'error'));
    expect(dialog.getByRole('button', { name: 'Create Role' })).toBeEnabled();
    await user.click(dialog.getByRole('button', { name: 'Create Role' }));
    await waitFor(() => expect(state.notify).toHaveBeenCalledWith('Role "support" created', 'success'));
    expect(attempts).toBe(2);
  });

  describe('explicit role deletion replacement', () => {
    async function openDelete() {
      const view = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
      await view.user.click(await screen.findByRole('button', { name: 'Delete role Support agents' }));
      return { ...view, dialog: within(screen.getByRole('dialog')) };
    }

    it.each([
      ['assigned', { member_count: 2, is_default_for_new_members: false }],
      ['default with no members', { member_count: 0, is_default_for_new_members: true }],
    ])('requires an explicit choice for an %s role even with Admin first and a default available', async (_, changes) => {
      inventory = [adminRole, { ...supportRole, ...changes }, viewerRole];
      const { user, dialog } = await openDelete();
      expect(dialog.getByRole('combobox', { name: 'Replacement role' })).not.toHaveTextContent(/Admin|Viewer/);
      await user.click(dialog.getByRole('button', { name: 'Delete' }));
      expect(await dialog.findByText('Choose a replacement role before deleting this role.')).toBeInTheDocument();
      expect(deletes).toHaveLength(0);
    });

    it('confirms the chosen replacement by name and forwards exactly that role ID', async () => {
      inventory = [adminRole, { ...supportRole, member_count: 2 }, viewerRole];
      const { user, dialog } = await openDelete();
      await user.click(dialog.getByRole('combobox', { name: 'Replacement role' }));
      await user.click(screen.getByRole('option', { name: 'Viewer' }));
      expect(dialog.getByText('Members who would otherwise have no roles will receive "Viewer".')).toBeInTheDocument();
      await user.click(dialog.getByRole('button', { name: 'Delete' }));
      await waitFor(() => expect(state.notify).toHaveBeenCalledWith('Role "Support agents" deleted', 'success'));
      expect(deletes).toEqual([{ id: supportRole.id, replacement: viewerRole.id }]);
    });

    it.each(['removed', 'another organization'])('rejects a replacement that is %s when confirmation refreshes the inventory', async condition => {
      inventory = [adminRole, { ...supportRole, member_count: 2 }, viewerRole];
      const { user, dialog } = await openDelete();
      await user.click(dialog.getByRole('combobox', { name: 'Replacement role' }));
      await user.click(screen.getByRole('option', { name: 'Viewer' }));
      inventory = [adminRole, { ...supportRole, member_count: 2 },
        ...(condition === 'removed' ? [] : [{ ...viewerRole, organization_id: 'org-other' }])];
      await user.click(dialog.getByRole('button', { name: 'Delete' }));
      expect(await dialog.findByText('The selected replacement role is no longer available. Choose another role.')).toBeInTheDocument();
      expect(deletes).toHaveLength(0);
    });

    it('deletes an empty non-default role without requiring or sending a replacement', async () => {
      const { user, dialog } = await openDelete();
      expect(dialog.queryByRole('combobox', { name: 'Replacement role' })).not.toBeInTheDocument();
      await user.click(dialog.getByRole('button', { name: 'Delete' }));
      await waitFor(() => expect(state.notify).toHaveBeenCalledWith('Role "Support agents" deleted', 'success'));
      expect(deletes).toEqual([{ id: supportRole.id, replacement: null }]);
    });

    it('requires a choice if an empty role gained members before confirmation', async () => {
      const { user, dialog } = await openDelete();
      inventory = [adminRole, { ...supportRole, member_count: 1 }, viewerRole];
      await user.click(dialog.getByRole('button', { name: 'Delete' }));
      expect(await dialog.findByText('Choose a replacement role before deleting this role.')).toBeInTheDocument();
      expect(dialog.getByRole('combobox', { name: 'Replacement role' })).toBeInTheDocument();
      expect(deletes).toHaveLength(0);
    });

    it('keeps an explicit replacement selected when native deletion fails so it can be retried', async () => {
      inventory = [adminRole, { ...supportRole, member_count: 2 }, viewerRole];
      let attempts = 0;
      server.use(http.delete('*/v1/organizations/:org/roles/:id', ({ request }) => {
        attempts += 1;
        expect(new URL(request.url).searchParams.get('replacement_role_id')).toBe(viewerRole.id);
        return attempts === 1 ? HttpResponse.json({ detail: 'Role changed; try again' }, { status: 409 })
          : new HttpResponse(null, { status: 204 });
      }));
      const { user, dialog } = await openDelete();
      await user.click(dialog.getByRole('combobox', { name: 'Replacement role' }));
      await user.click(screen.getByRole('option', { name: 'Viewer' }));
      await user.click(dialog.getByRole('button', { name: 'Delete' }));
      expect(await dialog.findByText('Role changed; try again')).toBeInTheDocument();
      expect(dialog.getByRole('combobox', { name: 'Replacement role' })).toHaveTextContent('Viewer');
      await user.click(dialog.getByRole('button', { name: 'Delete' }));
      await waitFor(() => expect(state.notify).toHaveBeenCalledWith('Role "Support agents" deleted', 'success'));
      expect(attempts).toBe(2);
    });

    it('does not send a queued deletion after the delete grant is lost during validation', async () => {
      inventory = [adminRole, { ...supportRole, member_count: 2 }, viewerRole];
      const { user, dialog, rerender } = await openDelete();
      await user.click(dialog.getByRole('combobox', { name: 'Replacement role' }));
      await user.click(screen.getByRole('option', { name: 'Viewer' }));
      const gate = deferred(); const completed = deferred();
      let reads = 0;
      const actualListRoles = rbacApi.listRoles;
      vi.spyOn(rbacApi, 'listRoles').mockImplementation(async (...args) => {
        try { return await actualListRoles(...args); } finally { completed.resolve(); }
      });
      server.use(http.get('*/v1/organizations/:org/roles', async () => {
        reads += 1;
        if (reads === 1) await gate.promise;
        return HttpResponse.json(inventory);
      }));
      await user.click(dialog.getByRole('button', { name: 'Delete' }));
      await waitFor(() => expect(reads).toBe(1));
      state.grants.delete('role:delete'); rerender(<RolesPage />);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      await act(async () => { gate.resolve(); await completed.promise; });
      expect(deletes).toHaveLength(0);
      expect(state.notify).not.toHaveBeenCalled();
    });
  });

  describe('organization and grant lifetime', () => {
    it.each(['no organization', 'permissions loading', 'view denied'])('does not load role inventory while %s', async condition => {
      if (condition === 'no organization') state.orgId = '';
      if (condition === 'permissions loading') state.permissionsLoading = true;
      if (condition === 'view denied') state.grants.delete('role:view');
      let reads = 0;
      server.use(
        http.get('*/v1/organizations/:org/roles', () => { reads += 1; return HttpResponse.json(inventory); }),
        http.get('*/v1/organizations/:org/permissions', () => { reads += 1; return HttpResponse.json(catalog); }),
      );
      renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
      await act(async () => {});
      expect(reads).toBe(0);
      expect(screen.queryByRole('button', { name: 'Create Role' })).not.toBeInTheDocument();
      expect(screen.queryByText('Support agents')).not.toBeInTheDocument();
    });

    it.each(['success', 'error'])('ignores a delayed old-organization inventory %s', async result => {
      const gate = deferred(); const completed = deferred();
      const actualListRoles = rbacApi.listRoles;
      vi.spyOn(rbacApi, 'listRoles').mockImplementation(async (...args) => {
        try { return await actualListRoles(...args); }
        finally { if (args[0] === 'org-current') completed.resolve(); }
      });
      let oldReads = 0;
      server.use(
        http.get('*/v1/organizations/:org/roles', async ({ params }) => {
          if (params.org === 'org-current') {
            oldReads += 1; await gate.promise;
            return result === 'success' ? HttpResponse.json(inventory)
              : HttpResponse.json({ detail: 'Old request denied' }, { status: 403 });
          }
          return HttpResponse.json([{ ...supportRole, organization_id: 'org-other', display_name: 'Other organization role' }]);
        }),
        http.get('*/v1/organizations/:org/permissions', () => HttpResponse.json(catalog)),
      );
      const view = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
      await waitFor(() => expect(oldReads).toBe(1));
      state.orgId = 'org-other'; view.rerender(<RolesPage />);
      await screen.findByText('Other organization role');
      await act(async () => { gate.resolve(); await completed.promise; });
      expect(screen.getByText('Other organization role')).toBeInTheDocument();
      expect(screen.queryByText('Support agents')).not.toBeInTheDocument();
      expect(screen.queryByText('Failed to load roles. Please try again.')).not.toBeInTheDocument();
    });

    it.each(['organization', 'view grant'])('closes and clears a role form when the %s changes', async change => {
      const view = await openCreate();
      await view.user.type(view.dialog.getByRole('textbox', { name: /^Name/ }), 'old-draft');
      if (change === 'organization') state.orgId = 'org-other';
      else state.grants.delete('role:view');
      server.use(
        http.get('*/v1/organizations/:org/roles', () => HttpResponse.json([{ ...supportRole, organization_id: 'org-other', display_name: 'Other organization role' }])),
        http.get('*/v1/organizations/:org/permissions', () => HttpResponse.json(catalog)),
      );
      view.rerender(<RolesPage />);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(screen.queryByDisplayValue('old-draft')).not.toBeInTheDocument();
      if (change === 'organization') {
        await screen.findByText('Other organization role');
        await view.user.click(screen.getByRole('button', { name: 'Create Role' }));
        expect(within(screen.getByRole('dialog')).getByRole('textbox', { name: /^Name/ })).toHaveValue('');
      }
    });

    it.each(['success', 'error'])('drops obsolete save %s feedback and follow-up refreshes after switching organizations', async result => {
      const gate = deferred(); const completed = deferred();
      const actualCreateRole = rbacApi.createRole;
      vi.spyOn(rbacApi, 'createRole').mockImplementation(async (...args) => {
        try { return await actualCreateRole(...args); } finally { completed.resolve(); }
      });
      let writes = 0;
      server.use(http.post('*/v1/organizations/:org/roles', async () => {
        writes += 1; await gate.promise;
        return result === 'success' ? HttpResponse.json(supportRole, { status: 201 })
          : HttpResponse.json({ detail: 'Old save rejected' }, { status: 422 });
      }));
      const view = await openCreate();
      await view.user.type(view.dialog.getByRole('textbox', { name: /^Name/ }), 'old-draft');
      await view.user.click(view.dialog.getByRole('button', { name: 'Create Role' }));
      await waitFor(() => expect(writes).toBe(1));
      let currentReads = 0;
      server.use(
        http.get('*/v1/organizations/:org/roles', () => {
          currentReads += 1;
          return HttpResponse.json([{ ...supportRole, organization_id: 'org-other', display_name: 'Other organization role' }]);
        }),
        http.get('*/v1/organizations/:org/permissions', () => HttpResponse.json(catalog)),
      );
      state.orgId = 'org-other'; view.rerender(<RolesPage />);
      await screen.findByText('Other organization role');
      await act(async () => { gate.resolve(); await completed.promise; });
      expect(state.notify).not.toHaveBeenCalled();
      expect(state.refreshPermissions).not.toHaveBeenCalled();
      expect(currentReads).toBe(1);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it.each(['create', 'update', 'delete'] as const)('checks the %s handoff when unmounted in the final-await microtask', async operation => {
      const view = renderWithRouter(<RolesPage />, { initialEntries: ['/console/org/roles'] });
      await screen.findByText('Support agents');
      await view.user.click(screen.getByRole('button', { name: operation === 'create' ? 'Create Role'
        : operation === 'update' ? 'Edit role Support agents' : 'Delete role Support agents' }));
      const dialog = within(screen.getByRole('dialog'));
      if (operation === 'create') await view.user.type(dialog.getByRole('textbox', { name: /^Name/ }), 'reviewer');
      const pending = deferred();
      const request = vi.spyOn(rbacApi, operation === 'create' ? 'createRole'
        : operation === 'update' ? 'updateRole' : 'deleteRole').mockReturnValue(pending.promise);
      await view.user.click(dialog.getByRole('button', { name: operation === 'create' ? 'Create Role'
        : operation === 'update' ? 'Save Changes' : 'Delete' }));
      await waitFor(() => expect(request).toHaveBeenCalledOnce());
      // The real action.run is already awaiting this promise. Its finally runs
      // first, this observer unmounts next, then the caller resumes after await.
      const unmounted = pending.promise.then(() => view.unmount());
      await act(async () => { pending.resolve(); await unmounted; });
      expect(state.notify).not.toHaveBeenCalled();
      expect(state.refreshPermissions).not.toHaveBeenCalled();
    });
  });
});
