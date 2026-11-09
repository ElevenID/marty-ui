import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { listPermissions } from '../rbacApi';
import permissionCatalog from '../../../../contracts/organization-permission-catalog.json';

const invite = { id: '3cf8e000-26c5-4d2a-a880-000000000001', resource: 'team', action: 'invite', description: 'Invite team members' };
const view = { id: '3cf8e000-26c5-4d2a-a880-000000000002', resource: 'team', action: 'view' };
const groups = [{ resource: 'team', permissions: [invite, view] }];

describe('RBAC permission catalog contract', () => {
  it('retains all 109 native catalog permissions across all 26 resource groups', async () => {
    const permissions = permissionCatalog.permissions.map((permission, index) => ({
      ...permission, id: `3cf8e000-26c5-4d2a-a880-${String(index + 1).padStart(12, '0')}`,
    }));
    const resources = [...new Set(permissions.map(permission => permission.resource))];
    const nativeGroups = resources.map(resource => ({ resource,
      permissions: permissions.filter(permission => permission.resource === resource),
    }));
    server.use(http.get('*/v1/organizations/:org/permissions', () => HttpResponse.json(nativeGroups)));
    const result = await listPermissions('org-current');
    expect(nativeGroups).toHaveLength(26);
    expect(result).toHaveLength(109);
    expect(result).toEqual(nativeGroups.flatMap(group => group.permissions));
    expect(result.filter(permission => permission.resource === 'team').map(permission => permission.action).sort())
      .toEqual(['invite', 'manage', 'view']);
  });

  it.each([
    ['native resource groups', groups],
    ['legacy wrapped resource groups', { resources: groups }],
    ['legacy flat permissions', [invite, view]],
  ])('normalizes %s without substituting permission identities', async (_, response) => {
    server.use(http.get('*/v1/organizations/:org/permissions', ({ params }) => {
      expect(params.org).toBe('org-current');
      return HttpResponse.json(response);
    }));
    expect(await listPermissions('org-current')).toEqual([invite, view]);
  });

  it('accepts an empty native catalog', async () => {
    server.use(http.get('*/v1/organizations/:org/permissions', () => HttpResponse.json([])));
    expect(await listPermissions('org-current')).toEqual([]);
  });

  it.each([
    null, {}, [null], [{ resource: 'team' }], [{ resource: 'team', permissions: null }],
    [{ resource: 'team', permissions: [{ action: 'view' }] }],
    [{ resource: 'team', permissions: [{ ...view, id: '' }] }],
    [{ resource: 'team', permissions: [{ ...view, id: 'not-a-uuid' }] }],
    [{ resource: 'team', permissions: [{ ...view, action: ' ' }] }],
    [{ resource: 'team', permissions: [{ ...view, resource: 'role' }] }],
    [{ resource: 'team', permissions: [{ ...view, description: {} }] }],
    [{ resource: 'team', permissions: [view, view] }],
    [{ resource: 'team', permissions: [view, { ...invite, id: view.id.toUpperCase() }] }],
    [{ resource: 'team', permissions: [view, { ...view, id: invite.id }] }],
  ])('rejects malformed or ambiguous catalog entries instead of exposing blank grants %#', async response => {
    server.use(http.get('*/v1/organizations/:org/permissions', () => HttpResponse.json(response)));
    await expect(listPermissions('org-current')).rejects.toThrow('Permission catalog returned an invalid response.');
  });
});
