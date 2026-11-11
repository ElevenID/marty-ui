import { describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { loadOrgSettings, saveOrgSettings } from './orgSettingsUseCases';

const response = {
  id: 'selected-org', name: 'acme', display_name: 'Acme Corp', description: null,
  website: null, contact_email: null, contact_phone: null,
  visibility: 'PRIVATE', join_mechanism: 'invite', requires_approval: false,
};
const profile = {
  name: 'acme', displayName: 'Acme Corp', description: '', website: '', contactEmail: '', contactPhone: '',
  visibility: 'PRIVATE', joinMechanism: 'invite', requiresApproval: false,
};

describe('organization settings use cases', () => {
  it('loads via the selected organization URL with the real API client', async () => {
    const requests: string[] = [];
    server.use(http.get('*/v1/organizations/:orgId', ({ request, params }) => {
      requests.push(new URL(request.url).pathname);
      expect(params.orgId).toBe('selected-org');
      return HttpResponse.json(response);
    }));
    await expect(loadOrgSettings({ organizationId: 'selected-org' })).resolves.toEqual({ org: profile, error: null });
    expect(requests).toEqual(['/v1/organizations/selected-org']);
  });
  it('PATCHes basic/contact/admission edits to the same organization and uses the saved server result', async () => {
    const requests: string[] = [];
    let body: unknown;
    server.use(http.patch('*/v1/organizations/:orgId', async ({ request, params }) => {
      requests.push(new URL(request.url).pathname);
      expect(params.orgId).toBe('selected-org');
      body = await request.json();
      return HttpResponse.json({ ...response, display_name: 'Updated Acme', contact_email: 'admin@acme.example' });
    }));
    const result = await saveOrgSettings({ organizationId: 'selected-org', org: { ...profile, displayName: 'Updated Acme', contactEmail: 'admin@acme.example' } });
    expect(result.error).toBeNull();
    expect(result.org).toMatchObject({ displayName: 'Updated Acme', contactEmail: 'admin@acme.example' });
    expect(requests).toEqual(['/v1/organizations/selected-org']);
    expect(body).toEqual({
      name: 'acme', display_name: 'Updated Acme', description: null, website: null,
      contact_email: 'admin@acme.example', contact_phone: null,
      visibility: 'PRIVATE', join_mechanism: 'invite', requires_approval: false,
    });
  });
  it('does not dispatch unscoped loads or saves', async () => {
    const fetchSettings = vi.fn();
    const save = vi.fn();
    expect((await loadOrgSettings({ fetchSettings })).error).toBeTruthy();
    expect((await saveOrgSettings({ org: profile, save })).error).toBeTruthy();
    expect(fetchSettings).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
  });
  it('updates seeded Marty contact details without sending its legacy uppercase name', async () => {
    const originalOrg = { ...profile, name: 'Marty', displayName: 'Marty Identity Platform' };
    let body: unknown;
    server.use(http.patch('*/v1/organizations/:orgId', async ({ request }) => {
      body = await request.json();
      return HttpResponse.json({ ...response, name: 'Marty', display_name: 'Marty Identity Platform', contact_email: 'contact@example.com' });
    }));
    const result = await saveOrgSettings({ organizationId: 'selected-org', originalOrg, org: { ...originalOrg, contactEmail: 'contact@example.com' } });
    expect(result.error).toBeNull();
    expect(body).toEqual({ contact_email: 'contact@example.com' });
    expect(result.org?.name).toBe('Marty');
  });
  it('does not send an empty PATCH when the profile is unchanged', async () => {
    const save = vi.fn();
    const result = await saveOrgSettings({ organizationId: 'selected-org', org: profile, originalOrg: profile, save });
    expect(result).toEqual({ org: profile, error: null });
    expect(save).not.toHaveBeenCalled();
  });
  it('does not allow a wrong-org or incomplete response to become a successful load', async () => {
    const fetchSettings = vi.fn().mockResolvedValue({ ...response, id: 'auth-org' });
    const result = await loadOrgSettings({ organizationId: 'selected-org', fetchSettings });
    expect(fetchSettings).toHaveBeenCalledWith('selected-org');
    expect(result.org).toBeNull();
    expect(result.error).toContain('selected organization');
  });
  it('preserves read and write failures instead of reporting empty data or success', async () => {
    const fetchSettings = vi.fn().mockRejectedValue(new Error('Access denied'));
    const save = vi.fn().mockRejectedValue(new Error('Permission denied'));
    await expect(loadOrgSettings({ organizationId: 'selected-org', fetchSettings })).resolves.toMatchObject({ org: null, error: 'Access denied' });
    await expect(saveOrgSettings({ organizationId: 'selected-org', org: profile, save })).resolves.toMatchObject({ org: null, error: 'Permission denied' });
  });
});
