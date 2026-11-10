import { beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { approveMembershipRequest, getPendingRequests } from '../membershipApi';

const member = (id: string, status = 'pending', organization_id = 'org-a') => ({
  id, organization_id, user_id: 'user-' + id, email: id + '@example.invalid',
  status, roles: [{ id: 'role-applicant', name: 'applicant' }],
});

describe('native membership review client', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('exhausts raw pages when an older runtime ignores the Pending filter', async () => {
    const pages: Array<{ offset: string | null; limit: string | null; status: string | null }> = [];
    server.use(http.get('*/v1/organizations/:org/members', ({ request, params }) => {
      expect(params.org).toBe('org-a');
      const q = new URL(request.url).searchParams;
      pages.push({ offset: q.get('offset'), limit: q.get('limit'), status: q.get('status') });
      return HttpResponse.json(q.get('offset') === '0'
        ? Array.from({ length: 500 }, (_, i) => member('active-' + i, 'active'))
        : [member('pending-later'), member('invited', 'invited'), member('disabled', 'deactivated')]);
    }));
    expect(await getPendingRequests('org-a')).toEqual({ requests: [member('pending-later')] });
    expect(pages).toEqual([
      { offset: '0', limit: '500', status: 'pending' },
      { offset: '500', limit: '500', status: 'pending' },
    ]);
  });

  it('does not claim a full page is the complete inventory', async () => {
    const offsets: string[] = [];
    server.use(http.get('*/v1/organizations/:org/members', ({ request }) => {
      const offset = new URL(request.url).searchParams.get('offset')!;
      offsets.push(offset);
      return HttpResponse.json(offset === '0'
        ? Array.from({ length: 500 }, (_, i) => member('pending-' + i)) : []);
    }));
    expect((await getPendingRequests('org-a')).requests).toHaveLength(500);
    expect(offsets).toEqual(['0', '500']);
  });

  it('rejects a later-page failure instead of returning a partial inventory', async () => {
    server.use(http.get('*/v1/organizations/:org/members', ({ request }) => {
      const offset = new URL(request.url).searchParams.get('offset');
      return offset === '0'
        ? HttpResponse.json(Array.from({ length: 500 }, (_, i) => member('pending-' + i)))
        : HttpResponse.json({ detail: 'Unavailable' }, { status: 403 });
    }));
    await expect(getPendingRequests('org-a')).rejects.toBeInstanceOf(Error);
  });

  it('fails explicitly if a server repeats a full page instead of respecting offset', async () => {
    let reads = 0;
    server.use(http.get('*/v1/organizations/:org/members', () => {
      reads += 1;
      return HttpResponse.json(Array.from({ length: 500 }, (_, i) => member('pending-' + i)));
    }));
    await expect(getPendingRequests('org-a')).rejects.toThrow(/inventory changed/);
    expect(reads).toBe(2);
  });

  it.each([
    null, {}, { requests: [] }, [null], [{ ...member('a'), organization_id: 'org-b' }],
    [{ ...member('a'), id: '' }], [{ ...member('a'), user_id: null }],
    [{ ...member('a'), status: 'unknown' }], [{ ...member('a'), roles: null }],
    [{ ...member('a'), roles: [{ id: 'role-a' }] }], [{ ...member('a'), email: 42 }],
    [{ ...member('a'), roles: [{ id: 'role-a', name: 'applicant', display_name: {} }] }],
  ])('rejects malformed or cross-organization inventory %#', async response => {
    server.use(http.get('*/v1/organizations/:org/members', () => HttpResponse.json(response)));
    await expect(getPendingRequests('org-a')).rejects.toThrow(/invalid response/);
  });

  it('stops pagination when the requesting view changes account or organization', async () => {
    let current = true;
    let reads = 0;
    server.use(http.get('*/v1/organizations/:org/members', () => {
      reads += 1;
      current = false;
      return HttpResponse.json(Array.from({ length: 500 }, (_, i) => member('pending-' + i)));
    }));
    await expect(getPendingRequests('org-a', { isCurrent: () => current })).rejects.toMatchObject({ name: 'AbortError' });
    expect(reads).toBe(1);
  });

  it('makes no request for missing organization or an already replaced scope', async () => {
    let reads = 0;
    server.use(http.get('*/v1/organizations/:org/members', () => { reads += 1; return HttpResponse.json([]); }));
    await expect(getPendingRequests('')).rejects.toThrow(/Organization is required/);
    await expect(getPendingRequests('org-a', { isCurrent: () => false })).rejects.toMatchObject({ name: 'AbortError' });
    expect(reads).toBe(0);
  });

  it('approves through the scoped native action with an empty body and cookie credentials', async () => {
    let body: string | undefined;
    let credentials: RequestCredentials | undefined;
    server.use(http.post('*/v1/organizations/:org/members/:id/approve', async ({ request, params }) => {
      expect(params).toMatchObject({ org: 'org-a', id: 'member-a' });
      body = await request.text();
      credentials = request.credentials;
      return HttpResponse.json(member('member-a', 'active'));
    }));
    expect(await approveMembershipRequest('org-a', 'member-a')).toEqual(member('member-a', 'active'));
    expect(body).toBe('');
    expect(credentials).toBe('include');
  });

  it.each([
    null, {}, { success: true }, member('wrong', 'active'),
    member('member-a', 'active', 'org-b'), member('member-a', 'pending'),
  ])('does not report approval success for an invalid native result %#', async response => {
    server.use(http.post('*/v1/organizations/:org/members/:id/approve', () => HttpResponse.json(response)));
    await expect(approveMembershipRequest('org-a', 'member-a')).rejects.toThrow(/invalid response/);
  });

  it('does not retry a conflicting approval as a second write', async () => {
    let writes = 0;
    server.use(http.post('*/v1/organizations/:org/members/:id/approve', () => {
      writes += 1;
      return HttpResponse.json({ detail: 'Membership is not pending' }, { status: 409 });
    }));
    await expect(approveMembershipRequest('org-a', 'member-a')).rejects.toBeInstanceOf(Error);
    expect(writes).toBe(1);
  });

  it('rejects missing member scope before sending a write', async () => {
    let writes = 0;
    server.use(http.post('*/v1/organizations/:org/members/:id/approve', () => {
      writes += 1;
      return HttpResponse.json(member('member-a', 'active'));
    }));
    await expect(approveMembershipRequest('', 'member-a')).rejects.toThrow(/Organization is required/);
    await expect(approveMembershipRequest('org-a', ' ')).rejects.toThrow(/Membership is required/);
    await expect(approveMembershipRequest('org-a', 'undefined')).rejects.toThrow(/Membership is required/);
    expect(writes).toBe(0);
  });
});
