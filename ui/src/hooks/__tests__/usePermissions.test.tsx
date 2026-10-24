import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { usePermissions } from '../usePermissions';

const { auth, consoleState, getMyPermissions } = vi.hoisted(() => ({
  auth: { isAuthenticated: true, user: { sub: 'alice' } },
  consoleState: { activeOrgId: 'org-a', memberships: [{ id: 'org-a' }, { id: 'org-b' }], membershipsLoaded: true, mode: 'org' },
  getMyPermissions: vi.fn(),
}));
vi.mock('../useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../contexts/ConsoleContext', () => ({ useConsole: () => consoleState }));
vi.mock('../../services/rbacApi', () => ({ getMyPermissions }));
const grants = { permissions: ['signing-key:view', 'signing-key:create'], roles: [{ name: 'admin' }] };
const denied = { permissions: [], roles: [] };
function deferred() {
  let resolve!: (value: typeof denied | typeof grants) => void;
  const promise = new Promise<typeof denied | typeof grants>((done) => { resolve = done; });
  return { promise, resolve };
}

describe('organization-scoped permissions', () => {
  beforeEach(() => {
    vi.clearAllMocks(); auth.isAuthenticated = true; auth.user = { sub: 'alice' };
    consoleState.activeOrgId = 'org-a'; consoleState.membershipsLoaded = true;
    consoleState.memberships = [{ id: 'org-a' }, { id: 'org-b' }];
    consoleState.mode = 'org'; getMyPermissions.mockResolvedValue(grants);
  });
  it('denies synchronously on organization switch and ignores a late prior organization grant', async () => {
    const a = deferred(), b = deferred();
    getMyPermissions.mockImplementation((org: string) => org === 'org-a' ? a.promise : b.promise);
    const { result, rerender } = renderHook(() => usePermissions());
    expect(result.current.can('signing-key', 'create')).toBe(false);
    consoleState.activeOrgId = 'org-b'; rerender();
    await act(async () => { b.resolve(denied); });
    expect(result.current.isLoading).toBe(false);
    await act(async () => { a.resolve(grants); });
    expect(result.current.can('signing-key', 'create')).toBe(false);
    expect(result.current.roles).toEqual([]);
    expect(result.current.canAny([{ resource: 'signing-key', action: 'create' }])).toBe(false);
    expect(result.current.canAll([{ resource: 'signing-key', action: 'create' }])).toBe(false);
  });
  it('withdraws loaded grants before the new organization request completes', async () => {
    const { result, rerender } = renderHook(() => usePermissions());
    await waitFor(() => expect(result.current.can('signing-key', 'create')).toBe(true));
    const pending = deferred(); getMyPermissions.mockReturnValue(pending.promise);
    consoleState.activeOrgId = 'org-b'; rerender();
    expect(result.current.can('signing-key', 'create')).toBe(false);
    expect(result.current.roles).toEqual([]);
    await act(async () => { pending.resolve(denied); });
  });
  it('does not reuse another user grants or apply their late request', async () => {
    const old = deferred(); getMyPermissions.mockReturnValueOnce(old.promise).mockResolvedValue(denied);
    const { result, rerender } = renderHook(() => usePermissions());
    auth.user = { sub: 'bob' }; rerender();
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await act(async () => { old.resolve(grants); });
    expect(result.current.can('signing-key', 'view')).toBe(false);
    expect(getMyPermissions).toHaveBeenCalledTimes(2);
  });
  it('fails closed on logout and reloads grants after login', async () => {
    const { result, rerender } = renderHook(() => usePermissions());
    await waitFor(() => expect(result.current.can('signing-key', 'create')).toBe(true));
    auth.isAuthenticated = false; rerender();
    expect(result.current.can('signing-key', 'create')).toBe(false);
    getMyPermissions.mockResolvedValue(denied); auth.isAuthenticated = true; rerender();
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.can('signing-key', 'create')).toBe(false);
  });
  it('refresh overrides older in-flight results and revokes previous grants', async () => {
    const old = deferred(); getMyPermissions.mockReturnValueOnce(old.promise).mockResolvedValue(denied);
    const { result } = renderHook(() => usePermissions());
    await act(async () => { await result.current.refresh(); });
    await act(async () => { old.resolve(grants); });
    expect(result.current.can('signing-key', 'create')).toBe(false);
  });
  it.each(['00000000-0000-0000-0000-000000000001', 'not-a-member'])('never requests organization %s without membership', (org) => {
    consoleState.activeOrgId = org;
    const { result } = renderHook(() => usePermissions());
    expect(getMyPermissions).not.toHaveBeenCalled();
    expect(result.current.can('signing-key', 'view')).toBe(false);
  });
  it('uses backend Canvas grants for a real member of the default organization and withdraws them on membership loss', async () => {
    const organizationId = '00000000-0000-0000-0000-000000000001';
    consoleState.activeOrgId = organizationId;
    consoleState.memberships = [{ id: organizationId }];
    getMyPermissions.mockResolvedValue({ permissions: ['integration-connector:view'], roles: [{ name: 'admin' }] });
    const { result, rerender } = renderHook(() => usePermissions());
    await waitFor(() => expect(result.current.can('integration-connector', 'view')).toBe(true));
    expect(getMyPermissions).toHaveBeenCalledWith(organizationId);
    expect(result.current.can('integration-connector', 'edit')).toBe(false);
    consoleState.memberships = []; rerender();
    expect(result.current.can('integration-connector', 'view')).toBe(false);
    expect(result.current.roles).toEqual([]);
  });
  it('keeps a default organization member denied when the backend refuses permissions', async () => {
    consoleState.activeOrgId = '00000000-0000-0000-0000-000000000001';
    consoleState.memberships = [{ id: consoleState.activeOrgId }];
    getMyPermissions.mockRejectedValue({ status: 403 });
    const { result } = renderHook(() => usePermissions());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.can('integration-connector', 'view')).toBe(false);
    expect(result.current.roles).toEqual([]);
  });
  it('does not request organization grants in applicant mode despite a selected membership', () => {
    consoleState.mode = 'applicant';
    const { result } = renderHook(() => usePermissions());
    expect(getMyPermissions).not.toHaveBeenCalled();
    expect(result.current.can('signing-key', 'view')).toBe(false);
  });
  it('does not request permissions before memberships are loaded', () => {
    consoleState.membershipsLoaded = false;
    const { result } = renderHook(() => usePermissions());
    expect(getMyPermissions).not.toHaveBeenCalled();
    expect(result.current.can('signing-key', 'view')).toBe(false);
  });
});
