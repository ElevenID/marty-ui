import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import MembershipRequestsPage from './MembershipRequestsPage';

const scope = vi.hoisted(() => ({
  organizationId: 'org-a', principalId: 'user-a', authenticated: true, loading: false,
  canView: true, canApprove: true, showSuccess: vi.fn(),
}));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organizationId }) }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({
  user: { user_id: scope.principalId }, isAuthenticated: scope.authenticated,
}) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({
  isLoading: scope.loading,
  can: (resource: string, action: string) => resource === 'team'
    && (action === 'view' ? scope.canView : action === 'manage' && scope.canApprove),
}) }));
vi.mock('../../../hooks/useNotifications', () => ({ useNotifications: () => ({ showSuccess: scope.showSuccess }) }));

const member = (id = 'membership-a', organization_id = 'org-a') => ({
  id, organization_id, user_id: 'applicant-' + id, email: id + '@example.invalid',
  status: 'pending', roles: [{ id: 'role-applicant', name: 'applicant' }],
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

describe('native membership review scope and pending operations', () => {
  beforeEach(() => {
    Object.assign(scope, { organizationId: 'org-a', principalId: 'user-a', authenticated: true,
      loading: false, canView: true, canApprove: true });
    scope.showSuccess.mockReset();
    server.use(http.get('*/v1/organizations/:org/members', ({ params }) =>
      HttpResponse.json([member('membership-a', String(params.org))])));
  });
  afterEach(() => vi.restoreAllMocks());

  it.each(['organization', 'account'])('discards a late read after an %s change', async changed => {
    const first = deferred<Response>();
    let reads = 0;
    server.use(http.get('*/v1/organizations/:org/members', ({ params }) => {
      reads += 1;
      return reads === 1 ? first.promise : HttpResponse.json([member('membership-b', String(params.org))]);
    }));
    const view = renderWithRouter(<MembershipRequestsPage />);
    await waitFor(() => expect(reads).toBe(1));
    if (changed === 'organization') scope.organizationId = 'org-b';
    else scope.principalId = 'user-b';
    view.rerender(<MembershipRequestsPage />);
    expect(await screen.findByText('membership-b@example.invalid')).toBeInTheDocument();
    await act(async () => first.resolve(HttpResponse.json([member()])));
    expect(screen.queryByText('membership-a@example.invalid')).not.toBeInTheDocument();
    expect(screen.getByText('membership-b@example.invalid')).toBeInTheDocument();
  });

  it('stops an old account from requesting another page after its first page resolves', async () => {
    const first = deferred<Response>();
    const requests: string[] = [];
    server.use(http.get('*/v1/organizations/:org/members', ({ request }) => {
      const offset = new URL(request.url).searchParams.get('offset')!;
      requests.push(offset);
      return requests.length === 1 ? first.promise : HttpResponse.json([member('membership-b')]);
    }));
    const view = renderWithRouter(<MembershipRequestsPage />);
    await waitFor(() => expect(requests).toEqual(['0']));
    scope.principalId = 'user-b';
    view.rerender(<MembershipRequestsPage />);
    await screen.findByText('membership-b@example.invalid');
    await act(async () => first.resolve(HttpResponse.json(
      Array.from({ length: 500 }, (_, i) => member('old-' + i)),
    )));
    expect(requests).toEqual(['0', '0']);
    expect(screen.queryByText('old-0@example.invalid')).not.toBeInTheDocument();
  });

  it.each(['signed-out', 'no-organization', 'permission-refresh', 'read-revoked'])('removes old rows immediately when %s', async changed => {
    const view = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText('membership-a@example.invalid');
    if (changed === 'signed-out') scope.authenticated = false;
    if (changed === 'no-organization') scope.organizationId = '';
    if (changed === 'permission-refresh') scope.loading = true;
    if (changed === 'read-revoked') scope.canView = false;
    view.rerender(<MembershipRequestsPage />);
    expect(screen.queryByText('membership-a@example.invalid')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });

  it('sends one approval and blocks refresh while the operation is pending', async () => {
    const result = deferred<Response>();
    let writes = 0;
    server.use(http.post('*/v1/organizations/:org/members/:id/approve', () => {
      writes += 1; return result.promise;
    }));
    renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText('membership-a@example.invalid');
    const approve = screen.getByRole('button', { name: 'Approve' });
    act(() => { approve.click(); approve.click(); });
    await waitFor(() => expect(writes).toBe(1));
    expect(approve).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled();
    await act(async () => result.resolve(HttpResponse.json({ ...member(), status: 'active' })));
    await waitFor(() => expect(scope.showSuccess).toHaveBeenCalledTimes(1));
  });

  it.each(['organization', 'account', 'approval-grant'])('ignores old approval completion after %s changes', async changed => {
    const result = deferred<Response>();
    let reads = 0;
    let writes = 0;
    server.use(
      http.get('*/v1/organizations/:org/members', ({ params }) => {
        reads += 1;
        return HttpResponse.json([member(reads === 1 ? 'membership-a' : 'membership-b', String(params.org))]);
      }),
      http.post('*/v1/organizations/:org/members/:id/approve', () => {
        writes += 1; return result.promise;
      }),
    );
    const view = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText('membership-a@example.invalid');
    await view.user.click(screen.getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(writes).toBe(1));
    if (changed === 'organization') scope.organizationId = 'org-b';
    if (changed === 'account') scope.principalId = 'user-b';
    if (changed === 'approval-grant') scope.canApprove = false;
    view.rerender(<MembershipRequestsPage />);
    await screen.findByText('membership-b@example.invalid');
    const readsAfterSwitch = reads;
    await act(async () => result.resolve(HttpResponse.json({ ...member(), status: 'active' })));
    expect(scope.showSuccess).not.toHaveBeenCalled();
    expect(reads).toBe(readsAfterSwitch);
    expect(screen.getByText('membership-b@example.invalid')).toBeInTheDocument();
  });
});
