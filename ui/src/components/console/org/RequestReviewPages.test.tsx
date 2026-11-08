import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { act, renderWithRouter, screen, waitFor, within } from '@test/utils';
import { server } from '@test/mocks/server';
import MembershipRequestsPage from './MembershipRequestsPage';
import RoleEscalationRequestsPage from './RoleEscalationRequestsPage';
import * as membershipApi from '../../../services/membershipApi';
import * as rolesApi from '../../../services/rolesApi';

const scope = vi.hoisted(() => ({ organizationId: 'org-a', principalId: 'user-a', authenticated: true }));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organizationId }) }));
vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ user: { user_id: scope.principalId }, isAuthenticated: scope.authenticated }),
}));

const request = {
  id: 'request-a', user_id: 'applicant-a', user_email: 'member-a@example.org', status: 'pending',
  message: 'Please review', current_role: 'member', requested_role: 'operator', created_at: '2026-11-08T10:00:00Z',
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

describe.each([
  { name: 'Membership', Page: MembershipRequestsPage, base: '/api/onboarding', empty: 'No Pending Requests', approve: 'Approve', reject: 'Reject' },
  { name: 'Role', Page: RoleEscalationRequestsPage, base: '/api/roles', empty: 'No pending role escalation requests', approve: 'Approve request', reject: 'Reject request' },
])('$name request inventory', ({ Page, base, empty, approve, reject }) => {
  beforeEach(() => {
    scope.organizationId = 'org-a'; scope.principalId = 'user-a'; scope.authenticated = true;
    server.use(http.get(`*${base}/pending-requests`, () => HttpResponse.json({ requests: [request] })));
  });
  afterEach(() => vi.restoreAllMocks());

  it('shows a retryable failure without asserting an empty inventory', async () => {
    let reads = 0;
    server.use(http.get(`*${base}/pending-requests`, () => ++reads === 1
      ? HttpResponse.json({ detail: 'Review endpoint unavailable' }, { status: 404 })
      : HttpResponse.json({ requests: [] })));
    const { user } = renderWithRouter(<Page />);
    await screen.findByRole('alert');
    expect(screen.queryByText(empty)).not.toBeInTheDocument();
    expect(screen.queryByText('Pending Requests (0)')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText(empty)).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(reads).toBe(2);
  });

  it.each(['', ' \n\t '])('keeps a blank native Error message (%j) readable and retryable', async message => {
    const read = base === '/api/onboarding'
      ? vi.spyOn(membershipApi, 'getPendingRequests')
      : vi.spyOn(rolesApi, 'getPendingRoleRequests');
    read.mockRejectedValueOnce(new Error(message));
    const { user } = renderWithRouter(<Page />);
    expect(await screen.findByRole('alert')).toHaveTextContent(base === '/api/onboarding'
      ? 'Failed to load membership requests' : 'Failed to load role escalation requests');
    expect(screen.queryByText(empty)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText(request.user_email)).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows a fallback after an approval rejects with a blank Error', async () => {
    const review = base === '/api/onboarding'
      ? vi.spyOn(membershipApi, 'approveMembershipRequest')
      : vi.spyOn(rolesApi, 'approveRoleRequest');
    review.mockRejectedValueOnce(new Error(''));
    const { user } = renderWithRouter(<Page />);
    await screen.findByText(request.user_email);
    await user.click(screen.getByRole('button', { name: approve }));
    expect(await screen.findByRole('alert')).toHaveTextContent(base === '/api/onboarding'
      ? 'Failed to approve membership request' : 'Failed to approve role request');
    expect(screen.getByRole('button', { name: approve })).toBeEnabled();
  });

  it('shows a fallback inside the dialog for a whitespace-only rejection Error', async () => {
    const review = base === '/api/onboarding'
      ? vi.spyOn(membershipApi, 'rejectMembershipRequest')
      : vi.spyOn(rolesApi, 'rejectRoleRequest');
    review.mockRejectedValueOnce(new Error(' \t '));
    const { user } = renderWithRouter(<Page />);
    await screen.findByText(request.user_email);
    await user.click(screen.getByRole('button', { name: reject }));
    const dialog = screen.getByRole('dialog');
    await user.type(within(dialog).getByRole('textbox'), 'Missing evidence');
    await user.click(within(dialog).getByRole('button', { name: 'Reject Request' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(base === '/api/onboarding'
      ? 'Failed to reject membership request' : 'Failed to reject role request');
    expect(within(dialog).getByRole('textbox')).toHaveValue('Missing evidence');
    expect(within(dialog).getByRole('button', { name: 'Reject Request' })).toBeEnabled();
  });

  it.each([{}, { requests: null }, { requests: {} }])('rejects malformed inventory %j', async response => {
    server.use(http.get(`*${base}/pending-requests`, () => HttpResponse.json(response)));
    renderWithRouter(<Page />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid.*response/i);
    expect(screen.queryByText(empty)).not.toBeInTheDocument();
  });

  it('discards a previously empty inventory when refreshing fails', async () => {
    let reads = 0;
    server.use(http.get(`*${base}/pending-requests`, () => ++reads === 1
      ? HttpResponse.json({ requests: [] })
      : HttpResponse.json({ detail: 'Refresh unavailable' }, { status: 404 })));
    const { user } = renderWithRouter(<Page />);
    await screen.findByText(empty);
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await screen.findByRole('alert');
    expect(screen.queryByText(empty)).not.toBeInTheDocument();
    expect(screen.queryByText('Pending Requests (0)')).not.toBeInTheDocument();
  });

  it.each(['organization', 'account'])('isolates a late read after an %s switch', async changed => {
    const first = deferred<Response>();
    const second = deferred<Response>();
    let reads = 0;
    server.use(http.get(`*${base}/pending-requests`, () => ++reads === 1 ? first.promise : second.promise));
    const view = renderWithRouter(<Page />);
    await waitFor(() => expect(reads).toBe(1));
    if (changed === 'organization') scope.organizationId = 'org-b';
    else scope.principalId = 'user-b';
    view.rerender(<Page />);
    await waitFor(() => expect(reads).toBe(2));
    await act(async () => first.resolve(HttpResponse.json({ requests: [request] })));
    expect(screen.queryByText(request.user_email)).not.toBeInTheDocument();
    expect(screen.queryByText(empty)).not.toBeInTheDocument();
    await act(async () => second.resolve(HttpResponse.json({ requests: [{ ...request, id: 'request-b', user_email: 'member-b@example.org' }] })));
    expect(await screen.findByText('member-b@example.org')).toBeInTheDocument();
    expect(screen.queryByText(request.user_email)).not.toBeInTheDocument();
  });

  it('removes old rows and rejection dialog immediately when the native account changes', async () => {
    const view = renderWithRouter(<Page />);
    await screen.findByText(request.user_email);
    await view.user.click(screen.getByRole('button', { name: reject }));
    await view.user.type(within(screen.getByRole('dialog')).getByRole('textbox'), 'Private reviewer note');
    const pending = deferred<Response>();
    server.use(http.get(`*${base}/pending-requests`, () => pending.promise));
    scope.principalId = 'user-b';
    view.rerender(<Page />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByText(request.user_email)).not.toBeInTheDocument();
    await act(async () => pending.resolve(HttpResponse.json({ requests: [] })));
    await screen.findByText(empty);
  });

  it('does not reload or notify the new account after an old approval finishes', async () => {
    const mutation = deferred<Response>();
    let reads = 0;
    let writes = 0;
    server.use(
      http.get(`*${base}/pending-requests`, () => {
        reads++;
        return HttpResponse.json({ requests: scope.principalId === 'user-a' ? [request] : [] });
      }),
      http.post(`*${base}/review-request`, () => { writes++; return mutation.promise; }),
    );
    const view = renderWithRouter(<Page />);
    await screen.findByText(request.user_email);
    await view.user.click(screen.getByRole('button', { name: approve }));
    await waitFor(() => expect(writes).toBe(1));
    scope.principalId = 'user-b';
    view.rerender(<Page />);
    await screen.findByText(empty);
    expect(reads).toBe(2);
    await act(async () => mutation.resolve(HttpResponse.json({ success: true, message: 'Old account approval completed' })));
    expect(screen.queryByText('Old account approval completed')).not.toBeInTheDocument();
    expect(reads).toBe(2);
  });

  it('keeps the loaded request available after an approval fails', async () => {
    server.use(http.post(`*${base}/review-request`, () => HttpResponse.json({ detail: 'Review denied' }, { status: 403 })));
    const { user } = renderWithRouter(<Page />);
    await screen.findByText(request.user_email);
    await user.click(screen.getByRole('button', { name: approve }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Review denied');
    expect(screen.getByText(request.user_email)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: approve })).toBeEnabled();
    expect(screen.queryByText(empty)).not.toBeInTheDocument();
  });

  it('locks rejection controls until the review completes and reloads once', async () => {
    const mutation = deferred<Response>();
    const writes: Record<string, unknown>[] = [];
    let reads = 0;
    server.use(
      http.get(`*${base}/pending-requests`, () => HttpResponse.json({ requests: ++reads === 1 ? [request] : [] })),
      http.post(`*${base}/review-request`, async ({ request: incoming }) => {
        writes.push(await incoming.json() as Record<string, unknown>);
        return mutation.promise;
      }),
    );
    const { user } = renderWithRouter(<Page />);
    await screen.findByText(request.user_email);
    await user.click(screen.getByRole('button', { name: reject }));
    const dialog = screen.getByRole('dialog');
    await user.type(within(dialog).getByRole('textbox'), 'Missing evidence');
    await user.click(within(dialog).getByRole('button', { name: 'Reject Request' }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(within(dialog).getByRole('textbox')).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled();
    await user.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(writes).toEqual([{ request_id: request.id, action: 'reject', rejection_reason: 'Missing evidence' }]);
    await act(async () => mutation.resolve(HttpResponse.json({ success: true, message: 'Rejected' })));
    await screen.findByText(empty);
    expect(reads).toBe(2);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('shows a rejection failure inside the dialog and retains the reason for retry', async () => {
    const writes: Record<string, unknown>[] = [];
    server.use(
      http.post(`*${base}/review-request`, async ({ request: incoming }) => {
        writes.push(await incoming.json() as Record<string, unknown>);
        if (writes.length === 1) return HttpResponse.json({ detail: 'Rejection denied' }, { status: 403 });
        return HttpResponse.json({ success: true, message: 'Rejected' });
      }),
    );
    const { user } = renderWithRouter(<Page />);
    await screen.findByText(request.user_email);
    await user.click(screen.getByRole('button', { name: reject }));
    const dialog = screen.getByRole('dialog');
    await user.type(within(dialog).getByRole('textbox'), 'Missing evidence');
    await user.click(within(dialog).getByRole('button', { name: 'Reject Request' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Rejection denied');
    expect(within(dialog).getByRole('textbox')).toHaveValue('Missing evidence');
    expect(within(dialog).getByRole('button', { name: 'Reject Request' })).toBeEnabled();
    await user.click(within(dialog).getByRole('button', { name: 'Reject Request' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(writes).toEqual(Array(2).fill({ request_id: request.id, action: 'reject', rejection_reason: 'Missing evidence' }));
  });

  it('requires an authenticated selected organization before fetching requests', async () => {
    let reads = 0;
    server.use(http.get(`*${base}/pending-requests`, () => { reads++; return HttpResponse.json({ requests: [] }); }));
    scope.organizationId = '';
    const view = renderWithRouter(<Page />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/select an organization/i);
    expect(reads).toBe(0);
    scope.organizationId = 'org-a'; scope.authenticated = false;
    view.rerender(<Page />);
    expect(screen.queryByText(empty)).not.toBeInTheDocument();
    expect(reads).toBe(0);
  });
});
