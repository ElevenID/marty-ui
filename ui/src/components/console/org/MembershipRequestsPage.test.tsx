import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import MembershipRequestsPage from './MembershipRequestsPage';
import * as membershipApi from '../../../services/membershipApi';

const state = vi.hoisted(() => ({
  authenticated: true, organizationId: 'org-a', principalId: 'user-a',
  loading: false, grants: new Set(['team:view', 'team:manage']), showSuccess: vi.fn(),
}));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: state.organizationId }) }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({
  user: { user_id: state.principalId }, isAuthenticated: state.authenticated,
}) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({
  isLoading: state.loading, can: (resource: string, action: string) => state.grants.has(resource + ':' + action),
}) }));
vi.mock('../../../hooks/useNotifications', () => ({ useNotifications: () => ({ showSuccess: state.showSuccess }) }));

const pending = {
  id: 'membership-a', organization_id: 'org-a', user_id: 'applicant-a',
  email: 'member@example.invalid', status: 'pending',
  roles: [{ id: 'role-applicant', name: 'applicant', display_name: 'Applicant access' }],
};

describe('Membership Requests native review', () => {
  let reads: number;
  let writes: number;
  let inventory: typeof pending[];
  beforeEach(() => {
    Object.assign(state, { authenticated: true, organizationId: 'org-a', principalId: 'user-a', loading: false });
    state.grants = new Set(['team:view', 'team:manage']);
    state.showSuccess.mockReset();
    reads = 0; writes = 0; inventory = [pending];
    server.use(
      http.get('*/v1/organizations/:org/members', () => { reads += 1; return HttpResponse.json(inventory); }),
      http.post('*/v1/organizations/:org/members/:id/approve', async ({ request, params }) => {
        writes += 1;
        expect(params).toMatchObject({ org: 'org-a', id: 'membership-a' });
        expect(await request.text()).toBe('');
        inventory = [];
        return HttpResponse.json({ ...pending, status: 'active' });
      }),
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it('renders native identity and assigned roles without unsupported request fields/actions', async () => {
    renderWithRouter(<MembershipRequestsPage />);
    expect(await screen.findByText(pending.email)).toBeInTheDocument();
    expect(screen.getByText('Applicant access')).toBeInTheDocument();
    expect(screen.getByText('Pending Requests (1)')).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: /message|requested/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /reject/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByText(/Rejection is not available/)).toBeInTheDocument();
  });

  it('labels a native account reference when the member has no email', async () => {
    inventory = [{ ...pending, email: '' }];
    renderWithRouter(<MembershipRequestsPage />);
    expect(await screen.findByText('Account applicant-a')).toBeInTheDocument();
  });

  it('approves through the real native client and reloads only after verified activation', async () => {
    const { user } = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText(pending.email);
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(await screen.findByText('No Pending Requests')).toBeInTheDocument();
    expect(writes).toBe(1);
    expect(reads).toBe(2);
    expect(state.showSuccess).toHaveBeenCalledTimes(1);
  });

  it('allows view-only readers without exposing approval or unrelated tabs', async () => {
    state.grants = new Set(['team:view']);
    renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText(pending.email);
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.getByText(/do not have permission to approve/)).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Organization' })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Webhooks' })).not.toBeInTheDocument();
    expect(writes).toBe(0);
  });

  it.each(['signed-out', 'no-organization', 'loading', 'no-read-grant'])('does not fetch protected inventory while %s', async condition => {
    if (condition === 'signed-out') state.authenticated = false;
    if (condition === 'no-organization') state.organizationId = '';
    if (condition === 'loading') state.loading = true;
    if (condition === 'no-read-grant') state.grants = new Set(['team:manage']);
    renderWithRouter(<MembershipRequestsPage />);
    await act(async () => {});
    expect(reads).toBe(0);
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByText('No Pending Requests')).not.toBeInTheDocument();
  });

  it('fetches after current permissions finish loading', async () => {
    state.loading = true;
    const view = renderWithRouter(<MembershipRequestsPage />);
    expect(screen.getByRole('progressbar', { name: 'Checking membership permissions' })).toBeInTheDocument();
    expect(reads).toBe(0);
    state.loading = false;
    view.rerender(<MembershipRequestsPage />);
    expect(await screen.findByText(pending.email)).toBeInTheDocument();
  });

  it.each(['', ' \t '])('shows a readable failed-load fallback for blank native errors %#', async message => {
    vi.spyOn(membershipApi, 'getPendingRequests').mockRejectedValueOnce(new Error(message));
    const { user } = renderWithRouter(<MembershipRequestsPage />);
    expect(await screen.findByText('Failed to load membership requests.')).toBeInTheDocument();
    expect(screen.queryByText('No Pending Requests')).not.toBeInTheDocument();
    expect(screen.queryByText('Pending Requests (0)')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText(pending.email)).toBeInTheDocument();
  });

  it('keeps a failed refresh distinct from the preceding empty inventory', async () => {
    inventory = [];
    const view = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText('No Pending Requests');
    vi.spyOn(membershipApi, 'getPendingRequests').mockRejectedValueOnce(new Error('Review unavailable'));
    await view.user.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await screen.findByText('Review unavailable')).toBeInTheDocument();
    expect(screen.queryByText('No Pending Requests')).not.toBeInTheDocument();
    expect(screen.queryByText('Pending Requests (0)')).not.toBeInTheDocument();
  });

  it('keeps a failed approval retryable and does not remove the pending member', async () => {
    vi.spyOn(membershipApi, 'approveMembershipRequest').mockRejectedValueOnce(new Error(''));
    const view = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText(pending.email);
    await view.user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(await screen.findByText('Failed to approve membership request.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve' })).toBeEnabled();
    expect(screen.getByText(pending.email)).toBeInTheDocument();
    expect(state.showSuccess).not.toHaveBeenCalled();
    await view.user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(await screen.findByText('No Pending Requests')).toBeInTheDocument();
  });

  it('does not declare success when a 200 response leaves the membership pending', async () => {
    server.use(http.post('*/v1/organizations/:org/members/:id/approve', () => HttpResponse.json(pending)));
    const { user } = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText(pending.email);
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(await screen.findByText('Membership approval returned an invalid response.')).toBeInTheDocument();
    expect(state.showSuccess).not.toHaveBeenCalled();
    expect(screen.getByText(pending.email)).toBeInTheDocument();
    expect(reads).toBe(1);
  });

  it('keeps unavailable backend approval as a visible failure', async () => {
    server.use(http.post('*/v1/organizations/:org/members/:id/approve', () =>
      HttpResponse.json({ detail: 'Not found' }, { status: 404 })));
    const { user } = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText(pending.email);
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(screen.getAllByRole('alert')).toHaveLength(2));
    expect(state.showSuccess).not.toHaveBeenCalled();
    expect(screen.getByText(pending.email)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve' })).toBeEnabled();
  });
});
