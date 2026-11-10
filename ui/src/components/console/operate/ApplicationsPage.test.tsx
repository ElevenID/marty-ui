import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { act, fireEvent, renderWithRouter, screen, waitFor, within } from '@test/utils';
import { server } from '@test/mocks/server';
import ApplicationsPage from './ApplicationsPage';
import * as applicantApi from '../../../services/applicantApi';

const state = vi.hoisted(() => ({
  authenticated: true, organizationId: 'org-a', principalId: 'user-a',
  loading: false, grants: new Set<string>(), showSuccess: vi.fn(),
}));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: state.organizationId }) }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({
  user: { user_id: state.principalId }, isAuthenticated: state.authenticated,
}) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({
  isLoading: state.loading, can: (resource: string, action: string) => state.grants.has(resource + ':' + action),
}) }));
vi.mock('../../../hooks/useNotifications', () => ({ useNotifications: () => ({ showSuccess: state.showSuccess }) }));

const application = {
  id: 'application-a', applicant_id: 'applicant-a', applicant_identifier: 'applicant@example.invalid',
  organization_id: 'org-a', status: 'SUBMITTED', credential_display_name: 'Visitor pass',
  submitted_at: '2026-11-09T12:00:00Z',
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

describe('Applications list permissions, evidence and actions', () => {
  let inventory: Record<string, unknown>[];
  let reads: string[];
  let writes: { organizationId: string; id: string; action: string; body: unknown }[];
  let manualLocks: number;

  beforeEach(() => {
    Object.assign(state, { authenticated: true, organizationId: 'org-a', principalId: 'user-a', loading: false });
    state.grants = new Set(['application:view', 'application:approve', 'application:reject', 'issuance:initiate']);
    state.showSuccess.mockReset();
    inventory = [application]; reads = []; writes = []; manualLocks = 0;
    server.use(
      http.get('*/v1/organizations/:org/applicants', ({ params }) => {
        reads.push(String(params.org));
        return HttpResponse.json({ items: inventory });
      }),
      http.post('*/v1/organizations/:org/applicants/:id/lock', () => {
        manualLocks += 1;
        return HttpResponse.json({ locked: true });
      }),
      http.delete('*/v1/organizations/:org/applicants/:id/lock', () => {
        manualLocks += 1;
        return HttpResponse.json({ released: true });
      }),
      http.post('*/v1/organizations/:org/applicants/:id/:action', async ({ params, request }) => {
        writes.push({ organizationId: String(params.org), id: String(params.id), action: String(params.action), body: await request.json() });
        return HttpResponse.json(application);
      }),
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it('does not turn missing native evidence into successful verification and document claims', async () => {
    renderWithRouter(<ApplicationsPage />);
    const row = (await screen.findByText('Visitor pass')).closest('tr')!;
    expect(within(row).getAllByText('Not reported')).toHaveLength(2);
    expect(within(row).queryByText('Passed')).not.toBeInTheDocument();
    expect(within(row).queryByText('Uploaded')).not.toBeInTheDocument();
  });

  it('distinguishes explicit negative evidence from unreported signals', async () => {
    inventory = [{ ...application, documents_uploaded: false, verification_passed: false }];
    renderWithRouter(<ApplicationsPage />);
    const row = (await screen.findByText('Visitor pass')).closest('tr')!;
    expect(within(row).getByText('Pending')).toBeInTheDocument();
    expect(within(row).getByText('Failed')).toBeInTheDocument();
    expect(within(row).queryByText('Not reported')).not.toBeInTheDocument();
  });

  it.each(['signed-out', 'no-organization', 'loading', 'no-read-grant'])('does not load protected applications while %s', async condition => {
    if (condition === 'signed-out') state.authenticated = false;
    if (condition === 'no-organization') state.organizationId = '';
    if (condition === 'loading') state.loading = true;
    if (condition === 'no-read-grant') state.grants.delete('application:view');
    renderWithRouter(<ApplicationsPage />);
    await act(async () => {});
    expect(reads).toEqual([]);
    expect(screen.queryByText('No applications yet')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });

  it('loads after current permissions resolve and keeps a view-only inventory read-only', async () => {
    state.loading = true;
    state.grants = new Set(['application:view']);
    const view = renderWithRouter(<ApplicationsPage />);
    expect(screen.getByRole('progressbar', { name: 'Checking application permissions' })).toBeInTheDocument();
    state.loading = false;
    view.rerender(<ApplicationsPage />);
    await screen.findByText('Visitor pass');
    expect(reads).toEqual(['org-a']);
    expect(screen.getByRole('link', { name: 'View Details' })).toHaveAttribute('href', '/console/org/operate/applications/application-a');
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Reject' })).not.toBeInTheDocument();
    expect(writes).toEqual([]);
  });

  it.each(['approve', 'reject'])('uses the exact native %s grant without acquiring a separate reviewer lock', async action => {
    state.grants = new Set(['application:view', `application:${action}`]);
    const { user } = renderWithRouter(<ApplicationsPage />);
    await user.click(await screen.findByRole('button', { name: action === 'approve' ? 'Approve' : 'Reject' }));
    await waitFor(() => expect(reads).toHaveLength(2));
    expect(writes).toEqual([{
      organizationId: 'org-a', id: 'application-a', action,
      body: action === 'approve' ? {} : { reason: 'Rejected by organization reviewer' },
    }]);
    expect(manualLocks).toBe(0);
    expect(screen.queryByRole('button', { name: action === 'approve' ? 'Reject' : 'Approve' })).not.toBeInTheDocument();
  });

  it.each(['UNDER_REVIEW', 'PENDING_INFORMATION'])('allows current review actions for native %s records', async status => {
    inventory = [{ ...application, status }];
    renderWithRouter(<ApplicationsPage />);
    expect(await screen.findByRole('button', { name: 'Approve' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeEnabled();
    const row = screen.getByText('Visitor pass').closest('tr')!;
    expect(within(row).getByText(status === 'PENDING_INFORMATION' ? 'Needs Info' : 'Under Review')).toBeInTheDocument();
    expect(within(row).queryByText('Unknown')).not.toBeInTheDocument();
  });

  it.each(['APPROVED', 'OFFERED', 'CREDENTIALED'])('uses issuance:initiate for the native %s wallet offer action', async status => {
    state.grants = new Set(['application:view', 'issuance:initiate']);
    inventory = [{ ...application, status }];
    const { user } = renderWithRouter(<ApplicationsPage />);
    await user.click(await screen.findByRole('button', { name: status === 'APPROVED' ? 'Generate wallet invite' : 'Resend wallet invite' }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]).toMatchObject({ organizationId: 'org-a', id: 'application-a', action: 'issue' });
  });

  it('does not expose wallet offer creation to application reviewers without issuance permission', async () => {
    state.grants.delete('issuance:initiate');
    inventory = [{ ...application, status: 'APPROVED' }, { ...application, id: 'offered', status: 'OFFERED' }];
    renderWithRouter(<ApplicationsPage />);
    await screen.findAllByText('Visitor pass');
    expect(screen.queryByRole('button', { name: /wallet invite/i })).not.toBeInTheDocument();
  });

  it('blocks repeated actions while pending and keeps failures retryable in the current list', async () => {
    const pending = deferred<unknown>();
    const mutation = vi.spyOn(applicantApi, 'reviewOrganizationApplication').mockReturnValueOnce(pending.promise);
    const { user } = renderWithRouter(<ApplicationsPage />);
    const approve = await screen.findByRole('button', { name: 'Approve' });
    await act(async () => { fireEvent.click(approve); fireEvent.click(approve); });
    expect(mutation).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Reject' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled();
    await act(async () => pending.reject(new Error(' ')));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to update the application. Please try again.');
    expect(reads).toHaveLength(1);
    expect(approve).toBeEnabled();
    await user.click(approve);
    await waitFor(() => expect(reads).toHaveLength(2));
    expect(mutation).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it.each(['organization', 'account', 'permissions', 'unmount'])('ignores pending write completion after %s changes', async change => {
    inventory = [{ ...application, status: 'CREDENTIALED' }];
    const pending = deferred<unknown>();
    vi.spyOn(applicantApi, 'issueOrganizationApplication').mockReturnValueOnce(pending.promise);
    const view = renderWithRouter(<ApplicationsPage />);
    await view.user.click(await screen.findByRole('button', { name: 'Resend wallet invite' }));
    if (change === 'organization') state.organizationId = 'org-b';
    if (change === 'account') state.principalId = 'user-b';
    if (change === 'permissions') state.grants.delete('issuance:initiate');
    if (change === 'unmount') view.unmount();
    else {
      inventory = [];
      view.rerender(<ApplicationsPage />);
      await waitFor(() => expect(reads).toHaveLength(2));
    }
    const beforeCompletion = reads.length;
    await act(async () => pending.resolve(application));
    expect(reads).toHaveLength(beforeCompletion);
    expect(state.showSuccess).not.toHaveBeenCalled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('ignores failed actions and inventories from a former account at the same organization', async () => {
    const action = deferred<unknown>();
    vi.spyOn(applicantApi, 'reviewOrganizationApplication').mockReturnValueOnce(action.promise);
    const view = renderWithRouter(<ApplicationsPage />);
    await view.user.click(await screen.findByRole('button', { name: 'Approve' }));
    state.principalId = 'user-b'; inventory = [];
    view.rerender(<ApplicationsPage />);
    await waitFor(() => expect(reads).toHaveLength(2));
    await act(async () => action.reject(new Error('Former account failed')));
    expect(screen.queryByText('Former account failed')).not.toBeInTheDocument();
    expect(screen.queryByText('Visitor pass')).not.toBeInTheDocument();
  });

  it('does not show an empty queue after a failed request and retries in place', async () => {
    vi.spyOn(applicantApi, 'listOrganizationApplications').mockRejectedValueOnce(new Error(' '));
    const { user } = renderWithRouter(<ApplicationsPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load applications');
    expect(screen.queryByText('No applications yet')).not.toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Visitor pass')).toBeInTheDocument();
  });

  it.each([{}, { items: {} }, 'invalid'])('does not render a malformed successful native inventory as an empty queue %#', async response => {
    server.use(http.get('*/v1/organizations/:org/applicants', () => HttpResponse.json(response)));
    const { user } = renderWithRouter(<ApplicationsPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Application inventory returned an invalid response.');
    expect(screen.queryByText('No applications yet')).not.toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    server.use(http.get('*/v1/organizations/:org/applicants', () => HttpResponse.json({ items: [application] })));
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Visitor pass')).toBeInTheDocument();
  });

  it.each([['UNDER_REVIEW', 'Under Review'], ['PENDING_INFORMATION', 'Awaiting Information']])('filters the native %s state', async (status, option) => {
    inventory = [{ ...application, status }, { ...application, id: 'other', status: 'APPROVED', credential_display_name: 'Other pass' }];
    const { user } = renderWithRouter(<ApplicationsPage />);
    await screen.findByText('Other pass');
    await user.click(screen.getByRole('combobox', { name: 'Status' }));
    await user.click(screen.getByRole('option', { name: option, exact: true }));
    expect(screen.getByText('Visitor pass')).toBeInTheDocument();
    expect(screen.queryByText('Other pass')).not.toBeInTheDocument();
  });

  it('labels filters, tolerates missing optional display values and can clear a no-match search', async () => {
    inventory = [{ ...application, applicant_id: undefined, applicant_identifier: undefined, credential_display_name: undefined },
      { ...application, id: 'pending-info', status: 'PENDING_INFORMATION' }];
    const { user } = renderWithRouter(<ApplicationsPage />);
    await screen.findByText('Visitor pass');
    const search = screen.getByRole('textbox', { name: 'Search applications...' });
    await user.type(search, 'unknown');
    expect(screen.getByText('No applications match your filters. Try adjusting your search.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(search).toHaveValue('');
    await user.click(screen.getByRole('combobox', { name: 'Status' }));
    await user.click(screen.getByRole('option', { name: 'Pending', exact: true }));
    expect(screen.getByText('Visitor pass')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(3);
  });
});
