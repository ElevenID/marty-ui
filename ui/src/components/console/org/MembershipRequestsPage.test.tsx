import { beforeEach, describe, expect, it } from 'vitest';
import { waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { renderWithRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import MembershipRequestsPage from './MembershipRequestsPage';

const request = { id: 'request-1', user_email: 'member@example.org', status: 'pending', message: 'Please admit', created_at: '2026-10-28T10:00:00Z' };

describe('MembershipRequestsPage shared fetch lifecycle', () => {
  let reads: number;
  let inventory: typeof request[];
  let writes: Record<string, unknown>[];
  beforeEach(() => {
    reads = 0; inventory = [request]; writes = [];
    server.use(
      http.get('*/api/onboarding/pending-requests', () => {
        reads++;
        return HttpResponse.json({ requests: inventory });
      }),
      http.post('*/api/onboarding/review-request', async ({ request }) => {
        writes.push(await request.json() as Record<string, unknown>);
        inventory = [];
        return HttpResponse.json({ success: true, message: 'Review completed' });
      }),
    );
  });

  it('approves through the real client and reloads the pending inventory', async () => {
    const { user } = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText(request.user_email);
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(reads).toBe(2));
    expect(writes).toEqual([{ request_id: request.id, action: 'approve' }]);
    await waitFor(() => expect(screen.queryByText(request.user_email)).not.toBeInTheDocument());
    expect(await screen.findByText('Review completed')).toBeInTheDocument();
  });

  it('preserves rejection reason trimming, dialog closure and list reload', async () => {
    const { user } = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText(request.user_email);
    await user.click(screen.getByRole('button', { name: 'Reject' }));
    const dialog = screen.getByRole('dialog');
    await user.type(within(dialog).getByRole('textbox'), '  Missing evidence  ');
    await user.click(within(dialog).getByRole('button', { name: 'Reject Request' }));
    await waitFor(() => expect(reads).toBe(2));
    expect(writes).toEqual([{ request_id: request.id, action: 'reject', rejection_reason: 'Missing evidence' }]);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('dismisses a read error and retries without retaining the stale error', async () => {
    let attempts = 0;
    server.use(http.get('*/api/onboarding/pending-requests', () => ++attempts === 1
      ? HttpResponse.json({ detail: 'Temporarily unavailable' }, { status: 503 })
      : HttpResponse.json({ requests: [request] })));
    const { user } = renderWithRouter(<MembershipRequestsPage />);
    const message = await screen.findByText('Temporarily unavailable');
    await user.click(within(message.closest('[role="alert"]') as HTMLElement).getByRole('button', { name: 'Close' }));
    expect(screen.queryByText('Temporarily unavailable')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await screen.findByText(request.user_email)).toBeInTheDocument();
    expect(attempts).toBe(2);
  });

  it('shows a mutation error without dropping the loaded request', async () => {
    server.use(http.post('*/api/onboarding/review-request', () => HttpResponse.json({ detail: 'Approval refused' }, { status: 403 })));
    const { user } = renderWithRouter(<MembershipRequestsPage />);
    await screen.findByText(request.user_email);
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(await screen.findByText('Approval refused')).toBeInTheDocument();
    expect(screen.getByText(request.user_email)).toBeInTheDocument();
    expect(reads).toBe(1);
  });
});
