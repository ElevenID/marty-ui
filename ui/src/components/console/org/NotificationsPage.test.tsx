import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { renderWithRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import examples from '../../../../../contracts/notification-http-examples.json';
import NotificationsPage from './NotificationsPage';
import NotificationPreferencesPage from '../NotificationPreferencesPage';

const { context, auth, permission, can } = vi.hoisted(() => ({ context: { activeOrgId: 'org-a' }, auth: { user: { sub: 'user-a' } }, permission: { isLoading: false }, can: vi.fn() }));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ ...permission, can }) }));

describe('native notification inbox', () => {
  let items: typeof examples.response[];
  let reads: URL[];
  let writes: [string, string][];
  beforeEach(() => {
    context.activeOrgId = 'org-a'; auth.user = { sub: 'user-a' }; permission.isLoading = false; can.mockReturnValue(true);
    items = [structuredClone(examples.response)]; reads = []; writes = [];
    server.use(
      http.get('*/v1/notifications', ({ request }) => { reads.push(new URL(request.url)); return HttpResponse.json(items); }),
      http.patch('*/v1/notifications/:id/read', ({ request }) => { writes.push([request.method, new URL(request.url).search]); items[0].read = true; return HttpResponse.json(items[0]); }),
      http.delete('*/v1/notifications/:id/read', ({ request }) => { writes.push([request.method, new URL(request.url).search]); items[0].read = false; return HttpResponse.json(items[0]); }),
      http.post('*/v1/notifications/read-all', ({ request }) => { writes.push([request.method, new URL(request.url).search]); items = items.map((item) => ({ ...item, read: true })); return HttpResponse.json({ marked_read: items.length }); }),
      http.delete('*/v1/notifications/:id', ({ request }) => { writes.push([request.method, new URL(request.url).search]); items = []; return HttpResponse.json({ success: true }); }),
      http.get('*/v1/notifications/:id/delivery-results', () => HttpResponse.json([{ notification_id: examples.response.id, channel: 'SSE', success: false, attempted_at: examples.response.created_at, error_code: 'SSE_UNAVAILABLE', should_retry: true }])),
    );
  });
  it('uses the native scoped array/body/read projection and persists acknowledgement and confirmed deletion', async () => {
    const { user } = renderWithRouter(<NotificationsPage />);
    expect(await screen.findByText(examples.response.body)).toBeInTheDocument();
    expect(screen.getByRole('cell', { name: 'Unread' })).toBeInTheDocument();
    expect(Object.fromEntries(reads[0].searchParams)).toMatchObject({ organization_id: 'org-a', recipient_id: 'user-a', unread_only: 'false', limit: '25', offset: '0' });
    await user.click(screen.getByRole('button', { name: 'Mark as read' }));
    expect(await screen.findByText('Read')).toBeInTheDocument();
    expect(writes[0]).toEqual(['PATCH', '?organization_id=org-a']);
    await user.click(screen.getByRole('button', { name: 'Mark as unread' }));
    expect(await screen.findByRole('cell', { name: 'Unread' })).toBeInTheDocument();
    expect(writes[1]).toEqual(['DELETE', '?organization_id=org-a']);
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(writes).toHaveLength(2);
    await user.click(screen.getByRole('button', { name: 'Confirm deletion' }));
    expect(await screen.findByText('No notifications on this page.')).toBeInTheDocument();
    expect(writes[2]).toEqual(['DELETE', '?organization_id=org-a']);
  });
  it('reads actual delivery failures separately from acceptance and does not display target contact data', async () => {
    const { user } = renderWithRouter(<NotificationsPage />);
    await screen.findByText(examples.response.body);
    await user.click(screen.getByRole('button', { name: 'Delivery results' }));
    expect(await screen.findByText('SSE: Failed')).toBeInTheDocument();
    expect(screen.getByText(/not proof of delivery/)).toBeInTheDocument();
    expect(screen.getByText('Error code: SSE_UNAVAILABLE')).toBeInTheDocument();
  });
  it('uses the real recipient selector for mark-all-read', async () => {
    const { user } = renderWithRouter(<NotificationsPage />);
    await screen.findByText(examples.response.body);
    await user.click(screen.getByRole('button', { name: /mark all as read/i }));
    expect(await screen.findByText('Read')).toBeInTheDocument();
    expect(writes[0]).toEqual(['POST', '?recipient_id=user-a&organization_id=org-a']);
  });
  it('reports embedded-target support and absent rule/preferences editors without issuing phantom requests', async () => {
    let unsupportedCalls = 0;
    server.use(http.all('*/v1/notifications/preferences', () => { unsupportedCalls++; return HttpResponse.json({}); }), http.all('*/v1/notifications/rules', () => { unsupportedCalls++; return HttpResponse.json({}); }));
    const { user } = renderWithRouter(<NotificationsPage />);
    await screen.findByText(examples.response.body);
    await user.click(screen.getByRole('tab', { name: 'API support' }));
    expect(screen.getByText(/Notification targets are supported inside send requests/)).toBeInTheDocument();
    expect(screen.getByText(/Alert rules and notification preference read\/update operations are not supported/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /create.*rule/i })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View API contract' })).toHaveAttribute('href', '/openapi.json');
    expect(unsupportedCalls).toBe(0);
  });
  it('preserves the settings URL as an explicit unsupported page without save controls', () => {
    renderWithRouter(<NotificationPreferencesPage />);
    expect(screen.getByText('Notification preferences are not supported by the notification API.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /save/i })).not.toBeInTheDocument();
    expect(reads).toHaveLength(0);
  });
  it.each(['loading', 'denied', 'no organization', 'no principal'])('does not mount inbox loaders while %s', (condition) => {
    if (condition === 'loading') permission.isLoading = true;
    if (condition === 'denied') can.mockReturnValue(false);
    if (condition === 'no organization') context.activeOrgId = '';
    if (condition === 'no principal') auth.user = { sub: '' };
    renderWithRouter(<NotificationsPage />);
    expect(reads).toHaveLength(0); expect(writes).toHaveLength(0);
  });
  it('rejects a foreign response without showing its body and recovers after retry', async () => {
    items = [{ ...examples.response, organization_id: 'org-b', body: 'Foreign notification' }];
    const { user } = renderWithRouter(<NotificationsPage />);
    expect(await screen.findByText('Notification response is invalid or outside the selected organization.')).toBeInTheDocument();
    expect(screen.queryByText('Foreign notification')).not.toBeInTheDocument();
    expect(screen.queryByText('No notifications on this page.')).not.toBeInTheDocument();
    items = [structuredClone(examples.response)];
    await user.click(screen.getByRole('button', { name: 'Retry notifications' }));
    expect(await screen.findByText(examples.response.body)).toBeInTheDocument();
  });
  it('drops a late response after an organization change', async () => {
    let release: () => void = () => {};
    let calls = 0;
    server.use(http.get('*/v1/notifications', async ({ request }) => {
      calls++;
      const org = new URL(request.url).searchParams.get('organization_id');
      if (org === 'org-a') await new Promise<void>((resolve) => { release = resolve; });
      return HttpResponse.json([{ ...examples.response, organization_id: org, body: `Notification ${org}` }]);
    }));
    const { rerender } = renderWithRouter(<NotificationsPage />);
    await waitFor(() => expect(calls).toBe(1));
    context.activeOrgId = 'org-b'; rerender(<NotificationsPage />);
    expect(await screen.findByText('Notification org-b')).toBeInTheDocument();
    await act(async () => { release(); });
    expect(screen.queryByText('Notification org-a')).not.toBeInTheDocument();
  });
});
