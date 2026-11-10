import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import examples from '../../../../contracts/notification-http-examples.json';
import notificationsApi from '../../services/notificationsApi';
import NotificationDropdown from './NotificationDropdown';

describe('scoped native notification dropdown', () => {
  let anchor: HTMLButtonElement;
  beforeEach(() => {
    anchor = document.createElement('button');
    anchor.getBoundingClientRect = () => ({ x: 0, y: 0, top: 0, left: 0, right: 1, bottom: 1, width: 1, height: 1, toJSON: () => ({}) });
    document.body.appendChild(anchor);
  });
  afterEach(() => { anchor.remove(); vi.restoreAllMocks(); });
  it('uses the scoped recipient query and rechecks the authoritative count after acknowledgement', async () => {
    let read = false;
    const changed = vi.fn();
    server.use(
      http.get('*/v1/notifications', ({ request }) => {
        expect(Object.fromEntries(new URL(request.url).searchParams)).toMatchObject({ organization_id: 'org-a', recipient_id: 'user-a', limit: '10' });
        return HttpResponse.json([{ ...examples.response, read }]);
      }),
      http.patch('*/v1/notifications/:id/read', ({ request }) => {
        expect(new URL(request.url).searchParams.get('organization_id')).toBe('org-a');
        read = true; return HttpResponse.json({ ...examples.response, read });
      }),
    );
    const { user } = renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} onCountChange={changed} />);
    const notificationBody = await screen.findByText(examples.response.body);
    expect(notificationBody.parentElement?.closest('p')).toBeNull();
    await user.click(notificationBody);
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
    expect(changed).toHaveBeenCalledWith();
  });
  it.each(['javascript:alert(1)', 'https://foreign.example/', '//foreign.example/', '/console\\\\foreign.example/'])('does not turn an untrusted notification link into navigation: %s', async (link) => {
    server.use(http.get('*/v1/notifications', () => HttpResponse.json([{ ...examples.response, link }])));
    renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} />);
    await screen.findByText(examples.response.body);
    expect(screen.queryByRole('link', { name: 'Open notification' })).not.toBeInTheDocument();
  });
  it('preserves safe console navigation', async () => {
    server.use(http.get('*/v1/notifications', () => HttpResponse.json([{ ...examples.response, link: '/console/org/notifications' }])));
    renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} />);
    expect(await screen.findByRole('link', { name: 'Open notification' })).toHaveAttribute('href', '/console/org/notifications');
  });
  it('refreshes the open inbox and unread count after marking all notifications read', async () => {
    let read = false;
    const changed = vi.fn();
    const acknowledge = vi.fn();
    server.use(
      http.get('*/v1/notifications', () => HttpResponse.json([{ ...examples.response, read }])),
      http.post('*/v1/notifications/read-all', ({ request }) => {
        expect(Object.fromEntries(new URL(request.url).searchParams)).toEqual({ organization_id: 'org-a', recipient_id: 'user-a' });
        acknowledge(); read = true;
        return HttpResponse.json({ count: 1 });
      }),
    );
    const { user } = renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} onCountChange={changed} />);
    await user.click(await screen.findByRole('button', { name: 'Mark all read' }));
    await waitFor(() => expect(acknowledge).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByText('NEW')).not.toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Mark all read' })).not.toBeInTheDocument();
    expect(changed).toHaveBeenCalledTimes(1);
  });
  it('keeps failed acknowledgements visible and retryable while preventing duplicate submissions', async () => {
    let finish: () => void = () => {};
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    let requests = 0;
    let read = false;
    const changed = vi.fn();
    server.use(
      http.get('*/v1/notifications', () => HttpResponse.json([{ ...examples.response, read }])),
      http.post('*/v1/notifications/read-all', async () => {
        requests += 1;
        if (requests === 1) {
          await pending;
          return HttpResponse.json({ message: 'Could not mark notifications read' }, { status: 503 });
        }
        read = true;
        return HttpResponse.json({ count: 1 });
      }),
    );
    const { user } = renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} onCountChange={changed} />);
    const markAll = await screen.findByRole('button', { name: 'Mark all read' });
    await user.click(markAll);
    await waitFor(() => expect(requests).toBe(1));
    expect(markAll).toBeDisabled();
    await act(async () => { finish(); await pending; });
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not mark notifications read');
    expect(screen.getByText('NEW')).toBeInTheDocument();
    expect(changed).not.toHaveBeenCalled();
    await user.click(markAll);
    await waitFor(() => expect(requests).toBe(2));
    await waitFor(() => expect(screen.queryByText('NEW')).not.toBeInTheDocument());
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(changed).toHaveBeenCalledTimes(1);
  });
  it('allows keyboard users to acknowledge an individual notification', async () => {
    let read = false;
    server.use(
      http.get('*/v1/notifications', () => HttpResponse.json([{ ...examples.response, read }])),
      http.patch('*/v1/notifications/:id/read', () => {
        read = true;
        return HttpResponse.json({ ...examples.response, read });
      }),
    );
    const { user } = renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} />);
    const markRead = await screen.findByRole('button', { name: 'Mark as read: Credential ready' });
    markRead.focus();
    await user.keyboard('{Enter}');
    await waitFor(() => expect(read).toBe(true));
    await waitFor(() => expect(screen.queryByText('NEW')).not.toBeInTheDocument());
  });
  it.each(['success', 'failure'])('ignores an old acknowledgement %s after the dropdown is reopened', async (outcome) => {
    let finish: () => void = () => {};
    const pending = new Promise<void>((resolve, reject) => {
      finish = () => outcome === 'success' ? resolve() : reject(new Error('Old acknowledgement failed'));
    });
    const acknowledge = vi.spyOn(notificationsApi, 'markAllAsRead').mockImplementationOnce(() => pending);
    const changed = vi.fn();
    let loads = 0;
    server.use(http.get('*/v1/notifications', () => { loads += 1; return HttpResponse.json([examples.response]); }));
    const props = { anchorEl: anchor, organizationId: 'org-a', recipientId: 'user-a', onClose: vi.fn(), onCountChange: changed };
    const { user, rerender } = renderWithRouter(<NotificationDropdown {...props} open />);
    await user.click(await screen.findByRole('button', { name: 'Mark all read' }));
    expect(acknowledge).toHaveBeenCalledTimes(1);
    rerender(<NotificationDropdown {...props} open={false} />);
    rerender(<NotificationDropdown {...props} open />);
    await waitFor(() => expect(loads).toBe(2));
    await screen.findByText('NEW');
    await act(async () => { finish(); await pending.catch(() => {}); });
    expect(screen.getByText('NEW')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Mark all read' })).toBeEnabled();
    expect(changed).not.toHaveBeenCalled();
    expect(loads).toBe(2);
  });
});
