import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { createInstance } from 'i18next';
import { I18nextProvider } from 'react-i18next';
import { renderWithRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import examples from '../../../../../contracts/notification-http-examples.json';
import consoleEn from '../../../../public/locales/en/console.json';
import consoleDe from '../../../../public/locales/de/console.json';
import consoleEs from '../../../../public/locales/es/console.json';
import consoleFr from '../../../../public/locales/fr/console.json';
import consoleJa from '../../../../public/locales/ja/console.json';
import consoleNl from '../../../../public/locales/nl/console.json';
import NotificationsPage from './NotificationsPage';
import NotificationPreferencesPage from '../NotificationPreferencesPage';
import NotificationBell from '../../common/NotificationBell';
import notificationsApi from '../../../services/notificationsApi';
import { subscribeToNotificationChanges } from '../../../services/notificationEvents';

const { context, auth, permission, can } = vi.hoisted(() => ({ context: { activeOrgId: 'org-a' }, auth: { user: { sub: 'user-a' } }, permission: { isLoading: false }, can: vi.fn() }));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ ...permission, can }) }));

describe('native notification inbox', () => {
  let items: typeof examples.response[];
  let reads: URL[];
  let countReads: URL[];
  let writes: [string, string][];
  beforeEach(() => {
    context.activeOrgId = 'org-a'; auth.user = { sub: 'user-a' }; permission.isLoading = false; can.mockReturnValue(true);
    items = [structuredClone(examples.response)]; reads = []; countReads = []; writes = [];
    server.use(
      http.get('*/v1/notifications', ({ request }) => { reads.push(new URL(request.url)); return HttpResponse.json(items); }),
      http.get('*/v1/notifications/unread/count', ({ request }) => { countReads.push(new URL(request.url)); return HttpResponse.json({ count: items.filter((item) => !item.read).length }); }),
      http.patch('*/v1/notifications/:id/read', ({ request }) => { writes.push([request.method, new URL(request.url).search]); items[0].read = true; return HttpResponse.json(items[0]); }),
      http.delete('*/v1/notifications/:id/read', ({ request }) => { writes.push([request.method, new URL(request.url).search]); items[0].read = false; return HttpResponse.json(items[0]); }),
      http.post('*/v1/notifications/read-all', ({ request }) => { writes.push([request.method, new URL(request.url).search]); items = items.map((item) => ({ ...item, read: true })); return HttpResponse.json({ marked_read: items.length }); }),
      http.delete('*/v1/notifications/:id', ({ request }) => { writes.push([request.method, new URL(request.url).search]); items = []; return HttpResponse.json({ success: true }); }),
      http.get('*/v1/notifications/:id/delivery-results', () => HttpResponse.json([{ notification_id: examples.response.id, channel: 'SSE', success: false, attempted_at: examples.response.created_at, error_code: 'SSE_UNAVAILABLE', should_retry: true }])),
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it.each(['individual', 'all'])('refreshes the page, open dropdown and bell once after %s acknowledgement succeeds', async (kind) => {
    let finish: () => void = () => {};
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    let acknowledgements = 0;
    const acknowledge = async ({ request }: { request: Request }) => {
      acknowledgements += 1;
      await pending;
      items[0].read = true;
      return HttpResponse.json(request.method === 'POST' ? { marked_read: 1 } : items[0]);
    };
    server.use(http.patch('*/v1/notifications/:id/read', acknowledge), http.post('*/v1/notifications/read-all', acknowledge));
    const { user } = renderWithRouter(<><NotificationBell /><div data-testid="inbox-page"><NotificationsPage /></div></>);
    const page = within(screen.getByTestId('inbox-page'));
    await page.findByText('Unread', { selector: 'span' });
    const bell = screen.getByRole('button', { name: 'notifications' });
    await within(bell).findByText('1');
    await user.click(bell);
    const dropdown = within(screen.getByRole('menu'));
    await dropdown.findByText('NEW');
    await user.click(dropdown.getByRole('button', { name: kind === 'all' ? 'Mark all read' : `Mark as read: ${examples.response.title}` }));
    await waitFor(() => expect(acknowledgements).toBe(1));
    expect(page.getByText('Unread', { selector: 'span' })).toBeInTheDocument();
    expect(dropdown.getByText('NEW')).toBeInTheDocument();
    expect(reads).toHaveLength(2);
    expect(countReads).toHaveLength(1);

    await act(async () => { finish(); await pending; });
    expect(await page.findByText('Read')).toBeInTheDocument();
    await waitFor(() => expect(dropdown.queryByText('NEW')).not.toBeInTheDocument());
    await waitFor(() => expect(bell.querySelector('.MuiBadge-badge')).toHaveAttribute('aria-hidden', 'true'));
    expect(reads.filter((url) => url.searchParams.get('limit') === '25')).toHaveLength(2);
    expect(reads.filter((url) => url.searchParams.get('limit') === '10')).toHaveLength(2);
    expect(countReads).toHaveLength(2);
  });

  it('refreshes the bell and a newly opened dropdown when a pending page mutation succeeds', async () => {
    items[0].read = true;
    let finish: () => void = () => {};
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    let acknowledgements = 0;
    server.use(http.delete('*/v1/notifications/:id/read', async () => {
      acknowledgements += 1;
      await pending;
      items[0].read = false;
      return HttpResponse.json(items[0]);
    }));
    const { user } = renderWithRouter(<><NotificationBell /><div data-testid="inbox-page"><NotificationsPage /></div></>);
    const page = within(screen.getByTestId('inbox-page'));
    await user.click(await page.findByRole('button', { name: 'Mark as unread' }));
    await waitFor(() => expect(acknowledgements).toBe(1));
    const bell = screen.getByRole('button', { name: 'notifications' });
    await user.click(bell);
    const dropdown = within(screen.getByRole('menu'));
    await dropdown.findByText(examples.response.body);
    expect(dropdown.queryByText('NEW')).not.toBeInTheDocument();
    expect(page.getByText('Read')).toBeInTheDocument();

    await act(async () => { finish(); await pending; });
    expect(await page.findByText('Unread', { selector: 'span' })).toBeInTheDocument();
    expect(await dropdown.findByText('NEW')).toBeInTheDocument();
    await within(bell).findByText('1');
    expect(reads.filter((url) => url.searchParams.get('limit') === '25')).toHaveLength(2);
    expect(reads.filter((url) => url.searchParams.get('limit') === '10')).toHaveLength(2);
    expect(countReads).toHaveLength(2);
  });

  it.each(['mark all read', 'delete'])('updates the bell immediately after the page completes %s', async (action) => {
    const { user } = renderWithRouter(<><NotificationBell /><NotificationsPage /></>);
    await screen.findByText(examples.response.body);
    const bell = screen.getByRole('button', { name: 'notifications' });
    await within(bell).findByText('1');
    if (action === 'delete') {
      await user.click(screen.getByRole('button', { name: 'Delete' }));
      await user.click(screen.getByRole('button', { name: 'Confirm deletion' }));
      await screen.findByText('No notifications on this page.');
    } else {
      await user.click(screen.getByRole('button', { name: /mark all as read/i }));
      await screen.findByRole('cell', { name: 'Read' });
    }
    await waitFor(() => expect(bell.querySelector('.MuiBadge-badge')).toHaveAttribute('aria-hidden', 'true'));
    expect(reads).toHaveLength(2);
    expect(countReads).toHaveLength(2);
  });

  it.each(['organization', 'principal', 'unmount'])('does not broadcast an old page mutation after a change of %s', async (change) => {
    let finish: (value: unknown) => void = () => {};
    const pending = new Promise((resolve) => { finish = resolve; });
    const acknowledge = vi.spyOn(notificationsApi, 'markAsRead').mockImplementationOnce(() => pending);
    const changed = vi.fn();
    const unsubscribe = subscribeToNotificationChanges({ organizationId: 'org-a', recipientId: 'user-a' }, changed);
    try {
      const view = renderWithRouter(<NotificationsPage />);
      await view.user.click(await screen.findByRole('button', { name: 'Mark as read' }));
      expect(acknowledge).toHaveBeenCalledOnce();
      if (change === 'unmount') view.unmount();
      else {
        if (change === 'organization') {
          context.activeOrgId = 'org-b';
          items = [{ ...examples.response, organization_id: 'org-b' }];
        } else auth.user = { sub: 'user-b' };
        view.rerender(<NotificationsPage />);
        await screen.findByText(examples.response.body);
      }
      await act(async () => { finish({ ...examples.response, read: true }); await pending; });
      expect(changed).not.toHaveBeenCalled();
      if (change !== 'unmount') expect(screen.getByRole('cell', { name: 'Unread' })).toBeInTheDocument();
    } finally { unsubscribe(); }
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
  it('shows delete failures inside the open dialog and clears them while retrying the same notification', async () => {
    let finishRetry: () => void = () => {};
    const pendingRetry = new Promise<void>((resolve) => { finishRetry = resolve; });
    const deletions: string[] = [];
    server.use(http.delete('*/v1/notifications/:id', async ({ request }) => {
      deletions.push(new URL(request.url).pathname + new URL(request.url).search);
      if (deletions.length === 1) return HttpResponse.json({ message: 'Could not delete notification' }, { status: 503 });
      await pendingRetry;
      items = [];
      return HttpResponse.json({ success: true });
    }));
    const { user } = renderWithRouter(<NotificationsPage />);
    await screen.findByText(examples.response.body);
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    const dialog = screen.getByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Confirm deletion' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Could not delete notification');
    expect(within(dialog).getByText(examples.response.title)).toBeInTheDocument();
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    await user.click(within(dialog).getByRole('button', { name: 'Confirm deletion' }));
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Confirm deletion' })).toBeDisabled();
    await waitFor(() => expect(deletions).toHaveLength(2));
    expect(deletions).toEqual(Array(2).fill(`/v1/notifications/${examples.response.id}?organization_id=org-a`));
    await act(async () => { finishRetry(); await pendingRetry; });
    expect(await screen.findByText('No notifications on this page.')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.queryByText('Could not delete notification')).not.toBeInTheDocument();
  });
  it.each(['Cancel', 'Escape'])('clears a failed deletion when dismissed with %s before another notification is selected', async (dismiss) => {
    items.push({ ...examples.response, id: 'notification-2', title: 'Another notification' });
    server.use(http.delete('*/v1/notifications/:id', () => HttpResponse.json({ message: 'Could not delete notification' }, { status: 503 })));
    const { user } = renderWithRouter(<NotificationsPage />);
    await screen.findByText('Another notification');
    await user.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
    const dialog = screen.getByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Confirm deletion' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Could not delete notification');
    if (dismiss === 'Cancel') await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    else await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.queryByText('Could not delete notification')).not.toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: 'Delete' })[1]);
    const nextDialog = screen.getByRole('dialog');
    expect(within(nextDialog).getByText('Another notification')).toBeInTheDocument();
    expect(within(nextDialog).queryByText(examples.response.title)).not.toBeInTheDocument();
    expect(within(nextDialog).queryByRole('alert')).not.toBeInTheDocument();
  });
  it.each([false, true])('keeps acknowledgement failures on the page for a notification with read=%s', async (read) => {
    items[0].read = read;
    const reject = () => HttpResponse.json({ message: 'Could not update notification' }, { status: 503 });
    server.use(http.patch('*/v1/notifications/:id/read', reject), http.delete('*/v1/notifications/:id/read', reject));
    const { user } = renderWithRouter(<><NotificationBell /><NotificationsPage /></>);
    await screen.findByText(examples.response.body);
    await user.click(screen.getByRole('button', { name: read ? 'Mark as unread' : 'Mark as read' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not update notification');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('cell', { name: read ? 'Read' : 'Unread' })).toBeInTheDocument();
    expect(reads).toHaveLength(1);
    expect(countReads).toHaveLength(1);
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
  it.each([
    ['en', consoleEn], ['de', consoleDe], ['es', consoleEs],
    ['fr', consoleFr], ['ja', consoleJa], ['nl', consoleNl],
  ] as const)('explains unsupported preferences in %s without offering a save action', async (locale, translations) => {
    const instance = createInstance();
    await instance.init({
      lng: locale, fallbackLng: 'en', ns: ['console'], defaultNS: 'console',
      resources: { en: { console: consoleEn }, [locale]: { console: translations } },
      interpolation: { escapeValue: false },
    });
    renderWithRouter(<I18nextProvider i18n={instance}><NotificationPreferencesPage /></I18nextProvider>);
    const messages = translations.notificationPreferencesPage.messages;
    expect(screen.getByRole('alert')).toHaveTextContent(messages.unsupported);
    expect(screen.getByText(messages.unsupportedDetails)).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(reads).toHaveLength(0);
    expect(writes).toHaveLength(0);
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
