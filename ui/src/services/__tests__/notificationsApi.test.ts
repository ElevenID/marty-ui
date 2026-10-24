import { describe, it, expect } from 'vitest';
import { server } from '@test/mocks/server';
import { http, HttpResponse } from 'msw';
import * as api from '../notificationsApi';
import examples from '../../../../contracts/notification-http-examples.json';

const ORG = 'org-a';
describe('native notification client', () => {
  it('sends explicit organization, recipient, supported filters and zero offset to the native array route', async () => {
    let query: URLSearchParams;
    server.use(http.get('*/v1/notifications', ({ request }) => { query = new URL(request.url).searchParams; return HttpResponse.json([examples.response]); }));
    expect(await api.listNotifications({ organization_id: ' org-a ', recipient_id: 'user-a', unread_only: false, status: 'failed', limit: 25, offset: 0 })).toEqual([examples.response]);
    expect(Object.fromEntries(query!)).toEqual({ organization_id: ORG, recipient_id: 'user-a', unread_only: 'false', status: 'failed', limit: '25', offset: '0' });
  });
  it('scopes native counts, read updates, mark-all-read and deletion with actual response shapes', async () => {
    const seen: [string, string, string | null][] = [];
    const record = (request: Request) => seen.push([request.method, new URL(request.url).pathname, new URL(request.url).searchParams.get('organization_id')]);
    server.use(
      http.get('*/v1/notifications/unread/count', ({ request }) => { record(request); expect(new URL(request.url).searchParams.get('recipient_id')).toBe('user-a'); return HttpResponse.json({ count: 7 }); }),
      http.patch('*/v1/notifications/:id/read', ({ request }) => { record(request); return HttpResponse.json({ ...examples.response, read: true }); }),
      http.delete('*/v1/notifications/:id/read', ({ request }) => { record(request); return HttpResponse.json({ ...examples.response, read: false }); }),
      http.post('*/v1/notifications/read-all', ({ request }) => { record(request); return HttpResponse.json({ marked_read: 7 }); }),
      http.delete('*/v1/notifications/:id', ({ request }) => { record(request); return HttpResponse.json({ success: true }); }),
    );
    expect(await api.getUnreadCount(ORG, 'user-a')).toEqual({ count: 7 });
    expect((await api.markAsRead('notification/with space', ORG)).read).toBe(true);
    expect((await api.markAsUnread('notification-1', ORG)).read).toBe(false);
    expect(await api.markAllAsRead(ORG, 'user-a')).toEqual({ marked_read: 7 });
    expect(await api.deleteNotification('notification-1', ORG)).toEqual({ success: true });
    expect(seen.map((item) => item[2])).toEqual([ORG, ORG, ORG, ORG, ORG]);
    expect(seen[1][1]).toBe('/v1/notifications/notification%2Fwith%20space/read');
  });
  it('preserves the embedded native send target and keeps delivery results separate', async () => {
    let body: unknown;
    server.use(
      http.post('*/v1/notifications/send', async ({ request }) => { body = await request.json(); return HttpResponse.json(examples.response); }),
      http.get('*/v1/notifications/:id/delivery-results', ({ request }) => { expect(new URL(request.url).searchParams.get('organization_id')).toBe(ORG); return HttpResponse.json([{ notification_id: 'notification-1', channel: 'SSE', success: false }]); }),
    );
    expect((await api.sendNotification(examples.send)).status).toBe('failed');
    expect(body).toEqual(examples.send);
    expect((await api.getNotificationDeliveryResults('notification-1', ORG))[0].success).toBe(false);
  });
  it('rejects missing scope, foreign targets and foreign responses', async () => {
    let called = false;
    server.use(http.all('*/v1/notifications*', () => { called = true; return HttpResponse.json({ ...examples.response, organization_id: 'foreign' }); }));
    await expect(api.listNotifications()).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    await expect(api.getUnreadCount()).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    await expect(api.markAsRead('id')).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    await expect(api.markAsUnread('id')).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    await expect(api.markAllAsRead()).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    await expect(api.deleteNotification('id')).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    await expect(api.sendNotification({ ...examples.send, target: { organization_id: 'foreign' } })).rejects.toThrow('Notification target organization must match');
    expect(called).toBe(false);
    await expect(api.getNotification('id', ORG)).rejects.toThrow('outside the selected organization');
  });
  it.each(['getNotificationPreferences', 'updateNotificationPreferences', 'listAlertRules', 'createAlertRule', 'updateAlertRule', 'deleteAlertRule', 'toggleAlertRule'] as const)('reports %s as unsupported without a network request', async (method) => {
    let called = false;
    server.use(http.all('*/v1/notifications*', () => { called = true; return HttpResponse.json({}); }));
    await expect(api[method]()).rejects.toMatchObject({ code: 'UNSUPPORTED_OPERATION', status: 501 });
    expect(called).toBe(false);
  });
});
