import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { renderWithRouter, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import examples from '../../../../contracts/notification-http-examples.json';
import NotificationDropdown from './NotificationDropdown';

describe('scoped native notification dropdown', () => {
  let anchor: HTMLButtonElement;
  beforeEach(() => {
    anchor = document.createElement('button');
    anchor.getBoundingClientRect = () => ({ x: 0, y: 0, top: 0, left: 0, right: 1, bottom: 1, width: 1, height: 1, toJSON: () => ({}) });
    document.body.appendChild(anchor);
  });
  afterEach(() => { anchor.remove(); });
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
    const { user } = renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} onMarkAllRead={vi.fn()} onCountChange={changed} />);
    await user.click(await screen.findByText(examples.response.body));
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
    expect(changed).toHaveBeenCalledWith();
  });
  it.each(['javascript:alert(1)', 'https://foreign.example/', '//foreign.example/', '/console\\\\foreign.example/'])('does not turn an untrusted notification link into navigation: %s', async (link) => {
    server.use(http.get('*/v1/notifications', () => HttpResponse.json([{ ...examples.response, link }])));
    renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} onMarkAllRead={vi.fn()} />);
    await screen.findByText(examples.response.body);
    expect(screen.queryByRole('link', { name: 'Open notification' })).not.toBeInTheDocument();
  });
  it('preserves safe console navigation', async () => {
    server.use(http.get('*/v1/notifications', () => HttpResponse.json([{ ...examples.response, link: '/console/org/notifications' }])));
    renderWithRouter(<NotificationDropdown open anchorEl={anchor} organizationId="org-a" recipientId="user-a" onClose={vi.fn()} onMarkAllRead={vi.fn()} />);
    expect(await screen.findByRole('link', { name: 'Open notification' })).toHaveAttribute('href', '/console/org/notifications');
  });
});
