import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { renderWithRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import DeliveryDestinationsPage from './DeliveryDestinationsPage';

const { context, permission, can } = vi.hoisted(() => ({ context: { activeOrgId: 'org-1' }, permission: { isLoading: false }, can: vi.fn() }));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ ...permission, can }) }));

describe('DeliveryDestinationsPage', () => {
  let reads: string[];
  let writes: Record<string, unknown>[];
  beforeEach(() => {
    context.activeOrgId = 'org-1'; permission.isLoading = false; can.mockReturnValue(true);
    reads = []; writes = [];
    server.use(
      http.get('http://localhost:8000/v1/delivery-destinations', ({ request }) => {
        const org = new URL(request.url).searchParams.get('organization_id') || '';
        reads.push(org);
        return HttpResponse.json([{ id: 'system-wallet', name: 'Configured wallet destination', is_system: true, is_enabled: true, mode: 'holder_wallet' }]);
      }),
      http.post('http://localhost:8000/v1/delivery-destinations', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>;
        writes.push(body);
        expect(request.headers.get('Idempotency-Key')).toBeTruthy();
        return HttpResponse.json({ id: 'destination-1', ...body }, { status: 201 });
      }),
    );
  });

  it('uses existing wallet read grants and does not offer mutation to a viewer', async () => {
    can.mockImplementation((resource, action) => resource === 'wallet' && action === 'view');
    renderWithRouter(<DeliveryDestinationsPage />);
    expect(await screen.findByText('Configured wallet destination')).toBeInTheDocument();
    expect(reads).toEqual(['org-1']);
    expect(screen.queryByRole('button', { name: 'Add Production Destination' })).not.toBeInTheDocument();
    expect(screen.getByText(/does not establish approval, successful delivery or wallet interoperability/)).toBeInTheDocument();
  });

  it.each(['loading', 'denied', 'no organization'])('blocks direct loaders while %s', (condition) => {
    if (condition === 'loading') permission.isLoading = true;
    if (condition === 'denied') can.mockReturnValue(false);
    if (condition === 'no organization') context.activeOrgId = '';
    renderWithRouter(<DeliveryDestinationsPage />);
    expect(reads).toEqual([]); expect(writes).toEqual([]);
  });

  it('creates a scoped physical destination through the real client', async () => {
    const { user } = renderWithRouter(<DeliveryDestinationsPage />);
    await screen.findByText('Configured wallet destination');
    await user.click(screen.getByRole('button', { name: 'Add Production Destination' }));
    await user.type(screen.getByRole('textbox', { name: 'Destination name' }), 'Campus Bureau');
    await user.click(screen.getByRole('button', { name: 'Add Destination' }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]).toMatchObject({ organization_id: 'org-1', name: 'Campus Bureau', provider: 'physical_document_bureau', mode: 'physical_document', is_enabled: true });
    await waitFor(() => expect(reads).toHaveLength(2));
  });

  it('rejects a foreign inventory rather than displaying it as configuration', async () => {
    server.use(http.get('http://localhost:8000/v1/delivery-destinations', () => HttpResponse.json([{ id: 'foreign', organization_id: 'org-2', name: 'Foreign destination' }])));
    renderWithRouter(<DeliveryDestinationsPage />);
    expect(await screen.findByText('Destination inventory is invalid or outside the selected organization.')).toBeInTheDocument();
    expect(screen.queryByText('Foreign destination')).not.toBeInTheDocument();
    expect(screen.queryByText('No delivery destinations')).not.toBeInTheDocument();
  });

  it('ignores a prior organization response after a scope switch', async () => {
    let release: () => void = () => {};
    let requests = 0;
    server.use(http.get('http://localhost:8000/v1/delivery-destinations', async ({ request }) => {
      requests++;
      const org = new URL(request.url).searchParams.get('organization_id');
      if (org === 'org-1') await new Promise<void>((resolve) => { release = resolve; });
      return HttpResponse.json([{ id: `destination-${org}`, organization_id: org, name: `Destination ${org}` }]);
    }));
    const { rerender } = renderWithRouter(<DeliveryDestinationsPage />);
    await waitFor(() => expect(requests).toBe(1));
    context.activeOrgId = 'org-2'; rerender(<DeliveryDestinationsPage />);
    expect(await screen.findByText('Destination org-2')).toBeInTheDocument();
    await act(async () => { release(); });
    expect(screen.queryByText('Destination org-1')).not.toBeInTheDocument();
    expect(screen.getByText('Destination org-2')).toBeInTheDocument();
  });

  it('retries a failed inventory fetch and clears its error', async () => {
    let attempts = 0;
    server.use(http.get('http://localhost:8000/v1/delivery-destinations', () => ++attempts === 1
      ? HttpResponse.json({ detail: 'Destination service unavailable' }, { status: 403 })
      : HttpResponse.json([{ id: 'system-wallet', name: 'Recovered destination', is_system: true }])));
    const { user } = renderWithRouter(<DeliveryDestinationsPage />);
    await screen.findByText('Destination service unavailable');
    await user.click(screen.getByRole('button', { name: 'Reload destinations' }));
    expect(await screen.findByText('Recovered destination')).toBeInTheDocument();
    expect(screen.queryByText('Destination service unavailable')).not.toBeInTheDocument();
  });

  it.each(['retry', 'cancel'] as const)('shows creation failure inside the dialog and preserves the draft and inventory on %s', async (action) => {
    const keys: Array<string | null> = [];
    server.use(http.post('http://localhost:8000/v1/delivery-destinations', async ({ request }) => {
      const body = await request.json() as Record<string, unknown>;
      writes.push(body);
      keys.push(request.headers.get('Idempotency-Key'));
      return writes.length === 1
        ? HttpResponse.json({ detail: 'Bureau not approved' }, { status: 403 })
        : HttpResponse.json({ id: 'destination-1', ...body }, { status: 201 });
    }));
    const { user } = renderWithRouter(<DeliveryDestinationsPage />);
    await screen.findByText('Configured wallet destination');
    await user.click(screen.getByRole('button', { name: 'Add Production Destination' }));
    const dialog = screen.getByRole('dialog', { name: 'Add physical production destination' });
    await user.type(screen.getByRole('textbox', { name: 'Destination name' }), 'Campus Bureau');
    await user.type(screen.getByRole('textbox', { name: 'Description' }), 'Reviewed production destination');
    await user.click(screen.getByRole('button', { name: 'Add Destination' }));
    expect(await within(dialog).findByText('Bureau not approved')).toBeVisible();
    expect(screen.getByRole('textbox', { name: 'Destination name' })).toHaveValue('Campus Bureau');
    expect(screen.getByRole('textbox', { name: 'Description' })).toHaveValue('Reviewed production destination');
    expect(screen.getByRole('button', { name: 'Add Destination' })).toBeEnabled();
    expect(writes).toHaveLength(1);
    expect(reads).toHaveLength(1);
    expect(keys[0]).toBeTruthy();

    if (action === 'retry') {
      await user.click(screen.getByRole('button', { name: 'Add Destination' }));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
      expect(writes).toHaveLength(2);
      expect(writes[1]).toEqual(writes[0]);
      expect(keys[1]).toBeTruthy();
      expect(keys[1]).not.toBe(keys[0]);
      await waitFor(() => expect(reads).toHaveLength(2));
    } else {
      await user.click(screen.getByRole('button', { name: 'Cancel' }));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
      expect(screen.getByText('Configured wallet destination')).toBeVisible();
      expect(screen.queryByText('Bureau not approved')).not.toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Add Production Destination' }));
      expect(screen.queryByText('Bureau not approved')).not.toBeInTheDocument();
      expect(screen.getByRole('textbox', { name: 'Destination name' })).toHaveValue('Campus Bureau');
      expect(screen.getByRole('textbox', { name: 'Description' })).toHaveValue('Reviewed production destination');
      expect(writes).toHaveLength(1);
      expect(reads).toHaveLength(1);
    }
  });

});
