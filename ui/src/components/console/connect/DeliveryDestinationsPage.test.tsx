import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, waitFor } from '@testing-library/react';
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

  it('retains a failed creation form and offers the existing error recovery', async () => {
    server.use(http.post('http://localhost:8000/v1/delivery-destinations', () => HttpResponse.json({ detail: 'Bureau not approved' }, { status: 403 })));
    const { user } = renderWithRouter(<DeliveryDestinationsPage />);
    await screen.findByText('Configured wallet destination');
    await user.click(screen.getByRole('button', { name: 'Add Production Destination' }));
    await user.type(screen.getByRole('textbox', { name: 'Destination name' }), 'Campus Bureau');
    await user.click(screen.getByRole('button', { name: 'Add Destination' }));
    expect(await screen.findByText('Bureau not approved')).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Destination name' })).toHaveValue('Campus Bureau');
    expect(reads).toHaveLength(1);
  });

});
