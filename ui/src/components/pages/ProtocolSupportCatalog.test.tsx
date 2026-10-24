import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import catalog from '../../../../contracts/protocol-support-catalog.json';
import ProtocolSupportCatalog from './ProtocolSupportCatalog';

const mockGetCatalog = vi.fn();
vi.mock('../../services/protocolSupportApi', () => ({
  PROTOCOL_SUPPORT_PATH: '/v1/protocol-support',
  PROTOCOL_SUPPORT_LEVELS: ['implemented', 'derived', 'partial', 'unsupported'],
  getProtocolSupportCatalog: (...args: unknown[]) => mockGetCatalog(...args),
}));

describe('ProtocolSupportCatalog', () => {
  beforeEach(() => {
    mockGetCatalog.mockReset();
    mockGetCatalog.mockResolvedValue(catalog);
  });

  it('renders all explicit support states from the gateway catalog', async () => {
    render(<ProtocolSupportCatalog />);
    expect(screen.getByLabelText('Loading protocol support')).toBeInTheDocument();
    expect(await screen.findByTestId('protocol-support-catalog')).toBeInTheDocument();
    expect(screen.getByText('Implemented: 14')).toBeInTheDocument();
    expect(screen.getByText('Derived: 1')).toBeInTheDocument();
    expect(screen.getByText('Partial: 15')).toBeInTheDocument();
    expect(screen.getByText('Unsupported: 3')).toBeInTheDocument();
    expect(screen.getByText('Machine Identity')).toBeInTheDocument();
    expect(screen.getByText('Machine Authentication Policy')).toBeInTheDocument();
    expect(screen.getByText('Authorization Decision Receipt')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'machine-readable catalog' })).toHaveAttribute('href', '/v1/protocol-support');
  });

  it('shows an explicit failure and retries the owner endpoint', async () => {
    mockGetCatalog.mockRejectedValueOnce(new Error('gateway unavailable')).mockResolvedValueOnce(catalog);
    render(<ProtocolSupportCatalog />);
    expect(await screen.findByText(/Support status could not be loaded: gateway unavailable/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(mockGetCatalog).toHaveBeenCalledTimes(2));
    expect(await screen.findByTestId('protocol-support-catalog')).toBeInTheDocument();
  });
});
