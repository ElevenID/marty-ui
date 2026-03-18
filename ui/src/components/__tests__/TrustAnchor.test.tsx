import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import TrustAnchor from '../TrustAnchor';

const {
  mockLoadTrustAnchorPageData,
  mockSaveTrustAnchorConfig,
} = vi.hoisted(() => ({
  mockLoadTrustAnchorPageData: vi.fn(),
  mockSaveTrustAnchorConfig: vi.fn(),
}));

vi.mock('../../application/admin', async () => {
  const actual = await vi.importActual<typeof import('../../application/admin')>('../../application/admin');
  return {
    ...actual,
    loadTrustAnchorPageData: (...args: unknown[]) => mockLoadTrustAnchorPageData(...args),
    saveTrustAnchorConfig: (...args: unknown[]) => mockSaveTrustAnchorConfig(...args),
  };
});

describe('TrustAnchor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadTrustAnchorPageData.mockResolvedValue({
      config: {
        anchorName: 'Demo Trust Anchor',
        domain: 'trust.example',
        policy: 'strict',
        logLevel: 'info',
      },
      status: {
        rootCA: { status: 'valid', expires: '2035' },
        intermediateCA: { status: 'valid', expires: '2030' },
        crlStatus: 'up_to_date',
        healthy: true,
      },
    });
    mockSaveTrustAnchorConfig.mockResolvedValue({
      success: true,
      message: 'Configuration saved successfully.',
    });
  });

  it('loads trust anchor config and status into the page', async () => {
    render(<TrustAnchor />);

    expect(await screen.findByDisplayValue('Demo Trust Anchor')).toBeInTheDocument();
    expect(screen.getByText('Trust chain is healthy and operational.')).toBeInTheDocument();
    expect(mockLoadTrustAnchorPageData).toHaveBeenCalledTimes(1);
  });

  it('saves the current configuration through the application layer', async () => {
    const { user } = render(<TrustAnchor />);

    await screen.findByDisplayValue('Demo Trust Anchor');
    await user.click(screen.getByRole('button', { name: /save configuration/i }));

    await waitFor(() => {
      expect(mockSaveTrustAnchorConfig).toHaveBeenCalledWith({
        config: {
          anchorName: 'Demo Trust Anchor',
          domain: 'trust.example',
          policy: 'strict',
          logLevel: 'info',
        },
        storage: window.localStorage,
      });
    });

    expect(screen.getByText('Configuration saved successfully.')).toBeInTheDocument();
  });
});
