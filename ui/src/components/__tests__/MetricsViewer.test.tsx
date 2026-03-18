import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

import MetricsViewer from '../MetricsViewer';

const { mockLoadAdminMetrics } = vi.hoisted(() => ({
  mockLoadAdminMetrics: vi.fn(),
}));

vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div data-testid="responsive-container">{children}</div>,
  AreaChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  LineChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  CartesianGrid: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  Area: () => null,
  Line: () => null,
}));

vi.mock('../../application/admin', async () => {
  const actual = await vi.importActual<typeof import('../../application/admin')>('../../application/admin');
  return {
    ...actual,
    loadAdminMetrics: (...args: unknown[]) => mockLoadAdminMetrics(...args),
  };
});

describe('MetricsViewer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadAdminMetrics.mockResolvedValue({
      cpu_usage: 42,
      memory_usage: 67,
      request_rate: 13,
      transaction_volume: [{ name: '08:00', issuance: 3, verification: 2 }],
    });
  });

  it('loads metrics into the cards on mount', async () => {
    render(<MetricsViewer />);

    expect(await screen.findByText('42%')).toBeInTheDocument();
    expect(screen.getByText('67%')).toBeInTheDocument();
    expect(screen.getByText('13 req/s')).toBeInTheDocument();
    expect(mockLoadAdminMetrics).toHaveBeenCalledTimes(1);
  });
});
