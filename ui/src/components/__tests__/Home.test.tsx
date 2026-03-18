import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import Home from '../Home';

const { mockNavigate, mockLoadHomeDashboard } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockLoadHomeDashboard: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock('../../application/home', async () => {
  const actual = await vi.importActual<typeof import('../../application/home')>('../../application/home');
  return {
    ...actual,
    loadHomeDashboard: (...args: unknown[]) => mockLoadHomeDashboard(...args),
  };
});

describe('Home', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadHomeDashboard.mockResolvedValue({
      systemStatus: {
        healthy: false,
        services: { issuer: 'offline', verifier: 'online', wallet: 'online' },
      },
      stats: {
        credentials: 8,
        verifications: 13,
        masterLists: 4,
        certificates: 17,
      },
    });
  });

  it('loads dashboard data into the status and stats cards', async () => {
    render(<Home />);

    expect(await screen.findByText('Service Issues')).toBeInTheDocument();
    expect(screen.getByText('4 Countries · 17 Certificates')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument();
    expect(screen.getByText('13')).toBeInTheDocument();
    expect(mockLoadHomeDashboard).toHaveBeenCalledTimes(1);
  });

  it('navigates when a quick action is clicked', async () => {
    const { user } = render(<Home />);

    await waitFor(() => {
      expect(mockLoadHomeDashboard).toHaveBeenCalledTimes(1);
    });

    await user.click(screen.getByText('Travel Documents'));
    expect(mockNavigate).toHaveBeenCalledWith('/documents');
  });
});