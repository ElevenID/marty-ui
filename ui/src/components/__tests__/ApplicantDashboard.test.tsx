import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';

import ApplicantDashboard from '../console/applicant/ApplicantDashboard.jsx';

const { mockGetApplicantStats, authState } = vi.hoisted(() => ({
  mockGetApplicantStats: vi.fn(),
  authState: { user: { user_id: 'user-1', name: 'Ada Lovelace' } },
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({ user: authState.user }),
}));

vi.mock('../../services/applicantApi', () => ({
  getApplicantStats: mockGetApplicantStats,
}));

describe('ApplicantDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authState.user = { user_id: 'user-1', name: 'Ada Lovelace' };
    mockGetApplicantStats.mockResolvedValue({
      activeCredentials: 3,
      pendingApplications: 2,
      expiringSoon: 1,
    });
  });

  it('opens the catalog to start an application and the identity page to view existing credentials', async () => {
    renderWithRouter(<ApplicantDashboard />);

    expect(await screen.findByRole('link', { name: /Apply for Credential/ }))
      .toHaveAttribute('href', '/console/applicant/catalog');
    expect(screen.getByRole('link', { name: /View My Credentials/ }))
      .toHaveAttribute('href', '/console/applicant/identity');
    expect(screen.getByRole('link', { name: 'View Status' }))
      .toHaveAttribute('href', '/console/applicant/identity');
  });

  it('shows a recoverable error instead of crashing or claiming zero credentials when loading fails', async () => {
    mockGetApplicantStats.mockRejectedValueOnce(new Error('Gateway unavailable'));
    const { user } = renderWithRouter(<ApplicantDashboard />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Your credential summary could not be loaded.');
    expect(screen.queryByText('Active Credentials')).not.toBeInTheDocument();
    expect(screen.queryByText('0')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Apply for Credential/ })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Retry' }));

    expect(await screen.findByText('Active Credentials')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.queryByText(/credential summary could not be loaded/)).not.toBeInTheDocument();
    expect(mockGetApplicantStats).toHaveBeenCalledTimes(2);
  });

  it('reloads for a different account and ignores a late summary from the previous account', async () => {
    let resolvePrevious!: (value: unknown) => void;
    mockGetApplicantStats.mockImplementationOnce(() => new Promise((resolve) => { resolvePrevious = resolve; }));
    const view = renderWithRouter(<ApplicantDashboard />);
    await waitFor(() => expect(mockGetApplicantStats).toHaveBeenCalledOnce());

    authState.user = { user_id: 'user-2', name: 'Grace Hopper' };
    view.rerender(<ApplicantDashboard />);
    expect(await screen.findByText('Active Credentials')).toBeInTheDocument();

    await act(async () => resolvePrevious({ activeCredentials: 99, pendingApplications: 98, expiringSoon: 97 }));

    expect(screen.getByRole('heading', { name: 'Welcome back, Grace Hopper' })).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.queryByText('99')).not.toBeInTheDocument();
    expect(mockGetApplicantStats).toHaveBeenCalledTimes(2);
  });
});
