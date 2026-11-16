import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent } from '@testing-library/react';
import { render, renderWithRouter, screen, waitFor } from '@test/utils';
import DiscoverOrganizationsPage from '../pages/DiscoverOrganizationsPage';

const { discover, navigate, login, auth } = vi.hoisted(() => ({
  discover: vi.fn(),
  navigate: vi.fn(),
  login: vi.fn(),
  auth: {
    isAuthenticated: true,
    isLoading: false,
    user: { user_id: 'discovery-user-1' } as { user_id: string } | null,
  },
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({ ...auth, login }),
}));

vi.mock('../../services/organizationsApi', () => ({
  discoverOrganizations: (...args: unknown[]) => discover(...args),
}));
vi.mock('react-router', async () => ({
  ...await vi.importActual<typeof import('react-router')>('react-router'),
  useNavigate: () => navigate,
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

const organization = (name: string) => ({ id: name, name, join_mechanism: 'open' });

// The installed API client rejects with an empty Error.message and puts the
// gateway's useful message in response.error_description.
function gatewayError(status: number, description: string) {
  return Object.assign(new Error(''), {
    status,
    response: {
      error: status === 401 ? 'unauthorized' : 'service_unavailable',
      error_description: description,
      message_id: 'synthetic-discovery-request',
    },
  });
}

describe('DiscoverOrganizationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    discover.mockReset().mockResolvedValue([]);
    auth.isAuthenticated = true;
    auth.isLoading = false;
    auth.user = { user_id: 'discovery-user-1' };
  });

  it.each(['/organizations/discover?source=menu#browse', '/console/organizations/discover?source=menu#browse'])(
    'offers sign-in without fetching and preserves the return destination %s', async (destination) => {
      auth.isAuthenticated = false;
      auth.user = null;
      const { user } = renderWithRouter(<DiscoverOrganizationsPage />, { initialEntries: [destination] });

      expect(screen.getByRole('heading', { name: 'Discover Organizations' })).toBeVisible();
      expect(screen.getByText('Sign in to discover and join organizations.')).toBeVisible();
      expect(discover).not.toHaveBeenCalled();
      expect(login).not.toHaveBeenCalled();
      expect(screen.queryByRole('textbox', { name: 'Search organizations' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: /No Organizations/ })).not.toBeInTheDocument();

      await user.click(screen.getByRole('button', { name: 'Sign in' }));
      expect(login).toHaveBeenCalledExactlyOnceWith(destination);
      expect(navigate).not.toHaveBeenCalled();
      expect(discover).not.toHaveBeenCalled();
    },
  );

  it('waits for the authentication check before loading discovery', async () => {
    auth.isAuthenticated = false;
    auth.isLoading = true;
    auth.user = null;
    discover.mockResolvedValue([organization('Current School')]);
    const { rerender } = renderWithRouter(<DiscoverOrganizationsPage />, { initialEntries: ['/organizations/discover'] });

    expect(screen.getByRole('progressbar', { name: 'Checking authentication' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Sign in' })).not.toBeInTheDocument();
    expect(discover).not.toHaveBeenCalled();

    auth.isAuthenticated = true;
    auth.isLoading = false;
    auth.user = { user_id: 'discovery-user-1' };
    rerender(<DiscoverOrganizationsPage />);
    expect(await screen.findByRole('heading', { name: 'Current School' })).toBeVisible();
    expect(discover).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('offers direct reauthentication for a real-client-shaped 401 even while auth context still says signed in', async () => {
    discover.mockRejectedValueOnce(gatewayError(401, 'Authentication required'));
    const destination = '/organizations/discover?source=expired#browse';
    const { user } = renderWithRouter(<DiscoverOrganizationsPage />, { initialEntries: [destination] });

    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeVisible();
    expect(screen.getByRole('alert')).toHaveTextContent('Authentication required');
    expect(screen.getByRole('alert')).toHaveTextContent('Sign in again to discover organizations.');
    expect(screen.queryByText(/Failed to load organizations/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /No Organizations/ })).not.toBeInTheDocument();
    expect(login).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(login).toHaveBeenCalledExactlyOnceWith(destination);
    expect(navigate).not.toHaveBeenCalled();
    expect(discover).toHaveBeenCalledTimes(1);
  });

  it.each(['results', 'expired session'] as const)('discards previous account %s while the next account loads', async (previous) => {
    const current = deferred<ReturnType<typeof organization>[]>();
    if (previous === 'results') discover.mockResolvedValueOnce([organization('Previous School')]);
    else discover.mockRejectedValueOnce(gatewayError(401, 'Previous session expired'));
    discover.mockImplementationOnce(() => current.promise);
    const { rerender } = render(<DiscoverOrganizationsPage />);
    if (previous === 'results') await screen.findByRole('heading', { name: 'Previous School' });
    else await screen.findByRole('button', { name: 'Sign in' });

    auth.user = { user_id: 'discovery-user-2' };
    rerender(<DiscoverOrganizationsPage />);
    expect(screen.queryByRole('heading', { name: 'Previous School' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Sign in' })).not.toBeInTheDocument();
    expect(screen.queryByText('Previous session expired')).not.toBeInTheDocument();
    expect(screen.getByRole('progressbar', { name: 'Loading organizations' })).toBeVisible();

    await act(async () => current.resolve([organization('Current School')]));
    expect(await screen.findByRole('heading', { name: 'Current School' })).toBeVisible();
    expect(discover).toHaveBeenCalledTimes(2);
  });

  it('ignores a pending request after sign-out and loads afresh when the same account returns', async () => {
    const previous = deferred<ReturnType<typeof organization>[]>();
    discover.mockImplementationOnce(() => previous.promise)
      .mockResolvedValueOnce([organization('Current School')]);
    const { rerender } = render(<DiscoverOrganizationsPage />);
    expect(discover).toHaveBeenCalledTimes(1);

    auth.isAuthenticated = false;
    auth.user = null;
    rerender(<DiscoverOrganizationsPage />);
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeVisible();
    await act(async () => previous.resolve([organization('Previous School')]));
    expect(screen.queryByRole('heading', { name: 'Previous School' })).not.toBeInTheDocument();
    expect(discover).toHaveBeenCalledTimes(1);

    auth.isAuthenticated = true;
    auth.user = { user_id: 'discovery-user-1' };
    rerender(<DiscoverOrganizationsPage />);
    expect(await screen.findByRole('heading', { name: 'Current School' })).toBeVisible();
    expect(discover).toHaveBeenCalledTimes(2);
  });

  it('labels every filter and distinguishes an unavailable catalog from filtered results', async () => {
    render(<DiscoverOrganizationsPage />);
    expect(screen.getByRole('textbox', { name: 'Search organizations' })).toBeVisible();
    expect(screen.getByRole('combobox', { name: 'Organization Type' })).toBeVisible();
    expect(screen.getByRole('combobox', { name: 'Join Method' })).toBeVisible();
    expect(await screen.findByRole('heading', { name: 'No Organizations Available' })).toBeVisible();
    expect(screen.queryByText(/adjusting your search|match your filters/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument();
  });

  it('clears search, organization type, and join method together', async () => {
    const { user } = render(<DiscoverOrganizationsPage />);
    await screen.findByRole('heading', { name: 'No Organizations Available' });
    fireEvent.change(screen.getByRole('textbox', { name: 'Search organizations' }), { target: { value: 'School' } });
    await user.click(screen.getByRole('combobox', { name: 'Organization Type' }));
    await user.click(screen.getByRole('option', { name: 'Education', exact: true }));
    await user.click(screen.getByRole('combobox', { name: 'Join Method' }));
    await user.click(screen.getByRole('option', { name: 'Open', exact: true }));
    await waitFor(() => expect(discover).toHaveBeenLastCalledWith({
      search: 'School', orgType: 'education', joinMechanism: 'open', limit: 100,
    }));
    expect(await screen.findByRole('heading', { name: 'No Organizations Found' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(screen.getByRole('textbox', { name: 'Search organizations' })).toHaveValue('');
    await waitFor(() => expect(discover).toHaveBeenLastCalledWith({
      search: undefined, orgType: undefined, joinMechanism: undefined, limit: 100,
    }));
    expect(await screen.findByRole('heading', { name: 'No Organizations Available' })).toBeVisible();
  });

  it('keeps failed requests distinct from empty results and retries the current filters', async () => {
    discover.mockImplementation(({ search }) => search
      ? Promise.reject(gatewayError(503, 'Discovery is temporarily unavailable'))
      : Promise.resolve([]));
    const { user } = render(<DiscoverOrganizationsPage />);
    await screen.findByRole('heading', { name: 'No Organizations Available' });
    fireEvent.change(screen.getByRole('textbox', { name: 'Search organizations' }), { target: { value: 'School' } });
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load organizations. Discovery is temporarily unavailable');
    expect(screen.queryByRole('button', { name: 'Sign in' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /No Organizations/ })).not.toBeInTheDocument();
    discover.mockResolvedValueOnce([organization('Recovered School')]);
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('heading', { name: 'Recovered School' })).toBeVisible();
    expect(discover).toHaveBeenLastCalledWith({
      search: 'School', orgType: undefined, joinMechanism: undefined, limit: 100,
    });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('ignores a late success from an older search after the newer results load', async () => {
    const older = deferred<ReturnType<typeof organization>[]>();
    const newer = deferred<ReturnType<typeof organization>[]>();
    discover.mockImplementation(({ search }) => search === 'old' ? older.promise : search === 'new' ? newer.promise : Promise.resolve([]));
    render(<DiscoverOrganizationsPage />);
    await screen.findByRole('heading', { name: 'No Organizations Available' });
    const search = screen.getByRole('textbox', { name: 'Search organizations' });
    fireEvent.change(search, { target: { value: 'old' } });
    fireEvent.change(search, { target: { value: 'new' } });
    await act(async () => newer.resolve([organization('New School')]));
    expect(await screen.findByRole('heading', { name: 'New School' })).toBeVisible();
    await act(async () => older.resolve([organization('Old School')]));
    expect(screen.getByRole('heading', { name: 'New School' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Old School' })).not.toBeInTheDocument();
  });

  it('does not let an old failure end the loading state of the current search', async () => {
    const older = deferred<ReturnType<typeof organization>[]>();
    const current = deferred<ReturnType<typeof organization>[]>();
    discover.mockImplementation(({ search }) => search ? current.promise : older.promise);
    render(<DiscoverOrganizationsPage />);
    fireEvent.change(screen.getByRole('textbox', { name: 'Search organizations' }), { target: { value: 'current' } });
    await act(async () => older.reject(new Error('Old request failed')));
    expect(screen.getByRole('progressbar', { name: 'Loading organizations' })).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /No Organizations/ })).not.toBeInTheDocument();
    await act(async () => current.resolve([organization('Current School')]));
    expect(await screen.findByRole('heading', { name: 'Current School' })).toBeVisible();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('preserves the console join route when opening organization details', async () => {
    discover.mockResolvedValue([organization('School / One')]);
    const { user } = render(<DiscoverOrganizationsPage joinPath="/console/organizations/join" />);
    await user.click(await screen.findByRole('button', { name: 'Details', exact: true }));
    expect(navigate).toHaveBeenCalledWith('/console/organizations/join?orgId=School%20%2F%20One');
  });
});
