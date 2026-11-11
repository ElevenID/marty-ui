import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { Outlet, Route, Routes, useLocation } from 'react-router';
import { act, fireEvent, renderWithRouter, screen, waitFor } from '@test/utils';

import { server } from '../../test/mocks/server';
import { AuthProvider } from '../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../contexts/ConsoleContext';
import { useAuth } from '../../hooks/useAuth';
import { usePermissions } from '../../hooks/usePermissions';
import ProfilePage from '../ProfilePage';
import { ApplicantConsoleRoute } from '../ProtectedRoute';

const principal = {
  user_id: 'profile-owner',
  name: 'Profile Owner',
  email: 'owner@example.com',
  roles: ['applicant'],
  capabilities: {},
};

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(finish => { resolve = finish; });
  return { promise, resolve };
}

function SessionProbe() {
  const auth = useAuth();
  const consoleState = useConsole();
  const permissions = usePermissions();
  const location = useLocation();
  return <>
    <output data-testid="principal">{auth.user?.user_id || 'signed-out'}</output>
    <output data-testid="auth-loading">{String(auth.isLoading)}</output>
    <output data-testid="session-picture">{auth.user?.picture || 'no-picture'}</output>
    <output data-testid="memberships">{consoleState.memberships.map(org => org.id).join(',')}</output>
    <output data-testid="team-grant">{String(permissions.can('team', 'manage'))}</output>
    <output data-testid="path">{location.pathname}</output>
    <button onClick={() => auth.refreshUser()}>Refresh identity</button>
    <button onClick={() => auth.logout()}>Sign out</button>
  </>;
}

function ProfileApplication() {
  return <AuthProvider>
    <ConsoleProvider>
      <SessionProbe />
      <Routes>
        <Route path="/console/applicant" element={<ApplicantConsoleRoute redirectTo="/console/login"><Outlet /></ApplicantConsoleRoute>}>
          <Route path="profile" element={<ProfilePage />} />
        </Route>
        <Route path="/console/login" element={<h1>Sign in</h1>} />
      </Routes>
    </ConsoleProvider>
  </AuthProvider>;
}

async function savePicture(container: HTMLElement, user: ReturnType<typeof renderWithRouter>['user']) {
  await screen.findByRole('heading', { name: 'Profile Owner' });
  fireEvent.change(container.querySelector('input[type="file"]')!, {
    target: { files: [new File(['new picture'], 'profile.png', { type: 'image/png' })] },
  });
  const save = await screen.findByRole('button', { name: 'Save', exact: true });
  await waitFor(() => expect(save).toBeEnabled());
  await user.click(save);
}

describe('profile photo readback with the real session providers', () => {
  beforeEach(() => {
    window.localStorage.clear();
    server.use(
      http.get('*/v1/organizations/mine', () => HttpResponse.json([])),
      http.get('*/v1/me/preferences', () => HttpResponse.json({ last_view_mode: 'applicant', last_active_org_id: null })),
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it.each(['503', 'network', 'invalid JSON', 'invalid identity'])('keeps the validated account and reports a saved photo when readback fails with %s', async failure => {
    let saved = false;
    let writes = 0;
    server.use(
      http.get('*/v1/auth/me', () => {
        if (!saved) return HttpResponse.json({ authenticated: true, user: principal });
        if (failure === '503') return HttpResponse.json({ detail: 'Temporarily unavailable' }, { status: 503 });
        if (failure === 'network') return HttpResponse.error();
        if (failure === 'invalid JSON') return HttpResponse.text('{', { headers: { 'Content-Type': 'application/json' } });
        return HttpResponse.json({ authenticated: true, user: {} });
      }),
      http.patch('*/v1/auth/me', async ({ request }) => {
        const body = await request.json() as { picture: string };
        expect(body.picture).toMatch(/^data:image\/png;base64,/);
        writes += 1;
        saved = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    await savePicture(container, user);

    expect(await screen.findByText('Your picture was saved, but account details could not be refreshed. Reload the page to see it.')).toBeVisible();
    expect(screen.getByText('Profile picture updated.')).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Profile Owner' })).toBeVisible();
    expect(screen.getByTestId('principal')).toHaveTextContent('profile-owner');
    expect(screen.getByTestId('auth-loading')).toHaveTextContent('false');
    expect(screen.getByTestId('path')).toHaveTextContent('/console/applicant/profile');
    expect(writes).toBe(1);
    expect(screen.queryByRole('button', { name: 'Save', exact: true })).not.toBeInTheDocument();
  });

  it('refreshes the saved photo for the same account without remounting its confirmation', async () => {
    const unnecessaryConsoleRead = deferred();
    let picture: string | undefined;
    server.use(
      http.get('*/v1/auth/me', () => HttpResponse.json({ authenticated: true, user: { ...principal, picture } })),
      http.get('*/v1/me/preferences', async () => {
        if (picture) await unnecessaryConsoleRead.promise;
        return HttpResponse.json({ last_view_mode: 'applicant', last_active_org_id: null });
      }),
      http.patch('*/v1/auth/me', async ({ request }) => {
        picture = (await request.json() as { picture: string }).picture;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    try {
      await savePicture(container, user);
      await waitFor(() => expect(screen.getByTestId('session-picture')).toHaveTextContent(picture!));
      await waitFor(() => expect(screen.getByRole('button', { name: 'Change profile picture' })).toBeEnabled());
      expect(screen.getByText('Profile picture updated.')).toBeVisible();
      expect(container.querySelector('.MuiAvatar-img')).toHaveAttribute('src', picture);
      expect(screen.getByTestId('principal')).toHaveTextContent('profile-owner');
      expect(screen.getByTestId('auth-loading')).toHaveTextContent('false');
      expect(screen.queryByText(/account details could not be refreshed/)).not.toBeInTheDocument();
    } finally {
      await act(async () => unnecessaryConsoleRead.resolve());
    }
  });

  it.each(['401', 'signed-out response'])('clears a known account when photo readback confirms %s', async response => {
    let saved = false;
    server.use(
      http.get('*/v1/auth/me', () => {
        if (!saved) return HttpResponse.json({ authenticated: true, user: principal });
        return response === '401'
          ? HttpResponse.json({ detail: 'Session expired' }, { status: 401 })
          : HttpResponse.json({ authenticated: false, user: null });
      }),
      http.patch('*/v1/auth/me', () => {
        saved = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    await savePicture(container, user);
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeVisible();
    expect(screen.getByTestId('principal')).toHaveTextContent('signed-out');
    expect(screen.getByTestId('path')).toHaveTextContent('/console/login');
    expect(screen.queryByRole('heading', { name: 'Profile Owner' })).not.toBeInTheDocument();
    expect(screen.queryByText(/account details could not be refreshed/)).not.toBeInTheDocument();
  });

  it('discards the previous account and console before loading a replacement discovered by background readback', async () => {
    const memberships = deferred();
    const replacement = { ...principal, user_id: 'replacement-owner', name: 'Replacement Owner' };
    const oldOrganization = { id: 'private-old-org', name: 'Old Organization', membership: { roles: [{ name: 'owner' }], has_org_console_access: true } };
    let saved = false;
    let replacementOrganizationsStarted = false;
    server.use(
      http.get('*/v1/auth/me', () => HttpResponse.json({ authenticated: true, user: saved ? replacement : principal })),
      http.get('*/v1/organizations/mine', async () => {
        if (!saved) return HttpResponse.json([oldOrganization]);
        replacementOrganizationsStarted = true;
        await memberships.promise;
        return HttpResponse.json([]);
      }),
      http.patch('*/v1/auth/me', () => {
        saved = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    await waitFor(() => expect(screen.getByTestId('memberships')).toHaveTextContent('private-old-org'));
    await savePicture(container, user);
    await waitFor(() => expect(replacementOrganizationsStarted).toBe(true));
    expect(screen.getByTestId('auth-loading')).toHaveTextContent('true');
    expect(screen.getByTestId('memberships')).toBeEmptyDOMElement();
    expect(screen.getByTestId('principal')).not.toHaveTextContent('profile-owner');
    expect(screen.queryByRole('heading', { name: 'Profile Owner' })).not.toBeInTheDocument();
    expect(screen.queryByText('Profile picture updated.')).not.toBeInTheDocument();
    await act(async () => memberships.resolve());

    expect(await screen.findByRole('heading', { name: 'Replacement Owner' })).toBeVisible();
    expect(screen.getByTestId('principal')).toHaveTextContent('replacement-owner');
    expect(screen.getByTestId('memberships')).toBeEmptyDOMElement();
    expect(screen.queryByText('Profile picture updated.')).not.toBeInTheDocument();
  });

  it.each(['response', 'network failure'])('ignores an older background %s after a replacement identity wins', async outcome => {
    const oldRead = deferred();
    let reads = 0;
    server.use(
      http.get('*/v1/auth/me', async () => {
        reads += 1;
        if (reads === 1) return HttpResponse.json({ authenticated: true, user: principal });
        if (reads === 2) {
          await oldRead.promise;
          return outcome === 'response' ? HttpResponse.json({ authenticated: true, user: principal }) : HttpResponse.error();
        }
        return HttpResponse.json({ authenticated: true, user: { ...principal, user_id: 'replacement-owner', name: 'Replacement Owner' } });
      }),
      http.patch('*/v1/auth/me', () => HttpResponse.json({ ok: true })),
    );
    const { container, user } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    await savePicture(container, user);
    await waitFor(() => expect(reads).toBe(2));
    await user.click(screen.getByRole('button', { name: 'Refresh identity' }));
    expect(await screen.findByRole('heading', { name: 'Replacement Owner' })).toBeVisible();
    await act(async () => oldRead.resolve());

    expect(screen.getByTestId('principal')).toHaveTextContent('replacement-owner');
    expect(screen.getByRole('heading', { name: 'Replacement Owner' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Profile Owner' })).not.toBeInTheDocument();
    expect(screen.queryByText(/account details could not be refreshed/)).not.toBeInTheDocument();
    expect(reads).toBe(3);
  });

  it.each(['roles', 'capabilities', 'impersonation'])('invalidates existing grants before deferred enrichment when same-account %s change', async field => {
    const enrichment = deferred();
    const organization = { id: 'private-org', name: 'Private Organization', membership: { roles: [{ name: 'owner' }], has_org_console_access: true } };
    const previous = { ...principal, roles: ['owner'], capabilities: { 'org:manage': true }, impersonation: null };
    const replacement = {
      ...previous,
      ...(field === 'roles' ? { roles: ['applicant'] } : {}),
      ...(field === 'capabilities' ? { capabilities: { 'org:manage': false } } : {}),
      ...(field === 'impersonation' ? { impersonation: { active: true, admin_user_id: 'another-actor' } } : {}),
    };
    let saved = false;
    let enrichmentStarted = false;
    server.use(
      http.get('*/v1/auth/me', () => HttpResponse.json({ authenticated: true, user: saved ? replacement : previous })),
      http.get('*/v1/organizations/mine', async () => {
        if (saved) {
          enrichmentStarted = true;
          await enrichment.promise;
        }
        return HttpResponse.json([organization]);
      }),
      http.get('*/v1/me/preferences', () => HttpResponse.json({ last_view_mode: 'org', last_active_org_id: organization.id })),
      http.get('*/v1/organizations/private-org/members/me/permissions', () => HttpResponse.json({ permissions: saved ? [] : ['team:manage'], roles: [] })),
      http.patch('*/v1/auth/me', () => {
        saved = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    await waitFor(() => expect(screen.getByTestId('team-grant')).toHaveTextContent('true'));
    await savePicture(container, user);
    await waitFor(() => expect(enrichmentStarted).toBe(true));
    expect(screen.getByTestId('auth-loading')).toHaveTextContent('true');
    expect(screen.getByTestId('team-grant')).toHaveTextContent('false');
    expect(screen.getByTestId('memberships')).toBeEmptyDOMElement();
    await act(async () => enrichment.resolve());

    expect(await screen.findByRole('heading', { name: 'Profile Owner' })).toBeVisible();
    expect(screen.getByTestId('principal')).toHaveTextContent('profile-owner');
    expect(screen.getByTestId('team-grant')).toHaveTextContent('false');
  });

  it.each(['changed role', 'removed membership'])('uses one strict identity refresh when readback confirms %s', async change => {
    const strictRead = deferred();
    const organization = { id: 'private-org', name: 'Private Organization', membership: { roles: [{ name: 'owner' }], has_org_console_access: true } };
    const replacementOrganization = { ...organization, membership: { roles: [{ name: 'viewer' }], has_org_console_access: true } };
    let saved = false;
    let reads = 0;
    server.use(
      http.get('*/v1/auth/me', async () => {
        reads += 1;
        if (reads === 3) await strictRead.promise;
        return HttpResponse.json({ authenticated: true, user: principal });
      }),
      http.get('*/v1/organizations/mine', () => HttpResponse.json(!saved
        ? [organization]
        : change === 'removed membership' ? [] : [replacementOrganization])),
      http.get('*/v1/me/preferences', () => HttpResponse.json({ last_view_mode: 'org', last_active_org_id: organization.id })),
      http.get('*/v1/organizations/private-org/members/me/permissions', () => HttpResponse.json({ permissions: saved ? [] : ['team:manage'], roles: [] })),
      http.patch('*/v1/auth/me', () => {
        saved = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    await waitFor(() => expect(screen.getByTestId('team-grant')).toHaveTextContent('true'));
    await savePicture(container, user);
    await waitFor(() => expect(reads).toBe(3));
    expect(screen.getByTestId('auth-loading')).toHaveTextContent('true');
    expect(screen.getByTestId('team-grant')).toHaveTextContent('false');
    expect(screen.getByTestId('memberships')).toBeEmptyDOMElement();
    await act(async () => strictRead.resolve());

    expect(await screen.findByRole('heading', { name: 'Profile Owner' })).toBeVisible();
    expect(screen.getByTestId('team-grant')).toHaveTextContent('false');
    expect(reads).toBe(3);
  });

  it.each(['503', 'network'])('preserves the saved-photo feedback when unchanged account enrichment fails with %s', async failure => {
    const strictRead = deferred();
    const organization = { id: 'private-org', name: 'Private Organization', membership: { roles: [{ name: 'owner' }], has_org_console_access: true } };
    const warning = 'Your picture was saved, but account details could not be refreshed. Reload the page to see it.';
    let picture: string | undefined;
    let reads = 0;
    let writes = 0;
    let failedOrganizationReads = 0;
    server.use(
      http.get('*/v1/auth/me', async () => {
        reads += 1;
        if (reads > 2) await strictRead.promise;
        return HttpResponse.json({ authenticated: true, user: { ...principal, picture } });
      }),
      http.get('*/v1/organizations/mine', () => {
        if (!picture) return HttpResponse.json([organization]);
        failedOrganizationReads += 1;
        return failure === '503'
          ? HttpResponse.json({ detail: 'Temporarily unavailable' }, { status: 503 })
          : HttpResponse.error();
      }),
      http.get('*/v1/me/preferences', () => HttpResponse.json({ last_view_mode: 'org', last_active_org_id: organization.id })),
      http.get('*/v1/organizations/private-org/members/me/permissions', () => HttpResponse.json({ permissions: ['team:manage'], roles: [] })),
      http.patch('*/v1/auth/me', async ({ request }) => {
        writes += 1;
        picture = (await request.json() as { picture: string }).picture;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user, unmount } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    try {
      await waitFor(() => expect(screen.getByTestId('team-grant')).toHaveTextContent('true'));
      await savePicture(container, user);
      // Both outcomes settle the background request: either the truthful warning
      // appears, or the bug starts an unrelated strict identity refresh.
      await waitFor(() => expect(reads > 2 || screen.queryByText(warning) !== null).toBe(true), { timeout: 20000 });
      expect(reads, `Organization failure started an extra identity read after ${failedOrganizationReads} failed membership requests`).toBe(2);
      expect(screen.getByText(warning)).toBeVisible();
      expect(screen.getByText('Profile picture updated.')).toBeVisible();
      expect(screen.getByRole('heading', { name: 'Profile Owner' })).toBeVisible();
      expect(screen.getByTestId('auth-loading')).toHaveTextContent('false');
      expect(screen.getByTestId('memberships')).toHaveTextContent(organization.id);
      expect(screen.getByTestId('team-grant')).toHaveTextContent('true');
      expect(screen.getByTestId('path')).toHaveTextContent('/console/applicant/profile');
      expect(writes).toBe(1);
    } finally {
      unmount();
      await act(async () => strictRead.resolve());
    }
  });

  it.each([
    { status: 401, claimed: false },
    { status: 403, claimed: false },
    { status: 401, claimed: true },
    { status: 403, claimed: true },
  ])('withholds old membership grants when organization enrichment is denied with $status (raw claim fallback: $claimed)', async ({ status, claimed }) => {
    const strictRead = deferred();
    const organization = { id: 'private-org', name: 'Private Organization', display_name: 'Private Organization', membership: { roles: [{ name: 'owner' }], has_org_console_access: true } };
    const currentPrincipal = claimed ? { ...principal, organizations: [organization] } : principal;
    let saved = false;
    let reads = 0;
    server.use(
      http.get('*/v1/auth/me', async () => {
        reads += 1;
        if (reads === 3) await strictRead.promise;
        return HttpResponse.json({ authenticated: true, user: currentPrincipal });
      }),
      http.get('*/v1/organizations/mine', () => saved
        ? HttpResponse.json({ detail: 'Organization access denied' }, { status })
        : HttpResponse.json([organization])),
      http.get('*/v1/me/preferences', () => HttpResponse.json({ last_view_mode: 'org', last_active_org_id: organization.id })),
      http.get('*/v1/organizations/private-org/members/me/permissions', () => HttpResponse.json({ permissions: ['team:manage'], roles: [] })),
      http.patch('*/v1/auth/me', () => {
        saved = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user, unmount } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    try {
      await waitFor(() => expect(screen.getByTestId('team-grant')).toHaveTextContent('true'));
      await savePicture(container, user);
      await waitFor(() => expect(reads).toBe(3));
      expect(screen.getByTestId('auth-loading')).toHaveTextContent('true');
      expect(screen.getByTestId('memberships')).toBeEmptyDOMElement();
      expect(screen.getByTestId('team-grant')).toHaveTextContent('false');
      expect(screen.queryByRole('heading', { name: 'Profile Owner' })).not.toBeInTheDocument();
      expect(screen.queryByText(/account details could not be refreshed/)).not.toBeInTheDocument();
      await act(async () => strictRead.resolve());
      if (claimed) {
        expect(await screen.findByText('Organization access denied')).toBeVisible();
        expect(screen.getByRole('button', { name: 'Retry', exact: true })).toBeVisible();
        expect(screen.queryByRole('heading', { name: 'Profile Owner' })).not.toBeInTheDocument();
      } else {
        expect(await screen.findByRole('heading', { name: 'Profile Owner' })).toBeVisible();
      }
      expect(screen.getByTestId('principal')).toHaveTextContent('profile-owner');
      expect(screen.getByTestId('auth-loading')).toHaveTextContent('false');
      expect(screen.getByTestId('team-grant')).toHaveTextContent('false');
      expect(reads).toBe(3);
    } finally {
      unmount();
      await act(async () => strictRead.resolve());
    }
  });

  it.each([401, 403])('ignores a late organization %s after a replacement account wins', async status => {
    const oldEnrichment = deferred();
    const organization = { id: 'private-old-org', name: 'Old Organization', membership: { roles: [{ name: 'owner' }], has_org_console_access: true } };
    const replacement = { ...principal, user_id: 'replacement-owner', name: 'Replacement Owner' };
    let saved = false;
    let replaced = false;
    let enrichmentStarted = false;
    let enrichmentResponded = false;
    let reads = 0;
    server.use(
      http.get('*/v1/auth/me', () => {
        reads += 1;
        if (reads >= 3) replaced = true;
        return HttpResponse.json({ authenticated: true, user: replaced ? replacement : principal });
      }),
      http.get('*/v1/organizations/mine', async () => {
        if (replaced) return HttpResponse.json([]);
        if (!saved) return HttpResponse.json([organization]);
        enrichmentStarted = true;
        await oldEnrichment.promise;
        enrichmentResponded = true;
        return HttpResponse.json({ detail: 'Old organization request denied' }, { status });
      }),
      http.get('*/v1/me/preferences', () => HttpResponse.json(replaced
        ? { last_view_mode: 'applicant', last_active_org_id: null }
        : { last_view_mode: 'org', last_active_org_id: organization.id })),
      http.get('*/v1/organizations/private-old-org/members/me/permissions', () => HttpResponse.json({ permissions: ['team:manage'], roles: [] })),
      http.patch('*/v1/auth/me', () => {
        saved = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { container, user, unmount } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    try {
      await waitFor(() => expect(screen.getByTestId('team-grant')).toHaveTextContent('true'));
      await savePicture(container, user);
      await waitFor(() => expect(enrichmentStarted).toBe(true));
      await user.click(screen.getByRole('button', { name: 'Refresh identity' }));
      expect(await screen.findByRole('heading', { name: 'Replacement Owner' })).toBeVisible();
      await act(async () => oldEnrichment.resolve());
      await waitFor(() => expect(enrichmentResponded).toBe(true));

      expect(screen.getByTestId('principal')).toHaveTextContent('replacement-owner');
      expect(screen.getByTestId('auth-loading')).toHaveTextContent('false');
      expect(screen.getByTestId('memberships')).toBeEmptyDOMElement();
      expect(screen.getByTestId('team-grant')).toHaveTextContent('false');
      expect(screen.getByRole('heading', { name: 'Replacement Owner' })).toBeVisible();
      expect(screen.queryByText('Profile picture updated.')).not.toBeInTheDocument();
      expect(screen.queryByText(/account details could not be refreshed/)).not.toBeInTheDocument();
      expect(reads).toBe(3);
    } finally {
      unmount();
      await act(async () => oldEnrichment.resolve());
    }
  });

  it('ignores readback completed after logout starts without redirecting before the logout form is submitted', async () => {
    const oldRead = deferred();
    const submitted = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {});
    let reads = 0;
    server.use(
      http.get('*/v1/auth/me', async () => {
        reads += 1;
        if (reads === 1) return HttpResponse.json({ authenticated: true, user: principal });
        await oldRead.promise;
        return HttpResponse.json({ authenticated: true, user: { ...principal, user_id: 'late-owner', name: 'Late Owner' } });
      }),
      http.patch('*/v1/auth/me', () => HttpResponse.json({ ok: true })),
    );
    const { container, user } = renderWithRouter(<ProfileApplication />, { initialEntries: ['/console/applicant/profile'] });
    await savePicture(container, user);
    await waitFor(() => expect(reads).toBe(2));
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(submitted).toHaveBeenCalledTimes(1);
    const form = submitted.mock.instances[0] as HTMLFormElement;
    expect(form.getAttribute('action')).toBe('/v1/auth/logout');
    expect(form.method).toBe('post');
    await act(async () => oldRead.resolve());
    // Navigation is intercepted at form.submit in this test. The provider must
    // not change accounts or trigger a login redirect while logout owns it.
    expect(screen.getByTestId('principal')).toHaveTextContent('profile-owner');
    expect(screen.getByTestId('path')).toHaveTextContent('/console/applicant/profile');
    expect(screen.queryByRole('heading', { name: 'Late Owner' })).not.toBeInTheDocument();
    expect(screen.queryByText(/account details could not be refreshed/)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Refresh identity' }));
    expect(reads).toBe(2);
    form.remove();
  });
});
