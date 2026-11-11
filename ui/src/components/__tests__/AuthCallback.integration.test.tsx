import { beforeEach, describe, expect, it } from 'vitest';
import { StrictMode } from 'react';
import { http, HttpResponse } from 'msw';
import { Route, Routes, useLocation, useNavigate } from 'react-router';

import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { server } from '../../test/mocks/server';
import { AuthProvider } from '../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../contexts/ConsoleContext';
import { useAuth } from '../../hooks/useAuth';
import AuthCallback from '../AuthCallback';

const principal = { user_id: 'signed-in-user', roles: ['applicant'], capabilities: {}, organizations: [] };
const defaultPreferences = { last_view_mode: 'applicant', last_active_org_id: null };

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(finish => { resolve = finish; });
  return { promise, resolve };
}

function callbackUrl(code = 'one-use-code', returnTo = '/console/applicant/catalog') {
  const state = encodeURIComponent(btoa(JSON.stringify({ returnTo })));
  return `/console/auth/callback?code=${code}&state=${state}`;
}

function SessionProbe() {
  const auth = useAuth();
  const consoleState = useConsole();
  const location = useLocation();
  const navigate = useNavigate();
  return <>
    <output data-testid="auth-state">{auth.isLoading ? 'loading' : auth.user?.user_id || 'signed-out'}</output>
    <output data-testid="console-state">{consoleState.isLoading ? 'loading' : 'ready'}</output>
    <output data-testid="selected-org">{consoleState.activeOrgId}</output>
    <output data-testid="path">{location.pathname}</output>
    <button onClick={() => navigate('/console/abandoned')}>Leave sign-in</button>
    <button onClick={() => navigate(callbackUrl('replacement-code', '/console/after-second'))}>Start replacement sign-in</button>
    <button onClick={() => auth.refreshUser()}>Refresh identity</button>
  </>;
}

function CallbackApplication() {
  return <AuthProvider>
    <ConsoleProvider>
      <SessionProbe />
      <Routes>
        <Route path="/console/auth/callback" element={<AuthCallback />} />
        <Route path="/console/applicant/catalog" element={<h1>Applicant catalog</h1>} />
        <Route path="/console/org" element={<h1>Organization dashboard</h1>} />
        <Route path="/console/abandoned" element={<h1>Another page</h1>} />
        <Route path="/console/after-second" element={<h1>Replacement destination</h1>} />
      </Routes>
    </ConsoleProvider>
  </AuthProvider>;
}

describe('authentication callback with session providers', () => {
  beforeEach(() => {
    window.localStorage.clear();
    server.use(
      http.get('*/v1/organizations/mine', () => HttpResponse.json([])),
      http.get('*/v1/me/preferences', () => HttpResponse.json(defaultPreferences)),
    );
  });

  it.each([false, true])('exchanges a one-use code once and completes the handoff across authentication changes (StrictMode=%s)', async strict => {
    let exchanged = false;
    let exchanges = 0;
    let releaseExchange!: () => void;
    const exchange = new Promise<void>(resolve => { releaseExchange = resolve; });
    server.use(
      http.get('*/v1/auth/me', () => HttpResponse.json({ authenticated: exchanged, user: exchanged ? principal : null })),
      http.get('*/v1/auth/callback', async () => {
        exchanges += 1;
        if (exchanges > 1) return HttpResponse.json({ detail: 'Authorization code already used' }, { status: 400 });
        await exchange;
        exchanged = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const application = <CallbackApplication />;
    renderWithRouter(strict ? <StrictMode>{application}</StrictMode> : application, {
      initialEntries: [callbackUrl()],
    });
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-out'));
    await waitFor(() => expect(screen.getByTestId('console-state')).toHaveTextContent('ready'));
    await act(async () => releaseExchange());
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-in-user'));

    expect(exchanges).toBe(1);
    expect(await screen.findByRole('heading', { name: 'Applicant catalog' })).toBeInTheDocument();
    expect(screen.getByTestId('path')).toHaveTextContent('/console/applicant/catalog');
  });

  it.each(['identity', 'memberships'])('ignores the previous account initial %s response after callback refresh wins', async phase => {
    const initialRead = deferred();
    const exchange = deferred();
    const oldPrincipal = { ...principal, user_id: 'previous-account', roles: ['owner'] };
    const oldOrganization = { id: 'previous-private-org', membership: { roles: [{ name: 'owner' }], has_org_console_access: true } };
    let authReads = 0;
    let organizationReads = 0;
    server.use(
      http.get('*/v1/auth/me', async () => {
        authReads += 1;
        if (authReads === 1) {
          if (phase === 'identity') await initialRead.promise;
          return HttpResponse.json({ authenticated: true, user: oldPrincipal });
        }
        return HttpResponse.json({ authenticated: true, user: principal });
      }),
      http.get('*/v1/auth/callback', async () => {
        await exchange.promise;
        return HttpResponse.json({ ok: true });
      }),
      http.get('*/v1/organizations/mine', async () => {
        organizationReads += 1;
        if (phase === 'memberships' && organizationReads === 1) {
          await initialRead.promise;
          return HttpResponse.json([oldOrganization]);
        }
        return HttpResponse.json([]);
      }),
    );
    renderWithRouter(<CallbackApplication />, { initialEntries: [callbackUrl()] });
    await waitFor(() => expect(phase === 'identity' ? authReads : organizationReads).toBe(1));
    await act(async () => exchange.resolve());
    expect(await screen.findByRole('heading', { name: 'Applicant catalog' })).toBeInTheDocument();
    await act(async () => initialRead.resolve());

    expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-in-user');
    expect(screen.getByTestId('selected-org')).toBeEmptyDOMElement();
    expect(screen.getByTestId('console-state')).toHaveTextContent('ready');
    expect(authReads).toBe(2);
    expect(window.localStorage.getItem('activeOrgId')).toBeNull();
  });

  it('waits for the current console preferences before choosing the default destination', async () => {
    const preferences = deferred();
    let exchanged = false;
    const organization = { id: 'current-org', membership: { roles: [{ name: 'owner' }], has_org_console_access: true } };
    server.use(
      http.get('*/v1/auth/me', () => HttpResponse.json({ authenticated: exchanged, user: exchanged ? principal : null })),
      http.get('*/v1/auth/callback', () => {
        exchanged = true;
        return HttpResponse.json({ ok: true });
      }),
      http.get('*/v1/organizations/mine', () => HttpResponse.json([organization])),
      http.get('*/v1/me/preferences', async () => {
        await preferences.promise;
        return HttpResponse.json({ last_view_mode: 'org_admin', last_active_org_id: organization.id });
      }),
    );
    renderWithRouter(<CallbackApplication />, { initialEntries: [callbackUrl('default-code', '/')] });
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-in-user'));
    expect(screen.getByTestId('path')).toHaveTextContent('/console/auth/callback');
    expect(screen.getByTestId('console-state')).toHaveTextContent('loading');
    await act(async () => preferences.resolve());

    expect(await screen.findByRole('heading', { name: 'Organization dashboard' })).toBeInTheDocument();
    expect(screen.getByTestId('selected-org')).toHaveTextContent('current-org');
  });

  it('does not navigate back when an exchange finishes after leaving the callback route', async () => {
    const exchange = deferred();
    let exchanged = false;
    server.use(
      http.get('*/v1/auth/me', () => HttpResponse.json({ authenticated: exchanged, user: exchanged ? principal : null })),
      http.get('*/v1/auth/callback', async () => {
        await exchange.promise;
        exchanged = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { user } = renderWithRouter(<CallbackApplication />, { initialEntries: [callbackUrl()] });
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-out'));
    await user.click(screen.getByRole('button', { name: 'Leave sign-in' }));
    await act(async () => exchange.resolve());
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-in-user'));
    await waitFor(() => expect(screen.getByTestId('console-state')).toHaveTextContent('ready'));

    expect(screen.getByRole('heading', { name: 'Another page' })).toBeInTheDocument();
    expect(screen.getByTestId('path')).toHaveTextContent('/console/abandoned');
  });

  it('does not use a completed callback to redirect a replacement account', async () => {
    const preferences = deferred();
    let currentPrincipal: typeof principal | null = null;
    let exchanges = 0;
    server.use(
      http.get('*/v1/auth/me', () => HttpResponse.json({ authenticated: Boolean(currentPrincipal), user: currentPrincipal })),
      http.get('*/v1/auth/callback', () => {
        exchanges += 1;
        currentPrincipal = principal;
        return HttpResponse.json({ ok: true });
      }),
      http.get('*/v1/me/preferences', async () => {
        await preferences.promise;
        return HttpResponse.json(defaultPreferences);
      }),
    );
    const { user } = renderWithRouter(<CallbackApplication />, { initialEntries: [callbackUrl()] });
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-in-user'));
    expect(screen.getByTestId('console-state')).toHaveTextContent('loading');
    currentPrincipal = { ...principal, user_id: 'replacement-account' };
    await user.click(screen.getByRole('button', { name: 'Refresh identity' }));
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('replacement-account'));
    await act(async () => preferences.resolve());

    expect(await screen.findByText('Authentication changed before sign-in completed. Please sign in again.')).toBeVisible();
    expect(screen.getByTestId('path')).toHaveTextContent('/console/auth/callback');
    expect(screen.queryByRole('heading', { name: 'Applicant catalog' })).not.toBeInTheDocument();
    expect(exchanges).toBe(1);
  });

  it('does not refresh or redirect an obsolete callback after a newer callback completes', async () => {
    const firstExchange = deferred();
    let authenticated = false;
    let authReads = 0;
    const codes: string[] = [];
    server.use(
      http.get('*/v1/auth/me', () => {
        authReads += 1;
        return HttpResponse.json({ authenticated, user: authenticated ? principal : null });
      }),
      http.get('*/v1/auth/callback', async ({ request }) => {
        const code = new URL(request.url).searchParams.get('code')!;
        codes.push(code);
        if (code === 'one-use-code') await firstExchange.promise;
        else authenticated = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { user } = renderWithRouter(<CallbackApplication />, { initialEntries: [callbackUrl()] });
    await waitFor(() => expect(codes).toEqual(['one-use-code']));
    await user.click(screen.getByRole('button', { name: 'Start replacement sign-in' }));
    expect(await screen.findByRole('heading', { name: 'Replacement destination' })).toBeInTheDocument();
    const completedReads = authReads;
    await act(async () => firstExchange.resolve());

    expect(codes).toEqual(['one-use-code', 'replacement-code']);
    expect(authReads).toBe(completedReads);
    expect(screen.getByTestId('path')).toHaveTextContent('/console/after-second');
  });

  it.each(['503', 'invalid identity'])('never uses a previously displayed account as callback proof when the fresh session read returns %s', async failure => {
    let exchanged = false;
    let exchanges = 0;
    server.use(
      http.get('*/v1/auth/me', () => {
        if (!exchanged) return HttpResponse.json({ authenticated: true, user: principal });
        return failure === '503'
          ? HttpResponse.json({ detail: 'Session unavailable' }, { status: 503 })
          : HttpResponse.json({ authenticated: true, user: {} });
      }),
      http.get('*/v1/auth/callback', () => {
        exchanges += 1;
        exchanged = true;
        return HttpResponse.json({ ok: true });
      }),
    );
    const { user } = renderWithRouter(<CallbackApplication />, { initialEntries: ['/console/applicant/catalog'] });
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-in-user'));
    await waitFor(() => expect(screen.getByTestId('console-state')).toHaveTextContent('ready'));
    await user.click(screen.getByRole('button', { name: 'Start replacement sign-in' }));

    expect(await screen.findByText('Authentication could not be confirmed. Please sign in again.')).toBeVisible();
    expect(screen.getByTestId('auth-state')).toHaveTextContent('signed-out');
    expect(screen.getByTestId('path')).toHaveTextContent('/console/auth/callback');
    expect(screen.queryByRole('heading', { name: 'Replacement destination' })).not.toBeInTheDocument();
    expect(exchanges).toBe(1);
  });
});
