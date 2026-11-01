import { useContext } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthContext, AuthProvider } from '../AuthContext';
import { getCurrentUser, getUserOrganizations, initiateLogin, initiateRegister, initiateLogout, updateProfilePicture } from '../../services/authApi';
import * as handoff from '../../application/routing/appHandoff';

const alias = 'https://203.0.113.10:8443';
const canonical = 'https://marty.example.com:8443';
const originalUrl = window.location.href;

function AuthProbe() {
  const auth = useContext(AuthContext);
  return <>
    <output data-testid="auth-state">{auth.isLoading ? 'loading' : auth.isAuthenticated ? 'authenticated' : 'public'}</output>
    <button onClick={auth.refreshUser}>Refresh</button>
  </>;
}

beforeEach(() => {
  (globalThis as any).jsdom.reconfigure({ url: `${alias}/` });
  (window as any).__MARTY_RUNTIME_CONFIG__ = {
    hosting: { canonicalOrigin: canonical, publicEntryOrigins: [alias] },
  };
});

afterEach(() => {
  vi.restoreAllMocks();
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
  (globalThis as any).jsdom.reconfigure({ url: originalUrl });
});

describe('public entry authentication', () => {
  it('settles the provider immediately and performs no session requests on mount or refresh', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    render(<AuthProvider><AuthProbe /></AuthProvider>);
    expect(screen.getByTestId('auth-state')).toHaveTextContent('public');
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await getCurrentUser()).toEqual({ authenticated: false, user: null });
    expect(await getUserOrganizations()).toEqual([]);
    expect((await updateProfilePicture('data:image/png;base64,AQ==')).success).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('sends login and registration actions to DNS and never posts alias logout', () => {
    const navigate = vi.spyOn(handoff, 'redirectBrowser').mockReturnValue(true);
    const submit = vi.spyOn(HTMLFormElement.prototype, 'submit');
    initiateLogin('/console', 'en');
    expect(navigate).toHaveBeenLastCalledWith(`${canonical}/v1/auth/login?redirect_uri=%2Fconsole&kc_locale=en`, { replace: false });
    initiateRegister('/console/org/setup');
    expect(navigate).toHaveBeenLastCalledWith(`${canonical}/v1/auth/register?redirect_uri=%2Fconsole%2Forg%2Fsetup`, { replace: false });
    initiateLogout();
    expect(navigate).toHaveBeenLastCalledWith(`${canonical}/`);
    expect(submit).not.toHaveBeenCalled();
  });

  it('retains the ordinary session check on the canonical origin', async () => {
    (globalThis as any).jsdom.reconfigure({ url: `${canonical}/` });
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ authenticated: false, user: null }), { status: 200 }));
    render(<AuthProvider><AuthProbe /></AuthProvider>);
    await waitFor(() => expect(screen.getByTestId('auth-state')).toHaveTextContent('public'));
    expect(fetch).toHaveBeenCalledWith('/v1/auth/me', expect.objectContaining({ credentials: 'include' }));
  });
});
