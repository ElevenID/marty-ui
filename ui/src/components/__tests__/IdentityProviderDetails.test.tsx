import { describe, expect, it } from 'vitest';
import { List } from '@mui/material';
import { http, HttpResponse } from 'msw';
import { render, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import IdentityProviderDetails from '../IdentityProviderDetails';

const provider = {
  provider_mode: 'external', provider_name: 'Example Identity',
  registration_supported: false, passkey_enrollment_supported: false,
  provider_logout_supported: false,
  account_url: 'https://identity.example/account',
  recovery_url: 'https://identity.example/recover',
};

describe('identity provider account settings', () => {
  it('shows the configured provider, explicit account links and local logout behavior', async () => {
    server.use(http.get('*/v1/auth/provider', () => HttpResponse.json(provider)));
    render(<List><IdentityProviderDetails /></List>);
    await screen.findByText('Example Identity');
    expect(screen.queryByText('Keycloak OpenID Connect')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Manage sign-in account' })).toHaveAttribute('href', provider.account_url);
    expect(screen.getByRole('link', { name: 'Account recovery' })).toHaveAttribute('href', provider.recovery_url);
    expect(screen.getByText(/Your sign-in provider may keep you signed in/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create a passkey' })).not.toBeInTheDocument();
  });

  it('does not invent account actions when the provider has no configured links', async () => {
    server.use(http.get('*/v1/auth/provider', () => HttpResponse.json({
      ...provider, account_url: null, recovery_url: null, provider_logout_supported: true,
    })));
    render(<List><IdentityProviderDetails /></List>);
    await screen.findByText('Example Identity');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(screen.queryByText(/Your sign-in provider may keep you signed in/)).not.toBeInTheDocument();
  });

  it('recovers from unavailable account settings without navigating or altering the session', async () => {
    let ready = false;
    server.use(http.get('*/v1/auth/provider', () => ready
      ? HttpResponse.json(provider)
      : new HttpResponse('private diagnostic data', { status: 503 })));
    const { user } = render(<List><IdentityProviderDetails /></List>);
    await screen.findByText('Provider details unavailable');
    expect(screen.queryByText('private diagnostic data')).not.toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    ready = true;
    await user.click(screen.getByRole('button', { name: 'Retry account settings' }));
    await screen.findByText('Example Identity');
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Retry account settings' })).not.toBeInTheDocument());
  });
});
