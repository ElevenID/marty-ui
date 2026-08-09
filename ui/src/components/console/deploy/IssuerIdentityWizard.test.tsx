import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import IssuerIdentityWizard from './IssuerIdentityWizard';

const { createIssuerIdentity, showNotification } = vi.hoisted(() => ({
  createIssuerIdentity: vi.fn(),
  showNotification: vi.fn(),
}));

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    createIssuerIdentity: (...args: unknown[]) => createIssuerIdentity(...args),
  },
}));

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({ showNotification }),
}));

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationName: 'Test Org' }),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    activeOrgId: 'org-test-1',
    memberships: [{ id: 'org-test-1', display_name: 'Test Org' }],
  }),
}));

describe('IssuerIdentityWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createIssuerIdentity.mockResolvedValue({
      created: true,
      identity: {
        issuer_did: 'did:web:localhost:orgs:test-org',
        key_purpose: 'vc_jwt_issuer',
        algorithm: 'ES256',
        status: 'active',
      },
    });
  });

  it('exposes only provider-neutral issuer identity inputs', async () => {
    renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new?signing_service_id=forbidden&key_name=forbidden'],
    });

    expect(await screen.findByRole('heading', { name: 'Create issuer identity' })).toBeInTheDocument();
    expect(screen.getByLabelText(/Issuer DID/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Signing purpose/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Credential format/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Algorithm/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/key name/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/signing service/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/key reference/i)).not.toBeInTheDocument();
  });

  it('submits exactly the DID-first public tuple', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    });

    const didInput = await screen.findByLabelText(/Issuer DID/);
    await user.clear(didInput);
    await user.type(didInput, 'did:web:issuer.example:orgs:test-org');
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));

    await waitFor(() => {
      expect(createIssuerIdentity).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:issuer.example:orgs:test-org',
        key_purpose: 'vc_jwt_issuer',
        credential_format: 'SD_JWT_VC',
        algorithm: 'ES256',
      });
    });
    expect(showNotification).toHaveBeenCalledWith('Issuer identity created.', 'success');
  });

  it('does not submit a non-DID identity', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />);
    const didInput = await screen.findByLabelText(/Issuer DID/);
    await user.clear(didInput);
    await user.type(didInput, 'https://issuer.example');
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));

    expect(await screen.findByText(/Enter a valid DID/)).toBeInTheDocument();
    expect(createIssuerIdentity).not.toHaveBeenCalled();
  });
});
