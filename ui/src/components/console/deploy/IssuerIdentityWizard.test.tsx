import d10Controls from '../../../../../scripts/d10_ui_controls.json'
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

  it('D10 adapter selectors match the rendered production DID-first issuer submission', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />)
    const did = await screen.findByLabelText(d10Name('issuerDid'))
    const issuerDid = (did as HTMLInputElement).value
    expect(issuerDid).toMatch(/^did:/)
    expect(screen.getByRole('combobox', { name: /Signing purpose/ })).toHaveTextContent('Credential issuance')
    expect(screen.getByRole('combobox', { name: /Credential format/ })).toHaveTextContent('SD_JWT_VC')
    expect(screen.getByRole('combobox', { name: /Algorithm/ })).toHaveTextContent('ES256')
    await user.click(screen.getByRole(d10Controls.issuerSubmit.role, { name: d10Name('issuerSubmit') }))
    await waitFor(() => expect(createIssuerIdentity).toHaveBeenCalledWith({
      organization_id: 'org-test-1', issuer_did: issuerDid,
      key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256',
    }))
  })

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

  it('provisions a managed P-521 CSCA identity without exposing custody inputs', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />);

    await user.click(await screen.findByLabelText(/Signing purpose/));
    await user.click(screen.getByRole('option', { name: 'CSCA / IACA root authority' }));
    await user.click(screen.getByLabelText(/Algorithm/));
    await user.click(screen.getByRole('option', { name: 'ES512' }));
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));

    await waitFor(() => {
      expect(createIssuerIdentity).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:localhost%3A3000:orgs:test-org',
        key_purpose: 'csca',
        credential_format: 'MDOC',
        algorithm: 'ES512',
      });
    });
  });

  it('offers the ICAO CSCA tuple required for managed passport DSC issuance', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />);

    await user.click(await screen.findByLabelText(/Signing purpose/));
    await user.click(screen.getByRole('option', { name: 'CSCA / IACA root authority' }));
    await user.click(screen.getByLabelText(/Credential format/));
    await user.click(screen.getByRole('option', { name: 'ICAO_EMRTD' }));
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));

    await waitFor(() => {
      expect(createIssuerIdentity).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:localhost%3A3000:orgs:test-org',
        key_purpose: 'csca',
        credential_format: 'ICAO_EMRTD',
        algorithm: 'ES256',
      });
    });
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

const d10Name = (key: keyof typeof d10Controls) => {
  const definition = d10Controls[key] as { regex?: string; name?: string }
  return definition.regex ? new RegExp(definition.regex, 'i') : definition.name!
}
