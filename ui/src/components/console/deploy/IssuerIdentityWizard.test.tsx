import d10Controls from '../../../../../scripts/d10_ui_controls.json'
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import IssuerIdentityWizard from './IssuerIdentityWizard';

const { createIssuerIdentity, getIssuerIdentityCapabilities, showNotification, scope } = vi.hoisted(() => ({
  createIssuerIdentity: vi.fn(),
  getIssuerIdentityCapabilities: vi.fn(),
  showNotification: vi.fn(),
  scope: { activeOrgId: 'org-test-1' },
}));

vi.mock('../../../services/issuerIdentitiesApi', () => ({
  default: {
    createIssuerIdentity: (...args: unknown[]) => createIssuerIdentity(...args),
    getIssuerIdentityCapabilities: (...args: unknown[]) => getIssuerIdentityCapabilities(...args),
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
    activeOrgId: scope.activeOrgId,
    memberships: [{ id: 'org-test-1', display_name: 'Test Org' }],
  }),
}));

const capabilities = (organizationId = 'org-test-1') => ({
  organization_id: organizationId,
  managed_issuer_did_prefix: 'did:web:issuer.example:orgs:',
  basis: 'configuration',
  creation_options: [
    { key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256' },
    { key_purpose: 'vc_jwt_issuer', credential_format: 'VC_JWT', algorithm: 'RS256' },
    { key_purpose: 'vc_jwt_issuer', credential_format: 'JSON_LD', algorithm: 'EdDSA' },
    { key_purpose: 'csca', credential_format: 'MDOC', algorithm: 'ES256' },
    { key_purpose: 'csca', credential_format: 'MDOC', algorithm: 'ES512' },
    { key_purpose: 'csca', credential_format: 'ICAO_EMRTD', algorithm: 'ES256' },
  ],
});

async function readyDid() {
  const input = await screen.findByLabelText(/Issuer DID/);
  await waitFor(() => expect(input).toHaveValue('did:web:issuer.example:orgs:test-org'));
  return input;
}

describe('IssuerIdentityWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    scope.activeOrgId = 'org-test-1';
    getIssuerIdentityCapabilities.mockReset();
    getIssuerIdentityCapabilities.mockImplementation(async ({ organization_id }) => capabilities(organization_id));
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
    const did = await readyDid()
    expect(did).toHaveAccessibleName(d10Name('issuerDid'))
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

    const didInput = await readyDid();
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

    await readyDid();
    await user.click(await screen.findByLabelText(/Signing purpose/));
    await user.click(screen.getByRole('option', { name: 'CSCA / IACA root authority' }));
    await user.click(screen.getByLabelText(/Algorithm/));
    await user.click(screen.getByRole('option', { name: 'ES512' }));
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));

    await waitFor(() => {
      expect(createIssuerIdentity).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:issuer.example:orgs:test-org',
        key_purpose: 'csca',
        credential_format: 'MDOC',
        algorithm: 'ES512',
      });
    });
  });

  it('offers the ICAO CSCA tuple required for managed passport DSC issuance', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />);

    await readyDid();
    await user.click(await screen.findByLabelText(/Signing purpose/));
    await user.click(screen.getByRole('option', { name: 'CSCA / IACA root authority' }));
    await user.click(screen.getByLabelText(/Credential format/));
    await user.click(screen.getByRole('option', { name: 'ICAO_EMRTD' }));
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));

    await waitFor(() => {
      expect(createIssuerIdentity).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:issuer.example:orgs:test-org',
        key_purpose: 'csca',
        credential_format: 'ICAO_EMRTD',
        algorithm: 'ES256',
      });
    });
  });

  it('does not submit a non-DID identity', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />);
    const didInput = await readyDid();
    await user.clear(didInput);
    await user.type(didInput, 'https://issuer.example');
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));

    expect(await screen.findByText(/Enter a valid DID/)).toBeInTheDocument();
    expect(createIssuerIdentity).not.toHaveBeenCalled();
  });

  it('uses API tuples rather than a cross product of purpose algorithms', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />);
    await readyDid();
    await user.click(screen.getByRole('combobox', { name: /Credential format/ }));
    await user.click(screen.getByRole('option', { name: 'JSON_LD' }));
    expect(screen.getByRole('combobox', { name: /Algorithm/ })).toHaveTextContent('EdDSA');
    await user.click(screen.getByRole('combobox', { name: /Algorithm/ }));
    expect(screen.queryByRole('option', { name: 'ES256' })).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'EdDSA' })).toBeInTheDocument();
  });

  it('renders a newly advertised signing option without a UI catalog update', async () => {
    getIssuerIdentityCapabilities.mockResolvedValue({ ...capabilities(), creation_options: [
      { key_purpose: 'new_signing_purpose', credential_format: 'NEW_FORMAT', algorithm: 'NEW_ALGORITHM' },
    ] });
    const { user } = renderWithRouter(<IssuerIdentityWizard />);
    await readyDid();
    expect(screen.getByRole('combobox', { name: /Signing purpose/ })).toHaveTextContent('new signing purpose');
    expect(screen.getByRole('combobox', { name: /Credential format/ })).toHaveTextContent('NEW_FORMAT');
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));
    await waitFor(() => expect(createIssuerIdentity).toHaveBeenCalledWith({
      organization_id: 'org-test-1', issuer_did: 'did:web:issuer.example:orgs:test-org',
      key_purpose: 'new_signing_purpose', credential_format: 'NEW_FORMAT', algorithm: 'NEW_ALGORITHM',
    }));
  });

  it('fails closed on discovery failure and supports explicit retry', async () => {
    getIssuerIdentityCapabilities.mockRejectedValueOnce(new Error('offline'));
    const { user } = renderWithRouter(<IssuerIdentityWizard />);
    expect(await screen.findByText(/Issuer capabilities could not be loaded/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create managed identity' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Refresh issuer capabilities' }));
    await readyDid();
    expect(screen.getByRole('button', { name: 'Create managed identity' })).toBeEnabled();
  });

  it('rechecks changed capabilities before sending a provisioning request', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />);
    await readyDid();
    getIssuerIdentityCapabilities.mockResolvedValueOnce({ ...capabilities(), creation_options: [] });
    await user.click(screen.getByRole('button', { name: 'Create managed identity' }));
    expect(await screen.findByText(/Issuer capabilities changed/)).toBeInTheDocument();
    expect(createIssuerIdentity).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Create managed identity' })).toBeDisabled();
  });

  it('ignores late discovery responses after the organization changes', async () => {
    let completeOld!: (value: ReturnType<typeof capabilities>) => void;
    getIssuerIdentityCapabilities.mockReturnValueOnce(new Promise((resolve) => { completeOld = resolve; }));
    const view = renderWithRouter(<IssuerIdentityWizard />);
    scope.activeOrgId = 'org-other';
    view.rerender(<IssuerIdentityWizard />);
    await waitFor(() => expect(getIssuerIdentityCapabilities).toHaveBeenCalledWith({ organization_id: 'org-other' }));
    await readyDid();
    completeOld({ ...capabilities(), managed_issuer_did_prefix: 'did:web:stale.example:orgs:' });
    await waitFor(() => expect(screen.getByLabelText(/Issuer DID/)).toHaveValue('did:web:issuer.example:orgs:test-org'));
    expect(screen.queryByText(/stale.example/)).not.toBeInTheDocument();
  });

  it('does not provision for an old organization while a submit recheck is pending', async () => {
    const view = renderWithRouter(<IssuerIdentityWizard />);
    await readyDid();
    let completeCheck!: (value: ReturnType<typeof capabilities>) => void;
    getIssuerIdentityCapabilities.mockReturnValueOnce(new Promise((resolve) => { completeCheck = resolve; }));
    await view.user.click(screen.getByRole('button', { name: 'Create managed identity' }));
    scope.activeOrgId = 'org-other';
    view.rerender(<IssuerIdentityWizard />);
    await waitFor(() => expect(getIssuerIdentityCapabilities).toHaveBeenCalledWith({ organization_id: 'org-other' }));
    completeCheck(capabilities());
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create managed identity' })).toBeEnabled());
    expect(createIssuerIdentity).not.toHaveBeenCalled();
  });
});

const d10Name = (key: keyof typeof d10Controls) => {
  const definition = d10Controls[key] as { regex?: string; name?: string }
  return definition.regex ? new RegExp(definition.regex, 'i') : definition.name!
}
