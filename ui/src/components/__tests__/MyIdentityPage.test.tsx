import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, renderWithRouter, screen, act, waitFor, within } from '@test/utils'
import { initiateLogout } from '../../services/authApi'

import MyIdentityPage from '../console/applicant/MyIdentityPage'

const {
  mockGetMyCredentials,
  mockGetMyApplications,
} = vi.hoisted(() => ({
  mockGetMyCredentials: vi.fn(),
  mockGetMyApplications: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (_key: string, defaultValue?: string) => defaultValue || _key }),
}))

vi.mock('../../services/applicantApi', () => ({
  getMyCredentials: mockGetMyCredentials,
  getMyApplications: mockGetMyApplications,
}))

vi.mock('../console/applicant/ClaimCredentialDialog', () => ({
  default: ({ open, applicationId }: { open: boolean; applicationId?: string | null }) => (
    open ? <div data-testid="claim-credential-dialog">{applicationId}</div> : null
  ),
}))

function setMobileViewport(mobile: boolean) {
  vi.mocked(window.matchMedia).mockImplementation((query) => ({
    matches: mobile,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }))
}

function expectIdentityLayoutStyles() {
  const header = screen.getByText('My Identity').closest('.MuiStack-root')
  expect(header).toHaveStyle({ justifyContent: 'space-between' })
  expect(document.querySelector(
    '[justifycontent], [alignitems], [flexwrap], [fontweight], [texttransform], [letterspacing]',
  )).toBeNull()
}

function applicationFixture(overrides = {}) {
  return {
    id: 'application-1', organization_id: 'org-1', applicant_id: 'applicant-1',
    credential_template_id: 'template-1', credential_display_name: 'Membership application',
    status: 'CREDENTIALED', claim_state: 'CLAIMED',
    submitted_at: '2026-05-18T00:00:00.000Z', updated_at: '2026-05-18T00:05:00.000Z',
    ...overrides,
  };
}

function credentialFixture(overrides = {}) {
  return {
    id: 'credential-1', credential_id: 'credential-1', organization_id: 'org-1',
    application_id: 'application-1', credential_template_id: 'template-1',
    credential_type: 'MembershipCredential', subject_id: 'applicant-1',
    issuer_did: 'did:web:issuer.example', flow_execution_id: 'transaction-1',
    status: 'ACTIVE', issued_at: '2026-05-18T00:05:00.000Z',
    updated_at: '2026-05-18T00:05:00.000Z', valid_until: '2027-05-18T00:05:00.000Z',
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => { resolve = yes; });
  return { promise, resolve };
}

describe('MyIdentityPage', () => {
  it('aborts inventory requests before logout submission and stops focus refreshes', async () => {
    mockGetMyCredentials.mockImplementation(() => new Promise(() => {}))
    mockGetMyApplications.mockImplementation(() => new Promise(() => {}))
    const view = render(<MyIdentityPage />)
    await waitFor(() => expect(mockGetMyCredentials).toHaveBeenCalled())
    const signal = mockGetMyCredentials.mock.calls.at(-1)![1].signal as AbortSignal
    const applicationSignal = mockGetMyApplications.mock.calls.at(-1)![1].signal as AbortSignal
    expect(signal.aborted).toBe(false)
    const submit = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {
      expect(signal.aborted).toBe(true)
      expect(applicationSignal.aborted).toBe(true)
    })
    try {
      act(() => initiateLogout())
      expect(submit).toHaveBeenCalledOnce()
      const calls = mockGetMyCredentials.mock.calls.length
      act(() => window.dispatchEvent(new Event('focus')))
      expect(mockGetMyCredentials).toHaveBeenCalledTimes(calls)
    } finally {
      submit.mockRestore()
      document.querySelector('form[action="/v1/auth/logout"]')?.remove()
      view.unmount()
    }
  })

  beforeEach(() => {
    vi.clearAllMocks()
    setMobileViewport(false)
    mockGetMyCredentials.mockResolvedValue({ items: [] })
    mockGetMyApplications.mockResolvedValue({
      items: [
        {
          id: 'app-1',
          credential_display_name: 'Verified Member Badge',
          credential_template_id: 'cfg-login-badge',
          status: 'CREDENTIALED',
          submitted_at: '2026-05-18T00:00:00.000Z',
          updated_at: '2026-05-18T00:05:00.000Z',
        },
      ],
    })
  })

  it.each([
    ['ACTIVE', 'Active', 'To present a credential, use the wallet where it is stored.'],
    ['EXPIRED', 'Expired', 'This credential has expired. Contact the issuer about renewal.'],
    ['REVOKED', 'Revoked', 'This credential has been revoked. Contact the issuer for help.'],
    ['SUSPENDED', 'Suspended', null],
  ])('keeps the linked credential’s %s status authoritative over a completed application', async (status, label, guidance) => {
    mockGetMyApplications.mockResolvedValue({ items: [applicationFixture({
      integration_context: { issuer_did: 'did:web:application-context.example' },
    })] });
    mockGetMyCredentials.mockResolvedValue({ items: [credentialFixture({ status })] });
    const { user } = render(<MyIdentityPage />);

    const details = await screen.findByRole('button', { name: 'View MembershipCredential details' });
    expect(screen.queryByText('Membership application')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'All (1)' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Issued (1)' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: `Action Required (${status === 'EXPIRED' ? 1 : 0})` })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Claim' })).not.toBeInTheDocument();
    await user.click(details);

    const credentialDialog = await screen.findByRole('dialog', { name: 'Credential Details' });
    expect(within(credentialDialog).getByText(label!)).toBeInTheDocument();
    expect(within(credentialDialog).getByText('credential-1')).toBeInTheDocument();
    expect(within(credentialDialog).getByText('did:web:issuer.example')).toBeInTheDocument();
    expect(within(credentialDialog).queryByText('did:web:application-context.example')).not.toBeInTheDocument();
    if (guidance) expect(within(credentialDialog).getByText(guidance)).toBeInTheDocument();
    if (status !== 'ACTIVE') expect(within(credentialDialog).queryByText('To present a credential, use the wallet where it is stored.')).not.toBeInTheDocument();
    await user.click(within(credentialDialog).getByRole('button', { name: 'View application details' }));

    const applicationDialog = await screen.findByRole('dialog', { name: 'Application Details' });
    const linked = within(applicationDialog).getByRole('region', { name: 'Issued credentials' });
    expect(within(linked).getByText(label!)).toBeInTheDocument();
    expect(within(linked).getByText('Credential ID: credential-1')).toBeInTheDocument();
    expect(within(applicationDialog).getByText('Application status')).toBeInTheDocument();
  });

  it.each([false, true])('preserves original and renewal credentials and opens every current status through an application link (mobile=%s)', async (mobile) => {
    setMobileViewport(mobile);
    mockGetMyApplications.mockResolvedValue({ items: [applicationFixture({
      integration_context: { canvas: { canvas_course_name: 'Membership course' } },
    })] });
    mockGetMyCredentials.mockResolvedValue({ items: [
      credentialFixture({ status: 'EXPIRED', renewed_to_credential_id: 'credential-2' }),
      credentialFixture({ id: 'credential-2', credential_id: 'credential-2', status: 'ACTIVE',
        renewed_from_credential_id: 'credential-1', flow_execution_id: 'renewal-transaction' }),
    ] });
    const { user } = renderWithRouter(<MyIdentityPage />, {
      initialEntries: ['/console/applicant/identity?id=application-1'],
    });

    const dialog = await screen.findByRole('dialog', { name: 'Application Details' });
    const linked = within(dialog).getByRole('region', { name: 'Issued credentials' });
    expect(within(linked).getByText('Expired')).toBeInTheDocument();
    expect(within(linked).getByText('Active')).toBeInTheDocument();
    expect(within(linked).getByText('Credential ID: credential-1')).toBeInTheDocument();
    expect(within(linked).getByText('Credential ID: credential-2')).toBeInTheDocument();
    expect(within(dialog).getByText('Membership course')).toBeInTheDocument();
    const original = within(linked).getByText('Credential ID: credential-1').parentElement!;
    await user.click(within(original).getByRole('button', { name: 'View MembershipCredential details' }));
    expect(await screen.findByRole('dialog', { name: 'Credential Details' })).toHaveTextContent('credential-1');
    expect(screen.getByText('This credential has expired. Contact the issuer about renewal.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    expect(screen.getByRole('button', { name: 'All (2)' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Issued (2)' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Action Required (1)' })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'View MembershipCredential details' })).toHaveLength(2);
    expect(screen.queryByText('Membership application')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Action Required (1)' }));
    expect(screen.getAllByRole('button', { name: 'View MembershipCredential details' })).toHaveLength(1);
    expect(screen.getByRole('img', { name: 'Status: Expired' })).toBeInTheDocument();
  });

  it('keeps separate same-template applications without attaching a credential to the newer one', async () => {
    mockGetMyApplications.mockResolvedValue({ items: [
      applicationFixture(),
      applicationFixture({ id: 'application-rejected', credential_display_name: 'Rejected membership', status: 'REJECTED' }),
      applicationFixture({ id: 'application-new', credential_display_name: 'New membership request', status: 'NEEDS_INFO',
        updated_at: '2026-06-01T00:00:00.000Z' }),
    ] });
    mockGetMyCredentials.mockResolvedValue({ items: [credentialFixture({ status: 'REVOKED' })] });
    const { user } = render(<MyIdentityPage />);

    await screen.findByText('New membership request');
    expect(screen.getByText('Rejected membership')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Status: Revoked' })).toBeInTheDocument();
    expect(screen.queryByText('Membership application')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'All (3)' })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Details' })).toHaveLength(2);
    await user.click(screen.getByRole('button', { name: 'Action Required (1)' }));
    await user.click(screen.getByRole('button', { name: 'Details' }));
    const dialog = await screen.findByRole('dialog', { name: 'Application Details' });
    expect(within(dialog).getByText('New membership request')).toBeInTheDocument();
    expect(within(dialog).queryByRole('region', { name: 'Issued credentials' })).not.toBeInTheDocument();
  });

  it.each([
    ['missing application link', { application_id: null }],
    ['empty application link', { application_id: '' }],
    ['another application', { application_id: 'not-in-this-page' }],
    ['another organization', { organization_id: 'org-2' }],
    ['missing organization', { organization_id: null }],
    ['empty organization', { organization_id: '' }],
  ])('keeps an independent credential with %s despite sharing the same template', async (_reason, overrides) => {
    mockGetMyApplications.mockResolvedValue({ items: [applicationFixture()] });
    mockGetMyCredentials.mockResolvedValue({ items: [credentialFixture(overrides)] });
    const { user } = render(<MyIdentityPage />);

    await screen.findByText('Membership application');
    expect(screen.getByRole('button', { name: 'All (2)' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'View MembershipCredential details' }));
    expect(await screen.findByRole('dialog', { name: 'Credential Details' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'View application details' })).not.toBeInTheDocument();
  });

  it.each(['row', 'details'])('keeps a live reissue workflow and its older credential, including Claim from %s', async (source) => {
    mockGetMyApplications.mockResolvedValue({ items: [applicationFixture({
      status: 'OFFERED', claim_state: 'OFFER_READY',
      credential_offer_uri: 'openid-credential-offer://offer/reissue',
      offer_expires_at: new Date(Date.now() + 60000).toISOString(),
    })] });
    mockGetMyCredentials.mockResolvedValue({ items: [credentialFixture({ status: 'EXPIRED' })] });
    const { user } = render(<MyIdentityPage />);

    await screen.findByText('Membership application');
    expect(screen.getByRole('button', { name: 'All (2)' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Action Required (2)' })).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Status: Expired' })).toBeInTheDocument();
    if (source === 'details') {
      await user.click(screen.getByRole('button', { name: 'Details' }));
      expect(within(screen.getByRole('region', { name: 'Issued credentials' })).getByText('Expired')).toBeInTheDocument();
    }
    await user.click(screen.getByRole('button', { name: 'Claim' }));
    expect(await screen.findByTestId('claim-credential-dialog')).toHaveTextContent('application-1');
  });

  it('retains a credential and its open details when only the application refresh succeeds', async () => {
    mockGetMyCredentials.mockResolvedValueOnce({ items: [credentialFixture({ status: 'REVOKED' })] })
      .mockRejectedValue(new Error('Inventory unavailable'));
    mockGetMyApplications.mockResolvedValueOnce({ items: [] })
      .mockResolvedValue({ items: [applicationFixture()] });
    const { user } = render(<MyIdentityPage />);
    await user.click(await screen.findByRole('button', { name: 'View MembershipCredential details' }));

    await act(async () => { window.dispatchEvent(new Event('focus')); });
    const dialog = screen.getByRole('dialog', { name: 'Credential Details' });
    expect(within(dialog).getByText('Revoked')).toBeInTheDocument();
    expect(within(dialog).getByText('This credential has been revoked. Contact the issuer for help.')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'View application details' }));
    expect(await screen.findByRole('dialog', { name: 'Application Details' })).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Issued credentials' })).getByText('Revoked')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByText('Credential inventory could not be loaded.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'All (1)' })).toBeInTheDocument();
  });

  it.each(['credential', 'application'])('refreshes current %s details after revocation while retaining failed application inventory', async (selectedKind) => {
    mockGetMyCredentials.mockResolvedValueOnce({ items: [credentialFixture()] })
      .mockResolvedValue({ items: [credentialFixture({ status: 'REVOKED' })] });
    mockGetMyApplications.mockResolvedValueOnce({ items: [applicationFixture({
      integration_context: { canvas: { canvas_course_name: 'Retained course context' } },
    })] }).mockRejectedValue(new Error('Applications unavailable'));
    const { user } = render(<MyIdentityPage />);
    await user.click(await screen.findByRole('button', { name: 'View MembershipCredential details' }));
    if (selectedKind === 'application') await user.click(screen.getByRole('button', { name: 'View application details' }));

    await act(async () => { window.dispatchEvent(new Event('focus')); });
    const dialog = screen.getByRole('dialog');
    if (selectedKind === 'credential') {
      expect(within(dialog).getByText('Revoked')).toBeInTheDocument();
      expect(within(dialog).getByText('This credential has been revoked. Contact the issuer for help.')).toBeInTheDocument();
      expect(within(dialog).queryByText('To present a credential, use the wallet where it is stored.')).not.toBeInTheDocument();
      expect(within(dialog).getByRole('button', { name: 'View application details' })).toBeInTheDocument();
    } else {
      const linked = within(dialog).getByRole('region', { name: 'Issued credentials' });
      expect(within(linked).getByText('Revoked')).toBeInTheDocument();
      expect(within(linked).queryByText('Active')).not.toBeInTheDocument();
      expect(within(dialog).getByText('Retained course context')).toBeInTheDocument();
    }
    await user.click(within(dialog).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByText('Applications could not be loaded.')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Status: Revoked' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'All (1)' })).toBeInTheDocument();
  });

  it('closes removed credential details after a successful empty refresh', async () => {
    mockGetMyCredentials.mockResolvedValueOnce({ items: [credentialFixture()] }).mockResolvedValue({ items: [] });
    mockGetMyApplications.mockResolvedValue({ items: [] });
    const { user } = render(<MyIdentityPage />);
    await user.click(await screen.findByRole('button', { name: 'View MembershipCredential details' }));

    await act(async () => { window.dispatchEvent(new Event('focus')); });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByText('No credentials yet')).toBeInTheDocument();
    expect(screen.queryByText('To present a credential, use the wallet where it is stored.')).not.toBeInTheDocument();
  });

  it('lets a newer focus refresh finish initial loading and rejects the older ACTIVE response', async () => {
    const initial = deferred<{ items: ReturnType<typeof credentialFixture>[] }>();
    mockGetMyCredentials.mockReturnValueOnce(initial.promise)
      .mockResolvedValue({ items: [credentialFixture({ status: 'REVOKED' })] });
    mockGetMyApplications.mockResolvedValue({ items: [applicationFixture()] });
    render(<MyIdentityPage />);
    expect(screen.getByRole('progressbar')).toBeInTheDocument();

    await act(async () => { window.dispatchEvent(new Event('focus')); });
    expect(screen.getByRole('img', { name: 'Status: Revoked' })).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'All (1)' })).toBeInTheDocument();
    await act(async () => { initial.resolve({ items: [credentialFixture()] }); });

    expect(screen.getByRole('img', { name: 'Status: Revoked' })).toBeInTheDocument();
    expect(screen.queryByRole('img', { name: 'Status: Active' })).not.toBeInTheDocument();
    expect(mockGetMyCredentials).toHaveBeenCalledTimes(2);
  });

  it('coalesces scheduled polls during a slow latest request even after an older request settles', async () => {
    vi.useFakeTimers();
    const older = deferred<{ items: ReturnType<typeof credentialFixture>[] }>();
    const latest = deferred<{ items: ReturnType<typeof credentialFixture>[] }>();
    mockGetMyCredentials.mockReturnValueOnce(older.promise).mockReturnValueOnce(latest.promise)
      .mockResolvedValue({ items: [credentialFixture({ status: 'REVOKED' })] });
    mockGetMyApplications.mockResolvedValue({ items: [applicationFixture()] });
    const view = render(<MyIdentityPage />);
    try {
      await act(async () => { window.dispatchEvent(new Event('focus')); });
      expect(mockGetMyCredentials).toHaveBeenCalledTimes(2);
      await act(async () => { older.resolve({ items: [credentialFixture()] }); });
      await act(async () => { await vi.advanceTimersByTimeAsync(45000); });

      expect(mockGetMyCredentials).toHaveBeenCalledTimes(2);
      expect(screen.getByRole('progressbar')).toBeInTheDocument();
      await act(async () => { latest.resolve({ items: [credentialFixture({ status: 'REVOKED' })] }); });
      expect(screen.getByRole('img', { name: 'Status: Revoked' })).toBeInTheDocument();
      expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
      await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
      expect(mockGetMyCredentials).toHaveBeenCalledTimes(3);
      expect(screen.getByRole('img', { name: 'Status: Revoked' })).toBeInTheDocument();
    } finally {
      view.unmount();
      vi.useRealTimers();
    }
  });

  it('does not expose a claim action after the application is credentialed', async () => {
    render(<MyIdentityPage />)

    await screen.findByText('Verified Member Badge')
    expect(screen.queryByRole('button', { name: /claim|receive again/i })).not.toBeInTheDocument()
    expectIdentityLayoutStyles()
  })

  it('shows Canvas course source context in application details', async () => {
    mockGetMyApplications.mockResolvedValue({
      items: [
        {
          id: 'app-canvas-1',
          credential_display_name: 'Interoperable Credentials Foundations Badge',
          credential_template_id: 'cfg-canvas-badge',
          status: 'SUBMITTED',
          submitted_at: '2026-05-18T00:00:00.000Z',
          updated_at: '2026-05-18T00:05:00.000Z',
          integration_context: {
            delivery_mode: 'wallet_plus_canvas_mirror',
            canvas: {
              canvas_course_name: 'ElevenID LTI Test Course',
              canvas_assignment_name: 'Interoperable Credentials Quiz',
              canvas_account_id: 'canvas-real-account-1',
              canvas_program_binding_id: 'binding-1',
            },
          },
        },
      ],
    })

    const { user } = render(<MyIdentityPage />)

    await screen.findByText('Interoperable Credentials Foundations Badge')
    await user.click(screen.getByRole('button', { name: 'Details' }))

    expect(await screen.findByTestId('identity-canvas-source')).toBeInTheDocument()
    expect(screen.getByText('ElevenID LTI Test Course')).toBeInTheDocument()
    expect(screen.getByText('Interoperable Credentials Quiz')).toBeInTheDocument()
    expect(screen.getByText('canvas-real-account-1')).toBeInTheDocument()
    expect(screen.getByText('Delivery: wallet plus canvas mirror')).toBeInTheDocument()
    expectIdentityLayoutStyles()
  })

  it('shows issuer-owned waiting state for an approved blocked application', async () => {
    mockGetMyApplications.mockResolvedValue({
      items: [{
        id: 'app-blocked',
        credential_display_name: 'Member Credential',
        credential_template_id: 'cfg-member',
        status: 'APPROVED',
        claim_state: 'BLOCKED',
        claim_blocker: {
          code: 'NO_ACTIVE_ISSUANCE_FLOW',
          owner: 'ISSUER',
          message: 'The issuer is still preparing this credential.',
        },
        updated_at: '2026-05-18T00:05:00.000Z',
      }],
    })

    render(<MyIdentityPage />)

    await screen.findByText('Member Credential')
    expect(screen.getByText('Waiting for Issuer')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Claim' })).not.toBeInTheDocument()
  })

  it('does not present failed identity requests as an empty inventory and allows retry', async () => {
    mockGetMyCredentials
      .mockRejectedValueOnce(new Error('Inventory unavailable'))
      .mockResolvedValue({ items: [] })
    mockGetMyApplications
      .mockRejectedValueOnce(new Error('Applications unavailable'))
      .mockResolvedValue({ items: [] })

    const { user } = render(<MyIdentityPage />)

    expect(await screen.findByText(/Credential inventory could not be loaded/)).toBeInTheDocument()
    expect(screen.getByText(/Applications could not be loaded/)).toBeInTheDocument()
    expect(screen.queryByText('No credentials yet')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Retry' }))

    expect(await screen.findByText('No credentials yet')).toBeInTheDocument()
    expect(screen.queryByText(/could not be loaded/)).not.toBeInTheDocument()
    expect(mockGetMyCredentials).toHaveBeenCalledTimes(2)
    expect(mockGetMyApplications).toHaveBeenCalledTimes(2)
    expect(screen.getByText('Browse the catalog to apply for your first credential.')).toHaveStyle({ marginBottom: '16px' })
    expectIdentityLayoutStyles()
  })

  it('retains successful application data when credential inventory fails', async () => {
    mockGetMyCredentials.mockRejectedValue(new Error('Inventory unavailable'))

    render(<MyIdentityPage />)

    expect(await screen.findByText('Verified Member Badge')).toBeInTheDocument()
    expect(screen.getByText('Credential inventory could not be loaded.')).toBeInTheDocument()
    expect(screen.queryByText('No credentials yet')).not.toBeInTheDocument()
  })

  it('shows Canvas Credentials mirror delivery in credential details', async () => {
    mockGetMyApplications.mockResolvedValue({ items: [] })
    mockGetMyCredentials.mockResolvedValue({
      items: [
        {
          id: 'cred-1',
          credential_display_name: 'Interoperable Credentials Foundations Badge',
          credential_template_id: 'cfg-canvas-badge',
          issuer_did: 'did:web:beta.elevenidllc.com:orgs:marty',
          badge_image_url: 'https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge/image.svg',
          status: 'ACTIVE',
          issued_at: '2026-05-18T00:00:00.000Z',
          updated_at: '2026-05-18T00:05:00.000Z',
          deliveries: [
            {
              id: 'delivery-1',
              delivery_target: 'canvas_credentials',
              status: 'delivered',
              external_credential_id: 'canvas-cred-1',
            },
          ],
        },
      ],
    })

    const { user } = render(<MyIdentityPage />)

    await screen.findByText('Interoperable Credentials Foundations Badge')
    expect(screen.getByRole('img', { name: /interoperable credentials foundations badge/i })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /view interoperable credentials foundations badge details/i }))

    expect(await screen.findByText('Credential Details')).toBeInTheDocument()
    expect(screen.getByText('did:web:beta.elevenidllc.com:orgs:marty')).toBeInTheDocument()
    expect(screen.getAllByRole('img', { name: /interoperable credentials foundations badge/i }).length).toBeGreaterThan(0)
    expect(screen.getByText('Claim: Claimed')).toBeInTheDocument()
    expect(screen.getByTestId('identity-canvas-delivery')).toBeInTheDocument()
    expect(screen.getByText('Canvas Credentials display')).toBeInTheDocument()
    expect(screen.getByText('Delivered')).toBeInTheDocument()
    expect(screen.getByText(/canvas-cred-1/)).toBeInTheDocument()
    expect(screen.getByText('Mirror linked').closest('.MuiStack-root')).toHaveStyle({
      alignItems: 'center',
      flexWrap: 'wrap',
    })
    expectIdentityLayoutStyles()
  })

  it.each([false, true])('offers working credential details without inert QR or download controls (mobile=%s)', async (mobile) => {
    setMobileViewport(mobile)
    mockGetMyApplications.mockResolvedValue({ items: [] })
    mockGetMyCredentials.mockResolvedValue({
      items: [{ id: 'cred-1', credential_display_name: 'Member Credential', status: 'ACTIVE' }],
    })
    const { user } = render(<MyIdentityPage />)

    const details = await screen.findByRole('button', { name: 'View Member Credential details' })
    expect(screen.queryByRole('button', { name: /showQRCode|Show QR Code|download/i })).not.toBeInTheDocument()
    await user.click(details)

    expect(await screen.findByText('Credential Details')).toBeInTheDocument()
    expect(screen.getByText('To present a credential, use the wallet where it is stored.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^(Present|Renew)$/ })).not.toBeInTheDocument()
    expectIdentityLayoutStyles()
  })

  it.each([
    ['EXPIRED', 'This credential has expired. Contact the issuer about renewal.'],
    ['REVOKED', 'This credential has been revoked. Contact the issuer for help.'],
  ])('provides accurate guidance for a %s credential without a dead-end action', async (status, guidance) => {
    mockGetMyApplications.mockResolvedValue({ items: [] })
    mockGetMyCredentials.mockResolvedValue({
      items: [{ id: 'cred-1', credential_display_name: 'Member Credential', status }],
    })
    const { user } = render(<MyIdentityPage />)

    await user.click(await screen.findByRole('button', { name: 'View Member Credential details' }))

    expect(await screen.findByText(guidance)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^(Present|Renew)$/ })).not.toBeInTheDocument()
    expect(screen.queryByText('To present a credential, use the wallet where it is stored.')).not.toBeInTheDocument()
  })

  it('shows one Details action for an information request instead of a Continue button that only reopens itself', async () => {
    mockGetMyApplications.mockResolvedValue({
      items: [{ id: 'app-info', credential_display_name: 'Member Credential', status: 'NEEDS_INFO' }],
    })
    const { user } = render(<MyIdentityPage />)

    await screen.findByText('Member Credential')
    expect(screen.queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Details' }))

    expect(await screen.findByText('The issuer needs more information. Contact the issuer for instructions on how to provide it.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })

  it.each(['row', 'details'])('preserves the working live-offer Claim action from the %s', async (source) => {
    mockGetMyApplications.mockResolvedValue({
      items: [{
        id: 'app-offer',
        credential_display_name: 'Member Credential',
        status: 'APPROVED',
        claim_state: 'OFFER_READY',
        credential_offer_uri: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer',
        offer_expires_at: new Date(Date.now() + 60000).toISOString(),
      }],
    })
    const { user } = render(<MyIdentityPage />)

    await screen.findByText('Member Credential')
    if (source === 'details') await user.click(screen.getByRole('button', { name: 'Details' }))
    await user.click(screen.getByRole('button', { name: 'Claim' }))

    expect(await screen.findByTestId('claim-credential-dialog')).toHaveTextContent('app-offer')
  })
})
