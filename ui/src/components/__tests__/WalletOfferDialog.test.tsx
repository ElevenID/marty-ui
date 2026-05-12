import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { renderWithoutRouter, screen, waitFor } from '../../test/utils'
import WalletOfferDialog from '../applicant/WalletOfferDialog'
import { generateIssuanceOffer } from '../../services/credentialsApi'

const { mockWalletPreferenceState } = vi.hoisted(() => ({
  mockWalletPreferenceState: { walletIds: [] as string[] },
}))

type WalletOfferDisplayProps = {
  offerData?: { offer_url?: string | null }
  onRegenerate?: () => void
  loading?: boolean
  title?: string
  instructions?: string
}

vi.mock('../../services/credentialsApi', () => ({
  generateIssuanceOffer: vi.fn(),
}))

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      user_id: 'user-1',
      email: 'applicant@example.com',
    },
  }),
}))

vi.mock('../../hooks/useWalletPreferences', () => ({
  default: () => ({
    walletIds: mockWalletPreferenceState.walletIds,
  }),
}))

vi.mock('../issuance/OID4VCIInviteDisplay', () => ({
  default: ({ offerData, onRegenerate, loading, title, instructions }: WalletOfferDisplayProps) => (
    <div data-testid="wallet-offer-display">
      <div data-testid="wallet-offer-loading">{loading ? 'loading' : 'idle'}</div>
      <div data-testid="wallet-offer-title">{title}</div>
      <div data-testid="wallet-offer-instructions">{instructions}</div>
      <div data-testid="wallet-offer-url">{offerData?.offer_url || ''}</div>
      <button type="button" onClick={onRegenerate}>
        Regenerate Offer
      </button>
    </div>
  ),
}))

describe('WalletOfferDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockWalletPreferenceState.walletIds = []
  })

  it('blocks the QR handoff until a wallet app is selected', async () => {
    const onClose = vi.fn()
    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <WalletOfferDialog
          open
          onClose={onClose}
          applicationId="app-1"
          credentialName="Member Pass"
        />
      </MemoryRouter>,
    )

    expect(await screen.findByTestId('wallet-registration-guard')).toHaveTextContent(
      'Select a wallet app before you can receive this credential.',
    )
    expect(screen.queryByTestId('wallet-offer-display')).not.toBeInTheDocument()
    expect(generateIssuanceOffer).not.toHaveBeenCalled()

    const setupLink = screen.getByRole('link', { name: 'Choose Wallet' })
    expect(setupLink).toHaveAttribute('href', '/console/applicant/settings#wallet-selection')
    setupLink.addEventListener('click', (event) => event.preventDefault())

    await user.click(setupLink)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('loads a wallet offer on open, retries after an error, and closes cleanly once a wallet app is selected', async () => {
    const onClose = vi.fn()
    mockWalletPreferenceState.walletIds = ['wallet-1']

    vi.mocked(generateIssuanceOffer)
      .mockRejectedValueOnce(new Error('No wallet today'))
      .mockResolvedValueOnce({
        offer_url: 'openid://wallet-offer',
        expires_at: '2026-03-16T00:00:00Z',
        status: 'active',
      })

    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <WalletOfferDialog
          open
          onClose={onClose}
          applicationId="app-1"
          credentialName="Member Pass"
        />
      </MemoryRouter>,
    )

    expect(await screen.findByText('No wallet today')).toBeInTheDocument()
    expect(generateIssuanceOffer).toHaveBeenCalledWith('app-1')

    await user.click(screen.getByRole('button', { name: 'Retry' }))

    await waitFor(() => {
      expect(screen.getByTestId('wallet-offer-url')).toHaveTextContent('openid://wallet-offer')
    })

    expect(screen.getByTestId('wallet-offer-title')).toHaveTextContent('Scan with your wallet')
    expect(screen.getByText('Member Pass')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /close/i }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
