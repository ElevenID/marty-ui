import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithoutRouter, screen, waitFor } from '../../test/utils'
import WalletOfferDialog from '../applicant/WalletOfferDialog'
import { generateIssuanceOffer } from '../../services/credentialsApi'

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
  })

  it('loads a wallet offer on open, retries after an error, and closes cleanly', async () => {
    const onClose = vi.fn()

    vi.mocked(generateIssuanceOffer)
      .mockRejectedValueOnce(new Error('No wallet today'))
      .mockResolvedValueOnce({
        offer_url: 'openid://wallet-offer',
        expires_at: '2026-03-16T00:00:00Z',
        status: 'active',
      })

    const { user } = renderWithoutRouter(
      <WalletOfferDialog
        open
        onClose={onClose}
        applicationId="app-1"
        credentialName="Member Pass"
      />,
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
