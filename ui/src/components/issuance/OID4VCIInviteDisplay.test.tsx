import { describe, expect, it } from 'vitest'
import { renderWithoutRouter, screen } from '../../test/utils'
import OID4VCIInviteDisplay from './OID4VCIInviteDisplay'

const offerData = {
  offer_url: 'openid-credential-offer://generic',
  credential_offer_uris: {
    'wr-spruce-001': 'openid-credential-offer://spruce',
    'wr-marty-001': 'openid-credential-offer://marty',
    'wr-google-001': 'openid-credential-offer://google',
  },
  credential_offer_labels: {
    'wr-spruce-001': 'SpruceKit',
    'wr-marty-001': 'Marty Authenticator',
    'wr-google-001': 'Google Wallet',
  },
}

describe('OID4VCIInviteDisplay', () => {
  it('restricts wallet tabs to registered wallet ids and hides the generic tab when requested', () => {
    renderWithoutRouter(
      <OID4VCIInviteDisplay
        offerData={offerData}
        allowedWalletIds={['wr-spruce-001', 'wr-google-001']}
        showDefaultWalletTab={false}
      />,
    )

    expect(screen.getByRole('tab', { name: 'SpruceKit' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Google Wallet' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Marty Authenticator' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Other Wallets' })).not.toBeInTheDocument()
  })

  it('keeps all wallet tabs available when no allowlist is provided', () => {
    renderWithoutRouter(<OID4VCIInviteDisplay offerData={offerData} />)

    expect(screen.getByRole('tab', { name: 'SpruceKit' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Marty Authenticator' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Google Wallet' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Other Wallets' })).toBeInTheDocument()
  })
})
