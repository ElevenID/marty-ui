import { describe, expect, it, vi } from 'vitest'
import { renderWithoutRouter, screen, waitFor } from '../../test/utils'
import OID4VCIInviteDisplay from './OID4VCIInviteDisplay'

const { mockBuildWalletOpenLink } = vi.hoisted(() => ({
  mockBuildWalletOpenLink: vi.fn(),
}))

vi.mock('../../services/walletRegistryApi', () => ({
  buildWalletOpenLink: (...args: unknown[]) => mockBuildWalletOpenLink(...args),
}))

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

  it('uses a browser wallet fallback when stale registry metadata returns a raw protocol link', async () => {
    const originalLocation = window.location
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { href: '' },
    })
    mockBuildWalletOpenLink.mockResolvedValue({
      open_uri: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123',
    })

    const { user } = renderWithoutRouter(
      <OID4VCIInviteDisplay
        offerData={{
          offer_url: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123',
          credential_offer_uris: {
            'wr-waltid-001': 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123',
          },
          credential_offer_labels: {
            'wr-waltid-001': 'walt.id Wallet',
          },
          wallet_registry: {
            'wr-waltid-001': {
              id: 'wr-waltid-001',
              name: 'walt.id Wallet',
              routing_templates: {
                web: 'https://wallet.demo.walt.id/api/siop/initiateIssuance?{credential_offer_param}={offer_encoded}',
              },
            },
          },
        }}
        allowedWalletIds={['wr-waltid-001']}
        showDefaultWalletTab={false}
        showDeepLink
      />,
    )

    await user.click(screen.getByRole('button', { name: 'Open in mobile wallet app' }))

    await waitFor(() => {
      expect(window.location.href).toBe(
        'https://wallet.demo.walt.id/api/siop/initiateIssuance?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123',
      )
    })
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
    })
  })
})
