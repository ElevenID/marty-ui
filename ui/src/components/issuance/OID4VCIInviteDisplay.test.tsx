import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderWithoutRouter, screen, waitFor } from '../../test/utils'
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
  let locationDescriptor: PropertyDescriptor
  let location: { href: string }

  beforeEach(() => {
    mockBuildWalletOpenLink.mockReset()
    locationDescriptor = Object.getOwnPropertyDescriptor(window, 'location')!
    location = { href: '' }
    Object.defineProperty(window, 'location', { configurable: true, value: location })
  })

  afterEach(() => {
    Object.defineProperty(window, 'location', locationDescriptor)
  })

  function pendingLink() {
    let resolve!: (value: { open_uri: string }) => void
    let reject!: (reason: Error) => void
    const promise = new Promise<{ open_uri: string }>((yes, no) => { resolve = yes; reject = no })
    return { promise, resolve, reject }
  }

  const selectedOffer = {
    offerData,
    allowedWalletIds: ['wr-spruce-001'],
    showDefaultWalletTab: false,
    showDeepLink: true,
    active: true,
    requestScopeKey: 'application-1',
  }

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
  })

  it.each(['closed', 'unmounted'])('ignores an awaited wallet URI after the real invite view is %s', async (endState) => {
    const pending = pendingLink()
    mockBuildWalletOpenLink.mockReturnValue(pending.promise)
    const view = renderWithoutRouter(<OID4VCIInviteDisplay {...selectedOffer} />)
    await view.user.click(screen.getByRole('button', { name: 'Open in mobile wallet app' }))
    expect(screen.getByRole('button', { name: 'Open in mobile wallet app' })).toBeDisabled()
    if (endState === 'unmounted') view.unmount()
    else view.rerender(<OID4VCIInviteDisplay {...selectedOffer} active={false} />)
    await act(async () => pending.resolve({ open_uri: 'sprucekit://stale-offer' }))
    expect(location.href).toBe('')
  })

  it.each(['application', 'wallet', 'offer'])('invalidates old navigation when the %s context changes and permits the current open', async (change) => {
    const pending = pendingLink()
    mockBuildWalletOpenLink.mockReturnValueOnce(pending.promise).mockResolvedValueOnce({ open_uri: 'sprucekit://current-offer' })
    const view = renderWithoutRouter(<OID4VCIInviteDisplay {...selectedOffer} />)
    await view.user.click(screen.getByRole('button', { name: 'Open in mobile wallet app' }))
    const updated = { ...selectedOffer,
      ...(change === 'application' ? { requestScopeKey: 'application-2' } : {}),
      ...(change === 'wallet' ? { allowedWalletIds: ['wr-marty-001'] } : {}),
      ...(change === 'offer' ? { offerData: { ...offerData,
        credential_offer_uris: { ...offerData.credential_offer_uris, 'wr-spruce-001': 'openid-credential-offer://fresh-spruce' } } } : {}),
    }
    view.rerender(<OID4VCIInviteDisplay {...updated} />)
    expect(screen.getByRole('button', { name: 'Open in mobile wallet app' })).toBeEnabled()
    await view.user.click(screen.getByRole('button', { name: 'Open in mobile wallet app' }))
    await waitFor(() => expect(location.href).toBe('sprucekit://current-offer'))
    expect(mockBuildWalletOpenLink).toHaveBeenCalledTimes(2)
    if (change === 'wallet') expect(mockBuildWalletOpenLink).toHaveBeenLastCalledWith('wr-marty-001', expect.any(Object))
    if (change === 'offer') expect(mockBuildWalletOpenLink).toHaveBeenLastCalledWith('wr-spruce-001', expect.objectContaining({ innerUri: 'openid-credential-offer://fresh-spruce' }))
    await act(async () => pending.resolve({ open_uri: 'sprucekit://stale-offer' }))
    expect(location.href).toBe('sprucekit://current-offer')
  })

  it('coalesces two same-turn open clicks before disabled state renders', async () => {
    const pending = pendingLink()
    mockBuildWalletOpenLink.mockReturnValue(pending.promise)
    renderWithoutRouter(<OID4VCIInviteDisplay {...selectedOffer} />)
    const button = screen.getByRole('button', { name: 'Open in mobile wallet app' })
    act(() => { button.click(); button.click() })
    expect(mockBuildWalletOpenLink).toHaveBeenCalledTimes(1)
    expect(button).toBeDisabled()
    await act(async () => pending.resolve({ open_uri: 'sprucekit://current-offer' }))
    expect(location.href).toBe('sprucekit://current-offer')
    expect(button).toBeEnabled()
  })

  it('invalidates a pending handoff when the user chooses another wallet tab', async () => {
    const pending = pendingLink()
    mockBuildWalletOpenLink.mockReturnValueOnce(pending.promise).mockResolvedValueOnce({ open_uri: 'marty://current-offer' })
    const view = renderWithoutRouter(
      <OID4VCIInviteDisplay {...selectedOffer} allowedWalletIds={['wr-spruce-001', 'wr-marty-001']} />,
    )
    await view.user.click(screen.getByRole('button', { name: 'Open in mobile wallet app' }))
    await view.user.click(screen.getByRole('tab', { name: 'Marty Authenticator' }))
    expect(screen.getByRole('button', { name: 'Open in mobile wallet app' })).toBeEnabled()
    await view.user.click(screen.getByRole('button', { name: 'Open in mobile wallet app' }))
    await waitFor(() => expect(location.href).toBe('marty://current-offer'))
    expect(mockBuildWalletOpenLink).toHaveBeenLastCalledWith('wr-marty-001', expect.any(Object))
    await act(async () => pending.resolve({ open_uri: 'sprucekit://stale-offer' }))
    expect(location.href).toBe('marty://current-offer')
  })

  it('does not use an old fallback when the registry rejects after closing', async () => {
    const pending = pendingLink()
    mockBuildWalletOpenLink.mockReturnValue(pending.promise)
    const view = renderWithoutRouter(<OID4VCIInviteDisplay {...selectedOffer} />)
    await view.user.click(screen.getByRole('button', { name: 'Open in mobile wallet app' }))
    view.rerender(<OID4VCIInviteDisplay {...selectedOffer} active={false} />)
    await act(async () => pending.reject(new Error('Registry unavailable')))
    expect(location.href).toBe('')
  })

  it('keeps the direct generic-wallet handoff and loading-to-ready transition working', async () => {
    const view = renderWithoutRouter(<OID4VCIInviteDisplay loading offerData={undefined} showDeepLink />)
    view.rerender(<OID4VCIInviteDisplay offerData={{ offer_url: 'https://issuer.example/offers/generic' }} showDeepLink />)
    await view.user.click(screen.getByRole('button', { name: 'Open in mobile wallet app' }))
    expect(mockBuildWalletOpenLink).not.toHaveBeenCalled()
    expect(location.href).toBe('openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fgeneric')
  })
})
