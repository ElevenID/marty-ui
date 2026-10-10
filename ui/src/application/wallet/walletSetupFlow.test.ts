import { describe, expect, it } from 'vitest'
import {
  buildPairingState,
  buildPushRegistrationPayload,
  formatCountdown,
  generateWalletDeviceId,
  getWalletDeviceStorageKey,
  resolveNotificationPermissionState,
  resolveNotificationRequestOutcome,
  resolveSkipNotifications,
  resolveWalletSetupComplete,
  shouldPollWalletStatus,
  shouldTickPairingCountdown,
  walletSetupDefaults,
} from './walletSetupFlow'

describe('walletSetupFlow helpers', () => {
  it('builds a wallet QR only from an unexpired server ticket and HTTPS origin', () => {
    const pairingCode = 'A'.repeat(43)
    const pairingId = '11111111-2222-4333-8444-555555555555'
    const state = buildPairingState({ pairingCode, pairingId, apiOrigin: 'https://wallet.example', expiresAt: new Date(300000).toISOString(), now: 0 })
    expect(state.pairingCode).toBe(pairingCode)
    expect(state.pairingId).toBe(pairingId)
    expect(state.qrContent).toBe(`marty://pair?code=${pairingCode}&api=https%3A%2F%2Fwallet.example`)
    expect(state.expiresIn).toBe(walletSetupDefaults.expirySeconds)
    expect(() => buildPairingState({ pairingCode: 'SHORT', pairingId, apiOrigin: 'https://wallet.example', expiresAt: new Date(300000).toISOString(), now: 0 })).toThrow()
    expect(() => buildPairingState({ pairingCode, pairingId, apiOrigin: 'http://wallet.example', expiresAt: new Date(300000).toISOString(), now: 0 })).toThrow()
  })

  it('decides when countdown and polling should run', () => {
    expect(shouldTickPairingCountdown({ expiresIn: 10, pairingCode: 'ABC' })).toBe(true)
    expect(shouldTickPairingCountdown({ expiresIn: 0, pairingCode: 'ABC' })).toBe(false)
    expect(shouldPollWalletStatus({ activeStep: 0, walletConnected: false })).toBe(true)
    expect(shouldPollWalletStatus({ activeStep: 1, walletConnected: false })).toBe(false)
  })

  it('maps notification permission into state and outcomes', () => {
    expect(resolveNotificationPermissionState('granted')).toEqual({
      notificationPermission: 'granted',
      notificationsEnabled: true,
    })
    expect(resolveNotificationRequestOutcome('denied')).toEqual({
      successMessage: null,
      errorMessage: 'Notification permission denied. Please enable in browser settings.',
      nextStep: null,
      notificationsEnabled: false,
    })
  })

  it('creates stable device keys and generated ids', () => {
    expect(getWalletDeviceStorageKey('org-1')).toBe('wallet_device_id:org-1:')
    expect(generateWalletDeviceId({ organizationId: 'org-1', now: 123, random: () => 0.123456 })).toBe('org-1:web-123-4fzyo8')
  })

  it('builds push registration payloads', () => {
    expect(buildPushRegistrationPayload({ userId: 'user-1', deviceId: 'device-1', tokenFactory: () => 'token-1' })).toEqual({
      headers: {
        'Content-Type': 'application/json',
        'X-User-ID': 'user-1',
      },
      body: {
        device_id: 'device-1',
        fcm_token: 'token-1',
        platform: 'web',
        app_version: 'web-1.0.0',
      },
    })
  })

  it('resolves skip and completion outcomes', () => {
    expect(resolveSkipNotifications()).toEqual({
      nextStep: 2,
      successMessage: 'Wallet setup complete! (Notifications skipped)',
    })
    expect(resolveWalletSetupComplete()).toEqual({
      successMessage: 'Wallet setup complete! You can now receive credentials and notifications.',
    })
  })

  it('formats countdown text', () => {
    expect(formatCountdown(125)).toBe('2:05')
  })
})
