import { describe, expect, it } from 'vitest'
import {
  buildPairingState,
  buildPushRegistrationPayload,
  createPairingCode,
  formatCountdown,
  generateWalletDeviceId,
  getWalletDeviceStorageKey,
  resolveNotificationPermissionState,
  resolveNotificationRequestOutcome,
  resolveSimulatedPairing,
  resolveSkipNotifications,
  resolveWalletSetupComplete,
  resolveWalletStatusResponse,
  shouldPollWalletStatus,
  shouldTickPairingCountdown,
  walletSetupDefaults,
} from './walletSetupFlow'

describe('walletSetupFlow helpers', () => {
  it('creates pairing codes and QR state', () => {
    const code = createPairingCode({ random: () => 0.123456789 })
    expect(code).toHaveLength(8)
    expect(buildPairingState({ deepLinkProtocol: 'marty', pairingCode: 'ABC12345' })).toEqual({
      pairingCode: 'ABC12345',
      qrContent: 'marty//pair?code=ABC12345',
      expiresIn: walletSetupDefaults.expirySeconds,
    })
  })

  it('decides when countdown and polling should run', () => {
    expect(shouldTickPairingCountdown({ expiresIn: 10, pairingCode: 'ABC' })).toBe(true)
    expect(shouldTickPairingCountdown({ expiresIn: 0, pairingCode: 'ABC' })).toBe(false)
    expect(shouldPollWalletStatus({ activeStep: 0, walletConnected: false })).toBe(true)
    expect(shouldPollWalletStatus({ activeStep: 1, walletConnected: false })).toBe(false)
  })

  it('resolves wallet status responses', () => {
    expect(resolveWalletStatusResponse({ activeStep: 0, devices: [{ device_id: 'device-1' }] })).toEqual({
      walletConnected: true,
      walletDeviceId: 'device-1',
      nextStep: 1,
      successMessage: 'Wallet paired successfully!',
    })
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

  it('resolves skip, simulate, and completion outcomes', () => {
    expect(resolveSkipNotifications()).toEqual({
      nextStep: 2,
      successMessage: 'Wallet setup complete! (Notifications skipped)',
    })
    expect(resolveSimulatedPairing()).toEqual({
      walletConnected: true,
      nextStep: 1,
      successMessage: 'Wallet paired successfully!',
    })
    expect(resolveWalletSetupComplete()).toEqual({
      successMessage: 'Wallet setup complete! You can now receive credentials and notifications.',
    })
  })

  it('formats countdown text', () => {
    expect(formatCountdown(125)).toBe('2:05')
  })
})
