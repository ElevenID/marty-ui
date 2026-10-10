/**
 * Pure helpers for wallet setup flows.
 */

const DEFAULT_EXPIRY_SECONDS = 300;
const DEFAULT_POLL_INTERVAL_MS = 3000;

export function buildPairingState({ pairingCode, pairingId, apiOrigin, expiresAt, now = Date.now() }) {
  const expiresIn = Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 1000));
  if (!/^[A-Za-z0-9_-]{43}$/.test(pairingCode || '') ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(pairingId || '') ||
      !Number.isFinite(expiresIn) || expiresIn <= 0 ||
      !apiOrigin.startsWith('https://') || new URL(apiOrigin).origin !== apiOrigin) {
    throw new Error('Invalid server-issued wallet pairing ticket');
  }
  const query = new URLSearchParams({ code: pairingCode, api: apiOrigin });
  return {
    pairingCode,
    pairingId,
    qrContent: `marty://pair?${query}`,
    expiresIn,
  };
}

export function shouldTickPairingCountdown({ expiresIn, pairingCode }) {
  return Boolean(expiresIn > 0 && pairingCode);
}

export function shouldPollWalletStatus({ activeStep, walletConnected }) {
  return activeStep === 0 && !walletConnected;
}

export function resolveNotificationPermissionState(permission) {
  return {
    notificationPermission: permission,
    notificationsEnabled: permission === 'granted',
  };
}

export function getWalletDeviceStorageKey(organizationId) {
  const prefix = organizationId ? `${organizationId}:` : '';
  return `wallet_device_id:${prefix || 'default'}`;
}

/**
 * @param {{ organizationId?: string | null, now?: number, random?: () => number }} [params]
 * @returns {string}
 */
export function generateWalletDeviceId({ organizationId, now = Date.now(), random = Math.random } = {}) {
  const prefix = organizationId ? `${organizationId}:` : '';
  return `${prefix}web-${now}-${random().toString(36).slice(2, 8)}`;
}

export function buildPushRegistrationPayload({ userId, deviceId, tokenFactory = () => `fcm_token_${Date.now()}` }) {
  if (!userId) {
    throw new Error('Missing user context');
  }

  return {
    headers: {
      'Content-Type': 'application/json',
      'X-User-ID': userId,
    },
    body: {
      device_id: deviceId,
      fcm_token: tokenFactory(),
      platform: 'web',
      app_version: 'web-1.0.0',
    },
  };
}

export function resolveNotificationRequestOutcome(permission) {
  if (permission === 'granted') {
    return {
      successMessage: 'Notifications enabled successfully!',
      errorMessage: null,
      nextStep: 2,
      notificationsEnabled: true,
    };
  }

  if (permission === 'denied') {
    return {
      successMessage: null,
      errorMessage: 'Notification permission denied. Please enable in browser settings.',
      nextStep: null,
      notificationsEnabled: false,
    };
  }

  return {
    successMessage: null,
    errorMessage: null,
    nextStep: null,
    notificationsEnabled: false,
  };
}

export function resolveSkipNotifications() {
  return {
    nextStep: 2,
    successMessage: 'Wallet setup complete! (Notifications skipped)',
  };
}

export function resolveWalletSetupComplete() {
  return {
    successMessage: 'Wallet setup complete! You can now receive credentials and notifications.',
  };
}

export function formatCountdown(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}:${secs.toString().padStart(2, '0')}`;
}

export const walletSetupDefaults = {
  expirySeconds: DEFAULT_EXPIRY_SECONDS,
  pollIntervalMs: DEFAULT_POLL_INTERVAL_MS,
};
