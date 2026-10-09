import { get, getErrorMessage, post } from '../../services/api';
import {
  buildPushRegistrationPayload,
  generateWalletDeviceId,
  getWalletDeviceStorageKey,
} from './walletSetupFlow';

const DEFAULT_API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

export async function issueRemotePairingTicket({ organizationId, trustProfileId }) {
  if (!organizationId) throw new Error('Select an organization before pairing');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trustProfileId || '')) {
    throw new Error('Select a Trust Profile before pairing');
  }
  return post('/v1/devices/pairing-tickets', { organization_id: organizationId, trust_profile_id: trustProfileId });
}

export async function loadRemotePairingStatus({ pairingId }) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(pairingId || '')) {
    throw new Error('Invalid wallet pairing identifier');
  }
  return get(`/v1/devices/pairing-confirmations/${pairingId}`);
}

async function defaultRegisterDevice({ request, apiBaseUrl = DEFAULT_API_BASE_URL }) {
  return post(`${apiBaseUrl}/devices/register`, request.body, {
    headers: request.headers,
  });
}

export function getOrCreateWalletDeviceId({
  organizationId,
  storage,
  now,
  random,
} = {}) {
  const storageKey = getWalletDeviceStorageKey(organizationId);
  const existing = storage.getItem(storageKey);

  if (existing) {
    return existing;
  }

  const generated = generateWalletDeviceId({ organizationId, now, random });
  storage.setItem(storageKey, generated);
  return generated;
}

export async function registerWalletPushNotifications({
  userId,
  organizationId,
  storage,
  registerDevice = defaultRegisterDevice,
  tokenFactory,
} = {}) {
  try {
    const deviceId = getOrCreateWalletDeviceId({
      organizationId,
      storage,
    });
    const request = buildPushRegistrationPayload({
      userId,
      deviceId,
      tokenFactory,
    });
    const data = await registerDevice({ userId, request });

    return {
      deviceId: data.device_id || deviceId,
      error: null,
    };
  } catch (error) {
    return {
      deviceId: null,
      error: getErrorMessage(error) || 'Failed to register for notifications',
    };
  }
}
