import { get, getErrorMessage, post } from '../../services/api';
import {
  buildPushRegistrationPayload,
  generateWalletDeviceId,
  getWalletDeviceStorageKey,
  resolveWalletStatusResponse,
} from './walletSetupFlow';

const DEFAULT_API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

async function defaultLoadDevices({ userId, apiBaseUrl = DEFAULT_API_BASE_URL }) {
  return get(`${apiBaseUrl}/devices`, {
    headers: { 'X-User-ID': userId },
  });
}

async function defaultRegisterDevice({ userId, request, apiBaseUrl = DEFAULT_API_BASE_URL }) {
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

export async function loadWalletStatus({
  userId,
  activeStep,
  loadDevices = defaultLoadDevices,
} = {}) {
  if (!userId) {
    return {
      ...resolveWalletStatusResponse({ activeStep, devices: [] }),
      error: null,
    };
  }

  try {
    const data = await loadDevices({ userId });
    return {
      ...resolveWalletStatusResponse({
        activeStep,
        devices: data.devices,
      }),
      error: null,
    };
  } catch (error) {
    return {
      ...resolveWalletStatusResponse({ activeStep, devices: [] }),
      error: getErrorMessage(error) || 'Failed to load wallet status',
    };
  }
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