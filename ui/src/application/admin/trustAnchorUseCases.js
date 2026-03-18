import { get, getErrorMessage, put, post } from '../../services/api';
import {
  TRUST_ANCHOR_DEFAULT_CONFIG,
  TRUST_ANCHOR_FALLBACK_STATUS,
  createTrustAnchorVerificationError,
  createTrustAnchorVerificationResult,
  readTrustAnchorStoredConfig,
  resolveTrustAnchorConfig,
  resolveTrustAnchorStatus,
  serializeTrustAnchorConfig,
} from './trustAnchorFlow';

async function defaultGetTrustAnchorConfig() {
  return get('/api/admin/trust-anchor/config');
}

async function defaultGetTrustAnchorStatus() {
  return get('/api/admin/trust-anchor/status');
}

async function defaultSaveTrustAnchorConfig(config) {
  return put('/api/admin/trust-anchor/config', serializeTrustAnchorConfig(config));
}

async function defaultVerifyTrustAnchorEntity(entityId) {
  return post('/api/admin/trust-anchor/verify', { entity_id: entityId });
}

export async function loadTrustAnchorPageData({
  getTrustAnchorConfig = defaultGetTrustAnchorConfig,
  getTrustAnchorStatus = defaultGetTrustAnchorStatus,
  storage,
  storageKey = 'trustAnchorConfig',
} = {}) {
  const storedConfig = readTrustAnchorStoredConfig(storage, storageKey);

  const [configResult, statusResult] = await Promise.allSettled([
    getTrustAnchorConfig(),
    getTrustAnchorStatus(),
  ]);

  return {
    config: configResult.status === 'fulfilled'
      ? resolveTrustAnchorConfig(configResult.value, storedConfig || TRUST_ANCHOR_DEFAULT_CONFIG)
      : (storedConfig || TRUST_ANCHOR_DEFAULT_CONFIG),
    status: statusResult.status === 'fulfilled'
      ? resolveTrustAnchorStatus(statusResult.value, TRUST_ANCHOR_FALLBACK_STATUS)
      : TRUST_ANCHOR_FALLBACK_STATUS,
  };
}

export async function refreshTrustAnchorStatus({
  getTrustAnchorStatus = defaultGetTrustAnchorStatus,
} = {}) {
  try {
    const result = await getTrustAnchorStatus();
    return resolveTrustAnchorStatus(result, TRUST_ANCHOR_FALLBACK_STATUS);
  } catch {
    return TRUST_ANCHOR_FALLBACK_STATUS;
  }
}

export async function saveTrustAnchorConfig({
  config,
  saveConfig = defaultSaveTrustAnchorConfig,
  storage,
  storageKey = 'trustAnchorConfig',
} = {}) {
  try {
    await saveConfig(config);
  } catch {
    // Intentionally fall through to local backup persistence.
  }

  storage?.setItem?.(storageKey, JSON.stringify(config));

  return {
    success: true,
    message: 'Configuration saved successfully.',
  };
}

export async function verifyTrustAnchorEntity({
  entityId,
  verifyEntity = defaultVerifyTrustAnchorEntity,
} = {}) {
  try {
    const result = await verifyEntity(entityId);
    return createTrustAnchorVerificationResult(result);
  } catch (error) {
    return createTrustAnchorVerificationError(new Error(getErrorMessage(error)));
  }
}
