/**
 * Pure helpers for the trust anchor admin experience.
 */

export const TRUST_ANCHOR_DEFAULT_CONFIG = {
  anchorName: 'Marty Trust Anchor',
  domain: 'trust.marty.local',
  policy: 'strict',
  logLevel: 'info',
};

export const TRUST_ANCHOR_FALLBACK_STATUS = {
  rootCA: { status: 'valid', expires: '2035' },
  intermediateCA: { status: 'valid', expires: '2030' },
  crlStatus: 'up_to_date',
  healthy: true,
};

export function resolveTrustAnchorConfig(data, fallback = TRUST_ANCHOR_DEFAULT_CONFIG) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  return {
    ...fallback,
    anchorName: data.anchor_name || data.anchorName || fallback.anchorName,
    domain: data.domain || fallback.domain,
    policy: data.policy || fallback.policy,
    logLevel: data.log_level || data.logLevel || fallback.logLevel,
  };
}

export function serializeTrustAnchorConfig(config = TRUST_ANCHOR_DEFAULT_CONFIG) {
  return {
    anchor_name: config.anchorName,
    domain: config.domain,
    policy: config.policy,
    log_level: config.logLevel,
  };
}

export function resolveTrustAnchorStatus(data, fallback = TRUST_ANCHOR_FALLBACK_STATUS) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  return {
    ...fallback,
    ...data,
    rootCA: {
      ...fallback.rootCA,
      ...(data.rootCA || {}),
    },
    intermediateCA: {
      ...fallback.intermediateCA,
      ...(data.intermediateCA || {}),
    },
  };
}

export function readTrustAnchorStoredConfig(storage, storageKey = 'trustAnchorConfig') {
  if (!storage?.getItem) {
    return null;
  }

  const raw = storage.getItem(storageKey);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw);
    return resolveTrustAnchorConfig(parsed, TRUST_ANCHOR_DEFAULT_CONFIG);
  } catch {
    return null;
  }
}

export function createTrustAnchorVerificationResult(data) {
  const isTrusted = Boolean(data?.is_trusted);

  return {
    success: true,
    isTrusted,
    message: isTrusted ? 'Entity is trusted.' : 'Entity is NOT trusted.',
  };
}

export function createTrustAnchorVerificationError(error) {
  return {
    success: false,
    message: error?.message || 'Verification failed',
  };
}
