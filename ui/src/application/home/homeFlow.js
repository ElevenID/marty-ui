/**
 * Pure helpers for the admin home dashboard.
 */

export const HOME_DEFAULT_SYSTEM_STATUS = {
  healthy: true,
  services: {
    issuer: 'online',
    verifier: 'online',
    wallet: 'online',
  },
};

export const HOME_DEFAULT_STATS = {
  credentials: 0,
  verifications: 0,
  masterLists: 3,
  certificates: 11,
};

export function resolveHomeSystemStatus(data, fallback = HOME_DEFAULT_SYSTEM_STATUS) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  return {
    healthy: data.status === 'healthy',
    services: data.services || fallback.services,
  };
}

export function resolveHomeStats(data, fallback = HOME_DEFAULT_STATS) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  return {
    ...fallback,
    ...data,
  };
}