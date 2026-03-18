import { get, getErrorMessage } from '../../services/api';
import {
  ADMIN_DASHBOARD_DEFAULT_HEALTH,
  ADMIN_DASHBOARD_DEFAULT_STATS,
  buildAdminImpersonationUrl,
  buildAdminDashboardFallbackVendor,
  resolveAdminImpersonationResult,
  resolveAdminDashboardHealth,
  resolveAdminDashboardStats,
} from './adminDashboardFlow';

async function defaultGetAdminStats() {
  return get('/api/admin/stats');
}

async function defaultGetAdminHealth() {
  return get('/api/health');
}

async function defaultGetAdminVendors() {
  return get('/api/admin/vendors');
}

async function defaultPostAdminImpersonation({ url, token }) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (response.status === 403) {
    throw new Error('Impersonation not permitted. Check admin role and Keycloak settings.');
  }

  if (!response.ok) {
    throw new Error(`Impersonation failed: ${response.statusText}`);
  }

  return response.json();
}

export async function loadAdminDashboardBootstrap({
  getAdminStats = defaultGetAdminStats,
  getAdminHealth = defaultGetAdminHealth,
  getAdminVendors = defaultGetAdminVendors,
  nowIso = new Date().toISOString(),
} = {}) {
  const [statsResult, healthResult, vendorsResult] = await Promise.allSettled([
    getAdminStats(),
    getAdminHealth(),
    getAdminVendors(),
  ]);

  let vendorError = null;
  let vendors = [buildAdminDashboardFallbackVendor(nowIso)];

  if (vendorsResult.status === 'fulfilled') {
    vendors = Array.isArray(vendorsResult.value) ? vendorsResult.value : [];
  } else {
    vendorError = getErrorMessage(vendorsResult.reason) || 'Failed to load vendors';
  }

  return {
    stats: statsResult.status === 'fulfilled'
      ? resolveAdminDashboardStats(statsResult.value, ADMIN_DASHBOARD_DEFAULT_STATS)
      : ADMIN_DASHBOARD_DEFAULT_STATS,
    health: healthResult.status === 'fulfilled'
      ? resolveAdminDashboardHealth(healthResult.value, ADMIN_DASHBOARD_DEFAULT_HEALTH)
      : ADMIN_DASHBOARD_DEFAULT_HEALTH,
    vendors,
    vendorError,
  };
}

export async function impersonateAdminVendor({
  vendor,
  keycloak,
  authServerUrl,
  realm,
  postAdminImpersonation = defaultPostAdminImpersonation,
} = {}) {
  const url = buildAdminImpersonationUrl({
    vendorId: vendor?.id,
    keycloak,
    authServerUrl,
    realm,
  });

  const result = await postAdminImpersonation({
    url,
    token: keycloak?.token,
  });

  return resolveAdminImpersonationResult(result, vendor);
}