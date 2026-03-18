/**
 * Pure helpers for the admin dashboard.
 */

export const ADMIN_DASHBOARD_DEFAULT_STATS = {
  passport: 0,
  mdl: 0,
  mdoc: 0,
  verifications: 0,
};

export const ADMIN_DASHBOARD_DEFAULT_HEALTH = {
  issuer_api: 'unknown',
  passport_engine: 'unknown',
  mdl_engine: 'unknown',
  mdoc_engine: 'unknown',
  inspection_system: 'unknown',
};

export function buildAdminDashboardFallbackVendor(nowIso = new Date().toISOString()) {
  return {
    id: 'vendor-001',
    username: 'vendor@marty.demo',
    email: 'vendor@marty.demo',
    organizationName: 'Demo Vendor Corp',
    organizationId: 'org-001',
    tier: 'PROFESSIONAL',
    enabled: true,
    createdAt: nowIso,
  };
}

export function resolveAdminDashboardStats(data, fallback = ADMIN_DASHBOARD_DEFAULT_STATS) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  return {
    ...fallback,
    ...data,
  };
}

export function resolveAdminDashboardHealth(data, fallback = ADMIN_DASHBOARD_DEFAULT_HEALTH) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  const status = data.status || 'unknown';
  return {
    issuer_api: status,
    passport_engine: status,
    mdl_engine: status,
    mdoc_engine: status,
    inspection_system: status,
  };
}

export function filterAdminVendors(vendors, vendorSearch) {
  const query = vendorSearch?.trim().toLowerCase();
  if (!query) {
    return vendors;
  }

  return vendors.filter((vendor) =>
    vendor.email?.toLowerCase().includes(query) ||
    vendor.organizationName?.toLowerCase().includes(query) ||
    vendor.username?.toLowerCase().includes(query)
  );
}

export function getAdminTierColor(tier) {
  const colors = {
    FREE: 'default',
    STARTER: 'info',
    PROFESSIONAL: 'primary',
    ENTERPRISE: 'secondary',
  };

  return colors[tier] || 'default';
}

export function resolveAdminImpersonationBase({
  keycloak,
  authServerUrl,
  realm,
  defaultAuthServerUrl = 'http://localhost:8080',
  defaultRealm = '11id',
} = {}) {
  return {
    authServerUrl:
      keycloak?.authServerUrl ||
      authServerUrl ||
      defaultAuthServerUrl,
    realm:
      keycloak?.realm ||
      realm ||
      defaultRealm,
  };
}

export function buildAdminImpersonationUrl({ vendorId, keycloak, authServerUrl, realm } = {}) {
  const base = resolveAdminImpersonationBase({ keycloak, authServerUrl, realm });
  return `${base.authServerUrl}/admin/realms/${base.realm}/users/${vendorId}/impersonation`;
}

export function resolveAdminImpersonationResult(result, vendor) {
  if (result?.redirect) {
    return {
      action: 'open-tab',
      redirectUrl: result.redirect,
      successMessage: `Now impersonating ${vendor.email}. Check the new tab.`,
    };
  }

  return {
    action: 'reload',
    redirectUrl: null,
    successMessage: `Impersonation session started for ${vendor.email}`,
  };
}