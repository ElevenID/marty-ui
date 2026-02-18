/**
 * Authentication Context
 *
 * Provides authentication state and methods to the React component tree.
 * Handles user session, capability detection, organization membership, and auth status.
 */

import { createContext, useState, useEffect, useCallback, useMemo } from 'react';
import { getCurrentUser, initiateLogin, initiateRegister, initiateLogout } from '../services/authApi';
import { getMyOrganizations } from '../services/organizationsApi';
import i18n from '../i18n';

/**
 * @typedef {Object} User
 * @property {string} user_id - Unique user identifier (OIDC sub)
 * @property {string} email - User email
 * @property {string|null} username - Username
 * @property {string|null} given_name - First name
 * @property {string|null} family_name - Last name
 * @property {string|null} applicant_id - Linked ApplicantRecord ID (if available)
 * @property {string[]} roles - User roles (from Keycloak realm_access.roles)
 * @property {string|null} organization_id - Keycloak Organization ID (for vendors/org members)
 * @property {string|null} organization_name - Organization display name
 * @property {Object|null} organization - Raw organization claim from Keycloak
 * @property {Array<{id: string, name: string|null}>} organizations - Organization memberships
 * @property {Object<string, boolean>} capabilities - Normalized capability map
 */

/**
 * @typedef {Object} AuthContextValue
 * @property {User|null} user - Current authenticated user
 * @property {boolean} isAuthenticated - Whether user is authenticated
 * @property {boolean} isLoading - Whether auth state is loading
 * @property {boolean} isAdministrator - Whether user is a super-administrator
 * @property {boolean} isVendor - Whether user has organization console capabilities
 * @property {boolean} isApplicant - Always true for authenticated users
 * @property {string|null} organizationId - Current organization ID
 * @property {string|null} organizationName - Current organization name
 * @property {Array<{id: string, name: string|null}>} organizations - Organization memberships
 * @property {Object<string, boolean>} capabilities - Current user capabilities
 * @property {function} hasCapability - Capability check helper
 * @property {function} setActiveOrganizationId - Select active organization
 * @property {function} login - Initiate login flow
 * @property {function} register - Initiate registration flow
 * @property {function} logout - Initiate logout flow
 * @property {function} refreshUser - Refresh user info from server
 */

const defaultContextValue = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  isAdministrator: false,
  isVendor: false,
  isApplicant: false,
  organizationId: null,
  organizationName: null,
  organizations: [],
  capabilities: {},
  hasCapability: () => false,
  login: () => {},
  register: () => {},
  logout: () => {},
  refreshUser: async () => {},
  setActiveOrganizationId: () => {},
};

const AuthContext = createContext(defaultContextValue);

/**
 * Parse organization claim from Keycloak token.
 * Keycloak Organizations feature returns: { "org-id": { "name": "Org Name", ... } }
 * @param {Object|null} orgClaim - Raw organization claim from token
 * @returns {{ id: string|null, name: string|null }}
 */
function parseOrganizationClaim(orgClaim) {
  if (!orgClaim || typeof orgClaim !== 'object') {
    return { id: null, name: null, organizations: [] };
  }
  
  // Keycloak returns organization as { "org-id": { "name": "...", ... } }
  const orgIds = Object.keys(orgClaim);
  if (orgIds.length === 0) {
    return { id: null, name: null, organizations: [] };
  }
  
  const organizations = orgIds.map((orgId) => {
    const orgData = orgClaim[orgId];
    return {
      id: orgId,
      name: orgData?.name || null,
    };
  });

  // Use the first organization as default
  const primary = organizations[0];

  return {
    id: primary?.id || null,
    name: primary?.name || null,
    organizations,
  };
}

function normalizeCapabilities(rawCapabilities) {
  if (!rawCapabilities) return {};

  if (Array.isArray(rawCapabilities)) {
    return rawCapabilities.reduce((acc, capability) => {
      if (typeof capability === 'string' && capability.trim()) {
        acc[capability] = true;
      }
      return acc;
    }, {});
  }

  if (typeof rawCapabilities === 'object') {
    return Object.entries(rawCapabilities).reduce((acc, [capability, enabled]) => {
      acc[capability] = Boolean(enabled);
      return acc;
    }, {});
  }

  return {};
}

function deriveCapabilities(rawUser, organizations) {
  const roles = rawUser?.roles || [];
  const fromApi = normalizeCapabilities(rawUser?.capabilities);
  const hasOrganizations = organizations.length > 0;

  const inferred = {
    apply: true,
    'org:view': hasOrganizations || roles.includes('vendor') || roles.includes('administrator'),
    'org:manage': roles.includes('vendor') || roles.includes('administrator'),
    'org:issue': roles.includes('vendor') || roles.includes('administrator'),
    'admin:platform': roles.includes('administrator'),
  };

  return {
    ...inferred,
    ...fromApi,
  };
}

/**
 * Authentication Provider Component
 *
 * Wraps the application and provides authentication context.
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch current user on mount
  const fetchUser = useCallback(async () => {
    try {
      setIsLoading(true);
      const result = await getCurrentUser();

      if (result.authenticated && result.user) {
        // Enrich user object with parsed organization data
        const rawUser = result.user;
        const org = parseOrganizationClaim(rawUser.organization);
        
        // Fetch full list of organizations from new endpoint
        let userOrganizations = [];
        try {
          userOrganizations = await getMyOrganizations();
        } catch (orgError) {
          console.error('Error fetching user organizations:', orgError);
          // Fallback to organization claim parsing
          userOrganizations = org.organizations.length
            ? org.organizations
            : rawUser.organization_id
              ? [{ id: rawUser.organization_id, name: rawUser.organization_name || null }]
              : [];
        }
        
        // If no organizations from endpoint, use fallback
        if (userOrganizations.length === 0) {
          userOrganizations = org.organizations.length
            ? org.organizations
            : rawUser.organization_id
              ? [{ id: rawUser.organization_id, name: rawUser.organization_name || null }]
              : [];
        }
        
        // Determine active organization (priority: localStorage > first in list > claim)
        const storedOrgId = window.localStorage.getItem('activeOrgId');
        const activeOrg =
          userOrganizations.find((entry) => entry.id === storedOrgId) ||
          userOrganizations[0] ||
          (rawUser.organization_id ? { id: rawUser.organization_id, name: rawUser.organization_name || null } : null);

        const capabilities = deriveCapabilities(rawUser, userOrganizations);

        const enrichedUser = {
          ...rawUser,
          organization_id: activeOrg?.id || null,
          organization_name: activeOrg?.name || null,
          organizations: userOrganizations,
          capabilities,
        };

        setUser(enrichedUser);
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error('Error fetching user:', error);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  // Login handler - accepts optional redirect URI string
  // Note: When used as onClick handler, first arg is Event object - we ignore non-string args
  const login = useCallback((redirectUri) => {
    const redirect = typeof redirectUri === 'string' ? redirectUri : window.location.pathname;
    const currentLanguage = i18n.language;
    initiateLogin(redirect, currentLanguage);
  }, []);

  // Register handler - accepts optional redirect URI string
  // Note: When used as onClick handler, first arg is Event object - we ignore non-string args
  const register = useCallback((redirectUri) => {
    const redirect = typeof redirectUri === 'string' ? redirectUri : window.location.pathname;
    const currentLanguage = i18n.language;
    initiateRegister(redirect, currentLanguage);
  }, []);

  // Logout handler
  const logout = useCallback(() => {
    initiateLogout();
    setUser(null);
  }, []);

  // Refresh user info
  const refreshUser = useCallback(async () => {
    await fetchUser();
  }, [fetchUser]);

  // Computed values - derive role booleans and organization info
  const setActiveOrganizationId = useCallback(
    (orgId) => {
      setUser((prev) => {
        if (!prev) return prev;
        const memberships = prev.organizations || [];
        const selected = memberships.find((entry) => entry.id === orgId);

        // Keep auth state aligned with ConsoleContext even when memberships are
        // stale in AuthContext (e.g., org created in current session).
        const resolvedOrganization = selected || (orgId ? { id: orgId, name: null } : null);

        if (!resolvedOrganization && orgId) {
          return prev;
        }

        window.localStorage.setItem('activeOrgId', orgId);

        const nextMemberships = selected
          ? memberships
          : orgId
            ? [...memberships, resolvedOrganization]
            : memberships;

        const nextCapabilities = {
          ...(prev.capabilities || {}),
          ...(orgId ? { 'org:view': true } : {}),
        };

        return {
          ...prev,
          organization_id: resolvedOrganization?.id || null,
          organization_name: resolvedOrganization?.name || prev.organization_name,
          organizations: nextMemberships,
          capabilities: nextCapabilities,
        };
      });
    },
    [setUser]
  );

  const contextValue = useMemo(() => {
    const roles = user?.roles || [];
    const capabilities = user?.capabilities || {};
    const hasCapability = (capability) => Boolean(capabilities[capability]);
    
    return {
      user,
      isAuthenticated: !!user,
      isLoading,
      // Capability-first checks
      isAdministrator: hasCapability('admin:platform') || roles.includes('administrator'),
      isVendor: hasCapability('org:view') || hasCapability('org:manage') || roles.includes('vendor'),
      isApplicant: !!user,
      // Organization info
      organizationId: user?.organization_id || null,
      organizationName: user?.organization_name || null,
      organizations: user?.organizations || [],
      capabilities,
      hasCapability,
      // Actions
      login,
      register,
      logout,
      refreshUser,
      setActiveOrganizationId,
    };
  }, [user, isLoading, login, register, logout, refreshUser, setActiveOrganizationId]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export { AuthContext };


