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
import {
  createEnrichedUser,
  getAuthFlags,
  resolveInteractiveLoginRedirect,
  updateUserActiveOrganization,
} from '../application/session/authSession';

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
 * @property {Object|null} impersonation - Active admin impersonation context when present
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
  impersonation: null,
  isImpersonating: false,
  hasCapability: () => false,
  login: () => {},
  register: () => {},
  logout: () => {},
  refreshUser: async () => {},
  setActiveOrganizationId: () => {},
};

const AuthContext = createContext(defaultContextValue);

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
        const rawUser = result.user;
        let userOrganizations = [];

        try {
          userOrganizations = await getMyOrganizations();
        } catch (orgError) {
          console.error('Error fetching user organizations:', orgError);
        }

        const storedOrgId = window.localStorage.getItem('activeOrgId');
        const enrichedUser = createEnrichedUser(rawUser, userOrganizations, storedOrgId);

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
    const redirect = resolveInteractiveLoginRedirect(redirectUri);
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
  // Note: do NOT call setUser(null) here. The form POST in initiateLogout() triggers a
  // full page navigation. Calling setUser(null) first causes React Router's ProtectedRoute
  // to redirect to /login before the form navigation completes, cancelling the SSO logout.
  const logout = useCallback(() => {
    initiateLogout();
  }, []);

  // Refresh user info
  const refreshUser = useCallback(async () => {
    await fetchUser();
  }, [fetchUser]);

  // Computed values - derive role booleans and organization info
  const setActiveOrganizationId = useCallback(
    (orgId) => {
      setUser((prev) => {
        const normalizedOrgId = orgId || null;

        if (normalizedOrgId) {
          window.localStorage.setItem('activeOrgId', normalizedOrgId);
        } else {
          window.localStorage.removeItem('activeOrgId');
        }

        return updateUserActiveOrganization(prev, normalizedOrgId);
      });
    },
    [setUser]
  );

  const contextValue = useMemo(() => {
    const { isAdministrator, isVendor, isApplicant, capabilities } = getAuthFlags(user);
    const hasCapability = (capability) => Boolean(capabilities[capability]);
    
    return {
      user,
      isAuthenticated: !!user,
      isLoading,
      isAdministrator,
      isVendor,
      isApplicant,
      // Organization info
      organizationId: user?.organization_id || null,
      organizationName: user?.organization_name || null,
      organizations: user?.organizations || [],
      capabilities,
      impersonation: user?.impersonation || null,
      isImpersonating: Boolean(user?.impersonation?.active),
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


