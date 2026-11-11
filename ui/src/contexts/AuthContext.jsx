/**
 * Authentication Context
 *
 * Provides authentication state and methods to the React component tree.
 * Handles user session, capability detection, organization membership, and auth status.
 */

import { createContext, useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { getCurrentUser, initiateLogin, initiateRegister, initiateLogout } from '../services/authApi';
import { getMyOrganizations } from '../services/organizationsApi';
import i18n from '../i18n';
import { getPublicEntryCanonicalOrigin } from '../application/routing/publicEntry';
import { exchangeAuthCallbackCode } from '../application/routing/authCallback';
import { LOGOUT_STARTED_EVENT } from '../services/authEvents';
import {
  createEnrichedUser,
  getAuthFlags,
  resolveInteractiveLoginRedirect,
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
 * @property {function} login - Initiate login flow
 * @property {function} register - Initiate registration flow
 * @property {function} logout - Initiate logout flow
 * @property {function} refreshUser - Refresh user info from server
 * @property {function} completeLoginCallback - Share the current callback exchange and session refresh across console remounts
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
  completeLoginCallback: async () => { throw new Error('Authentication provider is unavailable.'); },
};

const AuthContext = createContext(defaultContextValue);

function logAuthContextError(message, error) {
  if (import.meta.env?.DEV && import.meta.env?.MODE !== 'test') {
    console.error(message, error);
  }
}

function principalId(user) {
  return user?.user_id || user?.sub || user?.id;
}

// Compare confirmed server authority with the prior raw response, not with
// capabilities/organizations added by createEnrichedUser. Display-only changes
// such as a new photo must not restart the console, while changed grants must.
function authoritySnapshot(user) {
  return JSON.stringify({
    principal: principalId(user),
    roles: user.roles,
    capabilities: user.capabilities,
    userType: user.user_type,
    applicantId: user.applicant_id,
    organization: user.organization,
    organizations: user.organizations,
    organizationId: user.organization_id,
    defaultOrganizationId: user.default_organization_id,
    impersonation: user.impersonation,
  });
}

function obsoleteAuthRequest() {
  const error = new Error('The authentication request changed.');
  error.name = 'AbortError';
  return error;
}

/**
 * Authentication Provider Component
 *
 * Wraps the application and provides authentication context.
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(() => !getPublicEntryCanonicalOrigin());
  const authRequestGeneration = useRef(0);
  const callbackAttempt = useRef(null);
  const currentUser = useRef(null);
  const confirmedAuthority = useRef(null);
  const identityRefreshPending = useRef(isLoading);
  const mounted = useRef(true);
  const logoutStarted = useRef(false);

  // Fetch current user on mount
  const fetchUser = useCallback(async function loadUser({ background = false } = {}) {
    if (!mounted.current || logoutStarted.current) return undefined;
    const generation = ++authRequestGeneration.current;
    const applies = () => mounted.current && authRequestGeneration.current === generation;
    const previousUser = currentUser.current;
    let canRetainUser = background && Boolean(principalId(previousUser)) && !identityRefreshPending.current;
    const updateUser = (nextUser) => {
      currentUser.current = nextUser;
      if (!nextUser) confirmedAuthority.current = null;
      setUser(nextUser);
    };
    if (getPublicEntryCanonicalOrigin()) {
      updateUser(null);
      identityRefreshPending.current = false;
      setIsLoading(false);
      return null;
    }
    try {
      // Photo readback can keep the current account mounted. Initial checks,
      // explicit identity refreshes, and callback proof still invalidate grants.
      if (!canRetainUser) {
        identityRefreshPending.current = true;
        setIsLoading(true);
      }
      const result = await getCurrentUser();
      if (!applies()) return undefined;

      if (result.authenticated && result.user) {
        const rawUser = result.user;
        const nextAuthority = authoritySnapshot(rawUser);
        if (canRetainUser && nextAuthority !== confirmedAuthority.current) {
          // A background read can discover an account or authority change. Drop
          // the old console before awaiting the newly confirmed account's data.
          canRetainUser = false;
          identityRefreshPending.current = true;
          updateUser(null);
          setIsLoading(true);
        }
        let userOrganizations = [];

        try {
          userOrganizations = await getMyOrganizations();
        } catch (orgError) {
          if (applies()) logAuthContextError('Error fetching user organizations:', orgError);
        }
        if (!applies()) return undefined;

        const storedOrgId = window.localStorage.getItem('activeOrgId');
        const enrichedUser = createEnrichedUser(rawUser, userOrganizations, storedOrgId);
        if (canRetainUser) {
          if (JSON.stringify(enrichedUser.organizations) !== JSON.stringify(previousUser.organizations)) {
            // A changed membership can change permissions too. Restart through
            // strict identity loading so old grants are invalidated first. The
            // default request cannot recurse and supersedes this generation.
            return loadUser();
          }
          enrichedUser.organizations = previousUser.organizations;
        }

        confirmedAuthority.current = nextAuthority;
        updateUser(enrichedUser);
        return enrichedUser;
      } else {
        updateUser(null);
        return null;
      }
    } catch (error) {
      if (!applies()) return undefined;
      logAuthContextError('Error fetching user:', error);
      // Retain display state only for an explicitly requested readback of the
      // same validated account. Never return it as fresh callback identity proof.
      if (canRetainUser) throw error;
      updateUser(null);
      return null;
    } finally {
      if (applies()) {
        identityRefreshPending.current = false;
        setIsLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    const stopForLogout = () => {
      logoutStarted.current = true;
      authRequestGeneration.current += 1;
      callbackAttempt.current = null;
    };
    window.addEventListener(LOGOUT_STARTED_EVENT, stopForLogout);
    fetchUser();
    return () => {
      mounted.current = false;
      authRequestGeneration.current += 1;
      window.removeEventListener(LOGOUT_STARTED_EVENT, stopForLogout);
    };
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
  const refreshUser = useCallback(async (options) => {
    const refreshedUser = await fetchUser(options);
    if (options?.background && refreshedUser === undefined) throw obsoleteAuthRequest();
  }, [fetchUser]);

  // The console subtree remounts when authentication changes. Keep the one-use
  // code exchange and its refresh here so replacement callback pages can await
  // the same operation. Retain only the latest callback route, code and state.
  const completeLoginCallback = useCallback(({ code, state, routeKey }) => {
    const key = JSON.stringify([routeKey, code, state]);
    if (callbackAttempt.current?.key === key) return callbackAttempt.current.promise;

    const attempt = { key, promise: null };
    callbackAttempt.current = attempt;
    const assertCurrent = () => {
      if (!mounted.current || logoutStarted.current || callbackAttempt.current !== attempt) {
        const error = new Error('The authentication callback changed.');
        error.name = 'AbortError';
        throw error;
      }
    };
    attempt.promise = (async () => {
      await exchangeAuthCallbackCode({ code, state });
      assertCurrent();
      const refreshedUser = await fetchUser();
      assertCurrent();
      if (refreshedUser === undefined) {
        throw obsoleteAuthRequest();
      }
      const principalId = refreshedUser?.user_id || refreshedUser?.sub || refreshedUser?.id;
      if (!principalId) throw new Error('Authentication could not be confirmed. Please sign in again.');
      return { principalId };
    })();
    return attempt.promise;
  }, [fetchUser]);

  // Computed values - derive role booleans and organization info
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
      completeLoginCallback,
    };
  }, [user, isLoading, login, register, logout, refreshUser, completeLoginCallback]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export { AuthContext };


