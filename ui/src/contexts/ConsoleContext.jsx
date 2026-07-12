/**
 * Console Context
 *
 * Manages console mode (applicant vs org) and active organization selection.
 * Replaces ViewModeContext with clearer separation of concerns.
 * 
 * State model:
 * - mode: "applicant" | "org" - which console the user is in
 * - activeOrgId: UUID | null - selected organization (only matters in org mode)
 * - memberships: Organization[] - user's org memberships
 * - membershipsLoaded: boolean - whether memberships have been fetched
 */

import { createContext, useState, useEffect, useCallback, useContext, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { getPreferences, updatePreferences } from '../services/preferencesApi';
import { getMyOrganizations } from '../services/organizationsApi';
import { AuthContext } from './AuthContext';
import { redirectBrowser, shouldBrowserRedirect } from '../application/routing/appHandoff';
import { getConsoleEligibleOrganizations } from '../application/session/authSession';
import {
  getDefaultLandingPath,
  isOrgConsoleBlocked,
  resolveActiveOrgSelection,
  resolveConsoleBootstrap,
  resolveModeChange,
} from '../application/session/consoleSession';

/**
 * @typedef {'applicant' | 'org'} ConsoleMode
 */

/**
 * @typedef {Object} ConsoleContextValue
 * @property {ConsoleMode} mode - Current console mode
 * @property {string|null} activeOrgId - Currently active organization ID
 * @property {Array} memberships - User's organization memberships
 * @property {boolean} membershipsLoaded - Whether memberships have been fetched
 * @property {boolean} isLoading - Whether context is loading
 * @property {boolean} isOrgConsoleAvailable - Whether org console should be shown
 * @property {boolean} isOrgBlocked - Whether org console is blocked (no org selected)
 * @property {function(ConsoleMode): Promise<void>} setMode - Change console mode
 * @property {function(string, Array=): Promise<void>} setActiveOrgId - Set active organization
 * @property {function(): void} clearActiveOrg - Clear active org (triggers setup flow)
 * @property {function(): Promise<void>} refreshMemberships - Reload memberships from backend
 */

const defaultContextValue = {
  mode: 'applicant',
  activeOrgId: null,
  memberships: [],
  membershipsLoaded: false,
  membershipLoadError: null,
  orgLoadError: null,
  isLoading: true,
  isOrgConsoleAvailable: false,
  isApplicantConsoleAvailable: true,
  isOrgBootstrapRequired: false,
  isOrgBlocked: false,
  setMode: async () => {},
  setActiveOrgId: async () => {},
  clearActiveOrg: () => {},
  refreshMemberships: async () => {},
  reloadConsoleState: async () => {},
};

export const ConsoleContext = createContext(defaultContextValue);

const ORG_BOOTSTRAP_ROLES = new Set([
  'admin',
  'administrator',
  'vendor',
  'org_admin',
  'organization-admin',
  'owner',
  'access_admin',
  'catalog_admin',
  'reviewer',
  'operator',
  'viewer',
]);

const BOOTSTRAP_MEMBERSHIP_RETRY_CONFIG = {
  maxRetries: 0,
};

const SHOULD_LOG_CONSOLE_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';

function logConsoleContextWarning(...args) {
  if (SHOULD_LOG_CONSOLE_DIAGNOSTICS) {
    console.warn(...args);
  }
}

function logConsoleContextError(...args) {
  if (SHOULD_LOG_CONSOLE_DIAGNOSTICS) {
    console.error(...args);
  }
}

function getMessageId(error) {
  return error?.response?.message_id
    || error?.response?.request_id
    || error?.requestId
    || error?.request_id
    || null;
}

function normalizeMembershipLoadError(error) {
  if (!error) {
    return null;
  }

  return {
    message: error?.response?.error?.user_message
      || error?.response?.error_description
      || error?.message
      || 'Organization memberships could not be loaded.',
    status: error?.status || null,
    messageId: getMessageId(error),
    raw: error,
  };
}

function userNeedsOrgBootstrap(user, fallbackMemberships = []) {
  if (!user) {
    return false;
  }

  const roles = Array.isArray(user.roles) ? user.roles : [];
  return Boolean(user.capabilities?.['org:view'])
    || getConsoleEligibleOrganizations(user.organizations).length > 0
    || fallbackMemberships.length > 0
    || roles.some((role) => ORG_BOOTSTRAP_ROLES.has(role))
    || ['administrator', 'vendor'].includes(user.user_type);
}

function mergePreferredFallbackMembership(fetchedMemberships, fallbackMemberships, preferredOrgId) {
  const safeFetchedMemberships = Array.isArray(fetchedMemberships) ? fetchedMemberships : [];
  if (
    !preferredOrgId
    || safeFetchedMemberships.some((organization) => organization.id === preferredOrgId)
  ) {
    return safeFetchedMemberships;
  }

  const preferredFallback = (fallbackMemberships || []).find((organization) => organization.id === preferredOrgId);
  return preferredFallback
    ? [...safeFetchedMemberships, preferredFallback]
    : safeFetchedMemberships;
}

/**
 * ConsoleProvider - Manages console mode and org selection state
 */
export function ConsoleProvider({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const {
    user,
    isAuthenticated,
    isLoading: authLoading,
  } = useContext(AuthContext);
  
  const [mode, setModeState] = useState('applicant');
  const [activeOrgId, setActiveOrgIdState] = useState(null);
  const [memberships, setMemberships] = useState([]);
  const [membershipsLoaded, setMembershipsLoaded] = useState(false);
  const [membershipLoadError, setMembershipLoadError] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const fallbackMemberships = useMemo(
    () => getConsoleEligibleOrganizations(user?.organizations),
    [user?.organizations]
  );
  const isCanvasApplicantOnlyUser = useMemo(
    () => Array.isArray(user?.roles)
      && user.roles.includes('canvas_lti_learner')
      && !user?.capabilities?.['org:view'],
    [user?.roles, user?.capabilities]
  );
  const isOrgBootstrapRequired = useMemo(
    () => !isCanvasApplicantOnlyUser && userNeedsOrgBootstrap(user, fallbackMemberships),
    [fallbackMemberships, isCanvasApplicantOnlyUser, user]
  );

  const transitionTo = useCallback((destination, options = {}) => {
    if (!destination) {
      return;
    }

    if (shouldBrowserRedirect({ currentPathname: location.pathname, destination })) {
      redirectBrowser(destination, { replace: options.replace === true });
      return;
    }

    navigate(destination, options);
  }, [location.pathname, navigate]);

  /**
   * Load preferences and memberships from backend
   */
  const loadState = useCallback(async () => {
    if (!isAuthenticated || authLoading) {
      setMembershipLoadError(null);
      setMemberships([]);
      setMembershipsLoaded(false);
      setIsLoading(Boolean(authLoading));
      return;
    }

    try {
      setIsLoading(true);

      const defaultPreferences = { last_view_mode: 'applicant', last_active_org_id: null };
      const [preferencesResult, organizationsResult] = await Promise.allSettled([
        getPreferences(),
        getMyOrganizations({ retryConfig: BOOTSTRAP_MEMBERSHIP_RETRY_CONFIG }),
      ]);

      const prefs = preferencesResult.status === 'fulfilled'
        ? preferencesResult.value
        : defaultPreferences;
      if (preferencesResult.status === 'rejected') {
        logConsoleContextWarning('[ConsoleContext] Failed to load console preferences:', preferencesResult.reason);
      }

      if (organizationsResult.status === 'rejected') {
        const normalizedError = normalizeMembershipLoadError(organizationsResult.reason);
        setMembershipLoadError(normalizedError);
        setMemberships(fallbackMemberships);
        setMembershipsLoaded(false);
        setModeState('applicant');
        setActiveOrgIdState(null);
        window.localStorage.removeItem('activeOrgId');
        return;
      }

      const orgs = Array.isArray(organizationsResult.value) ? organizationsResult.value : [];
      setMembershipLoadError(null);

      const localStoredOrgId = window.localStorage.getItem('activeOrgId');
      const preferredOrgId = localStoredOrgId || prefs?.last_active_org_id || null;
      const fetchedMemberships = getConsoleEligibleOrganizations(orgs);
      const resolvedMemberships = !isCanvasApplicantOnlyUser
        ? mergePreferredFallbackMembership(fetchedMemberships, fallbackMemberships, preferredOrgId)
        : [];
      setMemberships(resolvedMemberships);
      setMembershipsLoaded(true);

      // Restore last mode and org (fallback to localStorage when backend prefs are stale/unavailable)
      const { mode: effectiveMode, activeOrgId: validOrgId } = resolveConsoleBootstrap({
        preferences: prefs,
        memberships: resolvedMemberships,
        localStoredOrgId,
      });

      setModeState(effectiveMode);
      setActiveOrgIdState(validOrgId);

      if (validOrgId) {
        window.localStorage.setItem('activeOrgId', validOrgId);
      } else {
        window.localStorage.removeItem('activeOrgId');
      }

      if (
        prefs?.last_view_mode !== effectiveMode
        || (prefs?.last_active_org_id || null) !== validOrgId
      ) {
        updatePreferences({
          last_view_mode: effectiveMode,
          last_active_org_id: validOrgId,
        }).catch((error) => {
          logConsoleContextWarning('[ConsoleContext] Failed to heal stale console preferences:', error);
        });
      }
    } catch (error) {
      logConsoleContextError('[ConsoleContext] Failed to load state:', error);
      setMembershipLoadError(normalizeMembershipLoadError(error));
      setModeState('applicant');
      setActiveOrgIdState(null);
      setMemberships(fallbackMemberships);
      setMembershipsLoaded(false);
    } finally {
      setIsLoading(false);
    }
  }, [
    isAuthenticated,
    authLoading,
    fallbackMemberships,
    user?.organizations,
    isCanvasApplicantOnlyUser,
  ]);

  /**
   * Load state on mount and when auth state changes
   */
  useEffect(() => {
    loadState();
  }, [loadState]);

  /**
   * Set console mode
   */
  const setMode = useCallback(async (newMode) => {
    if (newMode === mode) return;

    const nextState = resolveModeChange({
      newMode,
      activeOrgId,
      memberships,
    });

    // Optimistically update UI
    setModeState(nextState.mode);
    setActiveOrgIdState(nextState.activeOrgId);

    if (nextState.activeOrgId) {
      window.localStorage.setItem('activeOrgId', nextState.activeOrgId);
    } else {
      window.localStorage.removeItem('activeOrgId');
    }

    transitionTo(nextState.destination);

    try {
      await updatePreferences(nextState.persistence);
    } catch (error) {
      // Keep in-memory UI state even if persistence fails (backend may reject some payloads)
      logConsoleContextWarning('[ConsoleContext] Failed to persist mode preference, keeping local state:', error);
    }
  }, [mode, activeOrgId, memberships, transitionTo]);

  /**
   * Set active organization
   */
  const setActiveOrgId = useCallback(async (orgId, membershipOverride = null) => {
    if (orgId === activeOrgId) return;
    const membershipsForSelection = Array.isArray(membershipOverride)
      ? membershipOverride
      : memberships;

    const nextSelection = resolveActiveOrgSelection({
      orgId,
      currentMode: mode,
      memberships: membershipsForSelection,
    });

    // Validate org exists in memberships
    if (!nextSelection.valid) {
      logConsoleContextWarning('[ConsoleContext] Attempted to set invalid org ID:', orgId);
      return;
    }

    // Optimistically update UI
    setActiveOrgIdState(orgId);
    if (orgId) {
      window.localStorage.setItem('activeOrgId', orgId);
    } else {
      window.localStorage.removeItem('activeOrgId');
    }

    // Auto-switch to org mode if selecting an org
    setActiveOrgIdState(nextSelection.activeOrgId);
    if (nextSelection.mode !== mode) {
      setModeState(nextSelection.mode);
    }

    try {
      await updatePreferences(nextSelection.persistence);

      // Always navigate to org console when selecting an org
      if (nextSelection.destination) {
        transitionTo(nextSelection.destination);
      }
    } catch (error) {
      // Keep selected org locally even if preference persistence fails
      logConsoleContextWarning('[ConsoleContext] Failed to persist active org preference, keeping local selection:', error);
      if (nextSelection.destination) {
        transitionTo(nextSelection.destination);
      }
    }
  }, [activeOrgId, mode, memberships, transitionTo]);

  /**
   * Clear active org (triggers setup flow)
   */
  const clearActiveOrg = useCallback(() => {
    setActiveOrgIdState(null);
    window.localStorage.removeItem('activeOrgId');
    if (mode === 'org') {
      transitionTo('/console/org/setup');
    }
  }, [mode, transitionTo]);

  /**
   * Refresh memberships from backend
   */
  const refreshMemberships = useCallback(async () => {
    try {
      const orgs = await getMyOrganizations();
      const resolvedMemberships = !isCanvasApplicantOnlyUser && Array.isArray(orgs)
        ? getConsoleEligibleOrganizations(orgs)
        : [];

      setMembershipLoadError(null);
      setMemberships(resolvedMemberships);
      setMembershipsLoaded(true);

      // If current activeOrgId is no longer valid, clear it
      if (activeOrgId && !resolvedMemberships.find((organization) => organization.id === activeOrgId)) {
        clearActiveOrg();
      }

      return resolvedMemberships;
    } catch (error) {
      logConsoleContextError('[ConsoleContext] Failed to refresh memberships:', error);
      setMembershipLoadError(normalizeMembershipLoadError(error));
      setMembershipsLoaded(false);
      return null;
    }
  }, [activeOrgId, clearActiveOrg, isCanvasApplicantOnlyUser]);

  /**
   * Computed: Is org console available?
   * Only available for users with admin or vendor roles.
   */
  const isOrgConsoleAvailable = useMemo(() => {
    return !membershipLoadError && memberships.length > 0;
  }, [membershipLoadError, memberships.length]);

  /**
   * Computed: Is applicant console available?
   * Always available for authenticated applicants.
   */
  const isApplicantConsoleAvailable = useMemo(() => {
    return true;
  }, []);

  /**
   * Computed: Is org console blocked?
   * Blocked when in org mode but no org selected
   */
  const isOrgBlocked = useMemo(() => {
    return isOrgConsoleBlocked(mode, activeOrgId);
  }, [mode, activeOrgId]);

  const value = useMemo(() => ({
    mode,
    activeOrgId,
    memberships,
    membershipsLoaded,
    membershipLoadError,
    orgLoadError: membershipLoadError,
    isLoading,
    isOrgConsoleAvailable,
    isApplicantConsoleAvailable,
    isOrgBootstrapRequired,
    isOrgBlocked,
    setMode,
    setActiveOrgId,
    clearActiveOrg,
    refreshMemberships,
    reloadConsoleState: loadState,
  }), [
    mode,
    activeOrgId,
    memberships,
    membershipsLoaded,
    membershipLoadError,
    isLoading,
    isOrgConsoleAvailable,
    isApplicantConsoleAvailable,
    isOrgBootstrapRequired,
    isOrgBlocked,
    setMode,
    setActiveOrgId,
    clearActiveOrg,
    refreshMemberships,
    loadState,
  ]);

  return (
    <ConsoleContext.Provider value={value}>
      {children}
    </ConsoleContext.Provider>
  );
}

/**
 * useConsole - Hook to access console context
 *
 * @returns {ConsoleContextValue}
 */
export function useConsole() {
  const context = useContext(ConsoleContext);
  if (context === undefined) {
    throw new Error('useConsole must be used within a ConsoleProvider');
  }
  return context;
}

/**
 * Get default landing path based on user context
 * Use this for post-login navigation
 *
 * @param {Object} context - Console context value
 * @param {string} fallback - Fallback path (default: '/console/applicant/catalog')
 * @returns {string} - Path to navigate to
 */
export { getDefaultLandingPath };
