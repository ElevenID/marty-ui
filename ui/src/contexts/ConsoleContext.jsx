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

import { createContext, startTransition, useState, useEffect, useLayoutEffect, useCallback, useContext, useMemo, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router';
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
 * @property {function(string, Array=, Object=): Promise<void>} setActiveOrgId - Set active organization; navigate=false leaves routing to the caller
 * @property {function(): void} clearActiveOrg - Clear active org (triggers setup flow)
 * @property {function(): Promise<void>} refreshMemberships - Reload memberships from backend
 * @property {function(string, Object): void} reconcileOrganizationProfile - Apply a verified profile save to the current membership
 * @property {function(string): void} reconcileMembershipRemoval - Remove the current user's verified deleted membership
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
  reconcileOrganizationProfile: () => {},
  reconcileMembershipRemoval: () => {},
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
  const { user, isAuthenticated, isLoading: authLoading } = useContext(AuthContext);
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const applicantOnly = Array.isArray(user?.roles) && user.roles.includes('canvas_lti_learner')
    && !user?.capabilities?.['org:view'];
  // An anonymous auth check has no account state to clear. Keep public resources
  // mounted while it settles; known identities still reset across auth loading.
  const sessionLoading = Boolean(principalId || isAuthenticated) && authLoading;
  const sessionKey = JSON.stringify([principalId, isAuthenticated, sessionLoading, Boolean(applicantOnly)]);
  const previousSession = useRef({ principalId, isAuthenticated });
  useLayoutEffect(() => {
    if (previousSession.current.principalId && (previousSession.current.principalId !== principalId
      || previousSession.current.isAuthenticated !== isAuthenticated)) {
      window.localStorage.removeItem('activeOrgId');
    }
    previousSession.current = { principalId, isAuthenticated };
  }, [principalId, isAuthenticated]);

  // Account changes must clear both context and its independently loading pages
  // in the same render, before the replacement account's requests complete.
  return <ConsoleSessionProvider key={sessionKey}>{children}</ConsoleSessionProvider>;
}

function obsoleteConsoleOperation() {
  const error = new Error('The console session or selection changed.');
  error.name = 'AbortError';
  return error;
}

function ConsoleSessionProvider({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const currentLocation = useRef(location);
  currentLocation.current = location;
  const {
    user,
    isAuthenticated,
    isLoading: authLoading,
  } = useContext(AuthContext);
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const sessionReady = Boolean(isAuthenticated && !authLoading && principalId);
  const active = useRef(false);
  const operationGeneration = useRef(0);
  useLayoutEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      operationGeneration.current += 1;
    };
  }, []);
  const assertSession = useCallback(() => {
    if (!active.current || !sessionReady) throw obsoleteConsoleOperation();
  }, [sessionReady]);
  const operationIsCurrent = useCallback((generation) => active.current && sessionReady
    && operationGeneration.current === generation, [sessionReady]);
  
  const [mode, setModeState] = useState('applicant');
  const [activeOrgId, setActiveOrgIdState] = useState(null);
  const [memberships, setMemberships] = useState([]);
  const [membershipsLoaded, setMembershipsLoaded] = useState(false);
  const [membershipLoadError, setMembershipLoadError] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const selection = useRef({ mode, activeOrgId, memberships });
  selection.current = { mode, activeOrgId, memberships };
  // A stale auth snapshot or stored preference cannot restore a membership
  // that this session has successfully removed.
  const removedFallbackMemberships = useRef(new Set());
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
    if (!active.current) return;
    const generation = ++operationGeneration.current;
    const applies = () => operationIsCurrent(generation);
    const currentFallbacks = fallbackMemberships.filter(org => !removedFallbackMemberships.current.has(org.id));
    if (!sessionReady) {
      selection.current = { mode: 'applicant', activeOrgId: null, memberships: [] };
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
      if (!applies()) return;

      const prefs = preferencesResult.status === 'fulfilled'
        ? preferencesResult.value
        : defaultPreferences;
      if (preferencesResult.status === 'rejected') {
        logConsoleContextWarning('[ConsoleContext] Failed to load console preferences:', preferencesResult.reason);
      }

      if (organizationsResult.status === 'rejected') {
        const normalizedError = normalizeMembershipLoadError(organizationsResult.reason);
        selection.current = { mode: 'applicant', activeOrgId: null, memberships: currentFallbacks };
        setMembershipLoadError(normalizedError);
        setMemberships(currentFallbacks);
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
        ? mergePreferredFallbackMembership(fetchedMemberships, currentFallbacks, preferredOrgId)
        : [];
      setMemberships(resolvedMemberships);
      setMembershipsLoaded(true);

      // Restore last mode and org (fallback to localStorage when backend prefs are stale/unavailable)
      const { mode: effectiveMode, activeOrgId: validOrgId } = resolveConsoleBootstrap({
        preferences: prefs,
        memberships: resolvedMemberships,
        localStoredOrgId,
      });

      selection.current = { mode: effectiveMode, activeOrgId: validOrgId, memberships: resolvedMemberships };
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
          if (applies()) logConsoleContextWarning('[ConsoleContext] Failed to heal stale console preferences:', error);
        });
      }
    } catch (error) {
      if (!applies()) return;
      selection.current = { mode: 'applicant', activeOrgId: null, memberships: currentFallbacks };
      logConsoleContextError('[ConsoleContext] Failed to load state:', error);
      setMembershipLoadError(normalizeMembershipLoadError(error));
      setModeState('applicant');
      setActiveOrgIdState(null);
      setMemberships(currentFallbacks);
      setMembershipsLoaded(false);
    } finally {
      if (applies()) setIsLoading(false);
    }
  }, [
    authLoading,
    sessionReady,
    operationIsCurrent,
    fallbackMemberships,
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
    assertSession();
    const current = selection.current;
    if (newMode === current.mode) return;
    const generation = ++operationGeneration.current;

    const nextState = resolveModeChange({
      newMode,
      activeOrgId: current.activeOrgId,
      memberships: current.memberships,
    });
    selection.current = { ...current, mode: nextState.mode, activeOrgId: nextState.activeOrgId };

    if (nextState.activeOrgId) {
      window.localStorage.setItem('activeOrgId', nextState.activeOrgId);
    } else {
      window.localStorage.removeItem('activeOrgId');
    }

    // Match the router's transition so the old org route never sees a cleared
    // selection before the applicant destination is ready.
    startTransition(() => {
      setIsLoading(false);
      setModeState(nextState.mode);
      setActiveOrgIdState(nextState.activeOrgId);
      transitionTo(nextState.destination);
    });

    try {
      await updatePreferences(nextState.persistence);
    } catch (error) {
      if (!operationIsCurrent(generation)) throw obsoleteConsoleOperation();
      // Keep in-memory UI state even if persistence fails (backend may reject some payloads)
      logConsoleContextWarning('[ConsoleContext] Failed to persist mode preference, keeping local state:', error);
    }
    if (!operationIsCurrent(generation)) throw obsoleteConsoleOperation();
  }, [assertSession, operationIsCurrent, transitionTo]);

  /**
   * Set active organization
   */
  const setActiveOrgId = useCallback(async (orgId, membershipOverride = null, options = {}) => {
    assertSession();
    const current = selection.current;
    if (orgId === current.activeOrgId) return;
    const membershipsForSelection = isCanvasApplicantOnlyUser
      ? []
      : Array.isArray(membershipOverride)
        ? getConsoleEligibleOrganizations(membershipOverride)
        : current.memberships;

    const nextSelection = resolveActiveOrgSelection({
      orgId,
      currentMode: current.mode,
      memberships: membershipsForSelection,
    });

    // Validate org exists in memberships
    if (!nextSelection.valid) {
      logConsoleContextWarning('[ConsoleContext] Attempted to set invalid org ID:', orgId);
      return;
    }
    const generation = ++operationGeneration.current;
    selection.current = {
      mode: nextSelection.mode,
      activeOrgId: nextSelection.activeOrgId,
      memberships: membershipsForSelection,
    };
    const originLocation = currentLocation.current;

    // Organization creation returns the creator's membership before a list
    // refresh is necessarily current. Retain that verified selection for route
    // guards, the organization header, and native permission loading.
    if (Array.isArray(membershipOverride)) {
      setMemberships(membershipsForSelection);
      setMembershipsLoaded(true);
      setMembershipLoadError(null);
    }

    // Optimistically update UI
    setIsLoading(false);
    setActiveOrgIdState(orgId);
    if (orgId) {
      window.localStorage.setItem('activeOrgId', orgId);
    } else {
      window.localStorage.removeItem('activeOrgId');
    }

    // Auto-switch to org mode if selecting an org
    setActiveOrgIdState(nextSelection.activeOrgId);
    if (nextSelection.mode !== current.mode) {
      setModeState(nextSelection.mode);
    }

    try {
      await updatePreferences(nextSelection.persistence);
    } catch (error) {
      if (!operationIsCurrent(generation)) throw obsoleteConsoleOperation();
      // Keep selected org locally even if preference persistence fails
      logConsoleContextWarning('[ConsoleContext] Failed to persist active org preference, keeping local selection:', error);
    }
    // Reject obsolete callers too: setup/join flows may navigate after awaiting us.
    if (!operationIsCurrent(generation) || currentLocation.current !== originLocation) throw obsoleteConsoleOperation();
    if (nextSelection.destination && options.navigate !== false) transitionTo(nextSelection.destination);
  }, [assertSession, operationIsCurrent, isCanvasApplicantOnlyUser, transitionTo]);

  /**
   * Clear active org (triggers setup flow)
   */
  const clearActiveOrg = useCallback(() => {
    if (!active.current || !sessionReady) return;
    operationGeneration.current += 1;
    selection.current = { ...selection.current, activeOrgId: null };
    setIsLoading(false);
    setActiveOrgIdState(null);
    try {
      window.localStorage.removeItem('activeOrgId');
    } catch (error) {
      logConsoleContextWarning('[ConsoleContext] Failed to clear stored organization selection:', error);
    }
    if (selection.current.mode === 'org') {
      transitionTo('/console/org/setup');
    }
  }, [sessionReady, transitionTo]);

  const reconcileOrganizationProfile = useCallback((organizationId, profile) => {
    assertSession();
    const current = selection.current;
    if (current.activeOrgId !== organizationId || !current.memberships.some(org => org.id === organizationId)) {
      throw obsoleteConsoleOperation();
    }
    // Only profile fields come from this response; membership roles and grants
    // remain the authoritative values already held by the console.
    if (typeof profile?.name !== 'string' || !profile.name.trim()
      || typeof profile?.displayName !== 'string' || !profile.displayName.trim()) return;
    operationGeneration.current += 1;
    const updatedMemberships = current.memberships.map(org => org.id === organizationId
      ? { ...org, name: profile.name, display_name: profile.displayName } : org);
    selection.current = { ...current, memberships: updatedMemberships };
    setMemberships(updatedMemberships);
    setMembershipsLoaded(true);
    setMembershipLoadError(null);
    setIsLoading(false);
  }, [assertSession]);

  const reconcileMembershipRemoval = useCallback((organizationId) => {
    assertSession();
    const current = selection.current;
    if (current.activeOrgId !== organizationId || !current.memberships.some(org => org.id === organizationId)) {
      throw obsoleteConsoleOperation();
    }
    operationGeneration.current += 1;
    removedFallbackMemberships.current.add(organizationId);
    const remainingMemberships = current.memberships.filter(org => org.id !== organizationId);
    selection.current = { ...current, memberships: remainingMemberships };
    setMemberships(remainingMemberships);
    setMembershipsLoaded(true);
    setMembershipLoadError(null);
    clearActiveOrg();
  }, [assertSession, clearActiveOrg]);

  /**
   * Refresh memberships from backend
   */
  const refreshMemberships = useCallback(async () => {
    assertSession();
    const generation = ++operationGeneration.current;
    const applies = () => operationIsCurrent(generation);
    try {
      const orgs = await getMyOrganizations();
      if (!applies()) throw obsoleteConsoleOperation();
      const resolvedMemberships = !isCanvasApplicantOnlyUser && Array.isArray(orgs)
        ? getConsoleEligibleOrganizations(orgs)
        : [];
      selection.current = { ...selection.current, memberships: resolvedMemberships };

      setMembershipLoadError(null);
      setMemberships(resolvedMemberships);
      setMembershipsLoaded(true);
      setIsLoading(false);

      // If current activeOrgId is no longer valid, clear it
      const currentOrgId = selection.current.activeOrgId;
      if (currentOrgId && !resolvedMemberships.find((organization) => organization.id === currentOrgId)) {
        clearActiveOrg();
      }

      return resolvedMemberships;
    } catch (error) {
      if (error?.name === 'AbortError' || !applies()) throw obsoleteConsoleOperation();
      logConsoleContextError('[ConsoleContext] Failed to refresh memberships:', error);
      setMembershipLoadError(normalizeMembershipLoadError(error));
      setMembershipsLoaded(false);
      return null;
    } finally {
      if (applies()) setIsLoading(false);
    }
  }, [assertSession, operationIsCurrent, clearActiveOrg, isCanvasApplicantOnlyUser]);

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
    reconcileOrganizationProfile,
    reconcileMembershipRemoval,
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
    reconcileOrganizationProfile,
    reconcileMembershipRemoval,
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
