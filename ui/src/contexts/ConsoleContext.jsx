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
  resolveApplicantOrganizationId,
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
 * @property {function(string): Promise<void>} setActiveOrgId - Set active organization
 * @property {function(): void} clearActiveOrg - Clear active org (triggers setup flow)
 * @property {function(): Promise<void>} refreshMemberships - Reload memberships from backend
 */

const defaultContextValue = {
  mode: 'applicant',
  activeOrgId: null,
  memberships: [],
  membershipsLoaded: false,
  isLoading: true,
  isOrgConsoleAvailable: false,
  isApplicantConsoleAvailable: true,
  isOrgBlocked: false,
  setMode: async () => {},
  setActiveOrgId: async () => {},
  clearActiveOrg: () => {},
  refreshMemberships: async () => {},
};

export const ConsoleContext = createContext(defaultContextValue);

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
    setActiveOrganizationId: updateAuthOrg,
  } = useContext(AuthContext);
  
  const [mode, setModeState] = useState('applicant');
  const [activeOrgId, setActiveOrgIdState] = useState(null);
  const [memberships, setMemberships] = useState([]);
  const [membershipsLoaded, setMembershipsLoaded] = useState(false);
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
  const currentOrganizationId = user?.organization_id || null;
  const defaultApplicantOrgId = user?.default_organization_id || null;

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
      setIsLoading(false);
      return;
    }

    try {
      setIsLoading(true);

      // Load preferences and memberships in parallel
      const [prefs, orgs] = await Promise.all([
        getPreferences().catch(() => ({ last_view_mode: 'applicant', last_active_org_id: null })),
        getMyOrganizations().catch(() => []),
      ]);

      const resolvedMemberships = !isCanvasApplicantOnlyUser && Array.isArray(orgs) && orgs.length > 0
        ? getConsoleEligibleOrganizations(orgs)
        : fallbackMemberships;
      const applicantOrganizations = Array.isArray(orgs) && orgs.length > 0
        ? orgs
        : (Array.isArray(user?.organizations) ? user.organizations : []);
      const resolvedApplicantOrgId = resolveApplicantOrganizationId({
        defaultOrganizationId: defaultApplicantOrgId,
        currentOrganizationId,
        organizations: applicantOrganizations,
      });

      setMemberships(resolvedMemberships);
      setMembershipsLoaded(true);

      // Restore last mode and org (fallback to localStorage when backend prefs are stale/unavailable)
      const localStoredOrgId = window.localStorage.getItem('activeOrgId');
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

      // Sync with AuthContext
      if (validOrgId && updateAuthOrg && currentOrganizationId !== validOrgId) {
        updateAuthOrg(validOrgId);
      } else if (!validOrgId && updateAuthOrg && currentOrganizationId !== resolvedApplicantOrgId) {
        updateAuthOrg(resolvedApplicantOrgId);
      }

      if (
        prefs?.last_view_mode !== effectiveMode
        || (prefs?.last_active_org_id || null) !== validOrgId
      ) {
        updatePreferences({
          last_view_mode: effectiveMode,
          last_active_org_id: validOrgId,
        }).catch((error) => {
          console.warn('[ConsoleContext] Failed to heal stale console preferences:', error);
        });
      }
    } catch (error) {
      console.error('[ConsoleContext] Failed to load state:', error);
      // Use defaults on error
      setModeState('applicant');
      setActiveOrgIdState(null);
      setMemberships(fallbackMemberships);
      setMembershipsLoaded(true);
      if (updateAuthOrg && currentOrganizationId !== defaultApplicantOrgId) {
        updateAuthOrg(defaultApplicantOrgId);
      }
    } finally {
      setIsLoading(false);
    }
  }, [
    isAuthenticated,
    authLoading,
    currentOrganizationId,
    defaultApplicantOrgId,
    fallbackMemberships,
    user?.organizations,
    isCanvasApplicantOnlyUser,
    updateAuthOrg,
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

    if (nextState.authOrgId && updateAuthOrg) {
      updateAuthOrg(nextState.authOrgId);
    } else if (newMode === 'applicant' && updateAuthOrg) {
      updateAuthOrg(defaultApplicantOrgId);
    }

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
      console.warn('[ConsoleContext] Failed to persist mode preference, keeping local state:', error);
    }
  }, [mode, activeOrgId, memberships, transitionTo, updateAuthOrg, defaultApplicantOrgId]);

  /**
   * Set active organization
   */
  const setActiveOrgId = useCallback(async (orgId) => {
    if (orgId === activeOrgId) return;

    const nextSelection = resolveActiveOrgSelection({
      orgId,
      currentMode: mode,
      memberships,
    });

    // Validate org exists in memberships
    if (!nextSelection.valid) {
      console.warn('[ConsoleContext] Attempted to set invalid org ID:', orgId);
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

    // Sync with AuthContext for permissions
    if (updateAuthOrg) {
      updateAuthOrg(orgId || defaultApplicantOrgId);
    }

    try {
      await updatePreferences(nextSelection.persistence);

      // Always navigate to org console when selecting an org
      if (nextSelection.destination) {
        transitionTo(nextSelection.destination);
      }
    } catch (error) {
      // Keep selected org locally even if preference persistence fails
      console.warn('[ConsoleContext] Failed to persist active org preference, keeping local selection:', error);
      if (nextSelection.destination) {
        transitionTo(nextSelection.destination);
      }
    }
  }, [activeOrgId, mode, memberships, transitionTo, updateAuthOrg, defaultApplicantOrgId]);

  /**
   * Clear active org (triggers setup flow)
   */
  const clearActiveOrg = useCallback(() => {
    setActiveOrgIdState(null);
    window.localStorage.removeItem('activeOrgId');
    if (updateAuthOrg) {
      updateAuthOrg(defaultApplicantOrgId);
    }
    if (mode === 'org') {
      transitionTo('/console/org/setup');
    }
  }, [defaultApplicantOrgId, mode, transitionTo, updateAuthOrg]);

  /**
   * Refresh memberships from backend
   */
  const refreshMemberships = useCallback(async () => {
    try {
      const orgs = await getMyOrganizations();
      const resolvedMemberships = !isCanvasApplicantOnlyUser && Array.isArray(orgs) && orgs.length > 0
        ? getConsoleEligibleOrganizations(orgs)
        : fallbackMemberships;

      setMemberships(resolvedMemberships);
      setMembershipsLoaded(true);

      // If current activeOrgId is no longer valid, clear it
      if (activeOrgId && !resolvedMemberships.find((organization) => organization.id === activeOrgId)) {
        clearActiveOrg();
      }
    } catch (error) {
      console.error('[ConsoleContext] Failed to refresh memberships:', error);
    }
  }, [activeOrgId, clearActiveOrg, fallbackMemberships, isCanvasApplicantOnlyUser]);

  /**
   * Computed: Is org console available?
   * Only available for users with admin or vendor roles.
   */
  const isOrgConsoleAvailable = useMemo(() => {
    return memberships.length > 0;
  }, [memberships.length]);

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
    isLoading,
    isOrgConsoleAvailable,
    isApplicantConsoleAvailable,
    isOrgBlocked,
    setMode,
    setActiveOrgId,
    clearActiveOrg,
    refreshMemberships,
  }), [
    mode,
    activeOrgId,
    memberships,
    membershipsLoaded,
    isLoading,
    isOrgConsoleAvailable,
    isApplicantConsoleAvailable,
    isOrgBlocked,
    setMode,
    setActiveOrgId,
    clearActiveOrg,
    refreshMemberships,
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
