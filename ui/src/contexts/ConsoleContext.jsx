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
import { useNavigate } from 'react-router-dom';
import { getPreferences, updatePreferences } from '../services/preferencesApi';
import { getMyOrganizations } from '../services/organizationsApi';
import { AuthContext } from './AuthContext';

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
  const { isAuthenticated, isLoading: authLoading, setActiveOrganizationId: updateAuthOrg } = useContext(AuthContext);
  
  const [mode, setModeState] = useState('applicant');
  const [activeOrgId, setActiveOrgIdState] = useState(null);
  const [memberships, setMemberships] = useState([]);
  const [membershipsLoaded, setMembershipsLoaded] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

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

      setMemberships(orgs || []);
      setMembershipsLoaded(true);

      const hasMemberships = (orgs || []).length > 0;

      // Restore last mode and org (fallback to localStorage when backend prefs are stale/unavailable)
      const localStoredOrgId = window.localStorage.getItem('activeOrgId');
      const restoredMode = prefs.last_view_mode || 'applicant';
      const restoredOrgId = prefs.last_active_org_id || localStoredOrgId || null;

      // Validate restored org is still in memberships
      const validOrgId = orgs?.find(o => o.id === restoredOrgId) ? restoredOrgId : null;

      // Keep applicant mode available even when user has no memberships.
      // This allows applicants to view existing applications and onboarding state.
      const effectiveMode = hasMemberships ? restoredMode : 'applicant';

      setModeState(effectiveMode);
      setActiveOrgIdState(validOrgId);

      // Sync with AuthContext
      if (validOrgId && updateAuthOrg) {
        updateAuthOrg(validOrgId);
      }
    } catch (error) {
      console.error('[ConsoleContext] Failed to load state:', error);
      // Use defaults on error
      setModeState('applicant');
      setActiveOrgIdState(null);
      setMemberships([]);
      setMembershipsLoaded(true);
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, authLoading, updateAuthOrg]);

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

    // Optimistically update UI
    setModeState(newMode);

    // Clear active org when switching to applicant
    if (newMode === 'applicant') {
      setActiveOrgIdState(null);
      navigate('/console/applicant/catalog');
    } else if (newMode === 'org') {
      // Auto-select if only one membership
      if (memberships.length === 1) {
        const singleOrg = memberships[0];
        setActiveOrgIdState(singleOrg.id);
        if (updateAuthOrg) {
          updateAuthOrg(singleOrg.id);
        }
        navigate('/console/org');
      } else if (activeOrgId) {
        // Has an org selected already
        navigate('/console/org');
      } else {
        // Multiple orgs, none selected - go to setup
        navigate('/console/org/setup');
      }
    }

    try {
      await updatePreferences({
        last_view_mode: newMode,
        last_active_org_id: newMode === 'applicant' ? null : activeOrgId,
      });
    } catch (error) {
      // Keep in-memory UI state even if persistence fails (backend may reject some payloads)
      console.warn('[ConsoleContext] Failed to persist mode preference, keeping local state:', error);
    }
  }, [mode, activeOrgId, memberships, navigate, updateAuthOrg]);

  /**
   * Set active organization
   */
  const setActiveOrgId = useCallback(async (orgId) => {
    if (orgId === activeOrgId) return;

    // Validate org exists in memberships
    if (orgId && !(memberships || []).find(o => o.id === orgId)) {
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
    const newMode = orgId ? 'org' : mode;
    if (newMode !== mode) {
      setModeState(newMode);
    }

    // Sync with AuthContext for permissions
    if (updateAuthOrg) {
      updateAuthOrg(orgId);
    }

    try {
      await updatePreferences({
        last_view_mode: newMode,
        last_active_org_id: orgId,
      });

      // Always navigate to org console when selecting an org
      if (orgId) {
        navigate('/console/org');
      }
    } catch (error) {
      // Keep selected org locally even if preference persistence fails
      console.warn('[ConsoleContext] Failed to persist active org preference, keeping local selection:', error);
      if (orgId) {
        navigate('/console/org');
      }
    }
  }, [activeOrgId, mode, memberships, navigate, updateAuthOrg]);

  /**
   * Clear active org (triggers setup flow)
   */
  const clearActiveOrg = useCallback(() => {
    setActiveOrgIdState(null);
    if (mode === 'org') {
      navigate('/console/org/setup');
    }
  }, [mode, navigate]);

  /**
   * Refresh memberships from backend
   */
  const refreshMemberships = useCallback(async () => {
    try {
      const orgs = await getMyOrganizations();
      setMemberships(orgs || []);
      setMembershipsLoaded(true);

      // If current activeOrgId is no longer valid, clear it
      if (activeOrgId && !orgs?.find(o => o.id === activeOrgId)) {
        clearActiveOrg();
      }
    } catch (error) {
      console.error('[ConsoleContext] Failed to refresh memberships:', error);
    }
  }, [activeOrgId, clearActiveOrg]);

  /**
   * Computed: Is org console available?
   * Available if user has memberships OR org discovery is enabled
   */
  const isOrgConsoleAvailable = useMemo(() => {
    // Always available: users can always access org setup/join flow.
    return true;
  }, []);

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
    return mode === 'org' && activeOrgId === null;
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
export function getDefaultLandingPath(context, fallback = '/console/applicant/catalog') {
  const { mode, activeOrgId, memberships } = context;

  // No memberships => keep applicant entrypoint available
  if (!memberships || memberships.length === 0) {
    return '/console/applicant/catalog';
  }

  // If user has org memberships and last mode was org with valid org selected
  if (mode === 'org' && activeOrgId && memberships.find(o => o.id === activeOrgId)) {
    return '/console/org';
  }

  // If user has org memberships but no org is selected (or mode is applicant)
  // Land on catalog instead of dashboard
  if (mode === 'applicant' || !activeOrgId) {
    return '/console/applicant/catalog';
  }

  // Fallback
  return fallback;
}
