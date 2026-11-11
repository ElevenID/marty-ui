/**
 * usePermissions Hook
 * 
 * Loads the current user's permissions from the backend for the active organization,
 * and provides check methods (can, canAny, canAll).
 * 
 * Permissions are scoped to the authenticated user and selected organization in React state.
 * Other components invalidate by calling `refresh()`.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from './useAuth';
import { useConsole } from '../contexts/ConsoleContext';
import { getMyPermissions } from '../services/rbacApi';
import {
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getPermissionDeniedMessage,
} from '../config/permissions';

/**
 * @typedef {Object} UsePermissionsReturn
 * @property {function(string, string): boolean} can - Check a single permission
 * @property {function(Array<{resource: string, action: string}>): boolean} canAny - Check any permission
 * @property {function(Array<{resource: string, action: string}>): boolean} canAll - Check all permissions
 * @property {function(string, string): boolean} hasPermission - Alias for can
 * @property {function(string): string} getPermissionMessage - Get denial message
 * @property {Array<{id: string, name: string, display_name: string}>} roles - User's roles
 * @property {boolean} isLoading - Whether permissions are still loading
 * @property {Error|null} error - Current permission load failure, separate from a confirmed denial
 * @property {function(): Promise<void>} refresh - Reload permissions from backend
 */

/**
 * Hook to access the current user's permissions in the active organization.
 * 
 * @returns {UsePermissionsReturn}
 */
export function usePermissions() {
  const { isAuthenticated, user } = useAuth();
  const { activeOrgId, memberships, membershipsLoaded, mode } = useConsole();
  // Require an actual selected membership, including for the default organization.
  // The backend remains authoritative for that member's grants; an organization
  // ID alone cannot establish either membership or a permission denial.
  const hasSelectedMembership = membershipsLoaded && Array.isArray(memberships)
    && memberships.some((membership) => membership.id === activeOrgId);
  const effectiveOrganizationId = mode === 'org' && hasSelectedMembership
    ? activeOrgId
    : null;
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const scope = useMemo(() => ({ organizationId: effectiveOrganizationId, principalId, isAuthenticated }),
    [effectiveOrganizationId, principalId, isAuthenticated]);
  const currentScope = useRef(scope);
  currentScope.current = scope;
  const generation = useRef(0);
  const active = useRef(false);
  const [state, setState] = useState({ scope: null, permissions: new Set(), roles: [], loading: true, error: null });

  const loadPermissions = useCallback(async () => {
    // A retained Retry callback must not dispatch for an obsolete scope or
    // invalidate a newer organization's in-flight request.
    if (!active.current || currentScope.current !== scope) return;
    const requestGeneration = ++generation.current;
    const applies = () => active.current && currentScope.current === scope && generation.current === requestGeneration;
    if (!scope.organizationId || !scope.isAuthenticated) {
      setState({ scope, permissions: new Set(), roles: [], loading: false, error: null });
      return;
    }
    setState({ scope, permissions: new Set(), roles: [], loading: true, error: null });
    // A hook-local request cannot reuse grants from an earlier login session.
    const request = getMyPermissions(scope.organizationId);
    try {
      const data = await request;
      if (applies()) setState({ scope, permissions: new Set(data.permissions || []), roles: data.roles || [], loading: false, error: null });
    } catch (err) {
      if (applies()) {
        if (err?.status !== 403) console.error('Failed to load permissions:', err);
        setState({
          scope, permissions: new Set(), roles: [], loading: false,
          error: err?.status === 403 ? null : err instanceof Error ? err : new Error('Failed to load permissions.'),
        });
      }
    }
  }, [scope]);

  useEffect(() => {
    active.current = true;
    loadPermissions();
    return () => { active.current = false; generation.current += 1; };
  }, [loadPermissions]);

  const isLoading = Boolean(scope.isAuthenticated && scope.organizationId && (state.scope !== scope || state.loading));
  const grantsCurrent = scope.isAuthenticated && scope.organizationId && state.scope === scope && !state.loading;
  const error = grantsCurrent ? state.error : null;
  const roles = useMemo(() => grantsCurrent ? state.roles : [], [grantsCurrent, state.roles]);
  const can = useCallback((resource, action) => Boolean(grantsCurrent && hasPermission(state.permissions, resource, action)), [grantsCurrent, state.permissions]);
  const canAny = useCallback((checks) => Boolean(grantsCurrent && hasAnyPermission(state.permissions, checks)), [grantsCurrent, state.permissions]);
  const canAll = useCallback((checks) => Boolean(grantsCurrent && hasAllPermissions(state.permissions, checks)), [grantsCurrent, state.permissions]);

  const getPermissionMessage = useCallback(
    (action) => getPermissionDeniedMessage(action),
    [],
  );

  const refresh = useCallback(() => loadPermissions(), [loadPermissions]);

  return useMemo(
    () => ({
      can,
      canAny,
      canAll,
      hasPermission: can,
      getPermissionMessage,
      roles,
      isLoading,
      error,
      refresh,
    }),
    [can, canAny, canAll, getPermissionMessage, roles, isLoading, error, refresh],
  );
}
