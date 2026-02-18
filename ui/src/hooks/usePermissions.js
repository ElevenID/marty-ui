/**
 * usePermissions Hook
 * 
 * Loads the current user's permissions from the backend for the active organization,
 * and provides check methods (can, canAny, canAll).
 * 
 * Permissions are fetched once per org and cached in React state.
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
 * @property {function(): Promise<void>} refresh - Reload permissions from backend
 */

/**
 * Hook to access the current user's permissions in the active organization.
 * 
 * @returns {UsePermissionsReturn}
 */
export function usePermissions() {
  const { organizationId, isAuthenticated } = useAuth();
  const { activeOrgId } = useConsole();
  const effectiveOrganizationId = activeOrgId || organizationId;
  const [permissions, setPermissions] = useState(/** @type {Set<string>} */ new Set());
  const [roles, setRoles] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const lastOrgRef = useRef(null);

  const loadPermissions = useCallback(async () => {
    if (!effectiveOrganizationId || !isAuthenticated) {
      setPermissions(new Set());
      setRoles([]);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    try {
      const data = await getMyPermissions(effectiveOrganizationId);
      setPermissions(new Set(data.permissions || []));
      setRoles(data.roles || []);
      lastOrgRef.current = effectiveOrganizationId;
    } catch (err) {
      console.error('Failed to load permissions:', err);
      // On error, grant no permissions (fail-closed)
      setPermissions(new Set());
      setRoles([]);
    } finally {
      setIsLoading(false);
    }
  }, [effectiveOrganizationId, isAuthenticated]);

  // Load when org changes
  useEffect(() => {
    if (effectiveOrganizationId !== lastOrgRef.current) {
      loadPermissions();
    }
  }, [effectiveOrganizationId, loadPermissions]);

  const can = useCallback(
    (resource, action) => {
      if (isLoading) return false; // Deny while loading (fail-closed)
      return hasPermission(permissions, resource, action);
    },
    [permissions, isLoading],
  );

  const canAny = useCallback(
    (checks) => {
      if (isLoading) return false;
      return hasAnyPermission(permissions, checks);
    },
    [permissions, isLoading],
  );

  const canAll = useCallback(
    (checks) => {
      if (isLoading) return false;
      return hasAllPermissions(permissions, checks);
    },
    [permissions, isLoading],
  );

  const getPermissionMessage = useCallback(
    (action) => getPermissionDeniedMessage(action),
    [],
  );

  const refresh = useCallback(async () => {
    lastOrgRef.current = null; // Force reload
    await loadPermissions();
  }, [loadPermissions]);

  return useMemo(
    () => ({
      can,
      canAny,
      canAll,
      hasPermission: can,
      getPermissionMessage,
      roles,
      isLoading,
      refresh,
    }),
    [can, canAny, canAll, getPermissionMessage, roles, isLoading, refresh],
  );
}
