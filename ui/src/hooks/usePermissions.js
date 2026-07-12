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

const permissionsCache = new Map();
const inflightPermissionsRequests = new Map();

// System/sentinel org IDs that backend policy blocks member-level operations on.
const SYSTEM_ORG_IDS = new Set([
  '00000000-0000-0000-0000-000000000001',
]);

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
  const { isAuthenticated } = useAuth();
  const { activeOrgId, memberships, membershipsLoaded, mode } = useConsole();
  // Never fall through to the system/sentinel org — it's policy-blocked for member operations.
  const hasSelectedMembership = membershipsLoaded && Array.isArray(memberships)
    && memberships.some((membership) => membership.id === activeOrgId);
  const effectiveOrganizationId = mode === 'org' && hasSelectedMembership
    && !SYSTEM_ORG_IDS.has(activeOrgId)
    ? activeOrgId
    : null;
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

    const cached = permissionsCache.get(effectiveOrganizationId);
    if (cached) {
      setPermissions(new Set(cached.permissions || []));
      setRoles(cached.roles || []);
      setIsLoading(false);
      lastOrgRef.current = effectiveOrganizationId;
      return;
    }

    setIsLoading(true);

    const existingRequest = inflightPermissionsRequests.get(effectiveOrganizationId);
    if (existingRequest) {
      try {
        const data = await existingRequest;
        setPermissions(new Set(data.permissions || []));
        setRoles(data.roles || []);
      } catch {
        setPermissions(new Set());
        setRoles([]);
      } finally {
        setIsLoading(false);
        lastOrgRef.current = effectiveOrganizationId;
      }
      return;
    }

    const request = getMyPermissions(effectiveOrganizationId);
    inflightPermissionsRequests.set(effectiveOrganizationId, request);

    try {
      const data = await request;
      permissionsCache.set(effectiveOrganizationId, {
        permissions: data.permissions || [],
        roles: data.roles || [],
      });
      setPermissions(new Set(data.permissions || []));
      setRoles(data.roles || []);
      lastOrgRef.current = effectiveOrganizationId;
    } catch (err) {
      // 403 is expected for routes where this endpoint is policy-protected.
      if (err?.status === 403) {
        permissionsCache.set(effectiveOrganizationId, {
          permissions: [],
          roles: [],
        });
      } else {
        console.error('Failed to load permissions:', err);
      }
      // On error, grant no permissions (fail-closed)
      setPermissions(new Set());
      setRoles([]);
      lastOrgRef.current = effectiveOrganizationId;
    } finally {
      inflightPermissionsRequests.delete(effectiveOrganizationId);
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
    if (effectiveOrganizationId) {
      permissionsCache.delete(effectiveOrganizationId);
      inflightPermissionsRequests.delete(effectiveOrganizationId);
    }
    lastOrgRef.current = null; // Force reload
    await loadPermissions();
  }, [effectiveOrganizationId, loadPermissions]);

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
