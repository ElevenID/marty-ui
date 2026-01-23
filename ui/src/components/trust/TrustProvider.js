/**
 * Trust Provider Context
 * 
 * React context for trust services following hexagonal architecture.
 * Provides ITrustService and ICertParser instances via hooks.
 * 
 * Uses factory function to create appropriate adapter based on environment.
 */

import React, { createContext, useContext, useMemo, useState, useCallback } from 'react';
import { createTrustService, createCertParser } from './adapters';
import { createDefaultTrustProfile, createDefaultHealthStatus } from './ports/types';

/**
 * Trust context value type.
 * @typedef {Object} TrustContextValue
 * @property {import('./adapters/api/TrustApiAdapter').default|import('./adapters/mock/MockTrustAdapter').default} trustService
 * @property {import('./adapters/parsing/NodeForgeCertParser').default} certParser
 * @property {import('./ports/types').TrustProfile|null} trustProfile - Current org trust profile
 * @property {import('./ports/types').TrustHealthStatus|null} healthStatus - Current health status
 * @property {boolean} loading - Loading state
 * @property {string|null} error - Error message
 * @property {function(string): Promise<void>} loadTrustProfile - Load profile for org
 * @property {function(Partial<import('./ports/types').TrustProfile>): Promise<void>} updateTrustProfile - Update profile
 * @property {function(): Promise<void>} refreshHealth - Refresh health status
 */

const TrustContext = createContext(null);

/**
 * Trust Provider Component.
 * 
 * Wraps children with trust service context.
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children
 * @param {Object} [props.config] - Service configuration
 * @param {boolean} [props.config.useMock] - Force mock adapter
 * @param {string} [props.config.baseUrl] - API base URL override
 * @param {string} [props.organizationId] - Pre-load profile for this org
 */
export const TrustProvider = ({ children, config = {}, organizationId = null }) => {
  // Create service instances (memoized)
  const trustService = useMemo(() => createTrustService(config), [config]);
  const certParser = useMemo(() => createCertParser(), []);

  // State
  const [trustProfile, setTrustProfile] = useState(null);
  const [healthStatus, setHealthStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [currentOrgId, setCurrentOrgId] = useState(organizationId);

  /**
   * Load trust profile for an organization.
   */
  const loadTrustProfile = useCallback(async (orgId) => {
    if (!orgId) {
      setTrustProfile(null);
      setHealthStatus(null);
      return;
    }

    setLoading(true);
    setError(null);
    setCurrentOrgId(orgId);

    try {
      const [profile, health] = await Promise.all([
        trustService.getTrustConfig(orgId),
        trustService.getTrustHealth(orgId),
      ]);
      setTrustProfile(profile);
      setHealthStatus(health);
    } catch (err) {
      console.error('Failed to load trust profile:', err);
      
      // Don't show auth errors to user - these are expected until backend is ready
      const isAuthError = err.message?.toLowerCase().includes('auth') || 
                          err.message?.toLowerCase().includes('401') ||
                          err.message?.toLowerCase().includes('403');
      
      if (!isAuthError) {
        setError(err.message);
      }
      
      // Set defaults on error (silent fallback)
      setTrustProfile(createDefaultTrustProfile(orgId));
      setHealthStatus(createDefaultHealthStatus());
    } finally {
      setLoading(false);
    }
  }, [trustService]);

  /**
   * Update trust profile.
   */
  const updateTrustProfile = useCallback(async (updates) => {
    if (!currentOrgId) {
      throw new Error('No organization ID set');
    }

    setLoading(true);
    setError(null);

    try {
      const updated = await trustService.updateTrustConfig(currentOrgId, updates);
      setTrustProfile(updated);
      
      // Refresh health after update
      const health = await trustService.getTrustHealth(currentOrgId);
      setHealthStatus(health);
      
      return updated;
    } catch (err) {
      console.error('Failed to update trust profile:', err);
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [trustService, currentOrgId]);

  /**
   * Refresh health status.
   */
  const refreshHealth = useCallback(async () => {
    if (!currentOrgId) return;

    try {
      const health = await trustService.getTrustHealth(currentOrgId);
      setHealthStatus(health);
    } catch (err) {
      console.error('Failed to refresh health:', err);
    }
  }, [trustService, currentOrgId]);

  /**
   * Upload BYOK certificates.
   */
  const uploadCertificates = useCallback(async (certificates) => {
    if (!currentOrgId) {
      throw new Error('No organization ID set');
    }

    setLoading(true);
    setError(null);

    try {
      const result = await trustService.uploadBYOKCertificates(currentOrgId, certificates);
      
      // Reload profile and health after upload
      await loadTrustProfile(currentOrgId);
      
      return result;
    } catch (err) {
      console.error('Failed to upload certificates:', err);
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [trustService, currentOrgId, loadTrustProfile]);

  /**
   * Generate a new signing key.
   */
  const generateKey = useCallback(async (options = {}) => {
    if (!currentOrgId) {
      throw new Error('No organization ID set');
    }

    setLoading(true);
    setError(null);

    try {
      const result = await trustService.generateKey(currentOrgId, options);
      
      // Reload profile and health after generation
      await loadTrustProfile(currentOrgId);
      
      return result;
    } catch (err) {
      console.error('Failed to generate key:', err);
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [trustService, currentOrgId, loadTrustProfile]);

  /**
   * Test key connection.
   */
  const testKeyConnection = useCallback(async (keyConfig) => {
    if (!currentOrgId) {
      throw new Error('No organization ID set');
    }

    return trustService.testKeyConnection(currentOrgId, keyConfig);
  }, [trustService, currentOrgId]);

  const contextValue = useMemo(() => ({
    // Services
    trustService,
    certParser,
    
    // State
    trustProfile,
    healthStatus,
    loading,
    error,
    organizationId: currentOrgId,
    
    // Actions
    loadTrustProfile,
    updateTrustProfile,
    refreshHealth,
    uploadCertificates,
    generateKey,
    testKeyConnection,
  }), [
    trustService,
    certParser,
    trustProfile,
    healthStatus,
    loading,
    error,
    currentOrgId,
    loadTrustProfile,
    updateTrustProfile,
    refreshHealth,
    uploadCertificates,
    generateKey,
    testKeyConnection,
  ]);

  return (
    <TrustContext.Provider value={contextValue}>
      {children}
    </TrustContext.Provider>
  );
};

/**
 * Hook to access trust service.
 * @returns {import('./adapters/api/TrustApiAdapter').default|import('./adapters/mock/MockTrustAdapter').default}
 */
export const useTrustService = () => {
  const context = useContext(TrustContext);
  if (!context) {
    throw new Error('useTrustService must be used within a TrustProvider');
  }
  return context.trustService;
};

/**
 * Hook to access certificate parser.
 * @returns {import('./adapters/parsing/NodeForgeCertParser').default}
 */
export const useCertParser = () => {
  const context = useContext(TrustContext);
  if (!context) {
    throw new Error('useCertParser must be used within a TrustProvider');
  }
  return context.certParser;
};

/**
 * Hook to access full trust context.
 * @returns {TrustContextValue}
 */
export const useTrust = () => {
  const context = useContext(TrustContext);
  if (!context) {
    throw new Error('useTrust must be used within a TrustProvider');
  }
  return context;
};

export default TrustProvider;
