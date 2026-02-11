/**
 * Dashboard Data Hook
 * 
 * Fetches all data required for the dashboard:
 * - Setup resources (Trust Profiles, Templates, Policies, Deployments, Flows)
 * - API Keys
 * - System Health
 * - Team snapshot
 * - Runtime status
 * - Critical events
 * - Environment setting
 */

import { useState, useEffect } from 'react';
import { listTrustProfiles, listCredentialTemplates, listPresentationPolicies } from '../services/presentationPolicyApi';
import { listDeploymentProfiles } from '../services/deploymentProfilesApi';
import { listFlows } from '../services/flowsApi';
import { listApiKeys } from '../services/apiKeysApi';
import { 
  getTeamSnapshot, 
  getRuntimeStatus, 
  getCriticalEvents,
  getOrganizationEnvironment,
} from '../services/dashboardApi';
import { useAuth } from './useAuth';

/**
 * Fetch all dashboard data in parallel
 * @returns {Object} Dashboard data and loading state
 */
export function useDashboardData() {
  const { organizationId } = useAuth();
  const [data, setData] = useState({
    trustProfiles: [],
    templates: [],
    policies: [],
    deployments: [],
    flows: [],
    apiKeys: [],
    systemHealth: null,
    teamData: null,
    runtimeStatus: null,
    criticalEvents: [],
    environment: 'development',
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refetchTrigger, setRefetchTrigger] = useState(0);

  const refetch = () => {
    setRefetchTrigger((prev) => prev + 1);
  };

  useEffect(() => {
    if (!organizationId) {
      setLoading(false);
      return;
    }

    let mounted = true;

    const loadDashboardData = async () => {
      try {
        setLoading(true);
        setError(null);

        // Fetch all resources in parallel
        const [
          trustProfilesRes,
          templatesRes,
          policiesRes,
          teamRes,
          runtimeRes,
          eventsRes,
          environmentRes,
        ] = await Promise.allSettled([
          listTrustProfiles({ organization_id: organizationId }),
          listCredentialTemplates({ organization_id: organizationId }),
          listPresentationPolicies({ organization_id: organizationId }),
          listDeploymentProfiles({ organization_id: organizationId }),
          listFlows({ organization_id: organizationId }),
          listApiKeys(organizationId),
          fetch('/health').then((r) => (r.ok ? r.json() : { status: 'error' })),
          getTeamSnapshot(organizationId),
          getRuntimeStatus(organizationId),
          getCriticalEvents(organizationId),
          getOrganizationEnvironment(organizationId),
        ]);

        if (!mounted) return;

        setData({
          trustProfiles: trustProfilesRes.status === 'fulfilled' ? trustProfilesRes.value : [],
          templates: templatesRes.status === 'fulfilled' ? templatesRes.value : [],
          policies: policiesRes.status === 'fulfilled' ? policiesRes.value : [],
          deployments: deploymentsRes.status === 'fulfilled' ? deploymentsRes.value : [],
          flows: flowsRes.status === 'fulfilled' ? flowsRes.value : [],
          apiKeys: apiKeysRes.status === 'fulfilled' ? apiKeysRes.value : [],
          systemHealth: healthRes.status === 'fulfilled' ? healthRes.value : null,
          teamData: teamRes.status === 'fulfilled' ? teamRes.value : null,
          runtimeStatus: runtimeRes.status === 'fulfilled' ? runtimeRes.value : null,
          criticalEvents: eventsRes.status === 'fulfilled' ? eventsRes.value : [],
          environment: environmentRes.status === 'fulfilled' ? environmentRes.value : 'development',
        });
      } catch (err) {
        if (!mounted) return;
        console.error('Error loading dashboard data:', err);
        setError(err.message || 'Failed to load dashboard data');
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    loadDashboardData();

    // Poll system health every 60 seconds
    const healthInterval = setInterval(async () => {
      try {
        const healthRes = await fetch('/health');
        const healthData = healthRes.ok ? await healthRes.json() : { status: 'error' };
        if (mounted) {
          setData((prev) => ({ ...prev, systemHealth: healthData }));
        }
      } catch (err) {
        console.error('Health check failed:', err);
      }
    }, 60000);

    return () => {
      mounted = false;
      clearInterval(healthInterval);
    };
  }, [organizationId, refetchTrigger]);

  return { data, loading, error, refetch };
}
