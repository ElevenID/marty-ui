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
import { listTrustProfiles, listCredentialTemplates, listPresentationPolicies, listRevocationProfiles } from '../services/presentationPolicyApi';
import { listDeploymentProfiles } from '../services/deploymentProfilesApi';
import { listFlows } from '../services/flowsApi';
import { listApiKeys } from '../services/apiKeysApi';
import { listApplicationTemplates } from '../services/applicationTemplatesApi';
import { listDeliveryDestinations } from '../services/deliveryDestinationsApi';
import { listPolicySets } from '../services/policySetsApi';
import { getPhysicalDocumentCapabilities } from '../services/physicalDocumentsApi';
import { getKeyManagementConfig, listIssuerProfiles, listSigningKeys } from '../services/signingKeysApi';
import { 
  getTeamSnapshot, 
  getRuntimeStatus, 
  getCriticalEvents,
  getOrganizationEnvironment,
  getOrganizationLifecycle,
} from '../services/dashboardApi';
import {
  DEFAULT_KEY_MANAGEMENT_CONFIG,
  normalizeKeyManagementConfig,
} from '../components/console/deploy/keyManagementServiceCatalog';
import { useAuth } from './useAuth';
import { useConsole } from '../contexts/ConsoleContext';

const SHOULD_LOG_DASHBOARD_HOOK_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';

function logDashboardHookError(message, error) {
  if (SHOULD_LOG_DASHBOARD_HOOK_DIAGNOSTICS) {
    console.error(message, error);
  }
}

function createEmptyDashboardData() {
  return {
    trustProfiles: [],
    signingKeys: [],
    issuerProfiles: [],
    keyManagementConfig: DEFAULT_KEY_MANAGEMENT_CONFIG,
    templates: [],
    applicationTemplates: [],
    deliveryDestinations: [],
    policySets: [],
    physicalDocumentCapabilities: null,
    policies: [],
    revocationProfiles: [],
    deployments: [],
    flows: [],
    apiKeys: [],
    systemHealth: null,
    teamData: null,
    runtimeStatus: null,
    criticalEvents: [],
    environment: null,
    lifecycle: null,
    resourceErrors: {},
    dashboardErrors: {},
  };
}

/**
 * Fetch all dashboard data in parallel
 * @returns {Object} Dashboard data and loading state
 */
export function useDashboardData() {
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;
  const [data, setData] = useState(() => createEmptyDashboardData());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refetchTrigger, setRefetchTrigger] = useState(0);

  const refetch = () => {
    setRefetchTrigger((prev) => prev + 1);
  };

  useEffect(() => {
    if (!organizationId) {
      setData(createEmptyDashboardData());
      setError('organization_id is required');
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
          applicationTemplatesRes,
          deliveryDestinationsRes,
          policySetsRes,
          physicalCapabilitiesRes,
          policiesRes,
          revocationProfilesRes,
          deploymentsRes,
          flowsRes,
          signingKeysRes,
          issuerProfilesRes,
          keyManagementConfigRes,
          apiKeysRes,
          healthRes,
          teamRes,
          runtimeRes,
          eventsRes,
          environmentRes,
          lifecycleRes,
        ] = await Promise.allSettled([
          listTrustProfiles({ organization_id: organizationId }),
          listCredentialTemplates({ organization_id: organizationId }),
          listApplicationTemplates(organizationId),
          listDeliveryDestinations({ organizationId, activeOnly: true }),
          listPolicySets(organizationId),
          getPhysicalDocumentCapabilities(),
          listPresentationPolicies({ organization_id: organizationId }),
          listRevocationProfiles({ organization_id: organizationId }),
          listDeploymentProfiles({ organization_id: organizationId }),
          listFlows({ organization_id: organizationId }),
          listSigningKeys({ organization_id: organizationId, limit: 1 }),
          listIssuerProfiles({ organization_id: organizationId }),
          getKeyManagementConfig({ organization_id: organizationId }),
          listApiKeys(organizationId),
          fetch('/health').then((r) => (r.ok ? r.json() : { status: 'error' })),
          getTeamSnapshot(organizationId),
          getRuntimeStatus(organizationId),
          getCriticalEvents(organizationId),
          getOrganizationEnvironment(organizationId),
          getOrganizationLifecycle(organizationId),
        ]);

        if (!mounted) return;

        const rawSigningKeys = signingKeysRes.status === 'fulfilled' ? signingKeysRes.value : [];
        const rawIssuerProfiles = issuerProfilesRes.status === 'fulfilled' ? issuerProfilesRes.value : { profiles: [] };
        const rawKeyManagementConfig = keyManagementConfigRes.status === 'fulfilled'
          ? keyManagementConfigRes.value
          : DEFAULT_KEY_MANAGEMENT_CONFIG;
        const rejectedReason = (result) => (result.status === 'rejected' ? result.reason : null);
        const dashboardErrors = {
          teamData: rejectedReason(teamRes),
          runtimeStatus: rejectedReason(runtimeRes),
          criticalEvents: rejectedReason(eventsRes),
          environment: rejectedReason(environmentRes),
          lifecycle: rejectedReason(lifecycleRes),
        };
        const resourceErrors = {
          trustProfiles: rejectedReason(trustProfilesRes),
          templates: rejectedReason(templatesRes),
          applicationTemplates: rejectedReason(applicationTemplatesRes),
          deliveryDestinations: rejectedReason(deliveryDestinationsRes),
          policySets: rejectedReason(policySetsRes),
          physicalDocumentCapabilities: rejectedReason(physicalCapabilitiesRes),
          policies: rejectedReason(policiesRes),
          revocationProfiles: rejectedReason(revocationProfilesRes),
          deployments: rejectedReason(deploymentsRes),
          flows: rejectedReason(flowsRes),
          apiKeys: rejectedReason(apiKeysRes),
          signingKeys: rejectedReason(signingKeysRes),
          issuerProfiles: rejectedReason(issuerProfilesRes),
          keyManagementConfig: rejectedReason(keyManagementConfigRes),
        };

        setData({
          trustProfiles: trustProfilesRes.status === 'fulfilled' ? trustProfilesRes.value : [],
          signingKeys: Array.isArray(rawSigningKeys)
            ? rawSigningKeys
            : (Array.isArray(rawSigningKeys?.keys) ? rawSigningKeys.keys : []),
          issuerProfiles: Array.isArray(rawIssuerProfiles?.profiles) ? rawIssuerProfiles.profiles : [],
          keyManagementConfig: normalizeKeyManagementConfig(rawKeyManagementConfig || DEFAULT_KEY_MANAGEMENT_CONFIG),
          templates: templatesRes.status === 'fulfilled' ? templatesRes.value : [],
          applicationTemplates: applicationTemplatesRes.status === 'fulfilled' ? applicationTemplatesRes.value : [],
          deliveryDestinations: deliveryDestinationsRes.status === 'fulfilled' ? deliveryDestinationsRes.value : [],
          policySets: policySetsRes.status === 'fulfilled' ? policySetsRes.value : [],
          physicalDocumentCapabilities: physicalCapabilitiesRes.status === 'fulfilled' ? physicalCapabilitiesRes.value : null,
          policies: policiesRes.status === 'fulfilled' ? policiesRes.value : [],
          revocationProfiles: revocationProfilesRes.status === 'fulfilled' ? revocationProfilesRes.value : [],
          deployments: deploymentsRes.status === 'fulfilled' ? deploymentsRes.value : [],
          flows: flowsRes.status === 'fulfilled' ? flowsRes.value : [],
          apiKeys: apiKeysRes.status === 'fulfilled' ? apiKeysRes.value : [],
          systemHealth: healthRes.status === 'fulfilled' ? healthRes.value : null,
          teamData: teamRes.status === 'fulfilled' ? teamRes.value : null,
          runtimeStatus: runtimeRes.status === 'fulfilled' ? runtimeRes.value : null,
          criticalEvents: eventsRes.status === 'fulfilled' ? eventsRes.value : [],
          environment: environmentRes.status === 'fulfilled' ? environmentRes.value : null,
          lifecycle: lifecycleRes.status === 'fulfilled' ? lifecycleRes.value : null,
          resourceErrors,
          dashboardErrors,
        });
      } catch (err) {
        if (!mounted) return;
        logDashboardHookError('Error loading dashboard data:', err);
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
        logDashboardHookError('Health check failed:', err);
      }
    }, 60000);

    return () => {
      mounted = false;
      clearInterval(healthInterval);
    };
  }, [organizationId, refetchTrigger]);

  return { data, loading, error, refetch };
}
