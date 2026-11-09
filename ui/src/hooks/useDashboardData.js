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

import { useState, useEffect, useMemo, useRef } from 'react';
import { listTrustProfiles, listCredentialTemplates, listPresentationPolicies, listRevocationProfiles } from '../services/presentationPolicyApi';
import { listDeploymentProfiles } from '../services/deploymentProfilesApi';
import { listFlows } from '../services/flowsApi';
import { listApiKeys } from '../services/apiKeysApi';
import { listApplicationTemplates } from '../services/applicationTemplatesApi';
import { listDeliveryDestinations } from '../services/deliveryDestinationsApi';
import { listPolicySets } from '../services/policySetsApi';
import { listComplianceProfiles } from '../services/complianceProfilesApi';
import { loadScopedCatalog } from '../services/loadScopedCatalog';
import { getPhysicalDocumentCapabilities } from '../services/physicalDocumentsApi';
import { listPublicIssuerIdentities } from '../services/issuerIdentitiesApi';
import { getSystemHealth } from '../services/healthApi';
import { 
  getTeamSnapshot, 
  getRuntimeStatus, 
  getCriticalEvents,
  getOrganizationEnvironment,
  getOrganizationLifecycle,
} from '../services/dashboardApi';
import { useConsole } from '../contexts/ConsoleContext';
import { useAuth } from './useAuth';

const SHOULD_LOG_DASHBOARD_HOOK_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';
const HEALTH_RESOURCE_KEYS = new Set(['trustProfiles', 'templates', 'policies', 'deployments', 'flows']);

function logDashboardHookError(message, error) {
  if (SHOULD_LOG_DASHBOARD_HOOK_DIAGNOSTICS) {
    console.error(message, error);
  }
}

function createEmptyDashboardData() {
  return {
    complianceProfiles: [],
    trustProfiles: [],
    issuerIdentities: [],
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
 * Fetch authorized dashboard sections in parallel for the current account.
 * @returns {Object} Dashboard data and loading state
 */
export function useDashboardData(access = {}, permissionsLoading = false) {
  const { activeOrgId } = useConsole();
  const { user } = useAuth();
  const organizationId = activeOrgId;
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const accessKey = JSON.stringify(access);
  const scope = useMemo(() => ({ organizationId, principalId, access: JSON.parse(accessKey), permissionsLoading }),
    [organizationId, principalId, accessKey, permissionsLoading]);
  const currentScope = useRef(scope);
  currentScope.current = scope;
  const [dataScope, setDataScope] = useState(null);
  const [data, setData] = useState(() => createEmptyDashboardData());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refetchTrigger, setRefetchTrigger] = useState(0);

  const refetch = () => {
    setRefetchTrigger((prev) => prev + 1);
  };

  useEffect(() => {
    setDataScope(scope);
    setData(createEmptyDashboardData());
    setError(null);
    if (!organizationId || !principalId) {
      setError(!organizationId ? 'organization_id is required' : null);
      setLoading(false);
      return;
    }
    if (scope.permissionsLoading) {
      setLoading(true);
      return;
    }

    let mounted = true;
    const applies = () => mounted && currentScope.current === scope;
    const controller = new AbortController();
    const catalog = (list) => loadScopedCatalog(list, organizationId, { signal: controller.signal });
    const permitted = (key, load, empty = null) => scope.access[key] === true
      ? load()
      : Promise.resolve(empty);
    const resource = (key, load, empty = null) => scope.access.setupOverview
      || (scope.access.healthOverview && HEALTH_RESOURCE_KEYS.has(key))
      ? permitted(key, load, empty)
      : Promise.resolve(empty);

    const loadDashboardData = async () => {
      try {
        setLoading(true);
        setError(null);

        // Fetch all resources in parallel
        const [
          complianceProfilesRes,
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
          issuerIdentitiesRes,
          apiKeysRes,
          healthRes,
          teamRes,
          runtimeRes,
          eventsRes,
          environmentRes,
          lifecycleRes,
        ] = await Promise.allSettled([
          resource('complianceProfiles', () => catalog(listComplianceProfiles), []),
          resource('trustProfiles', () => catalog(listTrustProfiles), []),
          resource('templates', () => catalog(listCredentialTemplates), []),
          resource('applicationTemplates', () => listApplicationTemplates(organizationId), []),
          resource('deliveryDestinations', () => listDeliveryDestinations({ organizationId, activeOnly: true }), []),
          resource('policySets', () => listPolicySets(organizationId), []),
          resource('physicalDocumentCapabilities', () => getPhysicalDocumentCapabilities()),
          resource('policies', () => catalog(listPresentationPolicies), []),
          resource('revocationProfiles', () => catalog(listRevocationProfiles), []),
          resource('deployments', () => catalog(listDeploymentProfiles), []),
          resource('flows', () => catalog(listFlows), []),
          resource('issuerIdentities', () => listPublicIssuerIdentities({ organization_id: organizationId }), { identities: [] }),
          resource('apiKeys', () => listApiKeys(organizationId), []),
          getSystemHealth({ signal: controller.signal }),
          permitted('teamData', () => getTeamSnapshot(organizationId)),
          permitted('runtimeStatus', () => getRuntimeStatus(organizationId)),
          permitted('criticalEvents', () => getCriticalEvents(organizationId), []),
          permitted('environment', () => getOrganizationEnvironment(organizationId)),
          permitted('lifecycle', () => getOrganizationLifecycle(organizationId)),
        ]);

        if (!applies()) return;

        const rawIssuerIdentities = issuerIdentitiesRes.status === 'fulfilled'
          ? issuerIdentitiesRes.value
          : { identities: [] };
        const rejectedReason = (result) => (result.status === 'rejected' ? result.reason : null);
        const dashboardErrors = {
          teamData: rejectedReason(teamRes),
          runtimeStatus: rejectedReason(runtimeRes),
          criticalEvents: rejectedReason(eventsRes),
          environment: rejectedReason(environmentRes),
          lifecycle: rejectedReason(lifecycleRes),
        };
        const resourceErrors = {
          complianceProfiles: rejectedReason(complianceProfilesRes),
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
          issuerIdentities: rejectedReason(issuerIdentitiesRes),
        };

        setData({
          complianceProfiles: complianceProfilesRes.status === 'fulfilled' ? complianceProfilesRes.value : [],
          trustProfiles: trustProfilesRes.status === 'fulfilled' ? trustProfilesRes.value : [],
          issuerIdentities: Array.isArray(rawIssuerIdentities?.identities)
            ? rawIssuerIdentities.identities
            : [],
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
        if (!applies()) return;
        logDashboardHookError('Error loading dashboard data:', err);
        setError(err.message || 'Failed to load dashboard data');
      } finally {
        if (applies()) {
          setLoading(false);
        }
      }
    };

    loadDashboardData();

    // Poll system health every 60 seconds
    const healthInterval = setInterval(async () => {
      try {
        const healthData = await getSystemHealth({ signal: controller.signal });
        if (applies()) {
          setData((prev) => ({ ...prev, systemHealth: healthData }));
        }
      } catch (err) {
        logDashboardHookError('Health check failed:', err);
      }
    }, 60000);

    return () => {
      mounted = false;
      controller.abort();
      clearInterval(healthInterval);
    };
  }, [organizationId, principalId, refetchTrigger, scope]);

  const scopeCurrent = dataScope === scope;
  return {
    data: scopeCurrent ? data : createEmptyDashboardData(),
    loading: Boolean(organizationId && principalId) && (!scopeCurrent || loading),
    error: scopeCurrent ? error : null,
    refetch,
  };
}
