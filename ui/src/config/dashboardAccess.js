// Match the native resource permissions used by the dashboard's backing APIs.
const RESOURCE_PERMISSIONS = {
  complianceProfiles: 'compliance-profile',
  trustProfiles: 'trust-profile',
  issuerIdentities: 'signing-key',
  templates: 'credential-template',
  applicationTemplates: 'application-template',
  deliveryDestinations: 'wallet',
  policySets: 'policy-set',
  policies: 'presentation-policy',
  revocationProfiles: 'revocation-profile',
  deployments: 'deployment-profile',
  flows: 'flow-definition',
  apiKeys: 'api-key',
};

const QUICK_ACTION_RESOURCES = {
  'register-signing-service': 'signing-key',
  'create-issuer-identity': 'signing-key',
  'create-trust-profile': 'trust-profile',
  'create-template': 'credential-template',
  'create-policy': 'presentation-policy',
  'generate-api-key': 'api-key',
  'create-flow': 'flow-definition',
};

export function getDashboardAccess(can, permissionsLoading = false) {
  const allowed = (resource, action = 'view') => !permissionsLoading
    && typeof can === 'function' && Boolean(can(resource, action));
  const resources = Object.fromEntries(
    Object.entries(RESOURCE_PERMISSIONS).map(([key, resource]) => [key, allowed(resource)]),
  );
  const organization = allowed('organization');
  const issuance = allowed('issuance');
  return {
    ...resources,
    physicalDocumentCapabilities: issuance,
    environment: organization,
    lifecycle: organization,
    integrationInfo: organization,
    teamData: allowed('team'),
    criticalEvents: allowed('audit'),
    applicantStats: allowed('application', 'review'),
    issuanceMetrics: issuance,
    notifications: allowed('notification'),
    // The gateway composes this response by reading all four native resources.
    runtimeStatus: organization && ['templates', 'policies', 'deployments', 'flows']
      .every((key) => resources[key]),
    healthOverview: ['trustProfiles', 'templates', 'policies', 'deployments', 'flows']
      .every((key) => resources[key]),
    // Setup recipes must not interpret resources outside the user's access as missing.
    setupOverview: organization && issuance && Object.values(resources).every(Boolean),
    actions: Object.fromEntries(Object.entries(QUICK_ACTION_RESOURCES)
      .map(([key, resource]) => [key, allowed(resource, 'create')])),
  };
}
