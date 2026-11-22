// These application previews require explicit build selection as well as the
// independent authenticated Gateway/service switches. They are not discovery.
export function isAgentTrustFeatureEnabled(feature) {
  if (feature === 'agentDirectory') return import.meta.env.VITE_AGENT_ADMIN_ENABLED === 'true';
  if (feature === 'delegationApproval') return import.meta.env.VITE_DELEGATION_APPROVAL_ENABLED === 'true';
  return false;
}
