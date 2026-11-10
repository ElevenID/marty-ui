/** Shared Operate destinations, in the same order as the console sidebar. */
export function getOperateTabs(t) {
  return [
    { label: t('flows.flowInstances'), path: '/console/org/operate/flow-instances' },
    { label: t('operate.tabs.applications'), path: '/console/org/operate/applications' },
    { label: t('operate.tabs.issuance'), path: '/console/org/operate/issuance' },
    { label: t('policies.verificationSessions'), path: '/console/org/operate/verify' },
  ];
}
