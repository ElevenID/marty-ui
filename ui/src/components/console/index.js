/**
 * Console Pages Index
 * 
 * All pages under /console namespace for authenticated admin/vendor users.
 */

// Dashboard
export { default as ConsoleDashboard } from './ConsoleDashboard';
export { default as GuidedSetupWizard } from './dashboard/GuidedSetupWizard';

// Trust
export { default as TrustPage } from './trust/TrustPage';
export { default as TrustProfilesPage } from './trust/TrustProfilesPage';
export { default as RevocationProfilesPage } from './trust/RevocationProfilesPage';
export { default as TrustProfileWizard } from './trust/TrustProfileWizard';
export { default as TrustProfileDetailPage } from './trust/TrustProfileDetailPage';
export { default as TrustProfileEditPage } from './trust/TrustProfileEditPage';
export { default as RevocationProfileDetailPage } from './trust/RevocationProfileDetailPage';
export { default as RevocationProfileWizard } from './trust/RevocationProfileWizard';

// Templates
export { default as TemplatesPage } from './templates/TemplatesPage';
export { default as CredentialTemplatesPage } from './templates/CredentialTemplatesPage';
export { default as CredentialTemplateDetailPage } from './templates/CredentialTemplateDetailPage';
export { default as ApplicationTemplatesPage } from './templates/ApplicationTemplatesPage';
export { default as CredentialTemplateWizard } from './templates/CredentialTemplateWizard';

// Policies
export { default as PoliciesPage } from './policies/PoliciesPage';
export { default as PresentationPoliciesPage } from './policies/PresentationPoliciesPage';
export { default as ComplianceProfilesPage } from './policies/ComplianceProfilesPage';
export { default as PresentationPolicyWizard } from './policies/PresentationPolicyWizard';

// Deploy
export { default as DeployPage } from './deploy/DeployPage';
export { default as DeploymentProfilesPage } from './deploy/DeploymentsPage';
export { default as ApiKeysPage } from './deploy/ApiKeysPage';
export { default as DidIdentitiesPage } from './deploy/DidIdentitiesPage';
export { default as SigningKeysPage } from './deploy/SigningKeysPage';
export { default as CanvasIntegrationsPage } from './deploy/CanvasIntegrationsPage';
export { default as KeyManagementServiceWizard } from './deploy/KeyManagementServiceWizard';
export { default as IssuerIdentityWizard } from './deploy/IssuerIdentityWizard';
export { default as LanesDevicesPage } from './deploy/LanesDevicesPage';
export { default as DeploymentProfileWizard } from './deploy/DeploymentProfileWizard';

// Flows
export { default as FlowsPage } from './flows/FlowsPage';
export { default as FlowDefinitionsPage } from './flows/FlowDefinitionsPage';
export { default as FlowInstancesPage } from './flows/FlowInstancesPage';
export { default as FlowDefinitionWizard } from './flows/FlowDefinitionWizard';
export { default as FlowDetailPage } from './flows/FlowDetailPage';

// Operate
export { default as OperatePage } from './operate/OperatePage';
export { default as IssuancePage } from './operate/IssuancePage';
export { default as ApplicationsPage } from './operate/ApplicationsPage';
export { default as ApplicationReviewPage } from './operate/ApplicationReviewPage';
export { default as VerificationSessionsPage } from './operate/VerificationSessionsPage';

// Org
export { default as OrgPage } from './org/OrgPage';
export { default as OrganizationSettingsPage } from './org/OrganizationSettingsPage';
export { default as OrgSetupPage } from './org/OrgSetupPage';
export { default as TeamPage } from './org/TeamPage';
export { default as RolesPage } from './org/RolesPage';
export { default as NotificationsPage } from './org/NotificationsPage';
export { default as MembershipRequestsPage } from './org/MembershipRequestsPage';
export { default as RoleEscalationRequestsPage } from './org/RoleEscalationRequestsPage';
export { default as NotificationPreferencesPage } from './NotificationPreferencesPage';
export { default as WebhooksPage } from './org/WebhooksPage';

// Audit
export { default as AuditPage } from './audit/AuditPage';

// Billing & Usage — moved to @marty/subscriptions, re-exported for backward compatibility
export { UsageDashboard } from '@marty/subscriptions';

// Applicant
export { default as ApplicantDashboard } from './applicant/ApplicantDashboard';
export { default as MyCredentialsPage } from './applicant/MyCredentialsPage';
export { default as MyApplicationsPage } from './applicant/MyApplicationsPage';
export { default as MyIdentityPage } from './applicant/MyIdentityPage';
export { default as ApplicantSettingsPage } from './applicant/ApplicantSettingsPage';
export { default as DeviceManagementPage } from './applicant/DeviceManagementPage';
