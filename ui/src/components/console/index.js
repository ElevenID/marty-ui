/**
 * Console Pages Index
 * 
 * All pages under /console namespace for authenticated admin/vendor users.
 */

// Dashboard
export { default as ConsoleDashboard } from './ConsoleDashboard';

// Trust
export { default as TrustPage } from './trust/TrustPage';
export { default as TrustProfilesPage } from './trust/TrustProfilesPage';
export { default as TrustedIssuersPage } from './trust/TrustedIssuersPage';
export { default as RevocationProfilesPage } from './trust/RevocationProfilesPage';
export { default as TrustProfileWizard } from './trust/TrustProfileWizard';

// Templates
export { default as TemplatesPage } from './templates/TemplatesPage';
export { default as CredentialTemplatesPage } from './templates/CredentialTemplatesPage';
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
export { default as LanesDevicesPage } from './deploy/LanesDevicesPage';
export { default as DeploymentProfileWizard } from './deploy/DeploymentProfileWizard';

// Flows
export { default as FlowsPage } from './flows/FlowsPage';
export { default as FlowDefinitionsPage } from './flows/FlowDefinitionsPage';
export { default as FlowInstancesPage } from './flows/FlowInstancesPage';
export { default as FlowDefinitionWizard } from './flows/FlowDefinitionWizard';

// Operate
export { default as OperatePage } from './operate/OperatePage';
export { default as IssuancePage } from './operate/IssuancePage';
export { default as ApplicationsPage } from './operate/ApplicationsPage';

// Org
export { default as OrgPage } from './org/OrgPage';
export { default as OrganizationSettingsPage } from './org/OrganizationSettingsPage';
export { default as TeamPage } from './org/TeamPage';
export { default as WebhooksPage } from './org/WebhooksPage';

// Audit
export { default as AuditPage } from './audit/AuditPage';

// Applicant
export { default as ApplicantDashboard } from './applicant/ApplicantDashboard';
export { default as MyCredentialsPage } from './applicant/MyCredentialsPage';
export { default as MyApplicationsPage } from './applicant/MyApplicationsPage';
export { default as ApplicantSettingsPage } from './applicant/ApplicantSettingsPage';
