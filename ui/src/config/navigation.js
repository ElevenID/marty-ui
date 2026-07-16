/**
 * Navigation Configuration
 * 
 * Defines role-based navigation structures for the ElevenID LLC Identity Management UI.
 * Following the resource-based "Configure + Operate + Monitor" model.
 */

import DashboardIcon from '@mui/icons-material/Dashboard';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import DescriptionIcon from '@mui/icons-material/Description';
import PolicyIcon from '@mui/icons-material/Policy';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import BusinessIcon from '@mui/icons-material/Business';
import HistoryIcon from '@mui/icons-material/History';
import BadgeIcon from '@mui/icons-material/Badge';
import FolderSharedIcon from '@mui/icons-material/FolderShared';
import StorefrontIcon from '@mui/icons-material/Storefront';
import SettingsIcon from '@mui/icons-material/Settings';
import DesignServicesIcon from '@mui/icons-material/DesignServices';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import IntegrationInstructionsIcon from '@mui/icons-material/IntegrationInstructions';

/**
 * Admin/Vendor Navigation (Resource-based)
 * Used by both Administrator and Vendor roles.
 * Data scope differs by role (Admin sees all orgs, Vendor sees their org).
 * 
 * Navigation hierarchy enforces the mental model:
 * - Design: Templates are inputs, not applicant-facing endpoints
 * - Deploy: Flows are the applicant-facing product ⭐
 * - Operate: Runtime execution and monitoring
 */
export const ADMIN_VENDOR_NAV = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    path: '/console/org',
    icon: DashboardIcon,
    exact: true,
  },
  {
    id: 'design',
    label: 'Design',
    path: '/console/org/design',
    icon: DesignServicesIcon,
    description: 'Credential Templates, Application Templates, Flows',
    children: [
      { 
        id: 'credential-templates', 
        label: 'Credential Templates', 
        path: '/console/org/templates/credentials',
        requiredPermission: { resource: 'credential-template', action: 'view' },
      },
      {
        id: 'application-templates',
        label: 'Application Templates',
        path: '/console/org/templates/applications',
        requiredPermission: { resource: 'application-template', action: 'view' },
      },
      {
        id: 'flows',
        label: 'Flows',
        path: '/console/org/flows/definitions',
        primary: true,
        requiredPermission: { resource: 'flow-definition', action: 'view' },
      },
    ],
  },
  {
    id: 'govern',
    label: 'Govern',
    path: '/console/org/govern',
    icon: PolicyIcon,
    description: 'Trust, lifecycle, presentation, compliance, and decision policies',
    children: [
      { id: 'trust-profiles', label: 'Trust Profiles', path: '/console/org/trust/profiles', requiredPermission: { resource: 'trust-profile', action: 'view' } },
      { id: 'revocation-profiles', label: 'Revocation Profiles', path: '/console/org/trust/revocation', requiredPermission: { resource: 'revocation-profile', action: 'view' } },
      { id: 'presentation-policies', label: 'Presentation Policies', path: '/console/org/policies/presentation', requiredPermission: { resource: 'presentation-policy', action: 'view' } },
      { id: 'compliance-profiles', label: 'Compliance Profiles', path: '/console/org/policies/compliance', requiredPermission: { resource: 'compliance-profile', action: 'view' } },
      {
        id: 'policy-sets',
        label: 'Policy Sets',
        path: '/console/org/policies/sets',
        requiredPermission: { resource: 'policy-set', action: 'view' },
      },
    ],
  },
  {
    id: 'deploy',
    label: 'Deploy',
    path: '/console/org/deploy',
    icon: CloudUploadIcon,
    description: 'Deployment Profiles, Issuer Identity, Key Management',
    children: [
      {
        id: 'deployment-profiles',
        label: 'Deployment Profiles',
        path: '/console/org/deploy/profiles',
        requiredPermission: { resource: 'deployment-profile', action: 'view' },
      },
      { id: 'issuer-identity', label: 'Issuer Identity', path: '/console/org/deploy/issuer-identity' },
      {
        id: 'key-management',
        label: 'Key Management',
        path: '/console/org/deploy/key-management',
        requiredPermission: { resource: 'signing-key', action: 'view' },
      },
    ],
  },
  {
    id: 'connect',
    label: 'Connect',
    path: '/console/org/connect',
    icon: IntegrationInstructionsIcon,
    description: 'Canvas, API Keys, Webhooks, Delivery Destinations',
    children: [
      { id: 'canvas-integrations', label: 'Canvas', path: '/console/org/deploy/canvas' },
      { id: 'api-keys', label: 'API Keys', path: '/console/org/api-keys', requiredPermission: { resource: 'api-key', action: 'view' } },
      { id: 'webhooks', label: 'Webhooks', path: '/console/org/webhooks', requiredPermission: { resource: 'webhook', action: 'view' } },
      { id: 'delivery-destinations', label: 'Delivery Destinations', path: '/console/org/connect/delivery-destinations', requiredPermission: { resource: 'delivery-destination', action: 'view' } },
    ],
  },
  {
    id: 'operate',
    label: 'Operate',
    path: '/console/org/operate',
    icon: PlayArrowIcon,
    description: 'Flow Instances, Applications, Issued Credentials, Verification Sessions',
    children: [
      {
        id: 'flow-instances',
        label: 'Flow Instances',
        path: '/console/org/operate/flow-instances',
        requiredPermission: { resource: 'flow-instance', action: 'view' },
      },
      {
        id: 'applications',
        label: 'Applicant Submissions',
        path: '/console/org/operate/applications',
        badge: true,
        requiredPermission: { resource: 'application', action: 'view' },
      },
      {
        id: 'issued-credentials',
        label: 'Issued Credentials',
        path: '/console/org/operate/issuance',
        requiredPermission: { resource: 'issuance', action: 'view' },
      },
      {
        id: 'verify',
        label: 'Verification Sessions',
        path: '/console/org/operate/verify',
        requiredPermission: { resource: 'verification', action: 'view' },
      },
    ],
  },
  {
    id: 'org',
    label: 'Org',
    path: '/console/org',
    icon: BusinessIcon,
    description: 'Organization, Team, Roles, Requests, Notifications',
    children: [
      { id: 'my-organizations', label: 'My Organizations', path: '/console/organizations' },
      { id: 'organization', label: 'Organization', path: '/console/org/settings', requiredPermission: { resource: 'organization', action: 'view' } },
      { id: 'team', label: 'Team', path: '/console/org/team', requiredPermission: { resource: 'team', action: 'view' } },
      { id: 'membership-requests', label: 'Membership Requests', path: '/console/org/membership-requests', requiredPermission: { resource: 'team', action: 'view' } },
      { id: 'roles', label: 'Roles', path: '/console/org/roles', requiredPermission: { resource: 'role', action: 'view' } },
      { id: 'role-requests', label: 'Role Requests', path: '/console/org/role-requests', requiredPermission: { resource: 'role', action: 'view' } },
      { id: 'notifications', label: 'Notifications', path: '/console/org/notifications', requiredPermission: { resource: 'notification', action: 'view' } },
    ],
  },
  {
    id: 'audit',
    label: 'Audit',
    path: '/console/org/audit',
    icon: HistoryIcon,
    description: 'Audit Events',
    exact: true,
    requiredPermission: { resource: 'audit', action: 'view' },
  },
];

/**
 * Applicant Navigation (Consumer-focused)
 * Simple, task-oriented navigation for end-users.
 */
export const APPLICANT_NAV = [
  {
    id: 'my-identity',
    label: 'My Identity',
    path: '/console/applicant/identity',
    icon: BadgeIcon,
    exact: true,
  },
  {
    id: 'catalog',
    label: 'Catalog',
    path: '/console/applicant/catalog',
    icon: StorefrontIcon,
    exact: true,
  },
  {
    id: 'organizations',
    label: 'Organizations',
    path: '/console/organizations',
    icon: BusinessIcon,
    exact: true,
  },
  {
    id: 'settings',
    label: 'Settings',
    path: '/console/applicant/settings',
    icon: SettingsIcon,
    exact: true,
  },
];

/**
 * Public Navigation (Unauthenticated)
 * Marketing and documentation pages.
 */
export const PUBLIC_NAV = [
  { id: 'home', label: 'Home', path: '/', exact: true },
  { id: 'product', label: 'Product', path: '/product' },
  { id: 'solutions', label: 'Solutions', path: '/solutions' },
  { id: 'developers', label: 'Developers', path: '/developers' },
  { id: 'standards', label: 'Standards', path: '/standards' },
  { id: 'resources', label: 'Resources', path: '/resources' },
  { id: 'pricing', label: 'Pricing', path: '/pricing' },
];

/**
 * Quick Actions for Dashboard
 * Role-specific quick action buttons.
 * Emphasizes flow creation as the primary action.
 */
export const DASHBOARD_QUICK_ACTIONS = {
  adminVendor: [
    { id: 'register-signing-service', label: 'Register Signing Service', path: '/console/org/deploy/key-management/services/new', icon: CloudUploadIcon },
    { id: 'create-issuer-identity', label: 'Set Up Issuer Identity', path: '/console/org/deploy/issuer-identity/new', icon: BadgeIcon },
    { id: 'create-trust-profile', label: 'Create Trust Profile', path: '/console/org/trust/profiles/new', icon: VerifiedUserIcon },
    { id: 'create-template', label: 'Create Credential Template', path: '/console/org/templates/credentials/new', icon: DescriptionIcon },
    { id: 'create-policy', label: 'Create Presentation Policy', path: '/console/org/policies/presentation/new', icon: PolicyIcon },
    { id: 'generate-api-key', label: 'Create API Key', path: '/console/org/api-keys', icon: CloudUploadIcon },
    { id: 'create-flow', label: 'Create Flow', path: '/console/org/flows/definitions/new', icon: AccountTreeIcon, primary: true },
  ],
  applicant: [
    { id: 'browse-catalog', label: 'Browse Credentials', path: '/console/applicant/catalog', icon: StorefrontIcon },
    { id: 'view-applications', label: 'View Applications', path: '/console/applicant/applications', icon: FolderSharedIcon },
  ],
};

/**
 * User Menu Items (Profile Dropdown)
 */
export const USER_MENU_ITEMS = [
  { id: 'profile', label: 'Profile', path: '/profile', divider: false },
  { id: 'notifications', label: 'Notifications', path: '/settings/notifications', divider: false },
  { id: 'help', label: 'Help & API Docs', path: '/docs', external: false, divider: true },
];

/**
 * Get navigation items based on user role
 */
export function getNavigationForRole(role) {
  switch (role) {
    case 'administrator':
    case 'vendor':
      return ADMIN_VENDOR_NAV;
    case 'applicant':
      return APPLICANT_NAV;
    default:
      return PUBLIC_NAV;
  }
}

/**
 * Find active navigation item based on current path
 */
function matchesPath(pathname, path, exact = false) {
  if (!path) {
    return false;
  }

  if (exact) {
    return pathname === path;
  }

  return pathname === path || pathname.startsWith(`${path}/`);
}

function findBestNavMatch(items, pathname, ancestors = []) {
  let bestMatch = null;

  for (const item of items) {
    const nextAncestors = [...ancestors, item];

    if (item.children) {
      const childMatch = findBestNavMatch(item.children, pathname, nextAncestors);
      if (
        childMatch
        && (!bestMatch
          || childMatch.matchedPath.length > bestMatch.matchedPath.length
          || (
            childMatch.matchedPath.length === bestMatch.matchedPath.length
            && childMatch.ancestors.length > bestMatch.ancestors.length
          ))
      ) {
        bestMatch = childMatch;
      }
    }

    if (matchesPath(pathname, item.path, item.exact)) {
      const itemMatch = {
        ancestors: nextAncestors,
        matchedPath: item.path,
      };

      if (
        !bestMatch
        || itemMatch.matchedPath.length > bestMatch.matchedPath.length
        || (
          itemMatch.matchedPath.length === bestMatch.matchedPath.length
          && itemMatch.ancestors.length > bestMatch.ancestors.length
        )
      ) {
        bestMatch = itemMatch;
      }
    }
  }

  return bestMatch;
}

export function findActiveNavItem(navItems, pathname) {
  const bestMatch = findBestNavMatch(navItems, pathname);

  if (!bestMatch) {
    return { parent: null, child: null };
  }

  const [parent, child] = bestMatch.ancestors;
  return {
    parent: parent || null,
    child: child || null,
  };
}
