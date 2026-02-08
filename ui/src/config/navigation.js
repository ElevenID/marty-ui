/**
 * Navigation Configuration
 * 
 * Defines role-based navigation structures for the ElevenID Identity Management UI.
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
import PersonIcon from '@mui/icons-material/Person';

/**
 * Admin/Vendor Navigation (Resource-based)
 * Used by both Administrator and Vendor roles.
 * Data scope differs by role (Admin sees all orgs, Vendor sees their org).
 */
export const ADMIN_VENDOR_NAV = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    path: '/console',
    icon: DashboardIcon,
    exact: true,
  },
  {
    id: 'trust',
    label: 'Trust',
    path: '/console/trust',
    icon: VerifiedUserIcon,
    description: 'Trust Profiles, Trusted Issuers, Revocation',
    children: [
      { id: 'trust-profiles', label: 'Trust Profiles', path: '/console/trust/profiles' },
      { id: 'trusted-issuers', label: 'Trusted Issuers', path: '/console/trust/issuers' },
      { id: 'revocation', label: 'Revocation Profiles', path: '/console/trust/revocation' },
    ],
  },
  {
    id: 'templates',
    label: 'Templates',
    path: '/console/templates',
    icon: DescriptionIcon,
    description: 'Credential & Application Templates',
    children: [
      { id: 'credential-templates', label: 'Credential Templates', path: '/console/templates/credentials' },
      { id: 'application-templates', label: 'Application Templates', path: '/console/templates/applications' },
    ],
  },
  {
    id: 'policies',
    label: 'Policies',
    path: '/console/policies',
    icon: PolicyIcon,
    description: 'Presentation Policies, Compliance Profiles',
    children: [
      { id: 'presentation-policies', label: 'Presentation Policies', path: '/console/policies/presentation' },
      { id: 'compliance-profiles', label: 'Compliance Profiles', path: '/console/policies/compliance' },
    ],
  },
  {
    id: 'deploy',
    label: 'Deploy',
    path: '/console/deploy',
    icon: CloudUploadIcon,
    description: 'Deployment Profiles, API Keys, Webhooks',
    children: [
      { id: 'deployment-profiles', label: 'Deployment Profiles', path: '/console/deploy/profiles' },
      { id: 'api-keys', label: 'API Keys', path: '/console/deploy/api-keys' },
      { id: 'lanes-devices', label: 'Lanes & Devices', path: '/console/deploy/lanes' },
      { id: 'webhooks', label: 'Webhooks', path: '/console/deploy/webhooks' },
    ],
  },
  {
    id: 'flows',
    label: 'Flows',
    path: '/console/flows',
    icon: AccountTreeIcon,
    description: 'Flow Definitions',
    children: [
      { id: 'flow-definitions', label: 'Flow Definitions', path: '/console/flows/definitions' },
    ],
  },
  {
    id: 'operate',
    label: 'Operate',
    path: '/console/operate',
    icon: PlayArrowIcon,
    description: 'Run issuance, process applications, and manage live activity',
    children: [
      { id: 'issuance', label: 'Issuance', path: '/console/operate/issuance' },
      { id: 'applications', label: 'Applications', path: '/console/operate/applications' },
      { id: 'flow-instances', label: 'Flow Instances', path: '/console/operate/flow-instances' },
    ],
  },
  {
    id: 'org',
    label: 'Org',
    path: '/console/org',
    icon: BusinessIcon,
    description: 'Organization, Team, Profile',
    children: [
      { id: 'organization', label: 'Organization', path: '/console/org/settings' },
      { id: 'team', label: 'Team', path: '/console/org/team' },
    ],
  },
  {
    id: 'audit',
    label: 'Audit',
    path: '/console/audit',
    icon: HistoryIcon,
    description: 'Audit Events',
    exact: true,
  },
];

/**
 * Applicant Navigation (Consumer-focused)
 * Simple, task-oriented navigation for end-users.
 */
export const APPLICANT_NAV = [
  {
    id: 'my-credentials',
    label: 'My Credentials',
    path: '/credentials',
    icon: BadgeIcon,
    exact: true,
  },
  {
    id: 'my-applications',
    label: 'My Applications',
    path: '/my-applications',
    icon: FolderSharedIcon,
    exact: true,
  },
  {
    id: 'catalog',
    label: 'Catalog',
    path: '/catalog',
    icon: StorefrontIcon,
    exact: true,
  },
  {
    id: 'profile',
    label: 'Profile',
    path: '/profile',
    icon: PersonIcon,
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
  { id: 'how-it-works', label: 'How It Works', path: '/identity' },
  { id: 'why-verifiable', label: 'Why Verifiable Identity', path: '/from-idv-to-verifiable-identity' },
  { id: 'standards', label: 'Standards', path: '/standards' },
  { id: 'docs', label: 'Docs', path: '/docs' },
  { id: 'pricing', label: 'Pricing', path: '/pricing' },
];

/**
 * Quick Actions for Dashboard
 * Role-specific quick action buttons.
 */
export const DASHBOARD_QUICK_ACTIONS = {
  adminVendor: [
    { id: 'create-trust-profile', label: 'Create Trust Profile', path: '/console/trust/profiles/new', icon: VerifiedUserIcon },
    { id: 'create-template', label: 'Create Template', path: '/console/templates/credentials/new', icon: DescriptionIcon },
    { id: 'create-policy', label: 'Create Policy', path: '/console/policies/presentation/new', icon: PolicyIcon },
    { id: 'generate-api-key', label: 'Generate API Key', path: '/console/deploy/api-keys/new', icon: CloudUploadIcon },
    { id: 'start-verification', label: 'Start Verification Flow', path: '/console/flows/definitions/new', icon: AccountTreeIcon },
  ],
  applicant: [
    { id: 'browse-catalog', label: 'Browse Credentials', path: '/catalog', icon: StorefrontIcon },
    { id: 'view-applications', label: 'View Applications', path: '/my-applications', icon: FolderSharedIcon },
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
export function findActiveNavItem(navItems, pathname) {
  for (const item of navItems) {
    if (item.exact && pathname === item.path) {
      return { parent: item, child: null };
    }
    if (!item.exact && pathname.startsWith(item.path)) {
      // Check children first for more specific match
      if (item.children) {
        for (const child of item.children) {
          if (pathname.startsWith(child.path)) {
            return { parent: item, child };
          }
        }
      }
      return { parent: item, child: null };
    }
  }
  return { parent: null, child: null };
}
