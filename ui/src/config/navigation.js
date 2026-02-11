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
import SettingsIcon from '@mui/icons-material/Settings';
import DesignServicesIcon from '@mui/icons-material/DesignServices';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';

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
    path: '/console',
    icon: DashboardIcon,
    exact: true,
  },
  {
    id: 'design',
    label: 'Design',
    path: '/console/design',
    icon: DesignServicesIcon,
    description: 'Trust Profiles, Credential Templates, Application Rules, Compliance',
    children: [
      { id: 'trust-profiles', label: 'Trust Profiles', path: '/console/trust/profiles' },
      { 
        id: 'credential-templates', 
        label: 'Credential Templates', 
        path: '/console/templates/credentials',
        children: [
          { id: 'application-templates', label: 'Application Rules', path: '/console/templates/applications' },
          { id: 'compliance-profiles', label: 'Compliance Profiles', path: '/console/policies/compliance' },
        ],
      },
    ],
  },
  {
    id: 'deploy',
    label: 'Deploy',
    path: '/console/deploy',
    icon: CloudUploadIcon,
    description: 'Issuance Flows, Deployment Profiles, Signing Keys',
    children: [
      { 
        id: 'issuance-flows', 
        label: 'Issuance Flows', 
        path: '/console/flows/definitions', 
        primary: true,
        icon: AccountTreeIcon,
      },
      { id: 'deployment-profiles', label: 'Deployment Profiles', path: '/console/deploy/profiles' },
      { id: 'signing-keys', label: 'Signing Keys', path: '/console/deploy/signing-keys' },
    ],
  },
  {
    id: 'operate',
    label: 'Operate',
    path: '/console/operate',
    icon: PlayArrowIcon,
    description: 'Applications, Issued Credentials, Flow Instances',
    children: [
      { id: 'applications', label: 'Applicant Submissions', path: '/console/operate/applications', badge: true },
      { id: 'issued-credentials', label: 'Issued Credentials', path: '/console/operate/issuance' },
      { id: 'flow-instances', label: 'Flow Instances', path: '/console/operate/flow-instances' },
    ],
  },
  {
    id: 'org',
    label: 'Org',
    path: '/console/org',
    icon: BusinessIcon,
    description: 'Organization, Team, Notifications',
    children: [
      { id: 'organization', label: 'Organization', path: '/console/org/settings' },
      { id: 'team', label: 'Team', path: '/console/org/team' },
      { id: 'notifications', label: 'Notifications', path: '/console/org/notifications' },
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
 * Emphasizes flow creation as the primary action.
 */
export const DASHBOARD_QUICK_ACTIONS = {
  adminVendor: [
    { id: 'create-flow', label: 'Create Issuance Flow', path: '/console/flows/definitions/new', icon: AccountTreeIcon, primary: true },
    { id: 'create-trust-profile', label: 'Create Trust Profile', path: '/console/trust/profiles/new', icon: VerifiedUserIcon },
    { id: 'create-template', label: 'Create Credential Template', path: '/console/templates/credentials/new', icon: DescriptionIcon },
    { id: 'create-policy', label: 'Create Compliance Profile', path: '/console/policies/compliance/new', icon: PolicyIcon },
    { id: 'generate-signing-key', label: 'Generate Signing Key', path: '/console/deploy/signing-keys/new', icon: CloudUploadIcon },
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
