export const IS_SELFHOST_UI = true;
export const SELFHOST_PUBLIC_PROFILE = import.meta.env.VITE_SELFHOST_PUBLIC_PROFILE || 'full';
if (!['full', 'tester'].includes(SELFHOST_PUBLIC_PROFILE)) {
  throw new Error('Unsupported self-host public profile');
}

// Both historical customer profile names exclude production marketing. The
// full profile additionally advertises the deployment's API documentation.
export const SHOW_PUBLIC_DEMOS = false;
export const SHOW_PUBLIC_DOCUMENTATION_NAV = SELFHOST_PUBLIC_PROFILE !== 'tester';

export function getSelfhostPublicUiFlags(_hostname = '') {
  return {
    showPublicLoginButton: true,
    disablePublicLoginButton: false,
    showPublicGetStartedButtons: false,
    disablePublicGetStartedButtons: true,
    showPublicPricingButtons: false,
    disablePublicPricingButtons: true,
    enableLegacyAdminImpersonationBanner: false,
  };
}

export function getSelfhostPublicTabs(_hostname = '', profile = SELFHOST_PUBLIC_PROFILE) {
  return [
    { labelKey: 'navigation.home', defaultLabel: 'Home', path: '/', exact: true },
    { labelKey: 'navigation.console', defaultLabel: 'Console', path: '/console', prefixes: ['/console'] },
    { labelKey: 'navigation.applications', defaultLabel: 'Applications', path: '/apply' },
    ...(profile !== 'tester'
      ? [{ labelKey: 'navigation.apiDocumentation', defaultLabel: 'API documentation', path: '/docs' }]
      : []),
  ];
}

const selfhostPublicUiFlags = getSelfhostPublicUiFlags();

export const SHOW_PUBLIC_LOGIN_BUTTON = selfhostPublicUiFlags.showPublicLoginButton;
export const DISABLE_PUBLIC_LOGIN_BUTTON = selfhostPublicUiFlags.disablePublicLoginButton;
export const SHOW_PUBLIC_GET_STARTED_BUTTONS = selfhostPublicUiFlags.showPublicGetStartedButtons;
export const DISABLE_PUBLIC_GET_STARTED_BUTTONS = selfhostPublicUiFlags.disablePublicGetStartedButtons;
export const SHOW_PUBLIC_PRICING_BUTTONS = selfhostPublicUiFlags.showPublicPricingButtons;
export const DISABLE_PUBLIC_PRICING_BUTTONS = selfhostPublicUiFlags.disablePublicPricingButtons;
export const ENABLE_LEGACY_ADMIN_IMPERSONATION_BANNER = selfhostPublicUiFlags.enableLegacyAdminImpersonationBanner;
export const ENABLE_ORGANIZATION_CREATION = false;
export const WALLET_SELECTION_ALLOWED_WALLET_IDS = ['wr-spruce-001', 'wr-marty-001'];

export const I18N_NAMESPACES = ['common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor'];
export const PUBLIC_TABS = getSelfhostPublicTabs();
export const SHOW_PUBLIC_CTA = false;
