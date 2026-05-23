export const IS_SELFHOST_UI = true;

export const SELFHOST_PRODUCTION_PUBLIC_HOSTS = ['elevenidllc.com', 'www.elevenidllc.com'];

function normalizeHostname(hostname = '') {
  return hostname.trim().toLowerCase();
}

function getCurrentHostname() {
  if (typeof window === 'undefined' || !window.location) {
    return '';
  }

  return window.location.hostname;
}

export function isSelfhostProductionPublicHost(hostname = getCurrentHostname()) {
  return SELFHOST_PRODUCTION_PUBLIC_HOSTS.includes(normalizeHostname(hostname));
}

export function getSelfhostPublicUiFlags(hostname = getCurrentHostname()) {
  const disableProductionMarketingCtas = isSelfhostProductionPublicHost(hostname);

  return {
    showPublicLoginButton: true,
    disablePublicLoginButton: false,
    showPublicGetStartedButtons: true,
    disablePublicGetStartedButtons: disableProductionMarketingCtas,
    showPublicPricingButtons: true,
    disablePublicPricingButtons: disableProductionMarketingCtas,
    enableLegacyAdminImpersonationBanner: false,
  };
}

export function getSelfhostPublicTabs(hostname = getCurrentHostname()) {
  const { showPublicPricingButtons, disablePublicPricingButtons } = getSelfhostPublicUiFlags(hostname);

  return [
    { labelKey: 'navigation.home', defaultLabel: 'Home', path: '/', exact: true },
    {
      labelKey: 'navigation.product',
      defaultLabel: 'Product',
      path: '/product',
      prefixes: [
        '/product',
        '/verifiable-credential-api',
        '/eudi-wallet-verification',
        '/iso-18013-5-mdoc-verification',
        '/sd-jwt-verification',
        '/open-badges-verification',
        '/open-badges-issuance',
        '/trust-registry-infrastructure',
        '/ai',
      ],
    },
    { labelKey: 'navigation.solutions', defaultLabel: 'Solutions', path: '/solutions' },
    { labelKey: 'navigation.developers', defaultLabel: 'Developers', path: '/developers', prefixes: ['/developers'] },
    { labelKey: 'navigation.standards', defaultLabel: 'Standards', path: '/standards' },
    {
      labelKey: 'navigation.resources',
      defaultLabel: 'Resources',
      path: '/resources',
      prefixes: [
        '/resources',
        '/docs',
        '/blog',
        '/authors',
        '/identity',
        '/why-verifiable-identity',
        '/from-idv-to-verifiable-identity',
        '/architecture',
        '/security',
        '/protocol',
        '/what-is-credential-verification',
        '/what-is-open-badge',
        '/what-is-digital-credential',
        '/what-is-marty-protocol',
        '/privacy-policy',
        '/privacy',
        '/terms-of-service',
        '/terms',
      ],
    },
    ...(showPublicPricingButtons ? [{ labelKey: 'navigation.pricing', defaultLabel: 'Pricing', path: '/pricing', disabled: disablePublicPricingButtons }] : []),
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

export const I18N_NAMESPACES = ['common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor', 'marketing'];

export const PUBLIC_TABS = getSelfhostPublicTabs();

export const SHOW_PUBLIC_CTA = true;
