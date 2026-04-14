export const IS_SELFHOST_UI = false;

export const SHOW_PUBLIC_LOGIN_BUTTON = true;
export const DISABLE_PUBLIC_LOGIN_BUTTON = false;
export const SHOW_PUBLIC_GET_STARTED_BUTTONS = true;
export const DISABLE_PUBLIC_GET_STARTED_BUTTONS = false;
export const SHOW_PUBLIC_PRICING_BUTTONS = true;
export const DISABLE_PUBLIC_PRICING_BUTTONS = false;

export const I18N_NAMESPACES = ['common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor', 'marketing'];

export const PUBLIC_TABS = [
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
    ],
  },
  ...(SHOW_PUBLIC_PRICING_BUTTONS ? [{ labelKey: 'navigation.pricing', defaultLabel: 'Pricing', path: '/pricing', disabled: DISABLE_PUBLIC_PRICING_BUTTONS }] : []),
];

export const SHOW_PUBLIC_CTA = true;