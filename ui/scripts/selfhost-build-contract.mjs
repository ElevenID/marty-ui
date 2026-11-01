const marketingPageNames = [
  'LandingPage', 'ProductPage', 'StandardsPage', 'ProtocolPage', 'IdentityGuidePage', 'FromIDVPage',
  'PublicIAPages', 'VerifiableCredentialApiPage', 'EudiWalletVerificationPage',
  'IsoMdocVerificationPage', 'SdJwtVerificationPage', 'OpenBadgesVerificationPage',
  'OpenBadgesIssuancePage', 'TrustRegistryPage', 'AiCapabilityPage',
  'WhatIsCredentialVerificationPage', 'WhatIsOpenBadgePage', 'WhatIsDigitalCredentialPage',
  'WhatIsMartyProtocolPage', 'LegalPages', 'DemoPages',
];

export function isProductionMarketingModule(moduleId) {
  const id = moduleId.replace(/\\/g, '/').split('?', 1)[0];
  return id.includes('/@elevenid/marty-blog/')
    || id.endsWith('/variants/publicSite.public.jsx')
    || id.endsWith('/data/marketingContent.js')
    || id.includes('/components/landing/')
    || marketingPageNames.some((name) => id.endsWith(`/components/${name}.jsx`)
      || id.endsWith(`/components/pages/${name}.jsx`));
}

// Check module identities, not minified strings or chunk names: tree-shaking
// and changes to manual chunking must not hide a production marketing import.
export function selfhostBuildContractPlugin() {
  return {
    name: 'selfhost-build-contract',
    transformIndexHtml(html) {
      return html.replace(
        '<title>ElevenID LLC — Verifiable Identity Infrastructure</title>',
        '<title>ElevenID Application Portal</title>',
      );
    },
    generateBundle(_options, bundle) {
      const forbidden = new Set();
      for (const output of Object.values(bundle)) {
        if (output.type !== 'chunk') continue;
        for (const moduleId of Object.keys(output.modules)) {
          if (isProductionMarketingModule(moduleId)) forbidden.add(moduleId);
        }
      }
      if (forbidden.size) {
        throw new Error(`Customer UI includes production marketing modules:\n${[...forbidden].sort().join('\n')}`);
      }
    },
  };
}

export const SELFHOST_EXCLUDED_STATIC_PATHS = [
  'blog', 'authors', 'demos', 'images/authors', 'images/demos', 'images/social',
  'llms.txt', 'robots.txt', 'sitemap.xml', 'sitemap-index.xml',
];
