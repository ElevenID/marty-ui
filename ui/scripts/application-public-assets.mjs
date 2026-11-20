// Closed application-only source omissions from application-assets-audit.md.
// New image/locale files stay retained until their ownership is reviewed.
export const APPLICATION_ASSET_OMISSIONS = Object.freeze([
  'ui/public/blog/rss.xml',
  'ui/public/images/authors/aiko-tanaka.png',
  'ui/public/images/authors/daniel-ortega.png',
  'ui/public/images/authors/elena-kovacs.png',
  'ui/public/images/authors/marcus-vale.png',
  'ui/public/images/authors/nora-patel.png',
  'ui/public/images/authors/sofia-rahman.png',
  'ui/public/images/authors/victor-leclerc.png',
  'ui/public/images/demos/2026.07.0/canvas-learning-achievement.png',
  'ui/public/images/demos/2026.07.0/credential-lifecycle.png',
  'ui/public/images/demos/2026.07.0/first-party-browser-wallet.png',
  'ui/public/images/demos/2026.07.0/independent-wallet-interoperability.png',
  'ui/public/images/demos/2026.07.0/membership-badge-login.png',
  'ui/public/images/demos/2026.07.0/organization-primitives.png',
  'ui/public/images/demos/2026.08.0/portfolio-draft.svg',
  'ui/public/images/demos/2026.08.1/portfolio-draft.svg',
  'ui/public/images/social/elevenid-blog-default.png',
  'ui/public/images/social/trust-profiles-explained.png',
  'ui/public/images/social/understanding-csca-certificates-v2.png',
  'ui/public/images/social/why-identity-needs-a-protocol.png',
  'ui/public/llms.txt',
  'ui/public/locales/de/marketing.json',
  'ui/public/locales/es/marketing.json',
  'ui/public/locales/fr/marketing.json',
  'ui/public/locales/ja/marketing.json',
  'ui/public/locales/nl/marketing.json',
]);

export const APPLICATION_LOCALES = Object.freeze(['en', 'de', 'es', 'fr', 'ja', 'nl']);
export const APPLICATION_LOCALE_NAMESPACES = Object.freeze([
  'common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor',
]);
export const APPLICATION_SHARED_PUBLIC_FILES = Object.freeze([
  '.well-known/ai-plugin.json',
  'apple-touch-icon.png',
  'config.json',
  'favicon-96x96.png',
  'favicon.ico',
  'favicon.svg',
  'logo192.png',
  'logo512.png',
  'manifest.json',
  'runtime-config.js',
  'startup.js',
  'test-harness.html',
]);
export const APPLICATION_RETAINED_PUBLIC_FILES = Object.freeze([
  ...APPLICATION_SHARED_PUBLIC_FILES,
  ...APPLICATION_LOCALES.flatMap((locale) => APPLICATION_LOCALE_NAMESPACES.map(
    (namespace) => `locales/${locale}/${namespace}.json`,
  )),
].sort());

export const APPLICATION_RESOURCE_MIME_TYPES = Object.freeze({
  '.html': Object.freeze(['text/html']),
  '.json': Object.freeze(['application/json']),
  '.js': Object.freeze(['text/javascript', 'application/javascript']),
  '.mjs': Object.freeze(['text/javascript', 'application/javascript']),
  '.css': Object.freeze(['text/css']),
  '.wasm': Object.freeze(['application/wasm']),
  '.png': Object.freeze(['image/png']),
  '.svg': Object.freeze(['image/svg+xml']),
  '.ico': Object.freeze(['image/x-icon', 'image/vnd.microsoft.icon']),
  '.map': Object.freeze(['application/json']),
});
