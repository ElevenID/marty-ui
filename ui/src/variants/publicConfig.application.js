import { I18N_NAMESPACES as PUBLIC_I18N_NAMESPACES } from './publicConfig.public.js';

export * from './publicConfig.public.js';

// Application output retains website handoff links, but its static asset
// pruning removes the website-only marketing translations.
export const I18N_NAMESPACES = PUBLIC_I18N_NAMESPACES.filter((namespace) => namespace !== 'marketing');
