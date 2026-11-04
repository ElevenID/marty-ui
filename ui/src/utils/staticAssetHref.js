// This base is fixed by the build, never by mutable browser runtime settings.
const assetBase = import.meta.env.VITE_WEBSITE_ASSET_BASE || '/';

export function staticAssetHref(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || assetBase === '/') return path;
  return `${assetBase}${path.slice(1)}`;
}
