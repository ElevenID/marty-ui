import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { validateWebSurfaceContract, webPathOwner } from '../src/application/routing/webSurfaceContract.mjs';

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

export const WEB_SURFACE_ROUTES = validateWebSurfaceContract(JSON.parse(readFileSync(
  new URL('../../contracts/web-surface-routes.json', import.meta.url), 'utf8',
)));
export const WEB_ROUTE_CONTRACT = Object.freeze({
  version: WEB_SURFACE_ROUTES.schema_version,
  sha256: `sha256:${createHash('sha256').update(canonicalJson(WEB_SURFACE_ROUTES)).digest('hex')}`,
});
export const getWebSurface = (pathname) => webPathOwner(pathname, WEB_SURFACE_ROUTES);
