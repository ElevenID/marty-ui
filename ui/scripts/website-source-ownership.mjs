import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';

const repositoryRoot = path.resolve(import.meta.dirname, '../..');
function validateWebsiteSourceOwnershipSchema(value) {
  if (!value || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'modules,schema_version'
    || value.schema_version !== 1 || !Array.isArray(value.modules) || !value.modules.length
    || new Set(value.modules).size !== value.modules.length) throw new Error('Invalid website source ownership');
  for (const entry of value.modules) {
    if (typeof entry !== 'string' || !/^ui\/src\/[A-Za-z0-9/_.-]+\.(?:jsx?|tsx?)$/.test(entry)
      || entry.split('/').some((part) => !part || part === '.' || part === '..')) throw new Error('Invalid website module path');
  }
  return value;
}

export function validateWebsiteSourceOwnership(value, root = repositoryRoot) {
  validateWebsiteSourceOwnershipSchema(value);
  for (const entry of value.modules) {
    const stat = lstatSync(path.join(root, entry));
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Website module is not a regular file: ${entry}`);
  }
  return value;
}

// The application classifier needs the roster even when those forbidden
// sources are absent. Builds that retain website source audit its files when
// constructing their bundle contract plugin.
export const WEBSITE_SOURCE_OWNERSHIP = validateWebsiteSourceOwnershipSchema(JSON.parse(readFileSync(
  path.join(repositoryRoot, 'contracts/website-source-ownership.json'), 'utf8',
)));
export function isWebsiteOwnedModule(moduleId) {
  const id = moduleId.replace(/\\/g, '/').split('?', 1)[0];
  return WEBSITE_SOURCE_OWNERSHIP.modules.some((entry) => id.endsWith(`/${entry}`));
}
