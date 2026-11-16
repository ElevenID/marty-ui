import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';

const repositoryRoot = path.resolve(import.meta.dirname, '../..');
export function validateWebsiteSourceOwnership(value, root = repositoryRoot) {
  if (!value || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'modules,schema_version'
    || value.schema_version !== 1 || !Array.isArray(value.modules) || !value.modules.length
    || new Set(value.modules).size !== value.modules.length) throw new Error('Invalid website source ownership');
  for (const entry of value.modules) {
    if (typeof entry !== 'string' || !/^ui\/src\/[A-Za-z0-9/_.-]+\.(?:jsx?|tsx?)$/.test(entry)
      || entry.split('/').some((part) => !part || part === '.' || part === '..')) throw new Error('Invalid website module path');
    const stat = lstatSync(path.join(root, entry));
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Website module is not a regular file: ${entry}`);
  }
  return value;
}

export const WEBSITE_SOURCE_OWNERSHIP = validateWebsiteSourceOwnership(JSON.parse(readFileSync(
  path.join(repositoryRoot, 'contracts/website-source-ownership.json'), 'utf8',
)));
export function isWebsiteOwnedModule(moduleId) {
  const id = moduleId.replace(/\\/g, '/').split('?', 1)[0];
  return WEBSITE_SOURCE_OWNERSHIP.modules.some((entry) => id.endsWith(`/${entry}`));
}
