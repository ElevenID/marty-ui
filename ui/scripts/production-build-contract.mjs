import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

export const COMMERCE_REPOSITORY = 'ElevenID/marty-subscriptions';

export function productionBuildContract({ pages = 'public', selfhost = false, extensionPath, sourceSha }) {
  if (!['public', 'full'].includes(pages)) throw new Error('Unknown production page set');
  if (pages === 'public') {
    if (extensionPath || sourceSha) throw new Error('Commerce inputs require the full production page set');
    return null;
  }
  if (selfhost) throw new Error('Customer UI cannot include the production commerce extension');
  if (!extensionPath || !/^[0-9a-f]{40}$/.test(sourceSha || '')) {
    throw new Error('Full production pages require the exact private commerce source');
  }
  const entry = path.resolve(extensionPath);
  if (!entry.endsWith('/src/extension.jsx') || !existsSync(entry)) {
    throw new Error('Full production commerce entrypoint is missing');
  }
  const metadataPath = path.resolve(path.dirname(entry), '..', 'commerce-source.json');
  if (!existsSync(metadataPath)) throw new Error('Full production commerce source identity is missing');
  const metadata = JSON.parse(readFileSync(metadataPath, 'utf8'));
  if (Object.keys(metadata).sort().join(',') !== 'repository,source_sha'
    || metadata.repository !== COMMERCE_REPOSITORY || metadata.source_sha !== sourceSha) {
    throw new Error('Full production commerce source identity differs');
  }
  return entry;
}

export function productionBuildContractPlugin(entry) {
  return {
    name: 'production-commerce-build-contract',
    generateBundle(_options, bundle) {
      const present = Object.values(bundle).some((output) => output.type === 'chunk'
        && Object.keys(output.modules).some((id) => id.split('?', 1)[0] === entry));
      if (!present) throw new Error('Full production output omitted its commerce extension');
    },
  };
}
