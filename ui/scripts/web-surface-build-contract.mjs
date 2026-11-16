import { isProductionMarketingModule } from './selfhost-build-contract.mjs';
import { WEB_ROUTE_CONTRACT } from './web-surface-contract.mjs';

export function websiteBuildRevision({ sourceSha = 'development', commerceSha, pages = 'public', revision } = {}) {
  if (!['public', 'full'].includes(pages)) throw new Error('Unknown production page set');
  if (!/^[a-f0-9]{40}$/.test(sourceSha) && sourceSha !== 'development' && sourceSha !== 'unknown') throw new Error('Invalid website public source');
  if (pages === 'full' && !/^[a-f0-9]{40}$/.test(commerceSha || '')) throw new Error('Website requires exact private source');
  if (pages === 'public' && commerceSha) throw new Error('Public website cannot claim private source');
  const expected = /^[a-f0-9]{40}$/.test(sourceSha)
    ? `${sourceSha}${pages === 'full' ? `-${commerceSha}` : ''}` : 'development';
  if (revision && revision !== expected) throw new Error('Website revision differs from its source inputs');
  return expected;
}

export function forbiddenWebSurfaceModule(surface, moduleId, commerceEntry) {
  const id = moduleId.replace(/\\/g, '/').split('?', 1)[0];
  const privateRoot = commerceEntry?.replace(/\\/g, '/').replace(/\/(?:website|application|extension)\.jsx$/, '/');
  // Keep private commercial terms out of every delivered browser surface.
  // Authentication in a client route cannot protect downloadable static data.
  if (privateRoot && id.startsWith(privateRoot)
    && /^(?:components\/PricingPage\.jsx|data\/(?:pricingContent|pricingPageContent|pricingPlans)\.js)$/.test(id.slice(privateRoot.length))) return true;
  if (surface === 'application') return isProductionMarketingModule(id)
    || Boolean(privateRoot && id.startsWith(privateRoot) && /^(?:website\.jsx|components\/PricingPage\.jsx|data\/pricingPageContent\.js|seo\/SEOHead\.jsx)$/.test(id.slice(privateRoot.length)));
  if (surface !== 'website') return false;
  return id.includes('/@elevenid/marty-api-core/')
    || /\/src\/apps\/(?:public|console)\//.test(id)
    || /\/src\/(?:bootstrapApp\.jsx|hooks\/useAuth\.js|services\/(?:api(?:\.[jt]s|\/)|authApi\.js))/.test(id)
    || /\/src\/contexts\/(?:Auth|Console|Notification|Payment)Context/.test(id)
    || (privateRoot && id.startsWith(privateRoot) && /^(?:application\/|contexts\/|application\.jsx|extension\.jsx|index\.js|components\/(?:billing\/|PaymentCheckout\.jsx))/.test(id.slice(privateRoot.length)));
}

export function webSurfaceBuildContractPlugin({ surface, sourceSha = 'development', revision, pages = 'public', commerceSha, commerceEntry }) {
  if (!['combined', 'website', 'application'].includes(surface)) throw new Error('Unknown UI surface');
  const websiteRevision = surface === 'website' ? websiteBuildRevision({ sourceSha, commerceSha, pages, revision }) : null;
  return {
    name: 'web-surface-build-contract',
    generateBundle(_options, bundle) {
      for (const output of Object.values(bundle)) {
        if (output.type !== 'chunk') continue;
        for (const id of Object.keys(output.modules)) {
          if (forbiddenWebSurfaceModule(surface, id, commerceEntry)) throw new Error(`${surface} output includes forbidden module: ${id}`);
        }
      }
      const metadata = surface === 'website' ? {
        schema: 'marty.website-image/v1', audience: 'production', surface,
        repository: 'ElevenID/marty-ui', source_sha: sourceSha, revision: websiteRevision,
        production_pages: pages, route_contract: WEB_ROUTE_CONTRACT,
        commerce_extension: pages === 'full' ? { repository: 'ElevenID/marty-subscriptions', source_sha: commerceSha } : null,
      } : {
        schema: 'marty.application-web-compatibility/v1', surface, source_sha: sourceSha,
        route_contract: WEB_ROUTE_CONTRACT,
      };
      this.emitFile({ type: 'asset', fileName: surface === 'website' ? 'marty-website-release.json' : 'marty-web-routes.json', source: `${JSON.stringify(metadata)}\n` });
    },
  };
}
