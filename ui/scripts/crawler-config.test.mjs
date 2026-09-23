import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const configUrl = new URL('../vite.config.ts', import.meta.url)
const configSource = readFileSync(configUrl, 'utf8').replaceAll('\r\n', '\n')

function validateCrawlerStructure(source) {
  assert.equal(source.match(/\bSitemap\(\{/g)?.length, 1, 'exactly one sitemap plugin is required')
  assert.equal(
    source.match(/\[promotePrerenderedRootPlugin\(\)\]/g)?.length,
    1,
    'exactly one root promotion plugin is required',
  )

  const publicGuard = [
    '...(!isDev && !isSelfhostBuild ? [',
    '        Sitemap({',
  ].join('\n')
  assert.ok(
    source.includes(publicGuard),
    'sitemap/robots generation must be guarded by public-build status, not browser prerendering',
  )

  const crawlerStart = source.indexOf(publicGuard)
  const crawlerEnd = source.indexOf(
    '] : []),\n      ...(!disablePrerender ? [promotePrerenderedRootPlugin()] : []),',
    crawlerStart,
  )
  assert.ok(crawlerStart >= 0 && crawlerEnd > crawlerStart, 'root promotion must keep its own prerender guard')
  const crawlerBlock = source.slice(crawlerStart, crawlerEnd)

  assert.ok(
    crawlerBlock.includes(
      "route !== '/' && (disablePrerender || !prerenderRoutes.includes(route))",
    ),
    'dynamic routes must exclude the discovered root and emitted prerender routes',
  )
  for (const marker of [
    "hostname: 'https://elevenidllc.com'",
    "'/console/*'",
    "'/auth/*'",
    "'/api/*'",
    "'/v1/*'",
    'generateRobotsTxt: true',
  ]) {
    assert.ok(crawlerBlock.includes(marker), `crawler configuration must retain ${marker}`)
  }
  const sitemapOnlyStart = source.indexOf(
    "const sitemapOnlyRoutes = requireUniqueRoutes('sitemap-only', [",
  )
  const sitemapOnlyEnd = source.indexOf('  ])', sitemapOnlyStart)
  assert.ok(sitemapOnlyStart >= 0 && sitemapOnlyEnd > sitemapOnlyStart)
  const sitemapOnlyBlock = source.slice(sitemapOnlyStart, sitemapOnlyEnd)
  for (const marker of [
    "'/ai'",
    "'/what-is-credential-verification'",
    "'/what-is-open-badge'",
    "'/what-is-digital-credential'",
    "'/what-is-marty-protocol'",
  ]) {
    assert.ok(sitemapOnlyBlock.includes(marker), `sitemap-only routes must retain ${marker}`)
  }
  for (const duplicatedAuthority of [
    "'/'",
    "'/product'",
    '...demoRoutes',
    '...blogRoutes',
    '...authorRoutes',
    "'/docs'",
  ]) {
    assert.ok(
      !sitemapOnlyBlock.includes(duplicatedAuthority),
      `sitemap-only routes must not duplicate public authority ${duplicatedAuthority}`,
    )
  }

  const derivedSitemap = [
    "const sitemapRoutes = requireUniqueRoutes('sitemap', [",
    '    ...prerenderRoutes,',
    '    ...sitemapOnlyRoutes,',
    '  ])',
  ].join('\n')
  assert.ok(
    source.includes(derivedSitemap),
    'sitemap routes must derive from the prerender/public authority plus sitemap-only routes',
  )
  assert.equal(
    source.match(/const requireUniqueRoutes = /g)?.length,
    1,
    'route uniqueness must have one implementation',
  )
  for (const label of ['prerender', 'sitemap-only', 'sitemap']) {
    assert.ok(
      source.includes(`requireUniqueRoutes('${label}', [`),
      `${label} routes must fail the build on duplicates`,
    )
  }
}

test('crawler generation is independent from browser prerendering', () => {
  validateCrawlerStructure(configSource)
})

for (const [label, mutate] of [
  [
    'coupling crawler generation back to prerendering',
    (source) => source.replace(
      '...(!isDev && !isSelfhostBuild ? [\n        Sitemap({',
      '...(!disablePrerender ? [\n        Sitemap({',
    ),
  ],
  [
    'duplicating the discovered root URL',
    (source) => source.replace(
      "route !== '/' && (disablePrerender || !prerenderRoutes.includes(route))",
      '(disablePrerender || !prerenderRoutes.includes(route))',
    ),
  ],
  [
    'coupling root promotion to the crawler plugin',
    (source) => source.replace(
      '] : []),\n      ...(!disablePrerender ? [promotePrerenderedRootPlugin()] : []),',
      '        promotePrerenderedRootPlugin(),\n      ] : []),',
    ),
  ],
  [
    'removing a private API crawl rule',
    (source) => source.replace("                '/v1/*',", ''),
  ],
  [
    'copying public routes into a second sitemap authority',
    (source) => source.replace(
      '    ...prerenderRoutes,\n    ...sitemapOnlyRoutes,',
      "    '/product',\n    ...sitemapOnlyRoutes,",
    ),
  ],
  [
    'removing duplicate enforcement from sitemap composition',
    (source) => source.replace(
      "const sitemapRoutes = requireUniqueRoutes('sitemap', [",
      'const sitemapRoutes = [',
    ),
  ],
]) {
  test(`rejects ${label}`, () => {
    assert.throws(() => validateCrawlerStructure(mutate(configSource)), assert.AssertionError)
  })
}
