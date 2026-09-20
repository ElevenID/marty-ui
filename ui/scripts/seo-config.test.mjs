// Run from ui/: node --experimental-vm-modules --test scripts/seo-config.test.mjs
// Executes the real config with isolated plugin/content fixtures; not a build test.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as path from 'node:path'
import * as url from 'node:url'
import test from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

const configUrl = new URL('../vite.config.ts', import.meta.url)
const { outputText, diagnostics } = ts.transpileModule(readFileSync(configUrl, 'utf8'), {
  fileName: 'vite.config.ts',
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  reportDiagnostics: true,
})
assert.equal(diagnostics?.length ?? 0, 0, 'Vite config must parse')

async function loadConfig(mode, env = {}) {
  const context = vm.createContext({ console, process: { env, cwd: () => '/fixture' } })
  const plugin = (name) => (options) => ({ name, options })
  const unexpected = () => { throw new Error('Unexpected fixture filesystem access') }
  const fixtures = {
    'vite': { defineConfig: (config) => config, loadEnv: () => env },
    '@vitejs/plugin-react': { default: plugin('react') },
    'vite-plugin-checker': { default: plugin('checker') },
    '@prerenderer/rollup-plugin': { default: plugin('prerender') },
    '@prerenderer/renderer-puppeteer': { default: class Renderer {} },
    'rollup-plugin-visualizer': { visualizer: plugin('visualizer') },
    'vite-plugin-sitemap': { default: plugin('sitemap') },
    'node:url': { fileURLToPath: url.fileURLToPath, URL },
    'node:path': { resolve: path.resolve },
    'node:fs': {
      existsSync: unexpected, readdirSync: unexpected,
      unlinkSync: unexpected, writeFileSync: unexpected,
      readFileSync: (filename) => {
        if (filename.endsWith('/manifests//index.json')) {
          return JSON.stringify({ releases: [{ stack_version: '2026.07.0' }], latest_approved_stack_version: '2026.07.0' })
        }
        if (filename.endsWith('/manifests//2026.07.0.json')) {
          return JSON.stringify({ scenarios: [{ slug: 'membership' }] })
        }
        return unexpected()
      },
    },
    '@elevenid/marty-blog/prerender-data': {
      BLOG_POSTS: [{ slug: 'identity' }], BLOG_AUTHORS: { engineer: {} },
      BLOG_POST_CONCEPT_TAGS: { identity: ['cryptography'] }, BLOG_POST_STANDARDS_TAGS: {},
      GUIDE_ARTICLE_SLUGS: ['guide'], GUIDE_ARTICLES: [], GUIDE_CHAPTERS: [], ARTICLE_META: {},
      getBrowseVisiblePosts: (posts) => posts, buildBlogTagPath: (tag) => `/blog/tag/${tag}`,
    },
  }
  function fixtureModule(specifier) {
    assert.ok(Object.hasOwn(fixtures, specifier), `Unexpected import: ${specifier}`)
    const values = fixtures[specifier]
    return new vm.SyntheticModule(Object.keys(values), function () {
      for (const [key, value] of Object.entries(values)) this.setExport(key, value)
    }, { context })
  }
  const module = new vm.SourceTextModule(outputText, {
    context,
    initializeImportMeta: (meta) => { meta.url = configUrl.href },
    importModuleDynamically: async (specifier) => {
      const dependency = fixtureModule(specifier)
      await dependency.link(unexpected)
      await dependency.evaluate()
      return dependency
    },
  })
  await module.link(fixtureModule)
  await module.evaluate()
  return module.namespace.default({ mode, command: 'build' })
}

for (const [mode, variant, sitemapExpected] of [
  ['production', 'public', true],
  ['analyze', 'public', true],
  ['development', 'public', false],
  ['selfhost', 'public', false],
  ['production', 'selfhost', false],
]) {
  for (const disable of ['0', '1']) {
    test(`${mode}/${variant}: DISABLE_PRERENDER=${disable}`, async () => {
      const config = await loadConfig(mode, { VITE_UI_VARIANT: variant, DISABLE_PRERENDER: disable })
      const names = config.plugins.map(({ name }) => name)
      const prerenderExpected = sitemapExpected && disable !== '1'
      assert.equal(names.filter((name) => name === 'sitemap').length, Number(sitemapExpected))
      for (const name of ['prerender', 'prerender-locale-assets', 'promote-prerendered-root']) {
        assert.equal(names.includes(name), prerenderExpected, name)
      }
      if (prerenderExpected) assert.ok(names.indexOf('promote-prerendered-root') > names.indexOf('prerender'))
      if (sitemapExpected) {
        const { options } = config.plugins.find(({ name }) => name === 'sitemap')
        assert.equal(options.hostname, 'https://elevenidllc.com')
        assert.equal(options.generateRobotsTxt, true)
        for (const route of ['/', '/product', '/blog/identity', '/blog/guide', '/blog/tag/cryptography', '/authors/engineer', '/demos/2026.07.0/membership']) {
          assert.ok(options.dynamicRoutes.includes(route), route)
        }
        assert.ok(options.exclude.includes('/console/*'))
        assert.ok(options.robots.find(({ userAgent }) => userAgent === '*').disallow.includes('/v1/*'))
      }
      assert.equal(config.build.outDir, mode === 'selfhost' || variant === 'selfhost' ? 'dist-selfhost' : 'dist')
    })
  }
}

test('the prerender flag does not change public crawler options', async () => {
  const enabled = await loadConfig('production')
  const disabled = await loadConfig('production', { DISABLE_PRERENDER: '1' })
  const options = (config) => JSON.stringify(config.plugins.find(({ name }) => name === 'sitemap')?.options)
  assert.equal(options(enabled), options(disabled))
  assert.equal(JSON.stringify(enabled.server.proxy), JSON.stringify(disabled.server.proxy))
})
