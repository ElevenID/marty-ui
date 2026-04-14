import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const distRoot = path.join(projectRoot, 'dist')
const hasPrerenderedBuild = fs.existsSync(path.join(distRoot, 'blog', 'index.html'))
const describeIfBuilt = hasPrerenderedBuild ? describe : describe.skip

function readPrerenderedHtml(...segments: string[]) {
  const filePath = path.join(distRoot, ...segments, 'index.html')

  expect(
    fs.existsSync(filePath),
    `Expected prerendered file ${filePath} to exist. Run npm run build before running this test.`,
  ).toBe(true)

  return fs.readFileSync(filePath, 'utf8')
}

describeIfBuilt('prerendered blog SEO output', () => {
  it('keeps article and guide metadata in emitted post pages', () => {
    const guideHtml = readPrerenderedHtml('blog', 'foundations-identity')
    expect(guideHtml).toContain('data-seo-jsonld="true"')
    expect(guideHtml).toContain('"@type":"Article"')
    expect(guideHtml).toContain('meta property="article:section" content="Chapter 1: Foundations"')

    const articleHtml = readPrerenderedHtml('blog', 'why-identity-needs-a-protocol')
    expect(articleHtml).toContain('meta property="article:published_time" content="2025-01-06"')
    expect(articleHtml).toContain('meta property="article:author" content="Daniel Ortega"')
    expect(articleHtml).toContain('"dateModified":"2026-04-05"')
  })

  it('emits collection and author metadata for archive surfaces', () => {
    const blogIndexHtml = readPrerenderedHtml('blog')
    expect(blogIndexHtml).toContain('"@type":"CollectionPage"')
    expect(blogIndexHtml).toContain('"name":"Marty Identity Protocol Blog"')

    const tagHtml = readPrerenderedHtml('blog', 'tag', 'cryptography')
    expect(tagHtml).toContain('https://elevenidllc.com/blog/tag/cryptography')
    expect(tagHtml).toContain('"@type":"CollectionPage"')
    expect(tagHtml).toContain('Selective Disclosure')

    const authorsHtml = readPrerenderedHtml('authors')
    expect(authorsHtml).toContain('"@type":"CollectionPage"')
    expect(authorsHtml).toContain('https://elevenidllc.com/authors/daniel-ortega')

    const authorHtml = readPrerenderedHtml('authors', 'daniel-ortega')
    expect(authorHtml).toContain('<meta property="og:type" content="profile">')
    expect(authorHtml).toContain('"@type":"Person"')
    expect(authorHtml).toContain('"name":"Daniel Ortega"')
  })
})