// Adopt observations into the reviewed file consumed by run-vitest-shard.mjs.
// Downloaded artifacts are data only: never execute code from their source run.
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const uiRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const timingsPath = resolve(uiRoot, '..', '.github/test-timings/ui-vitest.json')
const [input, ...args] = process.argv.slice(2)
if (!input || (args.length !== 0 && (args.length !== 2 || args[0] !== '--output'))) {
  throw new Error('usage: node adopt-vitest-timings.mjs INPUT [--output OUTPUT]')
}
const output = args.length ? resolve(args[1]) : timingsPath
if (statSync(input).size > 1_048_576) throw new Error('timing plan exceeds 1 MiB')
const observed = JSON.parse(readFileSync(input, 'utf8'))
const current = JSON.parse(readFileSync(timingsPath, 'utf8'))
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const isDuration = value => Number.isInteger(value) && value > 0 && value <= 3_600_000
if (!isObject(observed) || !isObject(observed.tests) || !isDuration(observed.defaultMilliseconds)) {
  throw new Error('invalid timing plan schema or default duration')
}
for (const [path, duration] of Object.entries(observed.tests)) {
  if (!/^src\/(?:[\w.-]+\/)*[\w.-]+\.(test|spec)\.(ts|tsx)$/.test(path)
      || path.split('/').some(part => part === '.' || part === '..')
      || !isDuration(duration)) {
    throw new Error(`invalid timing observation: ${path}`)
  }
}
function discover(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return discover(path)
    return /\.(test|spec)\.(ts|tsx)$/.test(entry.name)
      ? [relative(uiRoot, path).replaceAll('\\', '/')]
      : []
  })
}
let adopted = 0
const tests = Object.fromEntries(discover(join(uiRoot, 'src')).sort().map(path => {
  if (Object.hasOwn(observed.tests, path)) adopted++
  return [path, observed.tests[path] ?? current.tests[path] ?? current.defaultMilliseconds]
}))
if (adopted === 0) throw new Error('no observations match current UI tests')
writeFileSync(output, `${JSON.stringify({
  source: `Reviewed Vitest observations for ${adopted} current test files`,
  defaultMilliseconds: current.defaultMilliseconds,
  tests,
}, null, 2)}\n`)
console.log(`Adopted ${adopted} observations; all ${Object.keys(tests).length} current tests retained. Review ${output} before committing.`)
