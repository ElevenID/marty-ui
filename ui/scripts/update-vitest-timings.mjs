import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const uiRoot = resolve(scriptDirectory, '..')
const defaultTimingsPath = resolve(uiRoot, '..', '.github', 'test-timings', 'ui-vitest.json')

function normalizePath(path) {
  return path.replaceAll('\\', '/')
}

function relativeTestPath(absolutePath) {
  const normalized = normalizePath(absolutePath)
  const local = normalizePath(relative(uiRoot, absolutePath))
  if (!local.startsWith('../')) return local

  // Timing artifacts can be downloaded and refreshed on a different machine.
  const uiMarker = '/ui/'
  const markerIndex = normalized.lastIndexOf(uiMarker)
  if (markerIndex >= 0) return normalized.slice(markerIndex + uiMarker.length)
  throw new Error(`test result is outside the UI root: ${absolutePath}`)
}

function discoverReports(path) {
  const resolvedPath = resolve(path)
  if (!statSync(resolvedPath).isDirectory()) return [resolvedPath]
  return readdirSync(resolvedPath, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = resolve(resolvedPath, entry.name)
    if (entry.isDirectory()) return discoverReports(entryPath)
    return entry.name.endsWith('.json') ? [entryPath] : []
  })
}

const args = process.argv.slice(2)
const outputIndex = args.indexOf('--output')
const outputPath = outputIndex >= 0 ? resolve(args[outputIndex + 1]) : defaultTimingsPath
if (outputIndex >= 0) args.splice(outputIndex, 2)
if (args.length === 0) throw new Error('provide at least one Vitest JSON report or report directory')

const current = JSON.parse(readFileSync(defaultTimingsPath, 'utf8'))
const observed = new Map()
for (const reportPath of args.flatMap(discoverReports)) {
  const report = JSON.parse(readFileSync(reportPath, 'utf8'))
  for (const result of report.testResults ?? []) {
    const path = relativeTestPath(result.name)
    if (!/^src\/.+\.(test|spec)\.(ts|tsx)$/.test(path)) {
      throw new Error(`unexpected Vitest result path: ${result.name}`)
    }
    const duration = Math.max(1, Math.round(result.endTime - result.startTime))
    observed.set(path, duration)
  }
}
if (observed.size === 0) throw new Error('no per-file timings found in the supplied reports')

const tests = { ...current.tests }
for (const [path, duration] of observed) {
  const previous = tests[path]
  // Smooth noisy hosted-runner observations while still adapting every successful run.
  tests[path] = previous === undefined ? duration : Math.round(previous * 0.7 + duration * 0.3)
}

const updated = {
  source: `Exponentially smoothed Vitest results; refreshed from ${observed.size} files`,
  defaultMilliseconds: current.defaultMilliseconds ?? 500,
  tests: Object.fromEntries(Object.entries(tests).sort(([left], [right]) => left.localeCompare(right))),
}
writeFileSync(outputPath, `${JSON.stringify(updated, null, 2)}\n`)
console.log(`Updated ${observed.size} test timings in ${outputPath}`)
