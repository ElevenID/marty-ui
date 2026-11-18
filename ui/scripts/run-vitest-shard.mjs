import { readdirSync, readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const uiRoot = resolve(scriptDirectory, '..')
const sourceRoot = join(uiRoot, 'src')
const timingsPath = resolve(uiRoot, '..', '.github', 'test-timings', 'ui-vitest.json')

function normalizePath(path) {
  return path.replaceAll('\\', '/')
}

function discoverTestFiles(directory = sourceRoot) {
  const files = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) {
      files.push(...discoverTestFiles(path))
    } else if (/\.(test|spec)\.(ts|tsx)$/.test(entry.name)) {
      files.push(normalizePath(relative(uiRoot, path)))
    }
  }
  return files.sort()
}

function buildPlan(totalShards) {
  if (!Number.isInteger(totalShards) || totalShards < 1) {
    throw new Error(`total shards must be a positive integer, received ${totalShards}`)
  }

  const timingData = JSON.parse(readFileSync(timingsPath, 'utf8'))
  const defaultMilliseconds = timingData.defaultMilliseconds ?? 500
  const testFiles = discoverTestFiles()
  const weightedFiles = testFiles.map((path) => ({
    path,
    milliseconds: timingData.tests[path] ?? defaultMilliseconds,
  }))

  weightedFiles.sort(
    (left, right) => right.milliseconds - left.milliseconds || left.path.localeCompare(right.path),
  )

  const shards = Array.from({ length: totalShards }, (_, index) => ({
    index: index + 1,
    estimatedMilliseconds: 0,
    files: [],
  }))

  for (const testFile of weightedFiles) {
    const shard = shards.reduce((lightest, candidate) => {
      if (candidate.estimatedMilliseconds < lightest.estimatedMilliseconds) return candidate
      if (candidate.estimatedMilliseconds === lightest.estimatedMilliseconds && candidate.index < lightest.index) {
        return candidate
      }
      return lightest
    })
    shard.files.push(testFile.path)
    shard.estimatedMilliseconds += testFile.milliseconds
  }

  const assignedFiles = shards.flatMap((shard) => shard.files)
  if (assignedFiles.length !== testFiles.length || new Set(assignedFiles).size !== testFiles.length) {
    throw new Error('timing-balanced shard plan did not assign every discovered test exactly once')
  }

  for (const shard of shards) shard.files.sort()
  return shards
}

const [firstArgument, secondArgument] = process.argv.slice(2)
if (firstArgument === '--plan') {
  const totalShards = Number(secondArgument)
  process.stdout.write(`${JSON.stringify(buildPlan(totalShards), null, 2)}\n`)
  process.exit(0)
}

const shardIndex = Number(firstArgument)
const totalShards = Number(secondArgument)
const plan = buildPlan(totalShards)
if (!Number.isInteger(shardIndex) || shardIndex < 1 || shardIndex > totalShards) {
  throw new Error(`shard index must be between 1 and ${totalShards}, received ${firstArgument}`)
}

const shard = plan[shardIndex - 1]
console.log(
  `Running timing-balanced Vitest shard ${shardIndex}/${totalShards}: ` +
    `${shard.files.length} files, ${shard.estimatedMilliseconds}ms historical weight`,
)

const vitestBin = join(uiRoot, 'node_modules', 'vitest', 'vitest.mjs')
const timingOutput = process.env.VITEST_TIMING_OUTPUT
const reporterArguments = timingOutput
  ? ['--reporter=default', '--reporter=json', `--outputFile.json=${timingOutput}`]
  : []
const result = spawnSync(process.execPath, [vitestBin, 'run', ...shard.files, ...reporterArguments], {
  cwd: uiRoot,
  env: process.env,
  stdio: 'inherit',
})

if (result.error) throw result.error
process.exit(result.status ?? 1)
