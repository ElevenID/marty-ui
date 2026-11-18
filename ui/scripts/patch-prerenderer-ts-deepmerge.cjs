'use strict'

const fs = require('node:fs')
const path = require('node:path')

const packageRoot = path.resolve(__dirname, '..', 'node_modules', '@prerenderer')
const vulnerableCall = 'ts_deepmerge_1.default'
const compatibleCall = '(ts_deepmerge_1.default || ts_deepmerge_1.merge)'
let patchedFiles = 0

function patchDirectory(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name)

    if (entry.isDirectory()) {
      patchDirectory(entryPath)
      continue
    }

    if (!entry.isFile() || !entry.name.endsWith('.js')) {
      continue
    }

    const source = fs.readFileSync(entryPath, 'utf8')
    if (!source.includes(vulnerableCall)) {
      continue
    }

    fs.writeFileSync(entryPath, source.replaceAll(vulnerableCall, compatibleCall))
    patchedFiles += 1
  }
}

if (!fs.existsSync(packageRoot)) {
  throw new Error(`Expected prerender packages at ${packageRoot}`)
}

patchDirectory(packageRoot)
console.log(`Applied the ts-deepmerge v8 compatibility fix to ${patchedFiles} prerender file(s).`)
