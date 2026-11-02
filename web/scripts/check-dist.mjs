#!/usr/bin/env node
// prepack: the committed src/ui/dist must be exactly what the source builds.
//
// The npm package ships the prebuilt page, not its source (contract D2), so a
// stale dist would ship code nobody reviewed. This builds into a temp dir and
// compares every file, byte for byte. It never writes src/ui/dist: only
// `npm run build:ui` does, so a test that reads the dist while this runs
// cannot see it half-written.

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildUi } from './build-ui.mjs'
import { compareTrees } from './compare-trees.mjs'

const DIST = fileURLToPath(new URL('../../src/ui/dist', import.meta.url))

export function checkDist() {
  const dir = mkdtempSync(join(tmpdir(), 'av-ui-dist-'))
  try {
    buildUi(dir)
    return compareTrees(dir, DIST)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const diffs = checkDist()
    if (diffs.length) {
      console.error('src/ui/dist does not match a fresh build of web/:')
      for (const d of diffs.slice(0, 20)) console.error(`  ${d}`)
      console.error('Run: npm run build:ui, then commit src/ui/dist with its source.')
      process.exit(1)
    }
    console.log('src/ui/dist matches a fresh build.')
  } catch (e) {
    console.error(e.message)
    process.exit(1)
  }
}
