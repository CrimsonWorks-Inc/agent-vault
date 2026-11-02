// Contract U8: the committed bundle is exactly what the source builds.
//
// The npm package ships src/ui/dist and not web/, so a dist that drifted from
// its source would ship code nobody reviewed. This builds into a temp dir and
// compares every file, ignoring nothing. It needs the devDependencies (npm ci).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildUi } from '../scripts/build-ui.mjs'
import { compareTrees } from '../scripts/compare-trees.mjs'

const DIST = fileURLToPath(new URL('../../src/ui/dist', import.meta.url))

test('src/ui/dist equals a fresh build of web/', { timeout: 180_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'av-ui-drift-'))
  try {
    buildUi(dir)
    const diffs = compareTrees(dir, DIST)
    assert.deepEqual(diffs, [], `the committed dist is stale; run npm run build:ui and commit it:\n${diffs.join('\n')}`)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
