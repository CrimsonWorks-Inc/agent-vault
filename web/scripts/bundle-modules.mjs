#!/usr/bin/env node
// Build the page into a temp dir, as `npm run build:ui` does, and print what
// went into it: for each chunk, every module's path (relative to the repo)
// and the exports it rendered; plus how that build compares with the
// committed src/ui/dist. test/security/one-source-of-truth.test.js reads this
// to prove C21 from the bundle itself: the parseOverrides the shipped page
// runs is src/pending.js's, and the shipped page is this build.
//
// It never writes src/ui/dist. Output: one JSON object on stdout.

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compareTrees } from './compare-trees.mjs'

const ROOT = fileURLToPath(new URL('../..', import.meta.url))
const DIST = join(ROOT, 'src', 'ui', 'dist')

const out = mkdtempSync(join(tmpdir(), 'av-ui-modules-'))
process.env.AV_UI_OUT_DIR = out
process.env.NODE_ENV = 'production'
try {
  const { build } = await import('vite')
  const result = await build({ configFile: join(ROOT, 'web', 'vite.config.js'), logLevel: 'error' })
  const outputs = (Array.isArray(result) ? result : [result]).flatMap((r) => r.output)
  const chunks = outputs.filter((o) => o.type === 'chunk').map((c) => ({
    file: c.fileName,
    isEntry: c.isEntry,
    modules: Object.fromEntries(Object.entries(c.modules).map(([id, m]) => [
      id.startsWith('\0') ? id : relative(ROOT, id).split('\\').join('/'),
      { exports: m.renderedExports, length: m.renderedLength },
    ])),
  }))
  process.stdout.write(JSON.stringify({ chunks, diffs: compareTrees(out, DIST) }))
} finally {
  rmSync(out, { recursive: true, force: true })
}
