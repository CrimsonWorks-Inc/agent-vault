// Compare two directory trees file by file, ignoring nothing.

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs'
import { join, relative } from 'node:path'

export function listFiles(dir) {
  const out = []
  const walk = (d) => {
    for (const name of readdirSync(d).sort()) {
      const p = join(d, name)
      if (statSync(p).isDirectory()) walk(p)
      else out.push(relative(dir, p).split('\\').join('/'))
    }
  }
  if (existsSync(dir)) walk(dir)
  return out
}

/** The differences between `fresh` and `committed`, as readable lines. */
export function compareTrees(fresh, committed) {
  const a = listFiles(fresh)
  const b = listFiles(committed)
  const diffs = []
  const inB = new Set(b)
  const inA = new Set(a)
  for (const f of a) if (!inB.has(f)) diffs.push(`missing from the committed dist: ${f}`)
  for (const f of b) if (!inA.has(f)) diffs.push(`in the committed dist but not built: ${f}`)
  for (const f of a) {
    if (!inB.has(f)) continue
    if (!readFileSync(join(fresh, f)).equals(readFileSync(join(committed, f)))) diffs.push(`differs: ${f}`)
  }
  return diffs
}
