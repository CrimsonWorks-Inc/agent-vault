// The mark has one geometry (src/ui/mark.svg) and the page draws it as JSX;
// the colours exist only in the theme (contract U1, U6).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { listFiles } from '../scripts/compare-trees.mjs'

const WEB = fileURLToPath(new URL('..', import.meta.url))
const read = (p) => readFileSync(join(WEB, p), 'utf8')
const mark = readFileSync(new URL('../../src/ui/mark.svg', import.meta.url), 'utf8')
const jsx = read('src/components/ui/Mark.jsx')

test('the page draws the same mark as src/ui/mark.svg', () => {
  const constant = (name) => new RegExp(`export const ${name} = '([^']+)'`).exec(jsx)[1]
  const squash = (s) => s.replace(/\s+/g, ' ').trim()
  assert.ok(squash(mark).includes(squash(constant('MARK_DOOR'))), 'the door differs')
  assert.ok(squash(mark).includes(squash(constant('MARK_TICKS'))), 'the dial ticks differ')
  assert.ok(mark.includes(constant('MARK_SLOT')), 'the keyhole slot differs')
  assert.ok(mark.includes('<circle cx="32" cy="25" r="8.5"/>') && jsx.includes('<circle cx="32" cy="25" r="8.5" />'), 'the keyhole bow differs')
  assert.ok(mark.includes('currentColor'), 'the mark follows the theme through currentColor')
})

test('colours are defined only in the theme', () => {
  const offenders = []
  for (const f of listFiles(join(WEB, 'src'))) {
    if (!/\.(jsx?|css)$/.test(f) || f === 'styles/theme.css' || /\.test\.jsx?$/.test(f)) continue
    const text = read(join('src', f))
      // The mark's mask paints in luminance: white keeps, black cuts. Those
      // are geometry, not colours, and are the only literals allowed.
      .replace(/fill="#(?:fff|000)"|stroke="#000"/g, '')
    for (const m of text.matchAll(/#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(|oklch\(/g)) offenders.push(`${f}: ${m[0]}`)
    for (const m of text.matchAll(/\b(?:bg|text|border|ring|fill|stroke|outline|from|to|via)-\[[^\]]*(?:#|rgb|hsl)/g)) offenders.push(`${f}: ${m[0]}`)
  }
  assert.deepEqual(offenders, [])
})

test('the theme defines every role BRAND.md names, for light and dark', () => {
  const theme = read('src/styles/theme.css')
  const brand = read('BRAND.md')
  for (const role of ['bg', 'surface', 'ink', 'muted', 'line', 'accent', 'accent-soft', 'ok', 'warn', 'crit', 'focus']) {
    assert.match(theme, new RegExp(`--color-${role}:`), `no ${role} token`)
    assert.ok(brand.includes(`\`${role}\``), `BRAND.md does not describe ${role}`)
    const defs = theme.match(new RegExp(`--av-${role}:`, 'g')) || []
    assert.ok(defs.length >= 3, `${role} is not defined for light, dark (system) and dark (chosen)`)
  }
})
