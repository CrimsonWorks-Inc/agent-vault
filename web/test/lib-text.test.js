// lib/text.js: untrusted text is cleaned by the CLI's own rules (U7).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cleanText, cleanLine, clip, wasCleaned, BIDI } from '../src/lib/text.js'
import { cleanText as cliCleanText } from '../../src/cli/control-commands.js'

test('cleanText removes exactly what the CLI removes, over every code point that matters', () => {
  const points = []
  for (let c = 0; c <= 0x2100; c++) points.push(c)
  for (let c = 0x2100; c <= 0x2200; c++) points.push(c)
  for (const c of points) {
    const s = `a${String.fromCodePoint(c)}b`
    assert.equal(cleanText(s), cliCleanText(s), `U+${c.toString(16)} is cleaned differently from the CLI`)
  }
})

test('a right-to-left override cannot reverse what is read', () => {
  assert.equal(cleanText('fix\u202elive'), 'fixlive')
  assert.equal(cleanLine('fix\u202elive'), 'fixlive')
  for (const c of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]) {
    assert.equal(cleanLine(`x${String.fromCodePoint(c)}y`), 'xy')
    assert.ok(BIDI.test(String.fromCodePoint(c)))
    BIDI.lastIndex = 0
  }
})

test('multi-line text keeps its newlines and tabs; one line does not', () => {
  assert.equal(cleanText('one\ntwo\tthree\r\x1b[31m'), 'one\ntwo\tthree[31m')
  assert.equal(cleanLine('one\ntwo\u2028three'), 'one two three')
})

test('markup is left as text for React to escape, never interpreted here', () => {
  assert.equal(cleanText('<img src=x onerror=alert(1)>'), '<img src=x onerror=alert(1)>')
})

test('clip cuts to the limit with an ellipsis, after cleaning', () => {
  assert.equal(clip('x'.repeat(130), 120).length, 120)
  assert.ok(clip('x'.repeat(130), 120).endsWith('…'))
  assert.equal(clip('short'), 'short')
  assert.equal(clip(null), '')
})

test('wasCleaned says when something was taken out', () => {
  assert.equal(wasCleaned('plain'), false)
  assert.equal(wasCleaned('a\u202eb'), true)
  assert.equal(wasCleaned('a\nb', true), false)
  assert.equal(wasCleaned('a\nb', false), true)
})
