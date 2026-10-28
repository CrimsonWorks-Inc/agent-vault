import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, openSync, readSync, closeSync, lstatSync, constants } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync, spawnSync } from 'node:child_process'

// A fifo that blocks the open would hang a synchronous writer forever, which no
// in-process timeout can interrupt. So each write runs in a child with a deadline.
const FILES = new URL('../../src/cli/files.js', import.meta.url).href
function attempt(call) {
  const script = `import(${JSON.stringify(FILES)}).then((m) => { try { ${call}; console.log('written') } catch (e) { console.log(e.code) } })`
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 5000 })
  assert.equal(r.signal, null, 'the write blocked on the fifo')
  return r.stdout.trim()
}
function fifo(t) {
  const dir = mkdtempSync(join(tmpdir(), 'av-cli-fifo-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const path = join(dir, 'planted')
  execFileSync('mkfifo', [path])
  return { dir, path }
}

test('appendLineExclusive refuses a fifo with no reader at once and writes nothing', (t) => {
  const { path } = fifo(t)
  assert.equal(attempt(`m.appendLineExclusive(${JSON.stringify(path)}, 'fake-line')`), 'ENOTREGULAR')
  assert.ok(lstatSync(path).isFIFO())
})

test('appendLineExclusive refuses a fifo with a reader and the reader gets no bytes', (t) => {
  const { path } = fifo(t)
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK)
  t.after(() => closeSync(fd))
  assert.equal(attempt(`m.appendLineExclusive(${JSON.stringify(path)}, 'fake-line')`), 'ENOTREGULAR')
  let n = 0
  try { n = readSync(fd, Buffer.alloc(64)) } catch (e) { assert.equal(e.code, 'EAGAIN') }
  assert.equal(n, 0)
})

test('writeFileExclusive refuses a fifo at once, with and without force', (t) => {
  const { path } = fifo(t)
  assert.equal(attempt(`m.writeFileExclusive(${JSON.stringify(path)}, 'fake-text')`), 'EEXIST')
  assert.equal(attempt(`m.writeFileExclusive(${JSON.stringify(path)}, 'fake-text', { force: true })`), 'ENOTREGULAR')
  assert.ok(lstatSync(path).isFIFO())
})

test('appendLineExclusive still creates and appends to an ordinary file', (t) => {
  const { dir } = fifo(t)
  const path = join(dir, 'ordinary.jsonl')
  assert.equal(attempt(`m.appendLineExclusive(${JSON.stringify(path)}, 'one'); m.appendLineExclusive(${JSON.stringify(path)}, 'two')`), 'written')
  assert.equal(execFileSync('cat', [path], { encoding: 'utf8' }), 'one\ntwo\n')
  assert.equal(lstatSync(path).mode & 0o777, 0o600)
})
