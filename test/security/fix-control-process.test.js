// One bad upstream must cost one request, not the daemon.
//
// An error emitted on a stream nobody listens to — the compressed SSE source
// was one — is an uncaught exception, and with no handler anywhere in the
// process Node ends it, taking every agent's session with it. The daemon now
// keeps a process-level guard while it runs: the fault is written to the
// audit log and to stderr, never swallowed, and the daemon goes on answering.
//
// Run in a child process, because the test runner keeps its own handlers on
// this one and would report the deliberate fault as a failed test.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'

const store = new URL('../../src/store/vault.js', import.meta.url).href
const server = new URL('../../src/daemon/server.js', import.meta.url).href

function run(body) {
  const script = `
    import { mkdtempSync } from 'node:fs'
    import { tmpdir } from 'node:os'
    import { join } from 'node:path'
    import { EventEmitter } from 'node:events'
    import { request } from 'node:http'
    const { Vault } = await import(${JSON.stringify(store)})
    const { Daemon } = await import(${JSON.stringify(server)})
    const dir = mkdtempSync(join(tmpdir(), 'av-fc-proc-'))
    const vault = Vault.create(dir, { factor: 'none' })
    const sock = join(dir, 'c.sock')
    const daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
    const status = () => new Promise((resolve) => {
      const req = request({ socketPath: sock, path: '/v1/status' }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)) })
      req.on('error', () => resolve(0)); req.end()
    })
    const kinds = () => vault.audit.read({ limit: 100 }).map((r) => r.kind)
    ${body}
  `
  return spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 20_000 })
}

test('an uncaught error in the daemon is recorded, and the daemon keeps answering', () => {
  const r = run(`
    // What an errored stream with no listener does: throw out of an emit.
    setImmediate(() => new EventEmitter().emit('error', new Error('read ECONNRESET from a bad upstream')))
    setImmediate(() => Promise.reject(new Error('a rejection nobody awaited')))
    await new Promise((r) => setTimeout(r, 100))
    const after = await status()
    const audited = vault.audit.read({ limit: 100 }).filter((r) => r.kind === 'daemon.uncaught')
    console.log(JSON.stringify({ after, audited }))
    await daemon.stop()
  `)
  assert.equal(r.status, 0, `the daemon process died: ${r.stderr.slice(0, 400)}`)
  const out = JSON.parse(r.stdout.trim().split('\n').pop())
  assert.equal(out.after, 200, 'the control socket should still answer')
  assert.equal(out.audited.length, 2, 'each fault is recorded in the audit log')
  // A class, never the message (C28): the message can quote what the
  // failing code was handed. The words are on stderr.
  assert.deepEqual(out.audited.map((x) => x.error), ['Error', 'Error'])
  assert.ok(out.audited.every((x) => !('detail' in x) && !JSON.stringify(x).includes('ECONNRESET')))
  // Not swallowed: the operator sees it on stderr too.
  assert.match(r.stderr, /ECONNRESET/)
})

test('an ordinary run records no fault, and stopping removes the guard', () => {
  const r = run(`
    const during = process.listenerCount('uncaughtException')
    await status()
    await daemon.stop()
    console.log(JSON.stringify({ during, after: process.listenerCount('uncaughtException'), faults: kinds().filter((k) => k === 'daemon.uncaught').length }))
  `)
  assert.equal(r.status, 0, r.stderr.slice(0, 400))
  const out = JSON.parse(r.stdout.trim().split('\n').pop())
  assert.equal(out.during, 1, 'the guard is installed while the daemon runs')
  assert.equal(out.after, 0, 'and removed when it stops, so it does not outlive it')
  assert.equal(out.faults, 0)
})
