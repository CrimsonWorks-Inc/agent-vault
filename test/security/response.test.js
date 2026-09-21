// Response handling. These cover the two defects found the first time the
// proxy met a real upstream instead of a test double: a compressed body was
// passed through still compressed with its Content-Encoding stripped, and a
// binary body was corrupted by being decoded as UTF-8. Server-sent events were
// buffered to completion, which turns a token stream into a long silence.

import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib'
import { Readable } from 'node:stream'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { Pipeline } from '../../src/daemon/pipeline.js'

const SECRET = 'ghp_RESPONSETEST00112233445566778899aa'
let dir, vault, cred, session, token, placeholder, grant

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'av-resp-'))
  vault = Vault.create(dir, { factor: 'none' })
  cred = vault.addCredential({
    slug: 'up', kind: 'http',
    connector: { host: '127.0.0.1:1', scheme: 'http' },
    fields: { token: SECRET },
    sites: { token: ['header:authorization:Bearer'] },
  })
  const created = vault.createSession({ label: 'resp', policy: {} })
  session = created.session
  token = created.token
  grant = vault.createGrant({
    sessionId: session.id, credentialId: cred.id, fields: ['token'],
    policy: { hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'auto' },
  })
  placeholder = vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

/** A pipeline whose upstream returns exactly the response we hand it. */
function pipelineReturning(response) {
  return new Pipeline(vault, {
    allowedHosts: new Set(['127.0.0.1']),
    fetchImpl: async () => response,
  })
}

const req = () => ({
  method: 'GET', path: '/p/up/thing', query: '',
  headers: [['host', '127.0.0.1'], ['authorization', `Bearer ${placeholder}`]],
  body: null,
})

test('a gzipped response is decompressed before it reaches the agent', async () => {
  const payload = JSON.stringify({ ok: true, note: 'compressed by the upstream' })
  const p = pipelineReturning({
    status: 200,
    headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
    body: gzipSync(payload),
  })
  const res = await p.handle(req())
  assert.equal(res.status, 200)
  assert.equal(res.body.toString('utf8'), payload)
  assert.equal(res.headers['content-encoding'], undefined, 'the stale encoding header must not survive')
})

test('deflate and brotli are handled too', async () => {
  for (const [encoding, compress] of [['deflate', deflateSync], ['br', brotliCompressSync]]) {
    const payload = `{"encoding":"${encoding}"}`
    const p = pipelineReturning({
      status: 200, headers: { 'content-type': 'application/json', 'content-encoding': encoding }, body: compress(payload),
    })
    const res = await p.handle(req())
    assert.equal(res.body.toString('utf8'), payload, `${encoding} was not decompressed`)
  }
})

test('a secret hidden inside a compressed body is still scrubbed', async () => {
  // Without decompression the scrubber would see compressed bytes, find
  // nothing, and hand the agent a gzip blob containing the credential.
  const p = pipelineReturning({
    status: 200,
    headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
    body: gzipSync(JSON.stringify({ echo: SECRET })),
  })
  const res = await p.handle(req())
  const text = res.body.toString('utf8')
  assert.ok(!text.includes(SECRET))
  assert.ok(text.includes(placeholder))
})

test('an encoding we cannot decode is refused rather than passed through unread', async () => {
  const p = pipelineReturning({
    status: 200, headers: { 'content-type': 'application/json', 'content-encoding': 'exotic-v9' }, body: Buffer.from('opaque'),
  })
  const res = await p.handle(req())
  assert.equal(res.status, 502)
  assert.equal(JSON.parse(res.body).code, 'AV_UNSCANNABLE')
})

test('a binary body survives byte for byte', async () => {
  // A PNG header plus every byte value: decoding this as UTF-8 replaces every
  // byte above 0x7f with U+FFFD and silently corrupts the download.
  const binary = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.from(Array.from({ length: 256 }, (_, i) => i)),
  ])
  const p = pipelineReturning({ status: 200, headers: { 'content-type': 'image/png' }, body: binary })
  const res = await p.handle(req())
  assert.equal(res.body.length, binary.length, 'length changed')
  assert.ok(res.body.equals(binary), 'bytes were altered in transit')
})

test('a gzipped binary body round-trips through decompression unchanged', async () => {
  const binary = Buffer.from(Array.from({ length: 512 }, (_, i) => i % 256))
  const p = pipelineReturning({
    status: 200, headers: { 'content-type': 'application/octet-stream', 'content-encoding': 'gzip' }, body: gzipSync(binary),
  })
  const res = await p.handle(req())
  assert.ok(res.body.equals(binary))
})

test('server-sent events are streamed and scrubbed per event, not buffered', async () => {
  const events = [
    `data: {"delta":"hello"}\n\n`,
    `data: {"leak":"${SECRET}"}\n\n`,
    `data: {"delta":"done"}\n\n`,
  ]
  const p = pipelineReturning({
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
    res: Readable.from(events.map((e) => Buffer.from(e))),
  })
  const res = await p.handle(req())
  assert.ok(res.stream, 'an event stream must be returned as a stream, not a body')

  const chunks = []
  for await (const c of res.stream) chunks.push(c)
  assert.equal(chunks.length, 3, 'each event is emitted on its own, as it arrives')
  const all = Buffer.concat(chunks).toString('utf8')
  assert.ok(!all.includes(SECRET), 'a secret inside an event must be scrubbed')
  assert.ok(all.includes(placeholder))
  assert.ok(all.includes('hello') && all.includes('done'))
})

test('a secret split across two stream chunks is still caught', async () => {
  const half = Math.floor(SECRET.length / 2)
  const p = pipelineReturning({
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
    res: Readable.from([
      Buffer.from(`data: {"leak":"${SECRET.slice(0, half)}`),
      Buffer.from(`${SECRET.slice(half)}"}\n\n`),
    ]),
  })
  const res = await p.handle(req())
  const chunks = []
  for await (const c of res.stream) chunks.push(c)
  const all = Buffer.concat(chunks).toString('utf8')
  assert.ok(!all.includes(SECRET), 'the split secret leaked')
})

test('end to end over real HTTP: a gzipping upstream and a streaming upstream both work', async () => {
  const upstream = createServer((r, res) => {
    if (r.url.startsWith('/sse')) {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.write('data: one\n\n')
      res.write('data: two\n\n')
      return res.end()
    }
    res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' })
    res.end(gzipSync('{"gzipped":true}'))
  })
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  const port = upstream.address().port

  const local = Vault.create(join(dir, 'v2'), { factor: 'none' })
  const c = local.addCredential({
    slug: 'up', kind: 'http', connector: { host: `127.0.0.1:${port}`, scheme: 'http' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  const s = local.createSession({ label: 'e2e', policy: {} })
  const g = local.createGrant({
    sessionId: s.session.id, credentialId: c.id, fields: ['token'],
    policy: { hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 10 }, approval: 'auto' },
  })
  const phText = local.issuePlaceholder({ grantId: g.id, field: 'token' }).placeholder
  const daemon = await new Daemon(local, { port: 0, socketPath: join(dir, 'v2.sock') }).start()

  try {
    const base = `http://127.0.0.1:${daemon.gatewayPort}`
    const headers = { host: '127.0.0.1', authorization: `Bearer ${phText}` }

    const gz = await fetch(`${base}/p/up/data`, { headers })
    assert.equal(await gz.text(), '{"gzipped":true}')

    const sse = await fetch(`${base}/p/up/sse`, { headers })
    assert.equal(sse.headers.get('content-type'), 'text/event-stream')
    assert.equal(await sse.text(), 'data: one\n\ndata: two\n\n')
  } finally {
    await daemon.stop()
    await new Promise((r) => upstream.close(r))
  }
})
