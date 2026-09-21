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
import { gzipSync, deflateSync, brotliCompressSync, gunzipSync, inflateSync, brotliDecompressSync } from 'node:zlib'
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

test('a COMPRESSED event stream is decompressed before it is scrubbed', async () => {
  // The event-stream branch returned before the decompression block ever ran,
  // so a response with both `content-type: text/event-stream` and
  // `content-encoding: gzip` had the scrubber search DEFLATE bytes for a
  // plaintext needle. It found nothing, every time, and handed the agent the
  // credential in full — readable with one gunzip, counted as zero redactions,
  // and audited as a clean `response.streamed`.
  //
  // Not an exotic upstream either: every LLM provider streams, and compressing
  // a stream is ordinary. An upstream that merely WANTED to defeat the
  // scrubber only had to set one header.
  for (const [encoding, compress] of Object.entries({
    gzip: gzipSync, deflate: deflateSync, br: brotliCompressSync,
  })) {
    const payload = `data: {"delta":"hi"}\n\ndata: {"leak":"${SECRET}"}\n\ndata: {"delta":"bye"}\n\n`
    const p = pipelineReturning({
      status: 200,
      headers: { 'content-type': 'text/event-stream', 'content-encoding': encoding },
      res: Readable.from([compress(Buffer.from(payload, 'utf8'))]),
    })
    const res = await p.handle(req())
    assert.ok(res.stream, `${encoding}: an event stream must still stream`)

    const chunks = []
    for await (const c of res.stream) chunks.push(Buffer.from(c, 'latin1'))
    const delivered = Buffer.concat(chunks)

    // However the agent reads it — as delivered, or by trying to decompress it
    // itself — the secret must not be there.
    const asDelivered = delivered.toString('utf8')
    assert.ok(!asDelivered.includes(SECRET), `${encoding}: the secret reached the agent`)
    for (const attempt of [gunzipSync, inflateSync, brotliDecompressSync]) {
      let out = null
      try { out = attempt(delivered).toString('utf8') } catch { continue }
      assert.ok(!out.includes(SECRET), `${encoding}: the secret reached the agent, decompressible`)
    }
    // And the stream still works: the non-secret content arrives, in order.
    assert.ok(asDelivered.includes('hi') && asDelivered.includes('bye'), `${encoding}: the stream was destroyed`)
    assert.ok(asDelivered.indexOf('hi') < asDelivered.indexOf('bye'), `${encoding}: order was lost`)
    assert.ok(asDelivered.includes(placeholder), `${encoding}: the secret should be replaced by the placeholder`)
  }
})

test('an event stream in an encoding we cannot read is refused, not passed through', async () => {
  // Bytes that cannot be decoded cannot be scrubbed, and the buffered path
  // already refuses those. The streaming path has to agree.
  const p = pipelineReturning({
    status: 200,
    headers: { 'content-type': 'text/event-stream', 'content-encoding': 'exotic-v9' },
    res: Readable.from([Buffer.from('data: anything\n\n')]),
  })
  const res = await p.handle(req())
  assert.equal(res.status, 502)
  assert.equal(JSON.parse(res.body).code, 'AV_UNSCANNABLE')
})

test('a secret inside an event is scrubbed, and the rest survives', async () => {
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
  // Chunk count is deliberately not asserted. The scrubber holds back the
  // length of its longest needle so a secret spanning a boundary is seen
  // whole, and this stream is shorter than that hold-back — so it arrives in
  // one piece, correctly. That the hold-back stays bounded on a realistic
  // stream is the next test's job.
  const all = Buffer.concat(chunks).toString('utf8')
  assert.ok(!all.includes(SECRET), 'a secret inside an event must be scrubbed')
  assert.ok(all.includes(placeholder))
  assert.ok(all.includes('hello') && all.includes('done'))
  assert.ok(all.indexOf('hello') < all.indexOf('done'), 'order must be preserved')
})

test('the stream hold-back is bounded, not the whole response', async () => {
  // The hold-back exists so a secret spanning a boundary is caught. It must
  // not become "buffer everything and scrub at the end", which would turn a
  // token stream into a long silence and then a wall of text.
  const many = Array.from({ length: 200 }, (_, i) => `data: {"delta":"tok${i}"}\n\n`)
  const p = pipelineReturning({
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
    res: Readable.from(many.map((e) => Buffer.from(e))),
  })
  const res = await p.handle(req())
  let first = null
  let seen = 0
  for await (const c of res.stream) {
    seen += c.length
    if (first === null) first = seen
  }
  const total = many.join('').length
  assert.ok(first < total / 4,
    `output should start early, not after most of the response (${first} of ${total})`)
  assert.ok(seen >= total * 0.9, 'and everything should still arrive')
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

test('a secret cannot escape through an internal error message', async () => {
  // An unexpected error's text becomes the detail of an AV_INTERNAL and is
  // served to the agent. Nothing builds such a message from a credential
  // today; this makes sure a future mistake of that shape is contained
  // rather than handed over.
  const dir = mkdtempSync(join(tmpdir(), 'av-errleak-'))
  try {
    const v = Vault.create(dir, { factor: 'none' })
    const cred = v.addCredential({
      slug: 'prod', kind: 'http', connector: { host: '127.0.0.1:1', scheme: 'http' },
      fields: { token: 'ERRLEAK-SECRET-00011122233' }, sites: { token: ['header:authorization:Bearer'] },
    })
    const made = v.createSession({ label: 'agent' })
    const grant = v.createGrant({
      sessionId: made.session.id, credentialId: cred.id, fields: ['token'],
      policy: {
        hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'],
        budget: { unit: 'requests', limit: 9 }, approval: 'auto',
      },
    })
    const placeholder = v.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder

    // Force an unexpected failure whose message carries the secret, the way a
    // careless future `throw new Error(\`bad value: ${value}\`)` would.
    const pipeline = new Pipeline(v)
    pipeline.upstream = async () => { throw new Error('boom while sending ERRLEAK-SECRET-00011122233 upstream') }

    const res = await pipeline.handle({
      method: 'GET', path: '/p/prod/x', query: '',
      headers: [['authorization', `Bearer ${placeholder}`]], body: null,
    })
    const text = res.body.toString('utf8')
    assert.ok(!text.includes('ERRLEAK-SECRET-00011122233'),
      `a credential escaped through an error message: ${text.slice(0, 200)}`)
    assert.match(text, /\[\[av:|REDACT|boom/i, 'the error should still say something useful')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('a secret split across two SSE events is caught', async () => {
  // Every SSE client concatenates the data: fields, so scrubbing each event on
  // its own is not scrubbing at all — `data: ghp_REAL` then `data: SECRET`
  // matched nothing in either and reassembled perfectly on the far side. That
  // is exactly the LLM token stream the streaming path exists for.
  const dir = mkdtempSync(join(tmpdir(), 'av-sse-'))
  const SECRET = 'ghp_SSESPLIT0123456789abcdefghij'
  let upstream
  try {
    upstream = createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      // Split mid-secret, the way a token stream naturally would.
      res.write(`data: {"delta":"${SECRET.slice(0, 14)}"}\n\n`)
      setTimeout(() => {
        res.write(`data: {"delta":"${SECRET.slice(14)}"}\n\n`)
        res.end()
      }, 10)
    })
    await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
    const port = upstream.address().port

    const v = Vault.create(dir, { factor: 'none' })
    const cred = v.addCredential({
      slug: 'llm', kind: 'http', connector: { host: `127.0.0.1:${port}`, scheme: 'http' },
      fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
    })
    const made = v.createSession({ label: 'agent' })
    const grant = v.createGrant({
      sessionId: made.session.id, credentialId: cred.id, fields: ['token'],
      policy: {
        hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'],
        budget: { unit: 'requests', limit: 9 }, approval: 'auto',
      },
    })
    const placeholder = v.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder

    const res = await new Pipeline(v).handle({
      method: 'GET', path: '/p/llm/stream', query: '',
      headers: [['authorization', `Bearer ${placeholder}`]], body: null,
    })
    assert.ok(res.stream, 'the response should stream')

    let delivered = ''
    for await (const chunk of res.stream) delivered += chunk.toString('latin1')

    // What a client actually reconstructs.
    const reassembled = [...delivered.matchAll(/"delta":"([^"]*)"/g)].map((m) => m[1]).join('')
    assert.ok(!reassembled.includes(SECRET),
      `the secret survived reassembly: ${reassembled.slice(0, 80)}`)
    assert.ok(!delivered.includes(SECRET), 'and must not appear in the raw stream either')
  } finally {
    if (upstream) upstream.close()
    rmSync(dir, { recursive: true, force: true })
  }
})
