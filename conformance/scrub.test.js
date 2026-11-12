// Response scrubbing past a buffered JSON echo: headers, redirects, compression,
// a secret split across chunks, and an event stream. Each shape has ordinary text
// that must arrive unchanged.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib'
import {
  rustSkipReason, openWorld, gateway, leaksSecret, secretForms, SECRET, LOOKALIKE,
} from './lib/harness.js'

const ORDINARY = 'ordinary-traffic-control'
const ORDINARY_ENCODED = 'hello%20world&tag=%2Fdocs%2F&b64=aGVsbG8vd29ybGQ='

function startReflector() {
  const hits = []
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const seen = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '')
      hits.push({ url: req.url, seen })
      const path = req.url.split('?')[0]
      if (path === '/hdr') {
        res.writeHead(200, {
          'content-type': 'text/plain',
          'x-ordinary': ORDINARY,
          'x-lookalike': LOOKALIKE,
          'x-echo': seen,
          'x-b64': Buffer.from(seen, 'utf8').toString('base64'),
          [seen]: '1',
        })
        return res.end(ORDINARY)
      }
      if (path === '/redir') {
        res.writeHead(302, {
          location: `http://127.0.0.1/land?token=${seen}&ok=${ORDINARY}`,
          'content-type': 'text/plain',
          'x-ordinary': ORDINARY,
        })
        return res.end(ORDINARY)
      }
      if (path === '/gz' || path === '/deflate' || path === '/br') {
        const plain = `${ORDINARY}\n${seen}\n${LOOKALIKE}\n${ORDINARY_ENCODED}`
        const body = path === '/gz' ? gzipSync(plain) : path === '/br' ? brotliCompressSync(plain) : deflateSync(plain)
        const encoding = path === '/gz' ? 'gzip' : path === '/br' ? 'br' : 'deflate'
        res.writeHead(200, {
          'content-type': 'text/plain',
          'content-encoding': encoding,
          'content-length': body.length,
        })
        return res.end(body)
      }
      if (path === '/exotic') {
        const body = `${ORDINARY}\n${seen}`
        res.writeHead(200, {
          'content-type': 'text/plain',
          'content-encoding': 'exotic-v9',
          'content-length': Buffer.byteLength(body),
        })
        return res.end(body)
      }
      if (path === '/chunks') {
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.write(seen.slice(0, 12))
        res.write(`${seen.slice(12)}\n${ORDINARY}\n${LOOKALIKE}`)
        return res.end()
      }
      if (path === '/sse') {
        // Ordinary text before the split must survive. The daemon cuts the
        // stream once the two halves reassemble, so anything after the secret
        // is not delivered.
        res.writeHead(200, { 'content-type': 'text/event-stream' })
        res.write(`data: ${ORDINARY}\n\n`)
        res.write(`data: ${LOOKALIKE}\n\n`)
        res.write(`data: ${seen.slice(0, 16)}\n\n`)
        res.write(`data: ${seen.slice(16)}\n\n`)
        res.write('data: after-cut-marker\n\n')
        return res.end()
      }
      if (path === '/plain') {
        const lines = [ORDINARY, LOOKALIKE, ORDINARY_ENCODED, ...secretForms(seen)]
        res.writeHead(200, { 'content-type': 'text/plain' })
        return res.end(lines.join('\n'))
      }
      if (path === '/pattern') {
        res.writeHead(200, { 'content-type': 'text/plain' })
        return res.end(`zzz123456789 ${ORDINARY}`)
      }
      if (path === '/reset') {
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.write(seen.slice(0, 8))
        return req.socket.destroy()
      }
      res.writeHead(404)
      res.end('missing')
    })
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        hits,
        close: () => new Promise((r) => server.close(r)),
      })
    })
  })
}

const skip = rustSkipReason()
if (skip) {
  test('scrub', { skip }, () => {})
} else {
  describe('scrub', { concurrency: false, timeout: 120_000 }, () => {
    let w
    let reflect
    before(async () => {
      w = await openWorld()
      reflect = await startReflector()
      const added = await w.control('POST', '/v1/credentials', {
        slug: 'reflect', kind: 'http', host: `127.0.0.1:${reflect.port}`, scheme: 'http',
        value: SECRET, sites: ['header:authorization:Bearer'],
      })
      if (added.status !== 200) throw new Error(added.text)
      const session = await w.control('POST', '/v1/sessions', {
        cred: 'reflect', label: 'reflect', methods: ['GET'], paths: ['/**'],
        budget: 40, approval: 'on-write', ttl_hours: 1,
      })
      if (session.status !== 200) throw new Error(session.text)
      w.slug = 'reflect'
      w.session = session.json
      const pattern = await w.control('POST', '/v1/credentials/scrub', {
        slug: 'reflect', pattern: 'zzz[0-9]{8,16}', sample: 'zzz12345678',
      })
      if (pattern.status !== 200) throw new Error(pattern.text)
    })
    after(async () => {
      await reflect?.close()
      await w?.close()
    })

    const get = (path) => gateway(w, `/p/reflect${path}`, {
      token: w.session.token, placeholder: w.session.placeholder,
    })

    test('a secret in a response header value or name does not reach the agent', async () => {
      const res = await get('/hdr')
      assert.equal(res.status, 200, res.text)
      assert.equal(res.text, ORDINARY)
      assert.equal(res.headers['x-ordinary'], ORDINARY)
      assert.equal(res.headers['x-lookalike'], LOOKALIKE)
      assert.equal(leaksSecret(res.text), null)
      assert.equal(leaksSecret(JSON.stringify(res.headers)), null)
      assert.equal(reflect.hits.at(-1).seen, SECRET)
    })

    test('a secret in a redirect Location is scrubbed and the ordinary query survives', async () => {
      const res = await get('/redir')
      assert.equal(res.status, 302, res.text)
      assert.equal(res.headers['av-redirect-stopped'], 'max')
      assert.equal(res.headers['x-ordinary'], ORDINARY)
      assert.match(res.headers.location, new RegExp(ORDINARY))
      assert.equal(leaksSecret(res.headers.location), null)
      assert.equal(leaksSecret(res.text), null)
    })

    test('a gzip body is decompressed and scrubbed, and ordinary text is unchanged', async () => {
      const res = await get('/gz')
      assert.equal(res.status, 200, res.text)
      assert.equal(res.headers['content-encoding'], undefined)
      assert.ok(res.text.includes(ORDINARY))
      assert.ok(res.text.includes(LOOKALIKE))
      assert.ok(res.text.includes(ORDINARY_ENCODED))
      assert.equal(leaksSecret(res.text), null)
    })

    test('a deflate body is decompressed and scrubbed the same way', async () => {
      const res = await get('/deflate')
      assert.equal(res.status, 200, res.text)
      assert.ok(res.text.includes(ORDINARY))
      assert.ok(res.text.includes(LOOKALIKE))
      assert.equal(leaksSecret(res.text), null)
    })

    test('a brotli body is decompressed and scrubbed the same way', async () => {
      const res = await get('/br')
      assert.equal(res.status, 200, res.text)
      assert.equal(res.headers['content-encoding'], undefined)
      assert.ok(res.text.includes(ORDINARY))
      assert.ok(res.text.includes(LOOKALIKE))
      assert.equal(leaksSecret(res.text), null)
    })

    test('an encoding the daemon cannot read is refused and the body is discarded', async () => {
      const res = await get('/exotic')
      assert.equal(res.status, 502, res.text)
      assert.equal(res.json.code, 'AV_UNSCANNABLE')
      assert.equal(res.json.rule, 'content_encoding')
      assert.equal(leaksSecret(res.text), null)
      assert.equal(res.text.includes(ORDINARY), false)
    })

    test('a secret split across chunked writes does not reach the agent', async () => {
      const res = await get('/chunks')
      assert.equal(res.status, 200, res.text)
      assert.ok(res.text.includes(ORDINARY))
      assert.ok(res.text.includes(LOOKALIKE))
      assert.equal(leaksSecret(res.text), null)
    })

    test('a secret split across event-stream events does not reach the agent', async () => {
      const res = await get('/sse')
      assert.equal(res.status, 200, res.text)
      assert.match(res.headers['content-type'], /text\/event-stream/)
      assert.ok(res.text.includes(ORDINARY), res.text)
      assert.ok(res.text.includes(LOOKALIKE), res.text)
      assert.equal(res.text.includes('after-cut-marker'), false, res.text)
      assert.match(res.text, /AV_UNSCANNABLE/)
      assert.equal(leaksSecret(res.text), null)
    })

    test('plain-text encodings of the secret are scrubbed and ordinary encodings survive', async () => {
      const res = await get('/plain')
      assert.equal(res.status, 200, res.text)
      assert.ok(res.text.includes(ORDINARY), res.text)
      assert.ok(res.text.includes(LOOKALIKE))
      assert.ok(res.text.includes(ORDINARY_ENCODED))
      assert.equal(leaksSecret(res.text), null)
    })

    test('a stored scrub pattern redacts a matching token and leaves ordinary text', async () => {
      const res = await get('/pattern')
      assert.equal(res.status, 200, res.text)
      assert.equal(res.text.includes('zzz123456789'), false, res.text)
      assert.ok(res.text.includes(ORDINARY))
      assert.equal(leaksSecret(res.text), null)
    })

    test('an upstream that resets mid-body does not deliver the secret', async () => {
      const res = await get('/reset')
      assert.equal(res.status, 502, res.text)
      assert.equal(res.json.code, 'AV_UPSTREAM_UNREACHABLE')
      assert.equal(leaksSecret(res.text), null)
    })
  })
}
