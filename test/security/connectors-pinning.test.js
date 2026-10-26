// F11. A pin is checked before any application byte. A mismatch destroys the
// socket and rejects AV_PIN_MISMATCH. A backup pin on an intermediate still
// matches after the leaf rotates. No pins leaves Node's own verification.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import https from 'node:https'
import http from 'node:http'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate, createHash } from 'node:crypto'
import { spkiOf, chainPins, pinnedRequest, fetchChainPins } from '../../src/connectors/pinning.js'
import { PROFILES } from '../../src/connectors/profiles.js'

function openssl(dir, args) {
  execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] })
}

function writeExt(dir, name, text) {
  writeFileSync(join(dir, name), text)
  return name
}

/** A private CA, one intermediate, and two leaves. Leaf 2 is the rotation. */
function makeChain() {
  const dir = mkdtempSync(join(tmpdir(), 'av-pin-'))
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.crt', '-days', '2', '-subj', '/CN=TestRoot', '-addext', 'basicConstraints=critical,CA:TRUE'])
  openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'int.key', '-out', 'int.csr', '-subj', '/CN=TestIntermediate'])
  writeExt(dir, 'int.ext', 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
  openssl(dir, ['x509', '-req', '-in', 'int.csr', '-CA', 'root.crt', '-CAkey', 'root.key', '-out', 'int.crt', '-days', '2', '-CAcreateserial', '-extfile', 'int.ext'])
  writeExt(dir, 'leaf.ext', 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
  for (const name of ['leaf', 'leaf2']) {
    openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', '/CN=localhost'])
    openssl(dir, ['x509', '-req', '-in', `${name}.csr`, '-CA', 'int.crt', '-CAkey', 'int.key', '-out', `${name}.crt`, '-days', '2', '-CAcreateserial', '-extfile', 'leaf.ext'])
  }
  const pin = (file) => spkiOf(new X509Certificate(readFileSync(join(dir, file))))
  return {
    dir,
    leafPin: pin('leaf.crt'),
    leaf2Pin: pin('leaf2.crt'),
    intPin: pin('int.crt'),
    material(which) {
      const cert = Buffer.concat([
        readFileSync(join(dir, `${which}.crt`)),
        readFileSync(join(dir, 'int.crt')),
      ])
      const key = readFileSync(join(dir, `${which}.key`))
      return { cert, key }
    },
    close() { rmSync(dir, { recursive: true, force: true }) },
  }
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
}

function track(server) {
  const seen = { bytes: 0, requests: 0 }
  server.on('request', (req, res) => {
    seen.requests++
    req.resume()
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok')
  })
  server.on('secureConnection', (socket) => {
    socket.on('data', (chunk) => { seen.bytes += chunk.length })
  })
  server.on('connection', (socket) => {
    if (server instanceof https.Server) return
    socket.on('data', (chunk) => { seen.bytes += chunk.length })
  })
  return seen
}

function readBody(stream) {
  return new Promise((resolve, reject) => {
    const chunks = []
    stream.on('data', (c) => chunks.push(c))
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    stream.on('error', reject)
  })
}

test('spkiOf is the SHA-256 of the SubjectPublicKeyInfo openssl emits', () => {
  const chain = makeChain()
  try {
    const der = execFileSync('openssl', ['x509', '-in', 'leaf.crt', '-pubkey', '-noout'], { cwd: chain.dir })
    const spkiDer = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'DER'], { input: der })
    const b64 = createHash('sha256').update(spkiDer).digest('base64')
    assert.equal(chain.leafPin, `sha256/${b64}`)
    assert.match(chain.leafPin, /^sha256\/[A-Za-z0-9+/]{43}=$/)
  } finally {
    chain.close()
  }
})

test('a matching pin is sent, and the response comes back', async () => {
  const chain = makeChain()
  const seen = { bytes: 0, requests: 0, body: '' }
  const server = https.createServer(chain.material('leaf'), (req, res) => {
    seen.requests++
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      seen.body = Buffer.concat(chunks).toString('utf8')
      res.writeHead(200, { 'x-ok': '1' })
      res.end('hello')
    })
  })
  server.on('secureConnection', (socket) => {
    socket.on('data', (c) => { seen.bytes += c.length })
  })
  try {
    const port = await listen(server)
    const result = await pinnedRequest({
      url: `https://127.0.0.1:${port}/user`,
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'SENTINEL',
      pins: [chain.leafPin],
    })
    assert.equal(result.status, 200)
    assert.equal(result.headers['x-ok'], '1')
    assert.equal(await readBody(result.res), 'hello')
    assert.equal(seen.requests, 1)
    assert.equal(seen.body, 'SENTINEL')
    assert.ok(seen.bytes > 0)
  } finally {
    server.close()
    chain.close()
  }
})

test('a mismatched pin sends nothing and rejects AV_PIN_MISMATCH', async () => {
  const chain = makeChain()
  const server = https.createServer(chain.material('leaf'))
  const seen = track(server)
  try {
    const port = await listen(server)
    const wrong = `sha256/${'A'.repeat(43)}=`
    await assert.rejects(
      () => pinnedRequest({
        url: `https://127.0.0.1:${port}/user`,
        method: 'POST',
        headers: { authorization: 'Bearer SUPERSECRET' },
        body: 'SENTINEL_BODY',
        pins: [wrong],
      }),
      (err) => {
        assert.equal(err.code, 'AV_PIN_MISMATCH')
        assert.equal(err.reason, undefined)
        assert.ok(Array.isArray(err.presented))
        assert.ok(err.presented.includes(chain.leafPin))
        assert.ok(err.presented.includes(chain.intPin))
        assert.equal(err.presented.includes(wrong), false)
        return true
      },
    )
    await new Promise((r) => setTimeout(r, 200))
    assert.equal(seen.bytes, 0, 'the socket got a handshake and then a close, and no application bytes')
    assert.equal(seen.requests, 0)
  } finally {
    server.close()
    chain.close()
  }
})

test('a rotated leaf still matches a backup pin on the intermediate', async () => {
  const chain = makeChain()
  const server = https.createServer(chain.material('leaf2'), (req, res) => {
    res.end('rotated')
  })
  const seen = { requests: 0 }
  server.on('request', () => { seen.requests++ })
  try {
    const port = await listen(server)
    // The old leaf pin does not match the new leaf. The intermediate does.
    const missed = await pinnedRequest({
      url: `https://127.0.0.1:${port}/user`,
      method: 'GET',
      headers: {},
      pins: [chain.leafPin],
    }).then(() => null, (err) => err)
    assert.equal(missed?.code, 'AV_PIN_MISMATCH')
    assert.equal(missed.presented.includes(chain.leaf2Pin), true)
    assert.equal(missed.presented.includes(chain.leafPin), false)
    assert.equal(seen.requests, 0)

    const result = await pinnedRequest({
      url: `https://127.0.0.1:${port}/user`,
      method: 'GET',
      headers: {},
      body: 'AFTER_ROTATION',
      pins: [chain.leafPin, chain.intPin],
    })
    assert.equal(result.status, 200)
    assert.equal(await readBody(result.res), 'rotated')
    assert.equal(seen.requests, 1)
  } finally {
    server.close()
    chain.close()
  }
})

function makeSelfSigned() {
  const dir = mkdtempSync(join(tmpdir(), 'av-pin-'))
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'])
  return {
    cert: readFileSync(join(dir, 'cert.pem')),
    key: readFileSync(join(dir, 'key.pem')),
    close() { rmSync(dir, { recursive: true, force: true }) },
  }
}

test('no pins keeps ordinary verification and still delivers a plaintext request', async () => {
  const leaf = makeSelfSigned()
  const tlsServer = https.createServer({ cert: leaf.cert, key: leaf.key })
  const seenTls = track(tlsServer)
  const httpSeen = { url: '', body: '', requests: 0 }
  const httpServer = http.createServer((req, res) => {
    httpSeen.requests++
    httpSeen.url = req.url
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      httpSeen.body = Buffer.concat(chunks).toString('utf8')
      res.writeHead(201, { 'x-plain': 'yes' })
      res.end('plain')
    })
  })
  try {
    const tlsPort = await listen(tlsServer)
    await assert.rejects(
      () => pinnedRequest({
        url: `https://127.0.0.1:${tlsPort}/user`,
        method: 'GET',
        headers: {},
        body: 'SHOULD_NOT_BE_A_PIN_ERROR',
        pins: null,
      }),
      (err) => {
        assert.notEqual(err.code, 'AV_PIN_MISMATCH')
        assert.equal(err.code, 'DEPTH_ZERO_SELF_SIGNED_CERT')
        return true
      },
    )
    await assert.rejects(
      () => pinnedRequest({
        url: `https://127.0.0.1:${tlsPort}/user`,
        method: 'GET',
        headers: {},
        pins: [],
      }),
      (err) => err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT',
    )

    const port = await listen(httpServer)
    const result = await pinnedRequest({
      url: `http://127.0.0.1:${port}/user?q=1`,
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'abc',
      pins: undefined,
    })
    assert.equal(result.status, 201)
    assert.equal(result.headers['x-plain'], 'yes')
    assert.equal(await readBody(result.res), 'plain')
    assert.equal(httpSeen.requests, 1)
    assert.equal(httpSeen.url, '/user?q=1')
    assert.equal(httpSeen.body, 'abc')
    assert.equal(seenTls.requests, 0)
  } finally {
    tlsServer.close()
    httpServer.close()
    leaf.close()
  }
})

test('pins on an http URL are refused before a connection, with reason plaintext', async () => {
  const seen = { connections: 0 }
  const server = http.createServer((req, res) => { res.end('nope') })
  server.on('connection', () => { seen.connections++ })
  try {
    const port = await listen(server)
    await assert.rejects(
      () => pinnedRequest({
        url: `http://127.0.0.1:${port}/user`,
        method: 'GET',
        headers: { authorization: 'Bearer SUPERSECRET' },
        body: 'SENTINEL',
        pins: [`sha256/${'B'.repeat(43)}=`],
      }),
      (err) => err.code === 'AV_PIN_MISMATCH' && err.reason === 'plaintext' && Array.isArray(err.presented) && err.presented.length === 0,
    )
    await new Promise((r) => setTimeout(r, 50))
    assert.equal(seen.connections, 0)
  } finally {
    server.close()
  }
})

test('fetchChainPins returns the presented chain and sends no request', async () => {
  const chain = makeChain()
  const server = https.createServer(chain.material('leaf'))
  const seen = track(server)
  try {
    const port = await listen(server)
    const rows = await fetchChainPins('127.0.0.1', port)
    assert.ok(rows.length >= 2)
    assert.equal(rows[0].spki, chain.leafPin)
    assert.equal(rows[1].spki, chain.intPin)
    assert.match(rows[0].subject, /localhost/)
    assert.match(rows[1].subject, /TestIntermediate/)
    assert.match(rows[0].not_after, /^\d{4}-\d{2}-\d{2}T/)
    await new Promise((r) => setTimeout(r, 100))
    assert.equal(seen.requests, 0)
    assert.equal(seen.bytes, 0)
  } finally {
    server.close()
    chain.close()
  }
})

test('chainPins de-duplicates and stops when the issuer points at itself', () => {
  const self = { raw: Buffer.from('not-a-cert'), fingerprint256: 'aa' }
  self.issuerCertificate = self
  const socket = { getPeerCertificate: () => self }
  assert.deepEqual(chainPins(socket), [])
  assert.deepEqual(chainPins({}), [])
})

test('profiles ship no built-in pins', () => {
  for (const [kind, profile] of Object.entries(PROFILES)) {
    assert.equal(Object.hasOwn(profile, 'pins'), false, kind)
  }
})
