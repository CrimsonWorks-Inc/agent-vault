// F11. A pin adds to Node's certificate verification and never replaces it.
// The chain must still verify to a trusted root and name the host; then a pin
// must match a certificate the peer proved. A mismatch sends nothing and
// rejects AV_PIN_MISMATCH. A pins value that is not a list of pins is refused
// before a connection. No pins leaves Node's own verification exactly as is.
//
// Node reads NODE_EXTRA_CA_CERTS once, at start-up, and pinnedRequest takes no
// trust option. A test that needs the private test root trusted runs the
// client in a child process with that variable set, which is also how an
// operator trusts a private CA. The servers stay in this process, so the
// byte and request counts are this process's own.

import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import https from 'node:https'
import http from 'node:http'
import { execFile, execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate, createHash } from 'node:crypto'
import * as pinning from '../../src/connectors/pinning.js'
import { PROFILES } from '../../src/connectors/profiles.js'

const { spkiOf, chainPins, pinnedRequest, fetchChainPins } = pinning
const PINNING_URL = new URL('../../src/connectors/pinning.js', import.meta.url).href
const SECRET = 'ghp_PINSECRET0000111122223333444455556666'
const WRONG = `sha256/${'A'.repeat(43)}=`

function openssl(dir, args) {
  execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] })
}

function writeExt(dir, name, text) {
  writeFileSync(join(dir, name), text)
  return name
}

/**
 * A private root, one intermediate, two leaves (leaf 2 is the rotation) and a
 * leaf for another name. Then what an on-path attacker can build holding only
 * the public intermediate: a throwaway "intermediate" with the same subject
 * and key identifier, and a leaf for this host signed by it. Last, an
 * unrelated self-signed leaf.
 */
function makeChain() {
  const dir = mkdtempSync(join(tmpdir(), 'av-pin-'))
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.crt', '-days', '2', '-subj', '/CN=TestRoot', '-addext', 'basicConstraints=critical,CA:TRUE'])
  openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'int.key', '-out', 'int.csr', '-subj', '/CN=TestIntermediate'])
  writeExt(dir, 'int.ext', 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
  openssl(dir, ['x509', '-req', '-in', 'int.csr', '-CA', 'root.crt', '-CAkey', 'root.key', '-out', 'int.crt', '-days', '2', '-CAcreateserial', '-extfile', 'int.ext'])
  writeExt(dir, 'leaf.ext', 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
  writeExt(dir, 'other.ext', 'subjectAltName=DNS:elsewhere.test\nextendedKeyUsage=serverAuth\n')
  for (const [name, ext] of [['leaf', 'leaf.ext'], ['leaf2', 'leaf.ext'], ['other', 'other.ext']]) {
    openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', '/CN=localhost'])
    openssl(dir, ['x509', '-req', '-in', `${name}.csr`, '-CA', 'int.crt', '-CAkey', 'int.key', '-out', `${name}.crt`, '-days', '2', '-CAcreateserial', '-extfile', ext])
  }

  // The attacker side reads only int.crt, which every server sends.
  const skid = execFileSync('openssl', ['x509', '-in', 'int.crt', '-noout', '-ext', 'subjectKeyIdentifier'], { cwd: dir })
    .toString().split('\n')[1].trim().replace(/:/g, '')
  writeExt(dir, 'fake.ext', `basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=${skid}\n`)
  openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'fake.key', '-out', 'fake.csr', '-subj', '/CN=TestIntermediate'])
  openssl(dir, ['x509', '-req', '-in', 'fake.csr', '-signkey', 'fake.key', '-out', 'fake.crt', '-days', '2', '-extfile', 'fake.ext'])
  openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'evil.key', '-out', 'evil.csr', '-subj', '/CN=localhost'])
  openssl(dir, ['x509', '-req', '-in', 'evil.csr', '-CA', 'fake.crt', '-CAkey', 'fake.key', '-out', 'evil.crt', '-days', '2', '-CAcreateserial', '-extfile', 'leaf.ext'])
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self.key', '-out', 'self.crt', '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'])

  const read = (file) => readFileSync(join(dir, file))
  const pin = (file) => spkiOf(new X509Certificate(read(file)))
  const serve = (key, ...certs) => ({ cert: Buffer.concat(certs.map(read)), key: read(key) })
  return {
    dir,
    trust: join(dir, 'root.crt'),
    read,
    leafPin: pin('leaf.crt'),
    leaf2Pin: pin('leaf2.crt'),
    otherPin: pin('other.crt'),
    intPin: pin('int.crt'),
    rootPin: pin('root.crt'),
    evilPin: pin('evil.crt'),
    selfPin: pin('self.crt'),
    material(which) { return serve(`${which}.key`, `${which}.crt`, 'int.crt') },
    forged: serve('evil.key', 'evil.crt', 'int.crt'),
    forgedWithRoot: serve('evil.key', 'evil.crt', 'int.crt', 'root.crt'),
    unlinked: serve('self.key', 'self.crt', 'int.crt'),
    selfSigned: serve('self.key', 'self.crt'),
    close() { rmSync(dir, { recursive: true, force: true }) },
  }
}

const chain = makeChain()
after(() => chain.close())

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
}

/** A server that counts application bytes and requests, and records them. */
async function serve(material, handler) {
  const seen = { bytes: 0, requests: 0, connections: 0, authorization: [], body: [], urls: [], reused: [] }
  const server = material ? https.createServer(material) : http.createServer()
  server.on('request', (req, res) => {
    seen.requests++
    seen.authorization.push(req.headers.authorization)
    seen.urls.push(req.url)
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      seen.body.push(Buffer.concat(chunks).toString('utf8'))
      if (handler) return handler(req, res)
      res.writeHead(200, { 'x-ok': '1' })
      res.end('hello')
    })
  })
  server.on('connection', (socket) => {
    seen.connections++
    if (material) return
    socket.on('data', (c) => { seen.bytes += c.length })
  })
  server.on('secureConnection', (socket) => {
    seen.reused.push(socket.isSessionReused())
    socket.on('data', (c) => { seen.bytes += c.length })
  })
  const port = await listen(server)
  return { server, seen, port, close: () => new Promise((r) => server.close(r)) }
}

function outcome(promise) {
  return promise.then(
    async (r) => {
      const chunks = []
      for await (const c of r.res) chunks.push(c)
      return { ok: true, status: r.status, headers: r.headers, body: Buffer.concat(chunks).toString('utf8') }
    },
    (e) => ({ ok: false, code: e.code, reason: e.reason, presented: e.presented, message: e.message }),
  )
}

const CHILD = `
const { pinnedRequest } = await import(process.env.AV_PINNING_URL)
const out = []
for (const call of JSON.parse(process.env.AV_CALLS)) {
  try {
    const r = await pinnedRequest(call)
    const chunks = []
    for await (const c of r.res) chunks.push(c)
    out.push({ ok: true, status: r.status, headers: r.headers, body: Buffer.concat(chunks).toString('utf8') })
  } catch (e) {
    out.push({ ok: false, code: e.code, reason: e.reason, presented: e.presented, message: e.message })
  }
}
process.stdout.write(JSON.stringify(out))
`

/** Run each call in turn in one child that trusts the test root. */
function trusted(...calls) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['--input-type=module', '-e', CHILD], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: chain.trust, AV_PINNING_URL: PINNING_URL, AV_CALLS: JSON.stringify(calls) },
      timeout: 30_000,
    }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`client child failed: ${err.message}\n${stderr}`))
      try { resolve(JSON.parse(stdout)) } catch (e) { reject(new Error(`client child printed ${stdout}\n${stderr}`)) }
    })
  })
}

const get = (port, pins, extra = {}) => ({
  url: `https://127.0.0.1:${port}/user`,
  method: 'GET',
  headers: { authorization: `Bearer ${SECRET}` },
  pins,
  ...extra,
})

const settle = () => new Promise((r) => setTimeout(r, 150))

test('spkiOf is the SHA-256 of the SubjectPublicKeyInfo openssl emits', () => {
  const der = execFileSync('openssl', ['x509', '-in', 'leaf.crt', '-pubkey', '-noout'], { cwd: chain.dir })
  const spkiDer = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'DER'], { input: der })
  const b64 = createHash('sha256').update(spkiDer).digest('base64')
  assert.equal(chain.leafPin, `sha256/${b64}`)
  assert.match(chain.leafPin, /^sha256\/[A-Za-z0-9+/]{43}=$/)
})

test('a trusted chain with a leaf, intermediate or root pin is sent, and the response comes back', async () => {
  const s = await serve(chain.material('leaf'))
  try {
    const [leaf, int, root] = await trusted(
      get(s.port, [chain.leafPin], { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'SENTINEL' }),
      get(s.port, [WRONG, chain.intPin]),
      get(s.port, [chain.rootPin]),
    )
    for (const out of [leaf, int, root]) {
      assert.equal(out.ok, true, JSON.stringify(out))
      assert.equal(out.status, 200)
      assert.equal(out.headers['x-ok'], '1')
      assert.equal(out.body, 'hello')
    }
    assert.equal(s.seen.requests, 3)
    assert.equal(s.seen.body[0], 'SENTINEL')
    assert.ok(s.seen.bytes > 0)
  } finally {
    await s.close()
  }
})

test('a trusted chain with a mismatched pin sends nothing and rejects AV_PIN_MISMATCH', async () => {
  const s = await serve(chain.material('leaf'))
  try {
    const [out] = await trusted(get(s.port, [WRONG], { method: 'POST', body: 'SENTINEL_BODY' }))
    assert.equal(out.code, 'AV_PIN_MISMATCH')
    assert.equal(out.reason, undefined)
    assert.ok(Array.isArray(out.presented))
    assert.ok(out.presented.includes(chain.leafPin))
    assert.ok(out.presented.includes(chain.intPin))
    assert.equal(out.presented.includes(WRONG), false)
    await settle()
    assert.equal(s.seen.bytes, 0, 'the socket got a handshake and then a close, and no application bytes')
    assert.equal(s.seen.requests, 0)
  } finally {
    await s.close()
  }
})

test('a rotated leaf still matches a backup pin on the intermediate', async () => {
  const s = await serve(chain.material('leaf2'), (req, res) => res.end('rotated'))
  try {
    const [missed, result] = await trusted(
      get(s.port, [chain.leafPin]),
      get(s.port, [chain.leafPin, chain.intPin]),
    )
    assert.equal(missed.code, 'AV_PIN_MISMATCH')
    assert.equal(missed.presented.includes(chain.leaf2Pin), true)
    assert.equal(missed.presented.includes(chain.leafPin), false)
    assert.equal(result.ok, true)
    assert.equal(result.status, 200)
    assert.equal(result.body, 'rotated')
    assert.equal(s.seen.requests, 1)
  } finally {
    await s.close()
  }
})

test('a pinned certificate the trust store does not accept is refused by Node, and nothing is sent', async () => {
  // The pin matches the leaf in both cases. Pinning must not turn that into
  // trust: an untrusted chain fails the handshake exactly as with no pins.
  const self = await serve(chain.selfSigned)
  const priv = await serve(chain.material('leaf'))
  try {
    const selfOut = await outcome(pinnedRequest(get(self.port, [chain.selfPin], { method: 'POST', body: 'SENTINEL' })))
    assert.equal(selfOut.ok, false)
    assert.equal(selfOut.code, 'DEPTH_ZERO_SELF_SIGNED_CERT')
    const privOut = await outcome(pinnedRequest(get(priv.port, [chain.leafPin, chain.intPin, chain.rootPin])))
    assert.equal(privOut.ok, false)
    assert.equal(privOut.code, 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY')
    await settle()
    for (const s of [self, priv]) {
      assert.equal(s.seen.requests, 0)
      assert.equal(s.seen.bytes, 0)
      assert.deepEqual(s.seen.authorization, [])
    }
  } finally {
    await self.close()
    await priv.close()
  }
})

test('a pinned, trusted certificate for another host name is refused, and nothing is sent', async () => {
  const s = await serve(chain.material('other'))
  try {
    const [pinned, unpinned] = await trusted(get(s.port, [chain.otherPin, chain.intPin]), get(s.port, null))
    for (const out of [pinned, unpinned]) {
      assert.equal(out.ok, false)
      assert.equal(out.code, 'ERR_TLS_CERT_ALTNAME_INVALID')
    }
    await settle()
    assert.equal(s.seen.requests, 0)
    assert.equal(s.seen.bytes, 0)
  } finally {
    await s.close()
  }
})

test('V-P1: a forged leaf plus the real intermediate does not satisfy an intermediate pin', async () => {
  // The attacker holds only the public intermediate certificate. Node links
  // getPeerCertificate's issuers by name and key identifier, so the real
  // intermediate shows up in the presented chain. It never signed this leaf.
  const s = await serve(chain.forged)
  try {
    const [inTrusted] = await trusted(get(s.port, [chain.intPin]))
    const inPlain = await outcome(pinnedRequest(get(s.port, [chain.intPin])))
    for (const out of [inTrusted, inPlain]) {
      assert.equal(out.ok, false, JSON.stringify(out))
      assert.notEqual(out.code, undefined)
    }
    await settle()
    assert.equal(s.seen.requests, 0, `the secret reached a server without the pinned key (${s.seen.authorization[0]})`)
    assert.equal(s.seen.bytes, 0)
  } finally {
    await s.close()
  }
})

test('V-P2: a forged leaf plus the real intermediate and root does not satisfy a root pin', async () => {
  const s = await serve(chain.forgedWithRoot)
  try {
    const [inTrusted] = await trusted(get(s.port, [chain.rootPin]))
    const inPlain = await outcome(pinnedRequest(get(s.port, [chain.rootPin])))
    for (const out of [inTrusted, inPlain]) assert.equal(out.ok, false, JSON.stringify(out))
    await settle()
    assert.equal(s.seen.requests, 0, 'the secret reached a server without the pinned key')
    assert.equal(s.seen.bytes, 0)
  } finally {
    await s.close()
  }
})

test('V-P4: an unrelated leaf with the real intermediate appended does not satisfy an intermediate pin', async () => {
  const s = await serve(chain.unlinked)
  try {
    const [out] = await trusted(get(s.port, [chain.intPin]))
    assert.equal(out.ok, false)
    await settle()
    assert.equal(s.seen.requests, 0)
  } finally {
    await s.close()
  }
})

test('verifiedChainPins counts an issuer only when its key signed the certificate below it', () => {
  // A stand-in for getPeerCertificate(true) that links the way Node does, by
  // name: the forged leaf points at the real intermediate.
  const der = (file) => new X509Certificate(chain.read(file)).raw
  const link = (...files) => {
    const nodes = files.map((f) => ({ raw: der(f), fingerprint256: f }))
    nodes.forEach((n, i) => { n.issuerCertificate = nodes[i + 1] || n })
    return { getPeerCertificate: () => nodes[0] }
  }
  const verified = pinning.verifiedChainPins
  assert.equal(typeof verified, 'function')
  assert.deepEqual(verified(link('leaf.crt', 'int.crt', 'root.crt')), [chain.leafPin, chain.intPin, chain.rootPin])
  const forged = link('evil.crt', 'int.crt', 'root.crt')
  assert.deepEqual(chainPins(forged), [chain.evilPin, chain.intPin, chain.rootPin])
  assert.deepEqual(verified(forged), [chain.evilPin])
  assert.deepEqual(verified(link('self.crt', 'int.crt')), [chain.selfPin])
  assert.deepEqual(verified({}), [])
})

test('V-P5: pins that are not a list of pins are refused before a connection, never read as no pins', async () => {
  const plain = await serve(null)
  const tls = await serve(chain.material('leaf'))
  try {
    const bad = [chain.intPin, { 'api.github.com': [chain.intPin] }, 42, true, 'sha256/', new Set([chain.intPin])]
    for (const pins of bad) {
      for (const port of [plain.port, tls.port]) {
        const scheme = port === plain.port ? 'http' : 'https'
        const out = await outcome(pinnedRequest(get(port, pins, { url: `${scheme}://127.0.0.1:${port}/user`, body: 'SENTINEL' })))
        assert.equal(out.code, 'AV_PIN_MISMATCH', `${scheme} ${String(pins)}`)
        assert.equal(out.reason, 'pin_format')
        assert.deepEqual(out.presented, [])
      }
    }
    await settle()
    assert.equal(plain.seen.connections, 0, 'a non-array pins value reached the network')
    assert.equal(tls.seen.connections, 0)
  } finally {
    await plain.close()
    await tls.close()
  }
})

test('V-P6: a list with a malformed entry is refused before a connection', async () => {
  const s = await serve(chain.material('leaf'))
  try {
    const lists = [['garbage'], [null], [42], [` ${chain.intPin}`], [chain.intPin, 'garbage'],
      [chain.intPin, chain.leafPin, chain.rootPin, chain.leaf2Pin, chain.otherPin]]
    for (const pins of lists) {
      const out = await outcome(pinnedRequest(get(s.port, pins)))
      assert.equal(out.code, 'AV_PIN_MISMATCH', JSON.stringify(pins))
      assert.equal(out.reason, 'pin_format')
    }
    await settle()
    assert.equal(s.seen.connections, 0)
  } finally {
    await s.close()
  }
})

test('V-P7 and V-P9: each pinned request makes its own handshake, and a redirect is returned, not followed', async () => {
  const other = await serve(chain.material('leaf'))
  const s = await serve(chain.material('leaf'), (req, res) => {
    if (req.url === '/user') {
      res.writeHead(302, { location: `https://127.0.0.1:${other.port}/steal` })
      return res.end()
    }
    res.end('ok')
  })
  try {
    const [first, second, third] = await trusted(
      get(s.port, [chain.leafPin], { url: `https://127.0.0.1:${s.port}/ok` }),
      get(s.port, [WRONG], { url: `https://127.0.0.1:${s.port}/ok` }),
      get(s.port, [chain.leafPin]),
    )
    assert.equal(first.ok, true)
    assert.equal(second.code, 'AV_PIN_MISMATCH')
    assert.equal(third.ok, true)
    assert.equal(third.status, 302)
    assert.equal(s.seen.requests, 2)
    assert.deepEqual(s.seen.reused.filter(Boolean), [], 'a pinned connection resumed a TLS session')
    assert.equal(other.seen.requests, 0)
  } finally {
    await s.close()
    await other.close()
  }
})

test('no pins (null, undefined, []) keeps Node verification unchanged', async () => {
  const plain = await serve(null, (req, res) => {
    res.writeHead(201, { 'x-plain': 'yes' })
    res.end('plain')
  })
  const self = await serve(chain.selfSigned)
  const genuine = await serve(chain.material('leaf'))
  try {
    for (const pins of [null, undefined, []]) {
      const out = await outcome(pinnedRequest(get(self.port, pins, { body: 'SHOULD_NOT_BE_A_PIN_ERROR' })))
      assert.equal(out.code, 'DEPTH_ZERO_SELF_SIGNED_CERT')
      const untrusted = await outcome(pinnedRequest(get(genuine.port, pins)))
      assert.equal(untrusted.code, 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY')
      const result = await outcome(pinnedRequest({
        url: `http://127.0.0.1:${plain.port}/user?q=1`,
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: 'abc',
        pins,
      }))
      assert.equal(result.status, 201)
      assert.equal(result.headers['x-plain'], 'yes')
      assert.equal(result.body, 'plain')
    }
    const trustedRuns = await trusted(get(genuine.port, null), get(genuine.port, []))
    for (const out of trustedRuns) assert.equal(out.ok, true)
    assert.equal(plain.seen.requests, 3)
    assert.deepEqual(plain.seen.urls, ['/user?q=1', '/user?q=1', '/user?q=1'])
    assert.deepEqual(plain.seen.body, ['abc', 'abc', 'abc'])
    assert.equal(self.seen.requests, 0)
    assert.equal(genuine.seen.requests, 2)
  } finally {
    await plain.close()
    await self.close()
    await genuine.close()
  }
})

test('pins on an http URL are refused before a connection, with reason plaintext', async () => {
  const s = await serve(null)
  try {
    const out = await outcome(pinnedRequest({
      url: `http://127.0.0.1:${s.port}/user`,
      method: 'GET',
      headers: { authorization: `Bearer ${SECRET}` },
      body: 'SENTINEL',
      pins: [`sha256/${'B'.repeat(43)}=`],
    }))
    assert.equal(out.code, 'AV_PIN_MISMATCH')
    assert.equal(out.reason, 'plaintext')
    assert.deepEqual(out.presented, [])
    await settle()
    assert.equal(s.seen.connections, 0)
  } finally {
    await s.close()
  }
})

test('fetchChainPins returns the presented chain and sends no request', async () => {
  const s = await serve(chain.material('leaf'))
  try {
    const rows = await fetchChainPins('127.0.0.1', s.port)
    assert.ok(rows.length >= 2)
    assert.equal(rows[0].spki, chain.leafPin)
    assert.equal(rows[1].spki, chain.intPin)
    assert.match(rows[0].subject, /localhost/)
    assert.match(rows[1].subject, /TestIntermediate/)
    assert.match(rows[0].not_after, /^\d{4}-\d{2}-\d{2}T/)
    await settle()
    assert.equal(s.seen.requests, 0)
    assert.equal(s.seen.bytes, 0)
  } finally {
    await s.close()
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
