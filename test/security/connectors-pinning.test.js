// F11. An exact pin on the leaf, the handshake's own certificate, stands in
// for CA trust, so a self-signed upstream can be pinned; the leaf must still
// name the host and be in date. Any other pin adds to Node's certificate
// verification and never replaces it: the chain must verify to a trusted root
// and name the host, then a pin must match a certificate the peer proved. A
// mismatch sends nothing and rejects AV_PIN_MISMATCH. A pins value that is not a list of pins is refused
// before a connection. No pins leaves Node's own verification exactly as is.
// The host every certificate check names is the URL's: a Host header that
// names anything else is refused before a connection, pinned or not.
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

const { spkiOf, chainPins, pinnedRequest, fetchChainPins, hostHeaderMatches } = pinning
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
 * and key identifier, and a leaf for this host signed by it. Last, self-signed
 * leaves: one for this host, one for another name, one expired, one not yet
 * valid, and one that copies the intermediate's public key into a leaf for
 * this host (signed by a key the attacker holds, since it has no other).
 */
function makeChain() {
  const dir = mkdtempSync(join(tmpdir(), 'av-pin-'))
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.crt', '-days', '2', '-subj', '/CN=TestRoot', '-addext', 'basicConstraints=critical,CA:TRUE'])
  openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'int.key', '-out', 'int.csr', '-subj', '/CN=TestIntermediate'])
  writeExt(dir, 'int.ext', 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
  openssl(dir, ['x509', '-req', '-in', 'int.csr', '-CA', 'root.crt', '-CAkey', 'root.key', '-out', 'int.crt', '-days', '2', '-CAcreateserial', '-extfile', 'int.ext'])
  writeExt(dir, 'leaf.ext', 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
  writeExt(dir, 'other.ext', 'subjectAltName=DNS:elsewhere.test\nextendedKeyUsage=serverAuth\n')
  writeExt(dir, 'v6.ext', 'subjectAltName=IP:::1\nextendedKeyUsage=serverAuth\n')
  for (const [name, ext] of [['leaf', 'leaf.ext'], ['leaf2', 'leaf.ext'], ['other', 'other.ext'], ['v6', 'v6.ext']]) {
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
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self6.key', '-out', 'self6.crt', '-days', '2', '-subj', '/CN=v6', '-addext', 'subjectAltName=IP:::1'])
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'selfother.key', '-out', 'selfother.crt', '-days', '2', '-subj', '/CN=elsewhere.test', '-addext', 'subjectAltName=DNS:elsewhere.test'])
  for (const [name, from, to] of [['expired', '20200101000000Z', '20200102000000Z'], ['future', '20990101000000Z', '20990102000000Z']]) {
    openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.crt`, '-not_before', from, '-not_after', to, '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'])
  }
  openssl(dir, ['pkey', '-in', 'int.key', '-pubout', '-out', 'int.pub'])
  openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'copy.key', '-out', 'copy.csr', '-subj', '/CN=localhost'])
  openssl(dir, ['x509', '-req', '-in', 'copy.csr', '-signkey', 'copy.key', '-force_pubkey', 'int.pub', '-out', 'copy.crt', '-days', '2', '-extfile', 'leaf.ext'])
  openssl(dir, ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'ec.key'])

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
    v6Pin: pin('v6.crt'),
    self6Pin: pin('self6.crt'),
    selfOtherPin: pin('selfother.crt'),
    expiredPin: pin('expired.crt'),
    futurePin: pin('future.crt'),
    copyPin: pin('copy.crt'),
    material(which) { return serve(`${which}.key`, `${which}.crt`, 'int.crt') },
    forged: serve('evil.key', 'evil.crt', 'int.crt'),
    forgedWithRoot: serve('evil.key', 'evil.crt', 'int.crt', 'root.crt'),
    unlinked: serve('self.key', 'self.crt', 'int.crt'),
    selfSigned: serve('self.key', 'self.crt'),
    selfSigned6: serve('self6.key', 'self6.crt'),
    selfOther: serve('selfother.key', 'selfother.crt'),
    expired: serve('expired.key', 'expired.crt'),
    future: serve('future.key', 'future.crt'),
    // The server holds a key, just not the one in the certificate it sends.
    copied: serve('ec.key', 'copy.crt'),
    copiedBehindSelf: serve('self.key', 'self.crt', 'copy.crt'),
    close() { rmSync(dir, { recursive: true, force: true }) },
  }
}

const chain = makeChain()
after(() => chain.close())

function listen(server, address) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, address, () => resolve(server.address().port))
  })
}

/** A server that counts application bytes and requests, and records them. */
async function serve(material, handler, address = '127.0.0.1') {
  const seen = { bytes: 0, requests: 0, connections: 0, authorization: [], body: [], urls: [], reused: [], servername: [], host: [] }
  const server = material ? https.createServer(material) : http.createServer()
  server.on('request', (req, res) => {
    seen.requests++
    seen.authorization.push(req.headers.authorization)
    seen.host.push(req.headers.host)
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
    seen.servername.push(socket.servername || null)
    socket.on('data', (c) => { seen.bytes += c.length })
  })
  const port = await listen(server, address)
  return { server, seen, port, close: () => new Promise((r) => server.close(r)) }
}

function outcome(promise) {
  return promise.then(
    async (r) => {
      const chunks = []
      for await (const c of r.res) chunks.push(c)
      return { ok: true, status: r.status, headers: r.headers, body: Buffer.concat(chunks).toString('utf8') }
    },
    (e) => ({ ok: false, code: e.code, rule: e.rule, reason: e.reason, presented: e.presented, message: e.message }),
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
    out.push({ ok: false, code: e.code, rule: e.rule, reason: e.reason, presented: e.presented, message: e.message })
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

test('only non-leaf pins on a chain the trust store does not accept: refused with Node\'s code, and nothing is sent', async () => {
  // An intermediate or root pin narrows Node's trust and never stands in for
  // it, even when the chain is genuine and every signature in it checks.
  const self = await serve(chain.selfSigned)
  const priv = await serve(chain.material('leaf'))
  try {
    const selfOut = await outcome(pinnedRequest(get(self.port, [WRONG], { method: 'POST', body: 'SENTINEL' })))
    assert.equal(selfOut.ok, false)
    assert.equal(selfOut.code, 'DEPTH_ZERO_SELF_SIGNED_CERT')
    for (const pins of [[chain.intPin], [chain.rootPin], [WRONG, chain.intPin, chain.rootPin]]) {
      const privOut = await outcome(pinnedRequest(get(priv.port, pins)))
      assert.equal(privOut.ok, false, JSON.stringify(pins))
      assert.equal(privOut.code, 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY')
    }
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

test('V-L1: an exact leaf pin stands in for CA trust, for a self-signed leaf and an untrusted chain', async () => {
  const self = await serve(chain.selfSigned)
  const priv = await serve(chain.material('leaf'))
  try {
    const selfOut = await outcome(pinnedRequest(get(self.port, [WRONG, chain.selfPin], { method: 'POST', headers: { authorization: `Bearer ${SECRET}`, 'content-type': 'text/plain' }, body: 'SENTINEL' })))
    assert.equal(selfOut.ok, true, JSON.stringify(selfOut))
    assert.equal(selfOut.status, 200)
    assert.equal(selfOut.body, 'hello')
    assert.deepEqual(self.seen.authorization, [`Bearer ${SECRET}`])
    assert.deepEqual(self.seen.body, ['SENTINEL'])
    const privOut = await outcome(pinnedRequest(get(priv.port, [chain.leafPin])))
    assert.equal(privOut.ok, true, JSON.stringify(privOut))
    assert.equal(priv.seen.requests, 1)
    // The same pin in a child that trusts the root goes the CA way and lands
    // in the same place.
    const [inTrusted] = await trusted(get(priv.port, [chain.leafPin]))
    assert.equal(inTrusted.ok, true)
    assert.equal(priv.seen.requests, 2)
  } finally {
    await self.close()
    await priv.close()
  }
})

test('V-L2: a pinned self-signed leaf for another host name is refused, and nothing is sent', async () => {
  const s = await serve(chain.selfOther)
  try {
    const out = await outcome(pinnedRequest(get(s.port, [chain.selfOtherPin], { method: 'POST', body: 'SENTINEL' })))
    assert.equal(out.ok, false)
    assert.equal(out.code, 'ERR_TLS_CERT_ALTNAME_INVALID')
    const [inTrusted] = await trusted(get(s.port, [chain.selfOtherPin]))
    assert.equal(inTrusted.code, 'ERR_TLS_CERT_ALTNAME_INVALID')
    await settle()
    assert.equal(s.seen.requests, 0)
    assert.equal(s.seen.bytes, 0)
  } finally {
    await s.close()
  }
})

test('V-L3: a self-signed leaf whose pin is not on the list is refused, and nothing is sent', async () => {
  const s = await serve(chain.selfSigned)
  try {
    for (const pins of [[WRONG], [chain.leafPin], [chain.intPin, chain.rootPin]]) {
      const out = await outcome(pinnedRequest(get(s.port, pins, { method: 'POST', body: 'SENTINEL' })))
      assert.equal(out.ok, false, JSON.stringify(pins))
      assert.equal(out.code, 'DEPTH_ZERO_SELF_SIGNED_CERT')
    }
    await settle()
    assert.equal(s.seen.requests, 0)
    assert.equal(s.seen.bytes, 0)
  } finally {
    await s.close()
  }
})

test('V-L4: a leaf copying the pinned intermediate\'s key cannot finish a handshake, and the handshake leaf is the one checked', async () => {
  // The copy carries the intermediate's SPKI, so a check that read pins off
  // the certificates without the handshake would accept it. The server has
  // no way to sign for that key: the handshake fails before secureConnect.
  assert.equal(chain.copyPin, chain.intPin)
  const copied = await serve(chain.copied)
  // The same copy, appended behind a self-signed leaf the server does hold.
  // Only position 0 can stand in for CA trust.
  const behind = await serve(chain.copiedBehindSelf)
  try {
    const plain = await outcome(pinnedRequest(get(copied.port, [chain.intPin], { method: 'POST', body: 'SENTINEL' })))
    const [inTrusted] = await trusted(get(copied.port, [chain.intPin]))
    for (const out of [plain, inTrusted]) {
      assert.equal(out.ok, false, JSON.stringify(out))
      assert.notEqual(out.code, 'AV_PIN_MISMATCH', 'the handshake should have failed before any pin was read')
    }
    const appended = await outcome(pinnedRequest(get(behind.port, [chain.intPin], { method: 'POST', body: 'SENTINEL' })))
    assert.equal(appended.ok, false)
    assert.equal(appended.code, 'DEPTH_ZERO_SELF_SIGNED_CERT')
    await settle()
    for (const s of [copied, behind]) {
      assert.equal(s.seen.requests, 0, 'the secret reached a server without the pinned key')
      assert.equal(s.seen.bytes, 0)
    }
  } finally {
    await copied.close()
    await behind.close()
  }
})

test('V-L5: a pinned self-signed leaf out of date is refused with AV_PIN_MISMATCH, and nothing is sent', async () => {
  const expired = await serve(chain.expired)
  const future = await serve(chain.future)
  try {
    const old = await outcome(pinnedRequest(get(expired.port, [chain.expiredPin], { method: 'POST', body: 'SENTINEL' })))
    assert.equal(old.code, 'AV_PIN_MISMATCH')
    assert.equal(old.reason, 'leaf_expired')
    assert.ok(old.presented.includes(chain.expiredPin))
    const early = await outcome(pinnedRequest(get(future.port, [chain.futurePin])))
    assert.equal(early.code, 'AV_PIN_MISMATCH')
    assert.equal(early.reason, 'leaf_not_yet_valid')
    const unpinned = await outcome(pinnedRequest(get(expired.port, [WRONG])))
    assert.equal(unpinned.ok, false)
    assert.notEqual(unpinned.code, 'AV_PIN_MISMATCH')
    await settle()
    for (const s of [expired, future]) {
      assert.equal(s.seen.requests, 0)
      assert.equal(s.seen.bytes, 0)
    }
  } finally {
    await expired.close()
    await future.close()
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

// F-1 (final review). `other.crt` names only elsewhere.test and is signed by
// the real intermediate; the server holds that leaf's key and nothing else.
// Node copies a Host header into the TLS server name when none is set, so a
// Host of elsewhere.test once made Node verify the certificate against that
// name while the bytes went to the URL host. Each of these delivered the
// secret before the fix.

// `host` undefined leaves the header out, so Node writes its own.
const withHost = (port, pins, host, extra = {}) => get(port, pins, {
  method: 'POST',
  headers: { authorization: `Bearer ${SECRET}`, ...(host === undefined ? {} : { host }), 'content-type': 'text/plain' },
  body: 'SENTINEL',
  ...extra,
})

function assertHostMismatch(out, label) {
  assert.equal(out.ok, false, `${label}: ${JSON.stringify(out)}`)
  assert.equal(out.code, 'AV_POLICY_DENIED', `${label}: ${JSON.stringify(out)}`)
  assert.equal(out.rule, 'host_mismatch', label)
}

test('F-1: a Host header the certificate names does not let a leaf, intermediate or root pin accept a server that does not name the URL host', async () => {
  const s = await serve(chain.material('other'))
  try {
    const cases = [
      ['intermediate pin, URL 127.0.0.1', withHost(s.port, [chain.intPin], 'elsewhere.test')],
      ['root pin, URL 127.0.0.1', withHost(s.port, [chain.rootPin], 'elsewhere.test')],
      ['intermediate pin, URL localhost', withHost(s.port, [chain.intPin], 'elsewhere.test', { url: `https://localhost:${s.port}/user` })],
      ['leaf pin, URL localhost', withHost(s.port, [chain.otherPin], 'elsewhere.test', { url: `https://localhost:${s.port}/user` })],
      ['leaf pin, URL 127.0.0.1', withHost(s.port, [chain.otherPin], 'elsewhere.test')],
      ['Host with the port, URL 127.0.0.1', withHost(s.port, [chain.intPin], `elsewhere.test:${s.port}`)],
    ]
    const outs = await trusted(...cases.map(([, call]) => call))
    outs.forEach((out, i) => assertHostMismatch(out, cases[i][0]))
    // The same in this process, where nothing trusts the root.
    for (const [label, call] of cases) assertHostMismatch(await outcome(pinnedRequest(call)), `${label} (untrusted)`)
    await settle()
    assert.equal(s.seen.connections, 0)
    assert.equal(s.seen.requests, 0)
    assert.equal(s.seen.bytes, 0)

    // Without a Host header the certificate is checked against the URL host,
    // which it does not name.
    const [bare] = await trusted(get(s.port, [chain.intPin]), get(s.port, [chain.otherPin]))
    assert.equal(bare.ok, false)
    assert.equal(bare.code, 'ERR_TLS_CERT_ALTNAME_INVALID')
    await settle()
    assert.equal(s.seen.requests, 0)
    assert.equal(s.seen.bytes, 0)
  } finally {
    await s.close()
  }
})

test('F-1: the TLS server name is the URL host, and a Host header naming another host is refused before a connection, pinned or not', async () => {
  const self = await serve(chain.selfSigned)
  const genuine = await serve(chain.material('leaf'))
  const plain = await serve(null)
  try {
    // A certificate that names the URL host, a Host header that names another:
    // this used to be delivered with the server name set to the header.
    for (const pins of [[chain.selfPin], null]) {
      assertHostMismatch(await outcome(pinnedRequest(withHost(self.port, pins, 'elsewhere.test'))), `self ${JSON.stringify(pins)}`)
    }
    const [trustedOut] = await trusted(withHost(genuine.port, [chain.intPin], 'elsewhere.test'), withHost(genuine.port, null, 'elsewhere.test'))
    assertHostMismatch(trustedOut, 'trusted chain')
    assertHostMismatch(await outcome(pinnedRequest(withHost(plain.port, null, 'elsewhere.test', { url: `http://127.0.0.1:${plain.port}/user` }))), 'http')
    await settle()
    for (const s of [self, genuine, plain]) {
      assert.equal(s.seen.connections, 0)
      assert.equal(s.seen.requests, 0)
    }

    // Matching Host headers, in another case or with the port written, are
    // sent. The server name is the URL host, lower case, not the header.
    const local = (port, pins, host) => withHost(port, pins, host, { url: `https://localhost:${port}/user` })
    const ok1 = await outcome(pinnedRequest(local(self.port, [chain.selfPin], `LocalHost:${self.port}`)))
    assert.equal(ok1.ok, true, JSON.stringify(ok1))
    const ok2 = await outcome(pinnedRequest(local(self.port, [chain.selfPin], undefined)))
    assert.equal(ok2.ok, true, JSON.stringify(ok2))
    assert.deepEqual(self.seen.servername, ['localhost', 'localhost'])
    assert.deepEqual(self.seen.host, [`LocalHost:${self.port}`, `localhost:${self.port}`])
    // An IP is not sent as a server name.
    const ok3 = await outcome(pinnedRequest(withHost(self.port, [chain.selfPin], `127.0.0.1:${self.port}`)))
    assert.equal(ok3.ok, true, JSON.stringify(ok3))
    assert.equal(self.seen.servername[2], null)
  } finally {
    await self.close()
    await genuine.close()
    await plain.close()
  }
})

test('F-1: a Host header with another port, no port, another case of another name, or a list is refused', async () => {
  const s = await serve(chain.selfSigned)
  try {
    const p = s.port
    const refusedHosts = [
      '127.0.0.1',
      `127.0.0.1:${p + 1 === 65536 ? 1 : p + 1}`,
      `127.0.0.1:${p}x`,
      ` 127.0.0.1:${p}`,
      'Elsewhere.TEST',
      `localhost:${p}`,
    ]
    for (const host of refusedHosts) {
      assertHostMismatch(await outcome(pinnedRequest(withHost(p, [chain.selfPin], host))), JSON.stringify(host))
    }
    // A Host that is not a string never reaches the check: the header copy
    // refuses it first.
    for (const host of [[`127.0.0.1:${p}`], 42]) {
      const out = await outcome(pinnedRequest(withHost(p, [chain.selfPin], host)))
      assert.equal(out.code, 'AV_POLICY_DENIED', JSON.stringify(out))
      assert.equal(out.rule, 'header_format', JSON.stringify(host))
    }
    // Any spelling of the header name, and the raw array form.
    assertHostMismatch(await outcome(pinnedRequest(get(p, [chain.selfPin], { headers: { HOST: 'elsewhere.test' } }))), 'HOST')
    assertHostMismatch(await outcome(pinnedRequest(get(p, [chain.selfPin], {
      headers: { host: `127.0.0.1:${p}`, Host: 'elsewhere.test' },
    }))), 'two spellings')
    assertHostMismatch(await outcome(pinnedRequest(get(p, [chain.selfPin], {
      headers: ['Authorization', `Bearer ${SECRET}`, 'Host', 'elsewhere.test'],
    }))), 'raw array')
    await settle()
    assert.equal(s.seen.connections, 0)
  } finally {
    await s.close()
  }
})

test('F-1: hostHeaderMatches allows only the URL host, any case, with or without the scheme\'s default port', () => {
  const https443 = new URL('https://API.github.com/user')
  for (const h of ['api.github.com', 'API.GITHUB.COM', 'api.github.com:443']) assert.equal(hostHeaderMatches(h, https443), true, h)
  for (const h of ['api.github.com:80', 'api.github.com:8443', 'api.github.com.', 'evil.example', 'api.github.com:443:443', '', null, ['api.github.com']]) {
    assert.equal(hostHeaderMatches(h, https443), false, JSON.stringify(h))
  }
  const http80 = new URL('http://example.test/')
  assert.equal(hostHeaderMatches('example.test:80', http80), true)
  assert.equal(hostHeaderMatches('example.test:443', http80), false)
  const odd = new URL('https://example.test:8443/')
  assert.equal(hostHeaderMatches('example.test:8443', odd), true)
  assert.equal(hostHeaderMatches('example.test', odd), false)
  assert.equal(hostHeaderMatches('example.test:443', odd), false)
  const v6 = new URL('https://[::1]:8443/')
  assert.equal(hostHeaderMatches('[::1]:8443', v6), true)
  assert.equal(hostHeaderMatches('::1', v6), false)
})

test('F-1 controls: a matching or absent Host header is delivered with and without pins', async () => {
  const genuine = await serve(chain.material('leaf'))
  const self = await serve(chain.selfSigned)
  const plain = await serve(null)
  try {
    const host = `127.0.0.1:${genuine.port}`
    const outs = await trusted(
      withHost(genuine.port, [chain.intPin], host),
      withHost(genuine.port, [chain.rootPin], undefined),
      withHost(genuine.port, [chain.leafPin], host),
      withHost(genuine.port, null, host),
      withHost(genuine.port, null, undefined),
    )
    for (const out of outs) {
      assert.equal(out.ok, true, JSON.stringify(out))
      assert.equal(out.body, 'hello')
    }
    assert.equal(genuine.seen.requests, 5)
    assert.equal(genuine.seen.authorization.every((a) => a === `Bearer ${SECRET}`), true)
    assert.deepEqual(genuine.seen.host, Array(5).fill(host))
    const selfOut = await outcome(pinnedRequest(withHost(self.port, [chain.selfPin], `127.0.0.1:${self.port}`)))
    assert.equal(selfOut.ok, true, JSON.stringify(selfOut))
    for (const h of [`127.0.0.1:${plain.port}`, undefined]) {
      const out = await outcome(pinnedRequest(withHost(plain.port, null, h, { url: `http://127.0.0.1:${plain.port}/user` })))
      assert.equal(out.ok, true, JSON.stringify(out))
    }
    assert.equal(plain.seen.requests, 2)
  } finally {
    await genuine.close()
    await self.close()
    await plain.close()
  }
})

// Round 5, F-1. The Host check and the request are one read of the headers.
// Node copies a headers object into the request after the check has run, so
// a getter or a Proxy could answer the check with the URL host and Node with
// another. Each of these delivered the bearer secret with Host evil.example
// before the copy. `leaf.crt` names 127.0.0.1 and is leaf-pinned, so every
// one of them completes a handshake: what is asserted is the Host on the wire.

function assertNoForeignHost(s, out, label) {
  assert.equal(s.seen.host.some((h) => String(h).toLowerCase().includes('evil.example')), false,
    `${label}: ${JSON.stringify({ out, host: s.seen.host })}`)
  if (out.ok) {
    assert.equal(s.seen.host.at(-1), `127.0.0.1:${s.port}`, label)
    assert.equal(s.seen.authorization.at(-1), `Bearer ${SECRET}`, label)
  } else {
    assertHostMismatch(out, label)
  }
}

test('Round 5 F-1: a getter or a Proxy cannot pass the Host check and then put another host on the wire', async () => {
  const s = await serve(chain.material('leaf'))
  try {
    const good = `127.0.0.1:${s.port}`
    const pins = [chain.leafPin]

    // A getter: the URL host on the first read, evil.example after.
    let getterReads = 0
    const getter = { authorization: `Bearer ${SECRET}` }
    Object.defineProperty(getter, 'host', {
      enumerable: true,
      get() { getterReads++; return getterReads === 1 ? good : 'evil.example' },
    })
    const viaGetter = await outcome(pinnedRequest(get(s.port, pins, { headers: getter })))
    assertNoForeignHost(s, viaGetter, 'getter')
    assert.equal(getterReads, 1, 'the getter is read once')
    assert.equal(viaGetter.ok, true, JSON.stringify(viaGetter))

    // A Proxy `get` trap with the same two answers.
    let trapReads = 0
    const trapped = new Proxy({ authorization: `Bearer ${SECRET}`, host: good }, {
      get(t, k) {
        if (k !== 'host') return t[k]
        trapReads++
        return trapReads === 1 ? good : 'evil.example'
      },
    })
    const viaTrap = await outcome(pinnedRequest(get(s.port, pins, { headers: trapped })))
    assertNoForeignHost(s, viaTrap, 'get trap')
    assert.equal(trapReads, 1, 'the get trap is read once')

    // A Proxy whose key list grows a Host after the first enumeration. The
    // copy has no Host, so Node writes the URL host.
    let listings = 0
    const phased = new Proxy({ authorization: `Bearer ${SECRET}`, host: 'evil.example' }, {
      ownKeys() { listings++; return listings === 1 ? ['authorization'] : ['host', 'authorization'] },
      getOwnPropertyDescriptor(t, k) { return { enumerable: true, configurable: true, value: t[k] } },
    })
    const viaKeys = await outcome(pinnedRequest(get(s.port, pins, { headers: phased })))
    assertNoForeignHost(s, viaKeys, 'ownKeys')
    assert.equal(listings, 1, 'the key list is read once')
    assert.equal(viaKeys.ok, true, JSON.stringify(viaKeys))

    // The flat array form, with a Proxy on the Host value's index.
    let indexReads = 0
    const pairs = new Proxy(['authorization', `Bearer ${SECRET}`, 'host', good], {
      get(t, k) {
        if (k !== '3') return Reflect.get(t, k)
        indexReads++
        return indexReads === 1 ? good : 'evil.example'
      },
    })
    const viaArray = await outcome(pinnedRequest(get(s.port, pins, { headers: pairs })))
    assertNoForeignHost(s, viaArray, 'array')
    assert.equal(indexReads, 1, 'the array entry is read once')
    assert.equal(viaArray.ok, true, JSON.stringify(viaArray))

    // The order flipped: a foreign Host on the first read is refused, and
    // nothing connects.
    const before = s.seen.connections
    let lateReads = 0
    const late = { authorization: `Bearer ${SECRET}` }
    Object.defineProperty(late, 'host', {
      enumerable: true,
      get() { lateReads++; return lateReads === 1 ? 'evil.example' : good },
    })
    assertHostMismatch(await outcome(pinnedRequest(get(s.port, pins, { headers: late }))), 'foreign first read')
    await settle()
    assert.equal(s.seen.connections, before)
  } finally {
    await s.close()
  }
})

test('Round 5 F-1: headers that are not names with string values are refused before a connection', async () => {
  const s = await serve(chain.material('leaf'))
  try {
    const refused = [
      ['number value', { authorization: `Bearer ${SECRET}`, 'content-length': 0 }],
      ['array value', { authorization: [`Bearer ${SECRET}`] }],
      ['object value', { authorization: { toString: () => `Bearer ${SECRET}` } }],
      ['odd array', ['authorization', `Bearer ${SECRET}`, 'host']],
      ['array name not a string', [1, 'x', 'authorization', `Bearer ${SECRET}`]],
      ['array name twice', ['authorization', `Bearer ${SECRET}`, 'authorization', 'Bearer other']],
      ['a string', 'authorization: x'],
      ['a getter that throws', Object.defineProperty({}, 'host', { enumerable: true, get() { throw new Error('boom') } })],
    ]
    for (const [label, headers] of refused) {
      const out = await outcome(pinnedRequest(get(s.port, [chain.leafPin], { headers })))
      assert.equal(out.code, 'AV_POLICY_DENIED', `${label}: ${JSON.stringify(out)}`)
      assert.equal(out.rule, 'header_format', label)
    }
    await settle()
    assert.equal(s.seen.connections, 0)

    // Controls: no headers, and a null-prototype object, are sent.
    for (const headers of [undefined, null, Object.assign(Object.create(null), { authorization: `Bearer ${SECRET}` })]) {
      const out = await outcome(pinnedRequest(get(s.port, [chain.leafPin], { headers })))
      assert.equal(out.ok, true, JSON.stringify(out))
    }
    assert.deepEqual(s.seen.host, Array(3).fill(`127.0.0.1:${s.port}`))
  } finally {
    await s.close()
  }
})

// Round 5, F-2. An IPv6 URL host keeps its brackets in parsed.hostname, and
// Node looked '[::1]' up as a name: every IPv6 request failed with
// ENOTFOUND. The connection uses the bare address; the certificate must name
// it as an IP SAN, and an IP is never sent as a server name.

async function serveV6(material) {
  try {
    return await serve(material, null, '::1')
  } catch (e) {
    if (e.code === 'EADDRNOTAVAIL' || e.code === 'EAFNOSUPPORT') return null
    throw e
  }
}

test('Round 5 F-2: an IPv6 URL connects, the certificate is checked against the IP SAN, and pins apply', async (t) => {
  const self6 = await serveV6(chain.selfSigned6)
  if (!self6) { t.skip('no IPv6 loopback'); return }
  const genuine6 = await serveV6(chain.material('v6'))
  const wrongSan = await serveV6(chain.selfSigned)
  const wrongChain = await serveV6(chain.material('leaf'))
  const v6 = (port, pins, extra = {}) => get(port, pins, { url: `https://[::1]:${port}/user`, ...extra })
  try {
    // A pinned self-signed leaf with IP:::1, with no Host and with the
    // bracketed Host Node itself writes.
    const bare = await outcome(pinnedRequest(v6(self6.port, [chain.self6Pin])))
    assert.equal(bare.ok, true, JSON.stringify(bare))
    assert.equal(bare.body, 'hello')
    const bracketed = await outcome(pinnedRequest(v6(self6.port, [chain.self6Pin], {
      headers: { authorization: `Bearer ${SECRET}`, host: `[::1]:${self6.port}` },
    })))
    assert.equal(bracketed.ok, true, JSON.stringify(bracketed))
    assert.deepEqual(self6.seen.host, [`[::1]:${self6.port}`, `[::1]:${self6.port}`])
    assert.deepEqual(self6.seen.servername, [null, null])
    assert.deepEqual(self6.seen.authorization, [`Bearer ${SECRET}`, `Bearer ${SECRET}`])

    // A chain the trusting child accepts: intermediate pin and no pins.
    const [viaInt, unpinned, wrongPin] = await trusted(
      v6(genuine6.port, [chain.intPin]),
      v6(genuine6.port, null),
      v6(genuine6.port, [WRONG]),
    )
    assert.equal(viaInt.ok, true, JSON.stringify(viaInt))
    assert.equal(unpinned.ok, true, JSON.stringify(unpinned))
    assert.equal(wrongPin.code, 'AV_PIN_MISMATCH', JSON.stringify(wrongPin))
    assert.equal(genuine6.seen.requests, 2)

    // A certificate without IP:::1 is refused, pinned leaf or trusted chain,
    // and nothing is written.
    const leafWrongSan = await outcome(pinnedRequest(v6(wrongSan.port, [chain.selfPin])))
    assert.equal(leafWrongSan.code, 'ERR_TLS_CERT_ALTNAME_INVALID', JSON.stringify(leafWrongSan))
    const [chainWrongSan, chainWrongSanUnpinned] = await trusted(v6(wrongChain.port, [chain.intPin]), v6(wrongChain.port, null))
    assert.equal(chainWrongSan.code, 'ERR_TLS_CERT_ALTNAME_INVALID', JSON.stringify(chainWrongSan))
    assert.equal(chainWrongSanUnpinned.ok, false, JSON.stringify(chainWrongSanUnpinned))

    // A Host that is not the URL host is still refused before a connection.
    for (const host of ['::1', 'evil.example', `127.0.0.1:${self6.port}`]) {
      assertHostMismatch(await outcome(pinnedRequest(v6(self6.port, [chain.self6Pin], {
        headers: { authorization: `Bearer ${SECRET}`, host },
      }))), host)
    }
    await settle()
    for (const s of [wrongSan, wrongChain]) {
      assert.equal(s.seen.requests, 0)
      assert.equal(s.seen.bytes, 0)
    }
    assert.equal(self6.seen.connections, 2)
  } finally {
    for (const s of [self6, genuine6, wrongSan, wrongChain]) await s?.close()
  }
})
