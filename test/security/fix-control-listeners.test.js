// A listener does what `listen` says it does.
//
// Two ways it did not. `listen rm` deleted the record and printed "removed",
// while the bound server went on serving the network until the next restart.
// And `--allow-cidr` was stored and never read, so a listener the operator
// believed was limited to their tailnet answered anyone who could reach it.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { connect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { startDaemon, PASSPHRASE } from './fix-control-helpers.js'

/** Whether a TCP peer on loopback gets an HTTP answer from this port at all. */
function answers(port) {
  return new Promise((resolve) => {
    const s = connect(port, '127.0.0.1')
    let got = ''
    s.on('connect', () => s.write('GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'))
    s.on('data', (c) => { got += c })
    s.on('close', () => resolve(/^HTTP\/1\.1 \d{3}/.test(got)))
    s.on('error', () => resolve(false))
    s.setTimeout(2000, () => { s.destroy(); resolve(false) })
  })
}

const kinds = (vault) => vault.audit.read({ limit: 500 }).map((r) => r.kind)

test('listen rm stops the listener at once, not at the next restart', async () => {
  const d = await startDaemon({
    listeners: [
      { id: 'gone', address: '127.0.0.1:0', surfaces: ['gateway'] },
      { id: 'kept', address: '127.0.0.1:0', surfaces: ['gateway'] },
    ],
  })
  try {
    const gone = d.daemon.listeners.find((l) => l.id === 'gone')
    const kept = d.daemon.listeners.find((l) => l.id === 'kept')
    assert.ok(await answers(gone.port), 'it should serve before removal')

    const res = await d.control('DELETE', '/v1/listeners?id=gone')
    assert.equal(res.status, 200, JSON.stringify(res.body))
    assert.equal(await answers(gone.port), false, 'a removed listener must stop answering')
    assert.ok(kinds(d.vault).includes('listen.unbound'))

    // The other one is untouched.
    assert.ok(await answers(kept.port), 'removing one listener must not stop another')
    assert.ok(!d.daemon.listeners.some((l) => l.id === 'gone'))
  } finally { await d.stop() }
})

test('removing a listener that is configured but not bound still works', async () => {
  const d = await startDaemon({ passphrase: PASSPHRASE })
  try {
    d.vault.addListener({ id: 'later', address: '127.0.0.1:0', surfaces: ['mcp'] })
    const res = await d.control('DELETE', '/v1/listeners?id=later')
    assert.equal(res.status, 200, JSON.stringify(res.body))
  } finally { await d.stop() }
})

test('--allow-cidr is enforced: a peer outside it is refused', async () => {
  const d = await startDaemon({
    listeners: [{ id: 'tailnet', address: '127.0.0.1:0', surfaces: ['gateway'], allow_cidr: ['100.64.0.0/10'] }],
  })
  try {
    const l = d.daemon.listeners.find((x) => x.id === 'tailnet')
    assert.equal(await answers(l.port), false, 'loopback is outside 100.64.0.0/10 and must be refused')
    assert.ok(kinds(d.vault).includes('listen.peer_refused'))
  } finally { await d.stop() }
})

test('a peer inside --allow-cidr is served, and no list means no restriction', async () => {
  const d = await startDaemon({
    listeners: [
      { id: 'mine', address: '127.0.0.1:0', surfaces: ['gateway'], allow_cidr: ['10.0.0.0/8', '127.0.0.0/8'] },
      { id: 'v6', address: '127.0.0.1:0', surfaces: ['gateway'], allow_cidr: ['::1/128', '127.0.0.1/32'] },
      { id: 'open', address: '127.0.0.1:0', surfaces: ['gateway'], allow_cidr: [] },
    ],
  })
  try {
    for (const id of ['mine', 'v6', 'open']) {
      const l = d.daemon.listeners.find((x) => x.id === id)
      assert.ok(await answers(l.port), `${id} should serve a loopback peer`)
    }
    assert.ok(!kinds(d.vault).includes('listen.peer_refused'))
  } finally { await d.stop() }
})

test('an allow-cidr that cannot be parsed is refused, not stored and ignored', async () => {
  const d = await startDaemon()
  try {
    for (const bad of [['10.0.0.0/33'], ['not-a-cidr'], ['10.0.0.0'], ['1.2.3.4/8x'], 'a-string']) {
      const res = await d.control('POST', '/v1/listeners', {
        id: 'bad', address: '127.0.0.1:0', surfaces: ['mcp'], allow_cidr: bad,
      })
      assert.ok(res.status >= 400, `${JSON.stringify(bad)} was accepted: ${JSON.stringify(res.body)}`)
      assert.ok(!d.vault.listListeners().some((l) => l.id === 'bad'))
    }
    const ok = await d.control('POST', '/v1/listeners', {
      id: 'good', address: '127.0.0.1:0', surfaces: ['mcp'], allow_cidr: ['100.64.0.0/10', 'fd7a:115c:a1e0::/48'],
    })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
  } finally { await d.stop() }
})

// TLS has a stage HTTP never sees. A peer that connected and sent no
// ClientHello was invisible to closeAllConnections(): `listen rm` took the
// listener out of the list, then waited on that peer, which could finish its
// handshake on the removed listener and be served there.

/** Speak TLS over `socket` (or a new connection), then ask for /v1/status. */
function tlsAnswers(port, socket) {
  return new Promise((resolve) => {
    const s = tlsConnect(socket ? { socket, rejectUnauthorized: false } : { port, host: '127.0.0.1', rejectUnauthorized: false })
    let got = ''
    s.on('secureConnect', () => s.write('GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'))
    s.on('data', (c) => { got += c })
    s.on('close', () => resolve(/^HTTP\/1\.1 \d{3}/.test(got)))
    s.on('error', () => resolve(false))
    s.setTimeout(2000, () => { s.destroy(); resolve(false) })
  })
}

const within = (ms, p) => Promise.race([p, new Promise((resolve) => setTimeout(() => resolve('timed out'), ms))])

test('a TLS peer connected before listen rm is not served after it', async () => {
  const d = await startDaemon({
    listeners: [
      { id: 'tls', address: '127.0.0.1:0', surfaces: ['gateway'], tls: { managed: true } },
      { id: 'kept', address: '127.0.0.1:0', surfaces: ['gateway'], tls: { managed: true } },
    ],
  })
  const raw = connect(d.daemon.listeners.find((l) => l.id === 'tls').port, '127.0.0.1')
  try {
    await new Promise((resolve) => raw.once('connect', resolve))
    // The peer says nothing yet: no ClientHello, so HTTP has no idea it exists.
    const res = await within(3000, d.control('DELETE', '/v1/listeners?id=tls'))
    assert.notEqual(res, 'timed out', 'a silent peer must not hold the removal open')
    assert.equal(res.status, 200, JSON.stringify(res.body))
    assert.equal(await tlsAnswers(0, raw), false, 'the removed listener served a request')

    const kept = d.daemon.listeners.find((l) => l.id === 'kept')
    assert.ok(await tlsAnswers(kept.port), 'removing one TLS listener must not stop another')
  } finally {
    raw.destroy()
    await d.stop()
  }
})

test('an established TLS connection is dropped by listen rm, and a fresh one is served before it', async () => {
  const d = await startDaemon({
    listeners: [{ id: 'tls', address: '127.0.0.1:0', surfaces: ['gateway'], tls: { managed: true } }],
  })
  let s
  try {
    const port = d.daemon.listeners.find((l) => l.id === 'tls').port
    assert.ok(await tlsAnswers(port), 'an ordinary TLS client is served')

    // Handshake done, connection kept open, nothing in flight.
    s = tlsConnect({ port, host: '127.0.0.1', rejectUnauthorized: false })
    await new Promise((resolve, reject) => { s.once('secureConnect', resolve); s.once('error', reject) })
    const closed = new Promise((resolve) => s.once('close', () => resolve(true)))
    const res = await within(3000, d.control('DELETE', '/v1/listeners?id=tls'))
    assert.notEqual(res, 'timed out')
    assert.equal(await within(2000, closed), true, 'the open connection must be dropped')
  } finally {
    // Ours to close if the daemon did not, or a failure here hangs the run.
    s?.destroy()
    await d.stop()
  }
})
