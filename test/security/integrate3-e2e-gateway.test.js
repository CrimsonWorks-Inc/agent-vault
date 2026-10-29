// A.7 items 4–5, end to end. Item 4: one session per gateway feature (F1
// rate and quota, F2 payload rules, F3 method-bound routes, F5 token spend,
// F6 redirects), each made with the real CLI and used through MCP vault_http,
// with a case that fires and one that does not. Item 5: F7 rotation with
// `keep` while an agent keeps calling.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { startE2E, PASSPHRASE, SECRETS, ROTATED } from './integrate3-e2e-helpers.js'

/** `session create` with these flags, answering the passphrase prompt. */
async function create(e, flags) {
  const r = await e.cli(['session', 'create', ...flags], { tty: true, input: `${PASSPHRASE}\n`, json: true })
  assert.equal(r.code, 0, r.stdout + r.stderr)
  return r.data
}

const call = (e, s, args) => e.mcp(s.token, 'vault_http', { reason: 'e2e', ...args })
const hitsTo = (e, path) => e.seen.filter((h) => h.url.split('?')[0] === path).length

test('A.7 4 (F1): --rate and --quota refuse the call past the limit with retry_after, and nothing past it is sent', async () => {
  const e = await startE2E({ passphrase: PASSPHRASE })
  try {
    const rated = await create(e, ['--cred', 'gh', '--rate', '2/min'])
    const quota = await create(e, ['--cred', 'gh', '--quota', '2/day'])
    const plain = await create(e, ['--cred', 'gh'])
    for (const [s, path] of [[rated, '/rate'], [quota, '/quota']]) {
      for (let i = 0; i < 2; i++) assert.equal((await call(e, s, { cred: 'gh', method: 'GET', path })).body.status, 200, path)
      const third = await call(e, s, { cred: 'gh', method: 'GET', path })
      assert.equal(third.body.status, 429, third.text)
      assert.match(third.text, /AV_QUOTA_EXCEEDED/)
      assert.match(third.text, /retry_after/)
      assert.equal(hitsTo(e, path), 2, `${path}: the refused call reached nothing`)
    }
    // Does not fire: the same three calls on a session with no limit.
    for (let i = 0; i < 3; i++) assert.equal((await call(e, plain, { cred: 'gh', method: 'GET', path: '/plain' })).body.status, 200)
    assert.equal(hitsTo(e, '/plain'), 3)
    assert.equal(e.audit('request.throttled').length, 2)
  } finally { await e.stop() }
})

test('A.7 4 (F1): --concurrency 1 refuses a second call while the first is in flight, and not one after it', async () => {
  const e = await startE2E({ passphrase: PASSPHRASE, reply: async (hit) => { if (hit.url === '/slow') await new Promise((r) => setTimeout(r, 300)) } })
  try {
    const s = await create(e, ['--cred', 'gh', '--concurrency', '1'])
    const [a, b] = await Promise.all([
      call(e, s, { cred: 'gh', method: 'GET', path: '/slow' }),
      new Promise((r) => setTimeout(r, 100)).then(() => call(e, s, { cred: 'gh', method: 'GET', path: '/second' })),
    ])
    assert.equal(a.body.status, 200, a.text)
    assert.equal(b.body.status, 429, b.text)
    assert.match(b.text, /AV_QUOTA_EXCEEDED/)
    assert.equal(hitsTo(e, '/second'), 0)
    // The slot came back: the same call afterwards goes through.
    assert.equal((await call(e, s, { cred: 'gh', method: 'GET', path: '/second' })).body.status, 200)
    assert.equal(hitsTo(e, '/second'), 1)
  } finally { await e.stop() }
})

test('A.7 4 (F2): a JSON payload rule refuses a value outside it before anything is sent, and passes one inside it', async () => {
  const e = await startE2E({ passphrase: PASSPHRASE })
  try {
    writeFileSync(join(e.dir, 'payload.json'), JSON.stringify({ json: { '/state': { one_of: ['open'] } } }))
    const s = await create(e, ['--cred', 'gh', '--methods', 'GET,POST', '--approval', 'auto', '--payload-file', join(e.dir, 'payload.json')])
    const refused = await call(e, s, { cred: 'gh', method: 'POST', path: '/issues', body: '{"state":"closed"}' })
    assert.equal(refused.body.status, 403, refused.text)
    assert.equal(JSON.parse(refused.body.body).rule, 'payload:json:0:one_of')
    assert.ok(!refused.text.includes('closed'), 'the refusal never echoes the value')
    assert.equal(hitsTo(e, '/issues'), 0)
    const allowed = await call(e, s, { cred: 'gh', method: 'POST', path: '/issues', body: '{"state":"open"}' })
    assert.equal(allowed.body.status, 200, allowed.text)
    assert.equal(hitsTo(e, '/issues'), 1)
    assert.equal(e.seen.at(-1).body, '{"state":"open"}')
  } finally { await e.stop() }
})

test('A.7 4 (F3): method-bound routes allow each method only on its own paths', async () => {
  const e = await startE2E({ passphrase: PASSPHRASE })
  try {
    const s = await create(e, ['--cred', 'gh', '--methods', 'GET,POST', '--approval', 'auto', '--route', 'GET:/repos/**', '--route', 'POST:/repos/*/issues'])
    // Fires: a POST on a GET-only path, and a GET outside every route.
    for (const [method, path] of [['POST', '/repos/a/pulls'], ['GET', '/user']]) {
      const r = await call(e, s, { cred: 'gh', method, path, ...(method === 'POST' ? { body: '{}' } : {}) })
      assert.equal(r.body.status, 403, `${method} ${path}: ${r.text}`)
      assert.equal(hitsTo(e, path), 0)
    }
    // Does not fire: each method on its own paths.
    for (const [method, path] of [['POST', '/repos/a/issues'], ['GET', '/repos/a/pulls']]) {
      const r = await call(e, s, { cred: 'gh', method, path, ...(method === 'POST' ? { body: '{}' } : {}) })
      assert.equal(r.body.status, 200, `${method} ${path}: ${r.text}`)
    }
    assert.equal(e.seen.length, 2)
  } finally { await e.stop() }
})

test('A.7 4 (F5): a token budget refuses a call that could exceed it, and settles a call that fits on its real usage', async () => {
  const usage = '{"usage":{"prompt_tokens":5,"completion_tokens":7}}'
  const e = await startE2E({ passphrase: PASSPHRASE, reply: () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: usage }) })
  try {
    const s = await create(e, ['--cred', 'openai', '--methods', 'GET,POST', '--approval', 'auto', '--spend-tokens', '200'])
    const chat = (maxTokens) => call(e, s, { cred: 'openai', method: 'POST', path: '/v1/chat/completions', body: JSON.stringify({ model: 'gpt-4.1-mini', max_tokens: maxTokens, messages: [] }) })
    const refused = await chat(5000)
    assert.equal(refused.body.status, 403, refused.text)
    assert.equal(JSON.parse(refused.body.body).rule, 'spend')
    assert.equal(e.seen.length, 0)
    const fits = await chat(20)
    assert.equal(fits.body.status, 200, fits.text)
    assert.equal(e.seen.length, 1)
    assert.equal(e.seen[0].host, 'api.openai.com')
    assert.equal(e.seen[0].headers.authorization, `Bearer ${SECRETS.openai}`)
    const grant = Object.values(e.vault.db.grants).find((g) => g.session_id === s.session_id)
    assert.equal(grant.spend.tokens_used, 12, 'charged what the upstream reported')
    assert.deepEqual(grant.spend.reserved, {})
  } finally { await e.stop() }
})

test('A.7 4 (F6): --redirects follows a hop the policy allows, stops at one it does not, and never follows without it', async () => {
  const e = await startE2E({
    passphrase: PASSPHRASE,
    reply: (hit) => {
      if (hit.url === '/start') return { status: 302, headers: { location: '/final' }, body: '' }
      if (hit.url === '/out') return { status: 302, headers: { location: 'http://elsewhere.invalid/x' }, body: '' }
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'final' }
    },
  })
  try {
    const follows = await create(e, ['--cred', 'gh', '--redirects', '1'])
    const never = await create(e, ['--cred', 'gh'])
    const followed = await call(e, follows, { cred: 'gh', method: 'GET', path: '/start' })
    assert.equal(followed.body.status, 200, followed.text)
    assert.equal(followed.body.body, 'final')
    assert.deepEqual(e.seen.map((h) => h.url), ['/start', '/final'])
    assert.equal(e.audit('request.redirect_followed').length, 1)

    // Fires: another host is not in the policy, so the 3xx comes back.
    const stopped = await call(e, follows, { cred: 'gh', method: 'GET', path: '/out' })
    assert.equal(stopped.body.status, 302, stopped.text)
    assert.equal(stopped.body.headers['av-redirect-stopped'], 'host')
    assert.equal(hitsTo(e, '/out'), 1)
    assert.ok(!e.seen.some((h) => h.host === 'elsewhere.invalid'), 'the credential never left for the other host')

    // Does not follow at all without --redirects.
    const plain = await call(e, never, { cred: 'gh', method: 'GET', path: '/start' })
    assert.equal(plain.body.status, 302, plain.text)
    assert.equal(hitsTo(e, '/final'), 1, 'only the first session reached /final')
  } finally { await e.stop() }
})

test('A.7 5 (F7): rotating with keep while an agent loops loses no request, and the old value stays scrubbed', async () => {
  // Every answer carries both values, as a careless upstream might.
  const e = await startE2E({ reply: (hit) => ({ status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ saw: hit.headers.authorization, old: SECRETS.gh, new: ROTATED }) }) })
  try {
    const made = await e.cli(['session', 'create', '--cred', 'gh'], { json: true })
    assert.equal(made.code, 0, made.stdout + made.stderr)
    const s = made.data
    const results = []
    let rotated = false
    const loop = (async () => {
      for (let i = 0; i < 40 && !(rotated && results.length > 25); i++) {
        results.push(await call(e, s, { cred: 'gh', method: 'GET', path: `/loop/${i}` }))
      }
    })()
    while (results.length < 5) await new Promise((r) => setTimeout(r, 5))
    const r = await e.cli(['cred', 'rotate', 'gh'], { input: `${ROTATED}\n`, json: true })
    assert.equal(r.code, 0, r.stdout + r.stderr)
    rotated = true
    await loop

    assert.ok(results.length > 5)
    for (const res of results) {
      assert.equal(res.body.status, 200, res.text)
      assert.ok(!res.text.includes(SECRETS.gh), 'the old value is scrubbed from every answer')
      assert.ok(!res.text.includes(ROTATED), 'and so is the new one')
    }
    const sent = e.seen.map((h) => h.headers.authorization)
    assert.equal(sent.length, results.length, 'every call reached the upstream once')
    assert.equal(sent[0], `Bearer ${SECRETS.gh}`)
    assert.equal(sent.at(-1), `Bearer ${ROTATED}`, 'the cutover happened during the loop')
    // Once the new value is sent, the old one is never sent again.
    const first = sent.indexOf(`Bearer ${ROTATED}`)
    assert.ok(first > 0 && sent.slice(first).every((v) => v === `Bearer ${ROTATED}`))
  } finally { await e.stop() }
})
