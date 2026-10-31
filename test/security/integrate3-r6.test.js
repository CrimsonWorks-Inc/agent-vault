// Integrate-3, fix round 6.
//
// B1: `tripwire show` crashed on every vault whose rules were never saved,
// because the daemon sent `rules: null`. The daemon now always sends the
// rules in force (the defaults until some are saved) with `rules_saved`.
//
// B2: `preflight` as documented (--cred/--method/--path) predicted a refusal
// for every request, because nothing put the placeholder in. The CLI now asks
// the gateway to assume one at the credential's site, as vault_preflight
// does; a placeholder that is present is still checked.
//
// N1: `approve … --methods GET` printed what the agent asked for. N2: `cred
// test --all` failed on any kind with no probe. N4: bidi controls in agent
// text reordered what the terminal and the page showed.
//
// Grok r6 F1: `response.streamed` recorded the upstream's raw Content-Type.
// F2: vault_explain_denial looked only at the last 200 audit rows, so code
// and rule were lost after later traffic, an eviction or a restart.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { startE2E } from './integrate3-e2e-helpers.js'
import { startApi, PASSPHRASE } from './control-api-helpers.js'
import { pageFunctions, pageConst } from './control-ui-helpers.js'
import { Daemon } from '../../src/daemon/server.js'
import { DEFAULT_RULES } from '../../src/daemon/tripwire.js'
import { cleanHeadline } from '../../src/daemon/notify.js'
import { safeEntry } from '../../src/cli/watch.js'
import { cleanText } from '../../src/cli/control-commands.js'
import { readFileSync } from 'node:fs'

const records = (text) => text.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
// Every character N4 strips from terminal text.
const BIDI = /[\u202a-\u202e\u2066-\u2069]/
const SEPARATORS = /[\u2028\u2029]/

// --- B1 ----------------------------------------------------------------------------

test('B1: tripwire show on a vault that never saved rules lists the defaults; set edits them; on keeps them', async () => {
  const e = await startE2E()
  try {
    const human = await e.cli(['tripwire', 'show'])
    assert.equal(human.code, 0, human.stdout + human.stderr)
    assert.match(human.stdout, /^tripwires off \(the default rules, used when you turn them on\)$/m)
    assert.match(human.stdout, /^replay  AV_PH_REPLAY  1 in 600s  → revoke_session$/m)
    assert.match(human.stdout, /^deny_paths  deny_paths:  5 in 600s  → revoke_session$/m)
    const shown = await e.cli(['tripwire', 'show'], { json: true })
    assert.equal(shown.code, 0)
    assert.equal(shown.data.rules_saved, false)
    assert.deepEqual(shown.data.rules, DEFAULT_RULES, 'the rules in force, never null')
    assert.equal(e.vault.getSettings().tripwires, undefined, 'showing stored nothing')

    // set changes one rule of those in force, so the other defaults stay.
    e.openWindow()
    const set = await e.cli(['tripwire', 'set', '--rule', 'replay', '--codes', 'AV_PH_REPLAY', '--threshold', '3', '--window', '10m', '--action', 'revoke_session'])
    assert.equal(set.code, 0, set.stdout + set.stderr)
    const after = await e.cli(['tripwire', 'show'], { json: true })
    assert.equal(after.data.rules_saved, true)
    assert.deepEqual(after.data.rules.map((r) => r.id).sort(), ['bad_location', 'cross_session', 'deny_paths', 'replay'])
    assert.equal(after.data.rules.find((r) => r.id === 'replay').threshold, 3)
    const text = await e.cli(['tripwire', 'show'])
    assert.match(text.stdout, /^tripwires off$/m, 'saved rules are not labelled as the defaults')
    assert.match(text.stdout, /^replay  AV_PH_REPLAY  3 in 600s/m)

    // on, with rules saved, only enables: the edited rule stays.
    const on = await e.cli(['tripwire', 'on'])
    assert.equal(on.code, 0, on.stdout + on.stderr)
    const saved = e.vault.getSettings().tripwires
    assert.equal(saved.enabled, true)
    assert.equal(saved.rules.find((r) => r.id === 'replay').threshold, 3)
  } finally { await e.stop() }
})

test('B1: the page shows the defaults as defaults, and turning on stores them, when none were saved', () => {
  const PRELUDE = 'const ago = (iso) => `since ${iso}`'
  const page = pageFunctions(['tripwireRuleText', 'containmentCard'], PRELUDE)
  const html = page.containmentCard({ enabled: false, rules: structuredClone(DEFAULT_RULES), rules_saved: false, defaults: DEFAULT_RULES }, [])
  assert.match(html, /Turning them on uses the default rules below/)
  const mine = page.containmentCard({ enabled: false, rules: [DEFAULT_RULES[0]], rules_saved: true, defaults: DEFAULT_RULES }, [])
  assert.match(mine, /Turning them on uses your rules below/)
  // The handler that turns them on, read as text: no saved rules means the
  // defaults go with it, which the daemon gates.
  const source = readFileSync(new URL('../../src/ui/app.html', import.meta.url), 'utf8')
  const on = source.slice(source.indexOf("async 'tripwires-on'()"), source.indexOf("async 'tripwires-off'()"))
  assert.match(on, /rules_saved !== false/)
})

// --- B2 ----------------------------------------------------------------------------

test('B2: preflight as documented predicts allow, hold and refuse correctly, and changes nothing but its records', async () => {
  const e = await startE2E()
  try {
    const made = await e.cli(['session', 'create', '--cred', 'gh', '--methods', 'GET,POST', '--paths', '/repos/**'], { json: true })
    assert.equal(made.code, 0, made.stdout + made.stderr)
    const s = made.data
    const before = e.files()
    const calls = [
      [['--method', 'GET', '--path', '/repos/my-org/x'], 0, 'allow'],
      [['--method', 'GET', '--path', '/repos/my-org/x', '--header', 'Content-Type: application/json'], 0, 'allow'],
      [['--method', 'POST', '--path', '/repos/my-org/x/issues', '--header', 'Content-Type: application/json'], 10, 'hold'],
      [['--method', 'GET', '--path', '/admin'], 6, 'deny'],
      // A placeholder the caller does send is checked where it is: this is
      // not where gh is injected, so it is refused, assumption or not.
      [['--method', 'GET', '--path', '/repos/my-org/x', '--header', `X-Note: ${s.placeholder}`], 6, 'deny'],
    ]
    for (const [args, exit, would] of calls) {
      const r = await e.cli(['preflight', '--cred', 'gh', ...args], { json: true })
      assert.equal(r.code, exit, `${args.join(' ')}: ${r.stdout}${r.stderr}`)
      assert.equal(r.data.would, would, args.join(' '))
      if (would === 'deny') assert.ok(!r.data.checks.some((c) => c.rule === 'no_placeholder'), JSON.stringify(r.data.checks))
    }
    const human = await e.cli(['preflight', '--cred', 'gh', '--method', 'GET', '--path', '/repos/my-org/x'])
    assert.equal(human.code, 0)
    assert.match(human.stdout, /^would allow$/m)
    const misplaced = await e.cli(['preflight', '--cred', 'gh', '--method', 'GET', '--path', '/repos/my-org/x', '--header', `X-Note: ${s.placeholder}`], { json: true })
    assert.equal(misplaced.data.checks.at(-1).code, 'AV_BAD_LOCATION')

    // C24: each one is its own request.preflighted record, and nothing else.
    const after = e.files()
    assert.equal(after.vault, before.vault, 'the vault is byte-for-byte unchanged')
    const added = records(after.audit.slice(before.audit.length))
    assert.deepEqual([...new Set(added.map((r) => r.kind))], ['request.preflighted'])
    assert.equal(added.length, calls.length + 2)
    assert.equal(e.seen.length, 0, 'no preflight reached the upstream')
    assert.equal(e.daemon.pipeline.pendingApprovals().length, 0, 'and none was held')

    // The gateway route assumes a placeholder only when asked to, and only
    // with the boolean true.
    const raw = (body) => e.gateway('/v1/preflight', { method: 'POST', headers: { 'content-type': 'application/json', 'av-session': s.token }, body: JSON.stringify(body) })
    const plain = await raw({ method: 'GET', path: '/p/gh/repos/my-org/x' })
    assert.equal(plain.status, 200, plain.text)
    assert.equal(plain.json.would, 'deny')
    assert.equal(plain.json.checks.at(-1).rule, 'no_placeholder')
    const assumed = await raw({ method: 'GET', path: '/p/gh/repos/my-org/x', assume_placeholder: true })
    assert.equal(assumed.json.would, 'allow', assumed.text)
    for (const v of ['yes', 1, null]) {
      const bad = await raw({ method: 'GET', path: '/p/gh/repos/my-org/x', assume_placeholder: v })
      assert.equal(bad.status, 403, `${JSON.stringify(v)}: ${bad.text}`)
      assert.equal(bad.json.rule, 'preflight_shape')
    }
  } finally { await e.stop() }
})

// --- N1, N2 --------------------------------------------------------------------------

test('N1: approving a narrowed session request prints what was granted, not what the agent asked for', async () => {
  const e = await startE2E()
  try {
    const asked = await e.mcp(null, 'vault_request_session', { cred: 'gh', methods: ['GET', 'POST'], paths: ['/user'], budget: 5, reason: 'read me' })
    assert.equal(asked.body.state, 'pending', asked.text)
    const r = await e.cli(['approve', asked.body.request_id, '--methods', 'GET', '--paths', '/user', '--grant-ttl', '10'])
    assert.equal(r.code, 0, r.stdout + r.stderr)
    const line = r.stdout.split('\n').find((l) => l.startsWith('approved'))
    assert.equal(line, 'approved session for gh · GET · /user · 5 requests · grant ends after 10 min')
    assert.ok(!r.stdout.includes('GET,POST'))
  } finally { await e.stop() }
})

test('N2: cred test names a kind with no probe as exit 7, and --all skips it without hiding a real failure', async () => {
  const e = await startE2E()
  try {
    const one = await e.cli(['cred', 'test', 'gh'])
    assert.equal(one.code, 7, one.stdout + one.stderr)
    // openai has a probe, and a probe would leave this machine: quarantine
    // it, so it fails without a request, and is still reported as failing.
    assert.equal((await e.cli(['cred', 'quarantine', 'openai'])).code, 0)
    const mixed = await e.cli(['cred', 'test', '--all'])
    assert.equal(mixed.code, 6, mixed.stdout + mixed.stderr)
    assert.match(mixed.stdout, /^skip gh +no probe for this kind$/m)
    assert.match(mixed.stdout, /^warn openai +AV_QUARANTINED$/m)
    e.vault.deleteCredential('openai')
    const only = await e.cli(['cred', 'test', '--all'])
    assert.equal(only.code, 0, only.stdout + only.stderr)
    assert.match(only.stdout, /^skip other +no probe for this kind$/m)
    assert.equal(e.seen.length, 0)
  } finally { await e.stop() }
})

// --- N4 ----------------------------------------------------------------------------

test('N4: bidi controls and line separators in agent text never reach the terminal', async () => {
  const e = await startE2E()
  try {
    const reason = 'fix\u202eevil\u2066x\u2069\u2028y\u2029\u001b[31mred'
    const asked = await e.mcp(null, 'vault_request_session', { cred: 'gh', methods: ['GET'], reason })
    assert.equal(asked.body.state, 'pending', asked.text)
    const made = await e.cli(['session', 'create', '--cred', 'gh', '--methods', 'GET,POST'], { json: true })
    const held = await e.mcp(made.data.token, 'vault_http', { cred: 'gh', method: 'POST', path: '/a\u202e/b', body: '{"t":"\u202ex"}', reason })
    assert.equal(held.body.status, 202, held.text)
    for (const args of [['approvals'], ['approvals', '--show', JSON.parse(held.body.body).approval_id]]) {
      const r = await e.cli(args)
      assert.equal(r.code, 0, r.stderr)
      assert.match(r.stdout, /claimed by the agent \(unverified\): fixevilxy\[31mred/)
      assert.ok(!BIDI.test(r.stdout) && !SEPARATORS.test(r.stdout) && !r.stdout.includes('\u001b'), JSON.stringify(r.stdout))
    }
    const tail = await e.cli(['audit', 'tail', '--limit', '50'])
    assert.ok(!BIDI.test(tail.stdout) && !SEPARATORS.test(tail.stdout))
  } finally { await e.stop() }
})

test('N4: every shared cleaner strips bidi controls; the terminal ones strip line separators too', () => {
  const hostile = 'a\u202ab\u202bc\u202cd\u202de\u202ef\u2066g\u2067h\u2068i\u2069j\u2028k\u2029l'
  assert.equal(cleanText(hostile), 'abcdefghijkl')
  assert.equal(cleanText('keep\ttabs\nand lines'), 'keep\ttabs\nand lines')
  assert.equal(safeEntry({ kind: 'request', id: 'ap_\u202e1', headline: hostile, created_at: 'x\u2066' }).headline, 'abcdefghijkl')
  assert.equal(safeEntry({ kind: 'request', id: 'ap_\u202e1', headline: 'x' }).id, 'ap_1')
  // A headline as it leaves the daemon (webhook, stream): bidi gone, the
  // separators a space, as the other controls are.
  assert.equal(cleanHeadline(hostile), 'abcdefghij k l')

  const page = pageFunctions(['previewBlock', 'notificationText'], [pageConst('UNTRUSTED')].join('\n'))
  const html = page.previewBlock({ method: 'POST', host: 'h', path: `/fix${'\u202e'}evil`, query: [['q', '\u2066v\u2069']], headers: [], body: { text: 'b\u202eody', bytes: 5, kind: 'json' }, placeholders: [] }, 'ap_1')
  assert.ok(!BIDI.test(html), JSON.stringify(html))
  assert.match(html, /fixevil/)
  const note = page.notificationText({ kind: 'request', headline: hostile })
  assert.equal(note, 'Held request: abcdefghij k l')
})

// --- Grok r6 F1 -----------------------------------------------------------------------

const VALUE = 'ghp/PLUS+slash/001122334455667788'
const NEEDLES = [VALUE, 'PLUS+slash', '001122334455667788', encodeURIComponent(VALUE)]

async function surfaces(a) {
  const file = readFileSync(a.vault.audit.path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
  const read = await a.control('GET', '/v1/audit?limit=100000')
  const exported = await a.control('GET', '/v1/audit/export')
  return [['audit.jsonl', file], ['GET /v1/audit', read.body], ['the export', exported.body.rows]]
}

test('r6 F1: a streamed response records a closed media type and encoding, never the upstream header text', async () => {
  let encoding = 'identity'
  const a = await startApi({
    passphrase: PASSPHRASE,
    upstreamReply: (req, res) => {
      const body = 'data: hello\n\n'
      res.writeHead(200, { 'content-type': `text/event-stream; note=${VALUE}`, 'content-encoding': encoding })
      res.end(encoding === 'gzip' ? gzipSync(body) : body)
    },
  })
  try {
    a.vault.rotateCredential('demo', { value: VALUE, mode: 'revoke', retireMs: 0 })
    const s = a.session({ policy: { methods: ['GET'] } })
    for (const enc of ['identity', 'gzip']) {
      encoding = enc
      const r = await a.gateway('/p/demo/x', { headers: { authorization: `Bearer ${s.placeholder}` } })
      assert.equal(r.status, 200, r.text)
      assert.match(r.text, /hello/)
      assert.ok(!r.headers['content-type'].includes(VALUE), 'the agent’s copy is scrubbed')
    }
    const rows = a.audit('response.streamed')
    assert.deepEqual(rows.map((r) => [r.content_type, r.content_encoding]), [['text/event-stream', 'identity'], ['text/event-stream', 'gzip']])
    for (const [where, list] of await surfaces(a)) {
      const text = JSON.stringify(list)
      for (const n of [...NEEDLES, 'note=']) assert.ok(!text.includes(n), `${where} holds ${JSON.stringify(n)}`)
    }
  } finally { await a.stop() }
})

// --- Grok r6 F2 -----------------------------------------------------------------------

test('r6 F2: explain-denial gives code and rule however much was logged since, after eviction and after a restart', async () => {
  const a = await startApi({ passphrase: PASSPHRASE })
  let restarted
  try {
    const mine = a.session({ policy: { methods: ['GET'], deny_paths: ['/admin/**'] } })
    const denied = await a.tool('vault_http', { cred: 'demo', method: 'GET', path: '/admin/x' }, { token: mine.token })
    assert.equal(denied.body.status, 403)
    const id = denied.body.request_id
    const explain = (token = mine.token) => a.tool('vault_explain_denial', { request_id: id }, { token })

    // 220 later rows: past the old 200-row window, well inside the 1000.
    for (let i = 0; i < 220; i++) await a.gateway('/p/demo/x')
    const later = await explain()
    assert.equal(later.body.code, 'AV_POLICY_DENIED', JSON.stringify(later.body))
    assert.equal(later.body.rule, 'deny_paths:0')
    assert.match(later.body.detail, /deny list/, 'the sentence is still remembered')

    // A restart: a new daemon on the same vault remembers no sentence, and
    // still has the record.
    restarted = await new Daemon(a.vault, { port: 0, socketPath: join(a.dir, 'r.sock') }).start()
    const call = async (token) => {
      const r = await restarted.mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'vault_explain_denial', arguments: { request_id: id } } }, a.vault.sessionByToken(token), token, null)
      return JSON.parse(r.result.content[0].text)
    }
    const after = await call(mine.token)
    assert.deepEqual([after.code, after.rule, after.detail], ['AV_POLICY_DENIED', 'deny_paths:0', null])

    // A thousand later denials evict the sentence; code and rule remain.
    for (let i = 0; i < 1000; i++) await a.gateway('/p/demo/x')
    const evicted = await explain()
    assert.deepEqual([evicted.body.code, evicted.body.rule, evicted.body.detail], ['AV_POLICY_DENIED', 'deny_paths:0', null])

    // Still only the caller's own: another session gets no record.
    const other = a.session()
    assert.match((await explain(other.token)).body.error, /no record/)
  } finally {
    await restarted?.stop()
    await a.stop()
  }
})

test('r6 F2: a caller with no session gets the code and rule of a no-session denial, never its sentence', async () => {
  const a = await startApi()
  try {
    const r = await a.gateway('/p/demo/secret-path-marker')
    assert.equal(r.status, 401, r.text)
    const id = r.headers['av-request-id'] || r.json?.request_id
    assert.ok(id, r.text)
    assert.ok(a.daemon.pipeline.explainDenial(id, null), 'the pipeline did keep the sentence')
    const explained = await a.tool('vault_explain_denial', { request_id: id })
    assert.equal(explained.body.code, r.json.code, JSON.stringify(explained.body))
    assert.equal(explained.body.detail, null)
    assert.ok(!('hint' in explained.body))
    // And a session cannot read a no-session denial at all.
    const s = a.session()
    assert.match((await a.tool('vault_explain_denial', { request_id: id }, { token: s.token })).body.error, /no record/)
  } finally { await a.stop() }
})
