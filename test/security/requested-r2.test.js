// R2: an env file of placeholders, from a session with several credentials.
//
// The file lands in a project directory, where an agent can read it and may
// be able to write. So: it holds placeholders and loopback gateway URLs and
// nothing else, not the session token and never a secret; it is 0600 under
// any umask; it is never overwritten or followed through a symlink unless the
// human says so; and the placeholders behind it are minted in one gated call
// that either issues all of them or none.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  mkdtempSync, rmSync, writeFileSync, readFileSync, statSync, symlinkSync, chmodSync, mkdirSync, existsSync, readlinkSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { spawnSync } from 'node:child_process'
import { startDaemon, cli, PASSPHRASE, SECRET } from './fix-control-helpers.js'
import { writeFileExclusive, appendLineExclusive, assertPlaceholderOnly } from '../../src/cli/files.js'
import * as ph from '../../src/core/placeholder.js'

const OPENAI_SECRET = 'sk-proj-REQUESTEDR2openai00112233445566'
const scratch = () => mkdtempSync(join(tmpdir(), 'av-r2-'))
const mode = (p) => statSync(p).mode & 0o777

/** A daemon whose vault also holds a second credential, for the same host, and an OpenAI key. */
async function twoCreds(opts = {}) {
  const d = await startDaemon({ socketName: 'control.sock', ...opts })
  try {
    add(d)
  } catch (e) {
    await d.stop()
    throw e
  }
  return d
}

function add(d) {
  d.vault.addCredential({
    slug: 'second', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'ghp_SECONDCRED00112233445566778899' }, sites: { token: ['header:authorization:Bearer'] },
  })
  d.vault.addCredential({
    slug: 'oai', kind: 'openai', connector: { host: 'api.openai.com', scheme: 'https' },
    fields: { apikey: OPENAI_SECRET }, sites: { apikey: ['header:authorization:Bearer'] },
  })
}

// ------------------------------------------------------------ the writer

test('a new file is created 0600 even under umask 000, and an existing one is refused', () => {
  const dir = scratch()
  const old = process.umask(0o000)
  try {
    const f = join(dir, '.env')
    assert.deepEqual(writeFileExclusive(f, 'A=1\n'), { replaced: false })
    assert.equal(mode(f), 0o600)
    assert.throws(() => writeFileExclusive(f, 'B=2\n'), { code: 'EEXIST' })
    assert.equal(readFileSync(f, 'utf8'), 'A=1\n', 'the bytes are unchanged')
    // A umask that removes the owner's own bits is undone by fchmod.
    process.umask(0o277)
    const g = join(dir, 'g.env')
    writeFileExclusive(g, 'C=3\n')
    assert.equal(mode(g), 0o600)
  } finally {
    process.umask(old)
    rmSync(dir, { recursive: true, force: true })
  }
})

test('a symlink is never followed, with or without force', () => {
  const dir = scratch()
  try {
    const target = join(dir, 'ssh-config')
    writeFileSync(target, 'Host *\n')
    const link = join(dir, '.env')
    symlinkSync(target, link)
    assert.throws(() => writeFileExclusive(link, 'A=1\n'), { code: 'EEXIST' })
    assert.throws(() => writeFileExclusive(link, 'A=1\n', { force: true }), { code: 'ENOTREGULAR' })
    assert.equal(readFileSync(target, 'utf8'), 'Host *\n', 'the link target is untouched')
    assert.equal(readlinkSync(link), target)
    // A dangling link is no invitation either.
    const dangling = join(dir, 'dangling.env')
    symlinkSync(join(dir, 'does-not-exist'), dangling)
    assert.throws(() => writeFileExclusive(dangling, 'A=1\n'), { code: 'EEXIST' })
    assert.ok(!existsSync(join(dir, 'does-not-exist')))
    // Nor is a directory.
    mkdirSync(join(dir, 'adir'))
    assert.throws(() => writeFileExclusive(join(dir, 'adir'), 'x', { force: true }), { code: 'ENOTREGULAR' })
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('force replaces a regular file atomically and leaves it 0600', () => {
  const dir = scratch()
  try {
    const f = join(dir, '.env')
    writeFileSync(f, 'OLD=1\n')
    chmodSync(f, 0o644)
    assert.deepEqual(writeFileExclusive(f, 'NEW=1\n', { force: true }), { replaced: true })
    assert.equal(readFileSync(f, 'utf8'), 'NEW=1\n')
    assert.equal(mode(f), 0o600)
    // Absent is fine under force, and is not a replacement.
    assert.deepEqual(writeFileExclusive(join(dir, 'fresh'), 'X=1\n', { force: true }), { replaced: false })
    // No temporary file is left behind.
    assert.deepEqual(spawnSync('ls', ['-A', dir], { encoding: 'utf8' }).stdout.split('\n').filter(Boolean).sort(), ['.env', 'fresh'])
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

// The temporary file sits in the same directory as the target, which an
// agent may be able to write, so its name can be swapped for a symlink
// between close and rename; rename then moves the link into place. The
// window is a few instructions wide, so the test makes it certain: a child
// process loads an interposer for rename(3) that does the swap first.
// files.js binds renameSync from the ESM namespace, so nothing in JS can
// reach it. macOS only (DYLD_INSERT_LIBRARIES), and it needs a C compiler;
// each child reports that the hook fired, so it cannot pass by missing.
const INTERPOSE_C = `
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int swapped = 0;
int av_rename(const char *from, const char *to) {
  const char *mode = getenv("AV_RACE_SWAP"), *secret = getenv("AV_RACE_SECRET");
  if (!swapped && mode && secret && from && to && strstr(from, ".av-")) {
    swapped = 1;
    fprintf(stderr, "AV_RACE once mode=%s\\n", mode);
    const char *victim = strcmp(mode, "temp") == 0 ? from : to;
    unlink(victim);
    if (symlink(secret, victim) != 0) perror("symlink");
  }
  return renameat(AT_FDCWD, from, AT_FDCWD, to);
}
__attribute__((used)) static struct { const void *repl; const void *orig; } interpose[]
  __attribute__((section("__DATA,__interpose"))) = { { (const void *)av_rename, (const void *)rename } };
`
let interposer
/** The interposer's path, built once; null without macOS or a compiler. */
function buildInterposer() {
  if (interposer !== undefined) return interposer
  interposer = null
  // Without the command line tools, /usr/bin/cc is a stub that offers to install them.
  if (process.platform !== 'darwin' || spawnSync('xcode-select', ['-p']).status !== 0) return null
  const dir = scratch()
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }))
  writeFileSync(join(dir, 'interpose.c'), INTERPOSE_C)
  const built = spawnSync('cc', ['-dynamiclib', '-o', join(dir, 'interpose.dylib'), join(dir, 'interpose.c')], { encoding: 'utf8' })
  if (built.error?.code === 'ENOENT') return null
  // A compiler that is there and fails is a broken test, not a skipped one.
  assert.equal(built.status, 0, built.stderr)
  return (interposer = join(dir, 'interpose.dylib'))
}

/** Replace `<dir>/.env` with `force` while rename swaps `swap` ('temp' or 'dest') for a link to `<dir>/secret`. */
function racedWrite(dir, swap) {
  const script = join(dir, 'race.mjs')
  writeFileSync(script, `
import { writeFileExclusive } from ${JSON.stringify(new URL('../../src/cli/files.js', import.meta.url).href)}
import { lstatSync, readFileSync } from 'node:fs'
const [dest, secret] = process.argv.slice(2)
let result = null, err = null
try { result = writeFileExclusive(dest, 'GH_TOKEN=placeholder\\n', { force: true }) } catch (e) { err = e.code || String(e) }
let kind = 'missing'
try { const st = lstatSync(dest); kind = st.isSymbolicLink() ? 'symlink' : st.isFile() ? 'file' : 'other' } catch {}
let body = null
try { body = readFileSync(dest, 'utf8') } catch {}
process.stdout.write(JSON.stringify({ result, err, kind, body, secret: readFileSync(secret, 'utf8') }))
`)
  const secret = join(dir, 'secret')
  writeFileSync(secret, 'SENSITIVE\n', { mode: 0o600 })
  const env = { ...process.env, DYLD_INSERT_LIBRARIES: interposer, AV_RACE_SWAP: swap, AV_RACE_SECRET: secret }
  const r = spawnSync(process.execPath, [script, join(dir, '.env'), secret], { env, encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stderr, new RegExp(`AV_RACE once mode=${swap}`), 'the swap happened')
  return JSON.parse(r.stdout)
}

test('a temporary file swapped for a symlink before the rename is refused, and no link is left', (t) => {
  if (!buildInterposer()) return t.skip('needs macOS and a C compiler')
  const dir = scratch()
  try {
    writeFileSync(join(dir, '.env'), 'old\n', { mode: 0o600 })
    const out = racedWrite(dir, 'temp')
    assert.equal(out.err, 'ENOTREGULAR', JSON.stringify(out))
    assert.equal(out.result, null, 'it did not report success')
    assert.equal(out.kind, 'missing', 'the link that landed was removed')
    assert.equal(out.secret, 'SENSITIVE\n', 'and what it pointed at is untouched')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('a destination that becomes a symlink just before the rename is replaced, and the target is untouched', (t) => {
  if (!buildInterposer()) return t.skip('needs macOS and a C compiler')
  const dir = scratch()
  try {
    writeFileSync(join(dir, '.env'), 'old\n', { mode: 0o600 })
    const out = racedWrite(dir, 'dest')
    assert.equal(out.err, null, JSON.stringify(out))
    assert.deepEqual(out.result, { replaced: true })
    assert.equal(out.kind, 'file')
    assert.equal(out.body, 'GH_TOKEN=placeholder\n')
    assert.equal(out.secret, 'SENSITIVE\n')
    assert.equal(mode(join(dir, '.env')), 0o600)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('appending makes the file 0600 whatever the umask, and tightens one that was not', () => {
  const dir = scratch()
  try {
    const f = join(dir, 'log')
    const old = process.umask(0o277)
    try { appendLineExclusive(f, 'one') } finally { process.umask(old) }
    assert.equal(mode(f), 0o600, 'a 0277 umask alone would leave 0400')
    const loose = join(dir, 'loose')
    writeFileSync(loose, 'zero\n')
    chmodSync(loose, 0o644)
    appendLineExclusive(loose, 'one')
    assert.equal(mode(loose), 0o600)
    assert.equal(readFileSync(loose, 'utf8'), 'zero\none\n')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('appending creates 0600, appends whole lines, and refuses a symlink', () => {
  const dir = scratch()
  try {
    const f = join(dir, 'log')
    appendLineExclusive(f, 'one')
    appendLineExclusive(f, 'two\n')
    assert.equal(readFileSync(f, 'utf8'), 'one\ntwo\n')
    assert.equal(mode(f), 0o600)
    const target = join(dir, 'target')
    writeFileSync(target, 'keep\n')
    symlinkSync(target, join(dir, 'link'))
    assert.throws(() => appendLineExclusive(join(dir, 'link'), 'x'), { code: 'ENOTREGULAR' })
    assert.equal(readFileSync(target, 'utf8'), 'keep\n')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

// ------------------------------------------------------- the final check

const SID = 'abcdefghjkmn'
const fakePh = (sid = SID, slug = 'demo', field = 'token') => `av1.${sid}.${slug}_${field}.${'a'.repeat(26)}.${'b'.repeat(6)}`

test('the final check passes placeholders for the session and loopback gateway URLs', () => {
  const ctx = { sid: SID, port: 7411, slugs: ['demo', 'oai'] }
  assertPlaceholderOnly([
    { name: 'GH_TOKEN', cred: 'demo', value: fakePh() },
    { name: 'OPENAI_API_KEY', cred: 'oai', value: fakePh(SID, 'oai', 'apikey') },
    { name: 'BASE', cred: 'demo', value: 'http://127.0.0.1:7411/p/demo' },
    { name: 'GW', cred: null, value: 'http://127.0.0.1:7411' },
  ], ctx)
})

test('the final check refuses everything else, and never says what it refused', () => {
  const ctx = { sid: SID, port: 7411, slugs: ['demo'] }
  const bad = [
    ['the session token', { cred: 'demo', value: `avs1.${SID}.c2VjcmV0c2VjcmV0c2VjcmV0` }],
    ['a real secret', { cred: 'demo', value: SECRET }],
    ['another session’s placeholder', { cred: 'demo', value: fakePh('zzzzzzzzzzzz') }],
    ['another credential’s placeholder', { cred: 'demo', value: fakePh(SID, 'other') }],
    ['a placeholder with a tail', { cred: 'demo', value: `${fakePh()}x` }],
    ['a placeholder with a newline', { cred: 'demo', value: `${fakePh()}\nEVIL=1` }],
    ['a URL on another port', { cred: 'demo', value: 'http://127.0.0.1:7412/p/demo' }],
    ['a URL elsewhere', { cred: 'demo', value: 'http://evil.example/p/demo' }],
    ['a URL for a credential outside the session', { cred: 'x', value: 'http://127.0.0.1:7411/p/x' }],
    ['a URL that walks out', { cred: 'demo', value: 'http://127.0.0.1:7411/p/demo/../..' }],
    ['nothing', { cred: 'demo', value: undefined }],
    ['a number', { cred: 'demo', value: 7411 }],
  ]
  for (const [what, entry] of bad) {
    assert.throws(() => assertPlaceholderOnly([{ name: 'X', ...entry }], ctx), (e) => {
      assert.equal(e.code, 'NOT_PLACEHOLDER', what)
      assert.equal(e.message, 'refusing to write a value that is not a placeholder')
      return true
    }, what)
  }
  // A name that would start a second line is refused as well.
  assert.throws(() => assertPlaceholderOnly([{ name: 'A\nB', cred: 'demo', value: fakePh() }], ctx), { code: 'NOT_PLACEHOLDER' })
})

// ------------------------------------------- sessions with several credentials

test('one session holds several credentials, each with its own grant and placeholder', async () => {
  const d = await twoCreds()
  try {
    const r = await d.control('POST', '/v1/sessions', { grants: [{ cred: 'demo', methods: ['GET'] }, { cred: 'oai', methods: ['GET', 'POST'] }] })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.deepEqual(r.body.grants.map((g) => g.cred), ['demo', 'oai'])
    for (const g of r.body.grants) {
      const p = ph.parseAt(g.placeholder)
      assert.equal(p.sid, r.body.session_id)
      assert.equal(p.slug, g.cred)
    }
    assert.deepEqual(r.body.grants[1].env, { base: 'OPENAI_BASE_URL', key: 'OPENAI_API_KEY' })
    assert.equal(r.body.grants[0].env, null)
    // The top level mirrors the first grant, for clients written for one.
    for (const k of ['grant_id', 'placeholder', 'usage', 'base_url', 'probe_path', 'lint']) {
      assert.deepEqual(r.body[k], r.body.grants[0][k], k)
    }
    assert.equal(r.body.infinite, false)
    const listed = (await d.control('GET', '/v1/sessions')).body.find((s) => s.id === r.body.session_id)
    assert.equal(listed.grants, 2)
    assert.deepEqual(listed.creds.map((c) => c.slug), ['demo', 'oai'])
  } finally { await d.stop() }
})

test('an ambiguous or mixed session body is refused, and leaves nothing behind', async () => {
  const d = await twoCreds()
  try {
    const sessions = () => Object.keys(d.vault.db.sessions).length
    const grants = () => Object.keys(d.vault.db.grants).length
    const before = [sessions(), grants()]
    const shapes = [
      { grants: [{ cred: 'demo' }], cred: 'demo' },
      { grants: [{ cred: 'demo' }], methods: ['GET'] },
      { grants: [{ cred: 'demo' }, { cred: 'demo' }] },
      { grants: [] },
      { grants: Array.from({ length: 17 }, (_, i) => ({ cred: `c${i}` })) },
      { grants: 'demo' },
      { grants: [['demo']] },
      { template: 'x' },
      { template: 'x', cred: 'demo' },
    ]
    for (const body of shapes) {
      const r = await d.control('POST', '/v1/sessions', body)
      assert.equal(r.status, 403, JSON.stringify(body))
      assert.equal(r.body.rule, 'session_shape', JSON.stringify(r.body))
    }
    const twice = await d.control('POST', '/v1/sessions', { grants: [{ cred: 'demo' }, { cred: 'demo' }] })
    assert.match(twice.body.detail, /credential demo appears twice/)
    // A credential that does not exist, second in the list: nothing is made.
    const missing = await d.control('POST', '/v1/sessions', { grants: [{ cred: 'demo' }, { cred: 'nope' }] })
    assert.equal(missing.status, 404)
    assert.deepEqual([sessions(), grants()], before, 'no half-made session')
  } finally { await d.stop() }
})

test('two credentials for one host stay apart: /p/ picks by name, /t/ refuses the other one', async () => {
  const d = await twoCreds()
  try {
    const r = await d.control('POST', '/v1/sessions', { grants: [{ cred: 'demo' }, { cred: 'second' }] })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const seen = []
    d.daemon.pipeline.upstream = async (req) => {
      seen.push(req.headers)
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') }
    }
    const second = r.body.grants[1].placeholder
    const gw = (path) => fetch(`http://127.0.0.1:${d.daemon.gatewayPort}${path}`, {
      headers: { 'av-session': r.body.token, authorization: `Bearer ${second}` },
    })
    const viaName = await gw('/p/second/x')
    assert.equal(viaName.status, 200, await viaName.text())
    const viaHost = await gw('/t/https/api.example.com/x')
    assert.equal(viaHost.status, 403)
    assert.equal((await viaHost.json()).code, 'AV_PH_WRONG_CONNECTOR')
  } finally { await d.stop() }
})

// ------------------------------------------------------- the batch route

async function sessionWith(d, grants) {
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  const r = await d.control('POST', '/v1/sessions', { grants })
  d.daemon.presenceGraceUntil = 0
  assert.equal(r.status, 200, JSON.stringify(r.body))
  return r.body
}
const issuedRecords = (d) => d.vault.audit.read({ limit: 500 }).filter((x) => x.kind === 'placeholder.issued').length

test('a batch is gated like a single placeholder', async () => {
  const d = await twoCreds({ passphrase: PASSPHRASE })
  try {
    const s = await sessionWith(d, [{ cred: 'demo' }, { cred: 'oai' }])
    const before = issuedRecords(d)
    const r = await d.control('POST', '/v1/placeholders/batch', { sid: s.session_id, items: [{ cred: 'demo' }] })
    assert.equal(r.status, 401)
    assert.equal(r.body.code, 'AV_PRESENCE_REQUIRED')
    assert.equal(issuedRecords(d), before)
  } finally { await d.stop() }
})

test('a batch issues one placeholder per item, in order, and records the batch', async () => {
  const d = await twoCreds({ passphrase: PASSPHRASE })
  try {
    const s = await sessionWith(d, [{ cred: 'demo' }, { cred: 'oai' }])
    d.daemon.presenceGraceUntil = Date.now() + 60_000
    const r = await d.control('POST', '/v1/placeholders/batch', {
      sid: s.session_id, items: [{ cred: 'oai' }, { cred: 'demo', field: 'token', uses: 3 }], purpose: 'env',
    })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    assert.equal(r.body.session_id, s.session_id)
    assert.equal(r.body.gateway_url, `http://127.0.0.1:${d.daemon.gatewayPort}`)
    assert.deepEqual(r.body.items.map((i) => [i.cred, i.field]), [['oai', 'apikey'], ['demo', 'token']])
    for (const item of r.body.items) {
      const p = ph.parseAt(item.placeholder)
      assert.equal(p.text, item.placeholder)
      assert.equal(p.sid, s.session_id)
    }
    assert.deepEqual(r.body.items[0].env, { base: 'OPENAI_BASE_URL', key: 'OPENAI_API_KEY' })
    const row = Object.values(d.vault.db.placeholders).find((x) => x.grant_id === s.grants[0].grant_id && x.max_uses === 3)
    assert.ok(row, 'uses is carried to the ledger')
    const batch = d.vault.audit.read({ limit: 50 }).filter((x) => x.kind === 'placeholder.issued_batch')
    assert.equal(batch.length, 1)
    assert.equal(batch[0].count, 2)
    assert.deepEqual(batch[0].credential_slugs, ['oai', 'demo'])
    assert.equal(batch[0].purpose, 'env')
    assert.ok(!JSON.stringify(batch[0]).includes('av1.'), 'no placeholder in the record')
  } finally { await d.stop() }
})

test('a batch is all or nothing', async () => {
  const d = await twoCreds()
  try {
    const s = await sessionWith(d, [{ cred: 'demo' }])
    const rows = () => Object.keys(d.vault.db.placeholders).length
    const before = [issuedRecords(d), rows()]
    const missing = await d.control('POST', '/v1/placeholders/batch', { sid: s.session_id, items: [{ cred: 'demo' }, { cred: 'nope' }] })
    assert.equal(missing.status, 404)
    const ungranted = await d.control('POST', '/v1/placeholders/batch', { sid: s.session_id, items: [{ cred: 'demo' }, { cred: 'oai' }] })
    assert.equal(ungranted.status, 403)
    assert.equal(ungranted.body.code, 'AV_NO_GRANT')
    const field = await d.control('POST', '/v1/placeholders/batch', { sid: s.session_id, items: [{ cred: 'demo', field: 'other' }] })
    assert.equal(field.body.code, 'AV_NO_GRANT')
    const nosession = await d.control('POST', '/v1/placeholders/batch', { sid: 'nosuchsession', items: [{ cred: 'demo' }] })
    assert.equal(nosession.status, 404)
    assert.deepEqual([issuedRecords(d), rows()], before, 'not one placeholder from a refused batch')
    d.vault.revokeSession(s.session_id)
    const revoked = await d.control('POST', '/v1/placeholders/batch', { sid: s.session_id, items: [{ cred: 'demo' }] })
    assert.equal(revoked.body.code, 'AV_SESSION_REVOKED')
  } finally { await d.stop() }
})

test('a batch with one quarantined credential issues nothing, not even the items before it', async () => {
  const d = await twoCreds()
  try {
    const s = await sessionWith(d, [{ cred: 'demo' }, { cred: 'oai' }])
    const rows = () => Object.keys(d.vault.db.placeholders).length
    const before = [issuedRecords(d), rows()]
    d.vault.setQuarantine('oai')
    const r = await d.control('POST', '/v1/placeholders/batch', { sid: s.session_id, items: [{ cred: 'demo' }, { cred: 'oai' }] })
    assert.equal(r.status, 403, JSON.stringify(r.body))
    assert.equal(r.body.code, 'AV_QUARANTINED')
    assert.equal(r.body.rule, 'quarantine')
    assert.deepEqual([issuedRecords(d), rows()], before)
  } finally { await d.stop() }
})

test('a batch of the wrong shape is refused before anything is resolved', async () => {
  const d = await twoCreds()
  try {
    const s = await sessionWith(d, [{ cred: 'demo' }])
    const sid = s.session_id
    for (const body of [
      { items: [{ cred: 'demo' }] },
      { sid, items: [] },
      { sid, items: Array.from({ length: 33 }, () => ({ cred: 'demo' })) },
      { sid, items: ['demo'] },
      { sid, items: [{ cred: 'demo' }, { cred: 'demo' }] },
      { sid, items: [{ cred: 'demo', uses: 0 }] },
      { sid, items: [{ cred: 'demo', uses: 1.5 }] },
      { sid, items: [{ cred: 'demo' }], purpose: 'curl' },
    ]) {
      const r = await d.control('POST', '/v1/placeholders/batch', body)
      assert.equal(r.status, 403, JSON.stringify(body))
      assert.equal(r.body.rule, 'batch_shape', JSON.stringify(r.body))
    }
  } finally { await d.stop() }
})

test('the grant’s use ceiling beats what a batch asks for', async () => {
  const d = await twoCreds()
  try {
    const cred = d.vault.findCredential('demo')
    const { session } = d.vault.createSession({ label: 'ceiling' })
    const grant = d.vault.createGrant({
      sessionId: session.id, credentialId: cred.id, fields: ['token'],
      policy: { hosts: ['api.example.com'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 50 }, placeholder_policy: { max_uses: 1 } },
    })
    const r = await d.control('POST', '/v1/placeholders/batch', { sid: session.id, items: [{ cred: 'demo', uses: 40 }] })
    assert.equal(r.status, 200, JSON.stringify(r.body))
    const row = Object.values(d.vault.db.placeholders).filter((p) => p.grant_id === grant.id).at(-1)
    assert.equal(row.max_uses, 1)
  } finally { await d.stop() }
})

// ---------------------------------------------------------- agent-vault env

async function cliSession(d, creds = 'demo,oai') {
  const r = await cli(d.dir, ['session', 'create', '--cred', creds, '--json'])
  assert.equal(r.code, 0, r.stderr)
  return JSON.parse(r.stdout).data
}

function assertOnlyPlaceholders(text, s) {
  assert.ok(!text.includes(SECRET) && !text.includes(OPENAI_SECRET), 'a stored secret is in the file')
  assert.ok(!text.includes(s.token), 'the session token is in the file')
  const lines = text.split('\n').filter((l) => l && !l.startsWith('#'))
  assert.ok(lines.length, 'the file has entries')
  for (const line of lines) {
    const value = line.replace(/^(export )?[A-Za-z_][A-Za-z0-9_]*=/, '')
    const p = ph.parseAt(value)
    assert.ok((p && p.text === value && p.sid === s.session_id) || /^http:\/\/127\.0\.0\.1:\d+(\/p\/[a-z0-9-]+)?$/.test(value), line)
  }
}

test('env writes a 0600 file of placeholders and URLs, and never a secret or the token', async () => {
  const d = await twoCreds()
  const old = process.umask(0o000)
  try {
    const s = await cliSession(d)
    const f = join(d.dir, '.env')
    const r = await cli(d.dir, ['env', '--out', f, '--map', 'GH_TOKEN=demo', '--map', 'GH_URL=demo:base_url', '--map', 'GW=:gateway', '--profile-vars'])
    assert.equal(r.code, 0, r.stderr)
    assert.equal(mode(f), 0o600)
    const text = readFileSync(f, 'utf8')
    assertOnlyPlaceholders(text, s)
    assert.match(text, /^# agent-vault env file: these are placeholders, not secrets\.\n# session \S+, written \S+ by agent-vault env\n/)
    const port = d.daemon.gatewayPort
    assert.match(text, new RegExp(`^GH_URL=http://127\\.0\\.0\\.1:${port}/p/demo$`, 'm'))
    assert.match(text, new RegExp(`^GW=http://127\\.0\\.0\\.1:${port}$`, 'm'))
    assert.match(text, new RegExp(`^OPENAI_BASE_URL=http://127\\.0\\.0\\.1:${port}/p/oai$`, 'm'))
    assert.match(text, /^OPENAI_API_KEY=av1\.\S+_apikey\./m)
    assert.match(text, /^GH_TOKEN=av1\.\S+\.demo_token\./m)
    // The batch was one call, recorded once.
    const batches = d.vault.audit.read({ limit: 100 }).filter((x) => x.kind === 'placeholder.issued_batch')
    assert.equal(batches.length, 1)
    assert.equal(batches[0].purpose, 'env')
  } finally {
    process.umask(old)
    await d.stop()
  }
})

test('env never replaces a file unless told to, and never follows a link', async () => {
  const d = await twoCreds()
  try {
    await cliSession(d)
    const f = join(d.dir, '.env')
    writeFileSync(f, 'MINE=1\n')
    chmodSync(f, 0o644)
    const again = await cli(d.dir, ['env', '--out', f, '--map', 'GH_TOKEN=demo'])
    assert.equal(again.code, 11, again.stderr)
    assert.match(again.stderr, /exists; pass --force to replace it/)
    assert.equal(readFileSync(f, 'utf8'), 'MINE=1\n')

    const forced = await cli(d.dir, ['env', '--out', f, '--force', '--map', 'GH_TOKEN=demo', '--json'])
    assert.equal(forced.code, 0, forced.stderr)
    assert.match(forced.stderr, /replaced /)
    assert.equal(mode(f), 0o600, 'a replaced 0644 file comes back 0600')
    const data = JSON.parse(forced.stdout).data
    assert.equal(data.replaced, true)
    assert.equal(data.mode, '0600')
    assert.deepEqual(data.entries, [{ name: 'GH_TOKEN', kind: 'placeholder', cred: 'demo', field: 'token' }])
    assert.ok(!forced.stdout.includes('av1.'), 'the json for a written file carries no values')

    const target = join(d.dir, 'precious')
    writeFileSync(target, 'keep\n')
    const link = join(d.dir, 'link.env')
    symlinkSync(target, link)
    for (const extra of [[], ['--force']]) {
      const r = await cli(d.dir, ['env', '--out', link, ...extra, '--map', 'GH_TOKEN=demo'])
      assert.equal(r.code, 11, r.stderr)
      assert.match(r.stderr, /is not a regular file you own/)
    }
    assert.equal(readFileSync(target, 'utf8'), 'keep\n')
  } finally { await d.stop() }
})

test('env refuses bad mappings before it calls anything, without echoing what was pasted', async () => {
  const d = await twoCreds()
  try {
    await cliSession(d)
    const pasted = 'ghp_PASTEDBYMISTAKE0011223344'
    const file = join(d.dir, 'map')
    writeFileSync(file, `# my tools\n\nexport GH_TOKEN=demo\nTOKEN=${pasted}\n`)
    const r = await cli(d.dir, ['env', '--map-file', file])
    assert.equal(r.code, 2, r.stderr)
    assert.match(r.stderr, /--map-file line 4 \(TOKEN\)/)
    assert.ok(!r.stderr.includes(pasted) && !r.stdout.includes(pasted), 'the right-hand side was echoed')

    const cases = [
      [['--map', 'GH=demo', '--map', 'GH=oai'], 2, /GH is mapped twice/],
      [['--map', '1BAD=demo'], 2, /not a NAME=SPEC/],
      [['--map', 'X=demo.bad.field'], 2, /expected/],
      [['--force', '--map', 'X=demo'], 2, /--force needs --out/],
      [['--map', 'X=second'], 7, /second is not in session/],
      [['--map', 'X=demo', '--format', 'yaml'], 2, /--format/],
    ]
    for (const [args, code, message] of cases) {
      const c = await cli(d.dir, ['env', ...args])
      assert.equal(c.code, code, `${args.join(' ')}: ${c.stderr}`)
      assert.match(c.stderr, message)
    }
    const batches = d.vault.audit.read({ limit: 100 }).filter((x) => x.kind === 'placeholder.issued_batch')
    assert.equal(batches.length, 0, 'nothing was minted for a refused mapping')
  } finally { await d.stop() }
})

test('env with a map file and no --out prints the lines', async () => {
  const d = await twoCreds()
  try {
    const s = await cliSession(d)
    const file = join(d.dir, 'map')
    writeFileSync(file, '# comment\nexport GH_TOKEN=demo\n\nOPENAI_BASE_URL=oai:base_url\n')
    const r = await cli(d.dir, ['env', '--map-file', file, '--format', 'shell'])
    assert.equal(r.code, 0, r.stderr)
    assertOnlyPlaceholders(r.stdout, s)
    assert.match(r.stdout, /^export GH_TOKEN=av1\./m)
    assert.match(r.stdout, /^export OPENAI_BASE_URL=http:\/\/127\.0\.0\.1:\d+\/p\/oai$/m)
    // It evaluates in a shell as exactly those values, with no quoting needed.
    const shown = spawnSync('sh', ['-c', 'eval "$1"; printf %s "$GH_TOKEN"', 'sh', r.stdout], { encoding: 'utf8' })
    assert.equal(ph.parseAt(shown.stdout)?.text, shown.stdout)
  } finally { await d.stop() }
})

test('env without a session says how to make one', async () => {
  const dir = scratch()
  try {
    const r = await cli(dir, ['env', '--map', 'X=demo'])
    assert.equal(r.code, 9, r.stderr)
    assert.match(r.stderr, /agent-vault session create --cred <slug>/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('env warns when the file would be committed', async (t) => {
  if (spawnSync('git', ['--version']).status !== 0) return t.skip('git is not installed')
  const d = await twoCreds()
  try {
    await cliSession(d)
    const repo = join(d.dir, 'repo')
    mkdirSync(repo)
    spawnSync('git', ['init', '-q', repo])
    const exposed = await cli(d.dir, ['env', '--out', join(repo, '.env'), '--map', 'GH_TOKEN=demo'])
    assert.equal(exposed.code, 0, exposed.stderr)
    assert.match(exposed.stderr, /is inside a git repository and is not ignored/)
    writeFileSync(join(repo, '.gitignore'), '.env.local\n')
    const ignored = await cli(d.dir, ['env', '--out', join(repo, '.env.local'), '--map', 'GH_TOKEN=demo'])
    assert.equal(ignored.code, 0, ignored.stderr)
    assert.doesNotMatch(ignored.stderr, /not ignored/)
    const outside = await cli(d.dir, ['env', '--out', join(d.dir, 'plain.env'), '--map', 'GH_TOKEN=demo'])
    assert.doesNotMatch(outside.stderr, /git repository/)
  } finally { await d.stop() }
})

// A control socket that answers like a daemon, with a batch answer of the
// test's choosing: the CLI's last check has to hold whatever comes back.
async function fakeDaemon(placeholderValue) {
  const dir = scratch()
  const server = createServer((req, res) => {
    const send = (obj) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)) }
    const route = `${req.method} ${req.url}`
    req.resume()
    req.on('end', () => {
      if (route === 'GET /v1/sessions') return send([{ id: SID, state: 'active', creds: [{ slug: 'demo' }] }])
      if (route === 'GET /v1/status') return send({ gateway_port: 7411 })
      if (route === 'POST /v1/placeholders/batch') {
        return send({ session_id: SID, gateway_url: 'http://127.0.0.1:7411', items: [{ cred: 'demo', field: 'token', placeholder: placeholderValue }] })
      }
      res.writeHead(404); res.end('{}')
    })
  })
  await new Promise((r) => server.listen(join(dir, 'control.sock'), r))
  return { dir, stop: () => { server.close(); rmSync(dir, { recursive: true, force: true }) } }
}

test('a batch answer that is not a placeholder is never written', async () => {
  for (const value of [SECRET, `avs1.${SID}.c2VjcmV0c2VjcmV0`, fakePh('zzzzzzzzzzzz'), fakePh(SID, 'other'), `${fakePh()} EVIL=1`]) {
    const fake = await fakeDaemon(value)
    try {
      const f = join(fake.dir, '.env')
      const r = await cli(fake.dir, ['env', '--session', SID, '--out', f, '--map', 'GH_TOKEN=demo'])
      assert.equal(r.code, 70, r.stderr)
      assert.match(r.stderr, /refusing to write a value that is not a placeholder/)
      assert.ok(!existsSync(f), 'no file was created')
      assert.ok(!r.stderr.includes(value) && !r.stdout.includes(value), 'the refused value was printed')
      const viaExec = await cli(fake.dir, ['exec', '--session', SID, '--map', 'GH_TOKEN=demo', '--', process.execPath, '-e', 'console.log("ran")'])
      assert.equal(viaExec.code, 70, viaExec.stderr)
      assert.doesNotMatch(viaExec.stdout, /ran/, 'the command must not run')
    } finally { fake.stop() }
  }
})

test('the same fake answering a real placeholder shape is written: the check is not a wall', async () => {
  const fake = await fakeDaemon(fakePh())
  try {
    const f = join(fake.dir, '.env')
    const r = await cli(fake.dir, ['env', '--session', SID, '--out', f, '--map', 'GH_TOKEN=demo'])
    assert.equal(r.code, 0, r.stderr)
    assert.match(readFileSync(f, 'utf8'), new RegExp(`^GH_TOKEN=${fakePh().replace(/\./g, '\\.')}$`, 'm'))
  } finally { fake.stop() }
})

// ------------------------------------------------------------ exec --map

test('exec --map puts a placeholder in the child under the name a tool reads', async () => {
  const d = await twoCreds()
  try {
    const s = await cliSession(d)
    const show = 'console.log(JSON.stringify({ gh: process.env.GH_TOKEN, oai: process.env.OPENAI_API_KEY, url: process.env.OPENAI_BASE_URL, stale: process.env.STRIPE_SECRET_KEY ?? null }))'
    const r = await cli(d.dir, ['exec', '--map', 'GH_TOKEN=demo', '--profile-vars', '--', process.execPath, '-e', show], {
      env: { GH_TOKEN: 'ghp_REALTOKENINTHESHELL00112233', STRIPE_SECRET_KEY: 'sk_live_x' },
    })
    assert.equal(r.code, 0, r.stderr)
    const got = JSON.parse(r.stdout.trim().split('\n').pop())
    // GH_TOKEN matches the scrub, and is set anyway: to the placeholder.
    assert.equal(ph.parseAt(got.gh)?.sid, s.session_id)
    assert.equal(ph.parseAt(got.oai)?.slug, 'oai')
    assert.equal(got.url, `http://127.0.0.1:${d.daemon.gatewayPort}/p/oai`)
    assert.equal(got.stale, null, 'the scrub still runs')
    const batch = d.vault.audit.read({ limit: 100 }).filter((x) => x.kind === 'placeholder.issued_batch').at(-1)
    assert.equal(batch.purpose, 'exec')
  } finally { await d.stop() }
})

test('exec reports a missing command as 127', async () => {
  const d = await twoCreds()
  try {
    await cliSession(d, 'demo')
    const r = await cli(d.dir, ['exec', '--', 'agent-vault-no-such-binary-xyz'])
    assert.equal(r.code, 127, r.stderr)
    assert.match(r.stderr, /command not found: agent-vault-no-such-binary-xyz/)
  } finally { await d.stop() }
})

test('session create takes several credentials and prints a block for each', async () => {
  const d = await twoCreds()
  try {
    const r = await cli(d.dir, ['session', 'create', '--cred', 'demo,oai', '--methods', 'GET'])
    assert.equal(r.code, 0, r.stderr)
    assert.equal((r.stdout.match(/^ {2}base url {5}/gm) || []).length, 2)
    assert.match(r.stdout, /\/p\/demo\n/)
    assert.match(r.stdout, /\/p\/oai\n/)
    const file = join(d.dir, 'grants.json')
    writeFileSync(file, JSON.stringify([{ cred: 'demo', methods: ['GET'] }, { cred: 'oai', methods: ['GET', 'POST'] }]))
    const fromFile = await cli(d.dir, ['session', 'create', '--grants-file', file, '--json'])
    assert.equal(fromFile.code, 0, fromFile.stderr)
    assert.equal(JSON.parse(fromFile.stdout).data.grants.length, 2)
    const mixed = await cli(d.dir, ['session', 'create', '--grants-file', file, '--cred', 'demo'])
    assert.equal(mixed.code, 2)
  } finally { await d.stop() }
})
