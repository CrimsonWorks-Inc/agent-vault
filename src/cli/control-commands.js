// Control-plane commands. Authentication remains the daemon's decision; every
// widening call uses the same presence flow as session creation.
import { readFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { request } from 'node:http'
import { EXIT, CODES } from '../core/errors.js'
import { fetchChainPins } from '../connectors/pinning.js'
import { PRICES_VERSION } from '../core/model-usage.js'
import { writeFileExclusive, appendLineExclusive } from './files.js'
import { grantInput, sessionInput, knownFlags, GRANT_FLAGS, readJson, numberFlag, textFlag, listFlag, expiryInput, usage, booleanFlag } from './policy-input.js'

// Terminal controls, and the Unicode ones a terminal obeys too: bidi
// embeddings, overrides and isolates (U+202A-202E, U+2066-2069) reorder what
// is shown, and U+2028/2029 break a line where none is printed.
export const cleanText = (value) => String(value ?? '').replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g, '')
const q = (params) => new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined)).toString()
const pretty = (value) => JSON.stringify(value, null, 2)
const show = (value) => typeof value === 'object' ? JSON.stringify(value) : String(value ?? 'none')
const required = (args, i = 0, label = 'credential') => textFlag(args._[i], label)

export const SCRUB_HELP = `cred scrub <slug> [--add PATTERN [--sample TEXT] | --rm ID]
  Patterns are 3–256 characters, with at most 16 alternation branches.
  Start each branch with at least 3 literal characters. Atoms may be literals,
  escaped characters or classes. Exact {n} quantifiers are allowed before the
  optional variable quantifier: at most one ? or {n,m} with n < m per branch,
  and only literal characters after it. Bounds are at most 256 and the maximum
  match length is 512. No *, +, {n,}, groups, backreferences, lookarounds or
  anchors. Patterns matching ordinary text, secrets or placeholders are refused.
  Request-name safety (C15/C16): query, form, multipart names and top-level JSON
  keys must be nonempty ASCII without controls or surrounding whitespace.
  Non-JSON names must start with a letter, digit, _, -, . or $. Array syntax
  a[], a[n], a[k] is a list; single-value rules check every element. Ambiguous
  spellings are refused as request_ambiguous; scrub patterns do not change that.`

/** Terminal presentation of the daemon's scrubbed, still-untrusted preview. */
export function approvalPreviewLines(p, full = false) {
  const lines = [`  sends: ${cleanText(p.content_type || p.body?.kind || 'none')} · ${p.body?.bytes || 0} bytes`]
  if (full) for (const key of ['query', 'headers', 'placeholders']) lines.push(`    ${key}: ${cleanText(JSON.stringify(p[key] || []))}`)
  const body = cleanText(p.body?.text || '')
  const shown = full ? Buffer.from(body).subarray(0, 4096).toString().split('\n') : body.split('\n').slice(0, 6)
  for (const line of shown) lines.push(`    ${line}`)
  lines.push('  (written by the agent, not verified)')
  return lines
}

export function controlCommands(ctx) {
  const { control, controlWithPresence: gated, readSecret, out, fail, C, loadState, stateDir, gatewayPortOf, ask, isJson } = ctx
  const output = (r, human = pretty(r)) => out(String(human).split(/(\x1b\[[0-9;]*m)/).map((part) => /^\x1b\[[0-9;]*m$/.test(part) ? part : cleanText(part)).join(''), r)
  const note = (s) => console.error(`${C.yellow('note')} ${cleanText(s)}`)
  const sidOf = (args) => {
    const sid = args._[0] || loadState().session_id
    if (!sid) throw Object.assign(new Error('no session selected'), { exit: EXIT.SESSION, next: 'agent-vault session create --cred <slug>' })
    return sid
  }
  const credential = async (slug) => {
    const creds = await control('GET', '/v1/credentials')
    const c = creds.find((c) => c.slug === slug)
    if (!c) throw Object.assign(new Error('credential not found'), { exit: EXIT.NOT_FOUND })
    return c
  }
  const write = async (path, text, force = false) => {
    textFlag(path, '--out')
    try { return writeFileExclusive(path, text, { force }) } catch (e) {
      if (e.code === 'EEXIST' && !force && process.stdin.isTTY && !isJson()) {
        if (/^(y|yes)$/i.test((await ask(`${path} exists. Replace it? [y/N] `)).trim())) return writeFileExclusive(path, text, { force: true })
      }
      if (['EEXIST', 'ENOTREGULAR', 'ELOOP'].includes(e.code)) e.exit = EXIT.CONFLICT
      throw e
    }
  }
  const append = (path, line) => {
    try { appendLineExclusive(path, line) } catch (e) {
      if (['EEXIST', 'ENOTREGULAR', 'ELOOP'].includes(e.code)) e.exit = EXIT.CONFLICT
      throw e
    }
  }
  const backupInput = async (args) => ({ bundle: readJson(required(args, 0, 'backup file'), 'backup file'), recovery_passphrase: await readSecret('recovery passphrase (not your vault passphrase): ') })
  return {
    async 'cred:rotate'(args) {
      const slug = required(args)
      const mode = booleanFlag(args, 'revoke') ? 'revoke' : 'keep'
      const options = {
        ...(args.field !== undefined ? { field: textFlag(args.field, '--field') } : {}),
        ...(args['retire-hours'] !== undefined ? { retire_hours: numberFlag(args['retire-hours'], '--retire-hours', { max: 168 }) } : {}),
        ...(args.expires !== undefined ? { expires_at: expiryInput(args.expires) } : {}),
      }
      const value = await readSecret(`new value for ${slug} (not echoed): `)
      if (!value) usage('no value given')
      const r = await gated('POST', '/v1/credentials/rotate', { slug, value, mode, ...options })
      const v = r.rotated
      output(r, `${C.green('rotated')} ${slug} ${C.dim(`v${v.version}, fingerprint ${v.previous_fp8} → ${v.fp8}`)}\n  ${mode === 'revoke' ? `${v.revoked_grants} grants revoked` : `sessions keep working; the old value is still scrubbed until ${v.retire_until}`}\n  ${r.invalidated_approvals} held requests were denied`)
      for (const w of r.warnings || []) note(w)
    },
    async 'cred:expiry'(args) {
      const r = await gated('POST', '/v1/credentials/expiry', { slug: required(args), expires_at: expiryInput(args._[1]) })
      output(r, `${C.green('expiry set')} ${r.slug}  ${r.expires_at || 'none'}`)
    },
    async 'cred:scrub'(args) {
      const slug = required(args)
      if (args.add && args.rm) usage('--add and --rm cannot be combined')
      if (args.sample !== undefined && !args.add) usage('--sample requires --add')
      if (args.add) {
        const results = []
        for (const pattern of args.add) results.push(await gated('POST', '/v1/credentials/scrub', { slug, pattern: textFlag(pattern, '--add'), ...(args.sample !== undefined ? { sample: textFlag(args.sample, '--sample') } : {}) }))
        const r = results.length === 1 ? results[0] : results
        output(r, results.map((v) => `${v.id}  ${v.source}  added ${v.added_at}${v.sample ? `\n  ${v.sample.redacted} (${v.sample.matches} matches)` : ''}`).join('\n'))
      } else if (args.rm) {
        output(await gated('DELETE', `/v1/credentials/scrub?${q({ slug, id: textFlag(args.rm, '--rm') })}`), 'scrub pattern removed')
      } else {
        const patterns = (await credential(slug)).scrub_patterns || []
        output(patterns, patterns.map((p) => `${p.id}  ${p.source}  added ${p.added_at}`).join('\n') || 'no scrub patterns')
      }
    },
    async 'cred:pin'(args) {
      const slug = required(args), host = textFlag(args.host, '--host')
      if ([args.add !== undefined, args.rm !== undefined, args.clear !== undefined].filter(Boolean).length > 1) usage('choose --add, --rm or --clear')
      booleanFlag(args, 'clear'); booleanFlag(args, 'live')
      if (args.live) {
        const r = await fetchChainPins(host)
        if (!args.add && !args.rm && !args.clear) return output(r, r.map((p) => `${show(p.subject)}  ${p.spki}  expires ${p.not_after}`).join('\n') + '\nverify these out of band before pinning')
        if (!isJson()) note(r.map((p) => `${show(p.subject)}  ${p.spki}  expires ${p.not_after}`).join('\n') + '\nverify these out of band before pinning')
      }
      if (args.add) {
        output(await gated('POST', '/v1/credentials/pins', { slug, host, pins: args.add.map((p) => textFlag(p, '--add')) }), `pinned ${slug} ${host}`)
      } else if (args.rm || args.clear) {
        output(await gated('DELETE', `/v1/credentials/pins?${q({ slug, host, spki: args.rm === undefined ? undefined : textFlag(args.rm, '--rm') })}`), `pins removed ${slug} ${host}`)
      } else {
        const pins = (await credential(slug)).pins?.[host] || 0
        output({ slug, host, pins }, `${slug}  pinned: ${host} (${pins})`)
      }
    },
    async 'cred:test'(args) {
      const all = booleanFlag(args, 'all')
      if (Boolean(args._[0]) === all) usage('usage: agent-vault cred test <slug> | --all')
      const r = await control('POST', '/v1/credentials/test', all ? { all: true } : { slug: required(args) })
      // With --all, a kind that has no probe (a generic http credential) is
      // skipped, not a failure: there was nothing to run.
      const skipped = (v) => all && v.rule === 'no_probe'
      const results = all ? r.results : [{ slug: args._[0], ...r }]
      output(r, results.map((v) => `${v.ok === true ? C.green('ok  ') : skipped(v) ? C.dim('skip') : C.yellow('warn')} ${v.slug.padEnd(26)} ${skipped(v) ? 'no probe for this kind' : v.error || `${v.http_status} · ${v.latency_ms}ms · scopes: ${(v.scopes || []).join(', ')}`}`).join('\n'))
      if (results.some((v) => v.ok !== true && !skipped(v))) process.exitCode = results.some((v) => ['AV_QUOTA_EXCEEDED', 'AV_QUARANTINED'].includes(v.error)) ? EXIT.POLICY_DENIED : EXIT.UPSTREAM
    },
    async 'cred:quarantine'(args) {
      const r = await control('POST', '/v1/credentials/quarantine', { slug: required(args), ...(args.reason !== undefined ? { reason: textFlag(args.reason, '--reason') } : {}) })
      output(r, `${C.yellow('quarantined')} ${r.slug} · ${r.denied_approvals} held requests denied`)
    },
    async 'cred:release'(args) {
      const r = await gated('POST', '/v1/credentials/release', { slug: required(args) })
      output(r, `${C.green('released')} ${r.slug}`)
    },
    async panic(args) {
      const r = await control('POST', '/v1/panic', { lock: booleanFlag(args, 'lock'), ...(args.reason !== undefined ? { reason: textFlag(args.reason, '--reason') } : {}) })
      output(r, `${C.red('panic')} ${r.revoked_sessions ?? 0} sessions revoked · ${r.denied_approvals ?? 0} held requests denied · ${r.denied_session_requests ?? 'unknown'} session requests denied${r.locked ? ' · vault locked' : ''}`)
      if (r.already === true) process.exitCode = EXIT.LOCKED
    },
    async 'tripwire:show'() {
      const r = await control('GET', '/v1/tripwires')
      // A daemon from before rules were always a list sends null for "never
      // saved"; either way those are the defaults.
      const saved = Array.isArray(r.rules) && r.rules_saved !== false
      const rules = Array.isArray(r.rules) ? r.rules : Array.isArray(r.defaults) ? r.defaults : []
      output(r, `tripwires ${r.enabled === true ? 'on' : 'off'}${saved ? '' : r.enabled === true ? ' (the default rules)' : ' (the default rules, used when you turn them on)'}\n` + (rules.map((v) => `${v.id}  ${v.codes?.join(',') || v.rule_prefix}  ${v.threshold} in ${v.window_s}s  → ${v.action}`).join('\n') || 'no rules'))
    },
    async 'tripwire:on'() {
      const current = await control('GET', '/v1/tripwires')
      const stored = current.rules_saved !== false && current.rules?.length
      output(await gated('POST', '/v1/tripwires', { enabled: true, ...(!stored ? { rules: 'defaults' } : {}) }), 'tripwires on')
    },
    async 'tripwire:off'() { output(await gated('POST', '/v1/tripwires', { enabled: false }), 'tripwires off') },
    async 'tripwire:set'(args) {
      const id = textFlag(args.rule, '--rule')
      const m = /^(\d+)(s|m|h|d)$/.exec(textFlag(args.window, '--window'))
      if (!m) usage('--window must be a duration such as 10m')
      const window_s = numberFlag(String(Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[m[2]]), '--window', { min: 10, max: 86400 })
      if (!['revoke_session', 'quarantine_credential', 'panic'].includes(args.action)) usage('invalid --action')
      if (Boolean(args.codes) === Boolean(args['rule-prefix'])) usage('choose --codes or --rule-prefix')
      const rule = { id, threshold: numberFlag(args.threshold, '--threshold', { min: 1, max: 1000 }), window_s, action: args.action,
        ...(args.codes ? { codes: listFlag(args.codes, '--codes') } : { rule_prefix: textFlag(args['rule-prefix'], '--rule-prefix') }) }
      const current = await control('GET', '/v1/tripwires')
      // Rules never saved are the defaults in force, so a set edits those.
      const rules = [...(current.rules || current.defaults || []).filter((v) => v.id !== id), rule]
      output(await gated('POST', '/v1/tripwires', { rules }), `tripwire ${id} set`)
    },
    async 'notify:set'(args) {
      const detail = args.detail ?? 'minimal'
      if (!['minimal', 'headline'].includes(detail)) usage('--detail is minimal or headline')
      const webhook_url = await readSecret('webhook URL (not echoed): ')
      if (!webhook_url) usage('no webhook URL given')
      const r = await gated('POST', '/v1/notify', { webhook_url, detail })
      output(r, `webhook  ${r.webhook.host}  ${r.webhook.detail}  since ${r.webhook.configured_at}`)
    },
    async 'notify:show'() {
      const r = await control('GET', '/v1/notify')
      output(r, r.webhook ? `webhook  ${r.webhook.host}  ${r.webhook.detail}  since ${r.webhook.configured_at}` : 'no webhook')
    },
    async 'notify:off'() { output(await control('DELETE', '/v1/notify'), 'webhook off') },
    async 'notify:test'() { output(await control('POST', '/v1/notify/test')) },
    async 'template:save'(args) {
      const name = required(args, 0, 'template name')
      if (args['from-file'] && Object.keys(args).some((key) => !['_', 'from-file'].includes(key))) usage('--from-file cannot be combined with session flags')
      const spec = args['from-file'] ? readJson(args['from-file'], '--from-file') : sessionInput(args)
      if (!spec || typeof spec !== 'object' || Array.isArray(spec)) usage('template spec must be an object')
      const r = await gated('POST', '/v1/templates', { name, spec })
      output(r, `${C.green('saved')} template ${r.name} v${r.version}`)
      for (const p of r.lint || []) note(p.message)
    },
    async 'template:list'() {
      const r = await control('GET', '/v1/templates')
      output(r, r.map((t) => `${t.name}  v${t.version}  ${t.summary} ${t.elevated?.length ? 'elevated ' : ''}creds:${t.creds.join(',')} updated:${t.updated_at}`).join('\n') || 'no templates')
    },
    async 'template:show'(args) { output(await control('GET', `/v1/templates?${q({ name: required(args, 0, 'template name') })}`)) },
    async 'template:rm'(args) { output(await control('DELETE', `/v1/templates?${q({ name: required(args, 0, 'template name') })}`), 'template removed') },
    async 'session:narrow'(args) {
      // A grant's use count is not a narrowable field (C22): the daemon refuses it, so refuse it here, before sending.
      if (args.uses !== undefined) usage('session narrow cannot change --uses; nothing was sent')
      knownFlags(args, [...GRANT_FLAGS, 'cred', 'ttl'], 'session narrow')
      const sid = sidOf(args), narrow = grantInput(args)
      // Grant lifetime is a route attribute, not part of the policy layer.
      const grant_ttl_minutes = narrow.grant_ttl_minutes
      delete narrow.grant_ttl_minutes
      const session_ttl_minutes = args.ttl === undefined ? undefined : numberFlag(args.ttl, '--ttl', { min: 1 })
      if (!Object.keys(narrow).length && session_ttl_minutes === undefined && grant_ttl_minutes === undefined) usage('session narrow needs at least one limit')
      const r = await control('POST', '/v1/sessions/narrow', { sid, ...(args.cred ? { cred: textFlag(args.cred, '--cred') } : {}), narrow, session_ttl_minutes, grant_ttl_minutes })
      output(r, r.grants.map((g) => `${C.green('narrowed')} ${g.cred}  ` + Object.keys(g.after).filter((k) => JSON.stringify(g.before[k]) !== JSON.stringify(g.after[k])).map((k) => `${k}: ${show(g.before[k])} → ${show(g.after[k])}`).join(' · ') + (g.expires_at ? ` · expires ${g.expires_at}` : '')).join('\n') + (session_ttl_minutes ? `\n  expires ${r.expires_at}` : ''))
    },
    async 'session:show'(args) {
      const markdown = booleanFlag(args, 'markdown')
      const r = await control('GET', `/v1/sessions/detail?${q({ sid: sidOf(args) })}`)
      output(r, sessionSummary(r, markdown))
      if (r.activity?.complete === false && !isJson()) note(r.activity.note || 'history is incomplete')
    },
    async report(args) {
      const markdown = booleanFlag(args, 'markdown')
      const r = await control('GET', `/v1/report/access?${q({ since: args.since === undefined ? '7d' : textFlag(args.since, '--since') })}`)
      output(r, reportSummary(r, markdown))
      if (r.complete === false && !isJson()) note('history is incomplete')
    },
    async 'backup:export'(args) {
      const path = textFlag(args.out, '--out'), force = booleanFlag(args, 'force')
      const recovery_passphrase = await readSecret('recovery passphrase (not your vault passphrase): ')
      if (recovery_passphrase !== await readSecret('again: ')) usage('recovery passphrases differ')
      const r = await gated('POST', '/v1/backup/export', { recovery_passphrase })
      const { replaced } = await write(path, pretty(r.bundle) + '\n', force)
      if (replaced) console.error(`replaced ${path}`)
      output({ path, ...r.summary, bundle_sha256: r.bundle_sha256, mode: '0600', replaced }, `${C.green('backed up')} ${r.summary.credentials} credentials to ${path} (encrypted; keep the recovery passphrase somewhere else)`)
    },
    async 'backup:inspect'(args) {
      const r = await control('POST', '/v1/backup/inspect', await backupInput(args))
      output(r, r.credentials.map((c) => `${c.slug}  ${c.kind}  ${c.host || ''}`).join('\n'))
    },
    async 'backup:restore'(args) {
      const on_conflict = args['on-conflict'] ?? 'skip'
      if (!['skip', 'rename', 'fail'].includes(on_conflict)) usage('--on-conflict is skip, rename or fail')
      const input = await backupInput(args)
      const inspection = await control('POST', '/v1/backup/inspect', input)
      if (!isJson()) console.log(cleanText(inspection.credentials.map((c) => `${c.slug}  ${c.kind}  ${c.host || ''}`).join('\n')))
      if (process.stdin.isTTY && !isJson() && !/^(y|yes)$/i.test((await ask(`Restore ${inspection.credentials.length} credentials? [y/N] `)).trim())) return output({ restored: [], cancelled: true }, 'restore cancelled')
      output(await gated('POST', '/v1/backup/restore', { ...input, on_conflict }))
    },
    async 'audit:export'(args) {
      let since = args['since-seq'] === undefined ? 0 : numberFlag(args['since-seq'], '--since-seq')
      const follow = booleanFlag(args, 'follow'), force = booleanFlag(args, 'force')
      if (force && !args.out) usage('--force requires --out')
      if (args.out !== undefined) textFlag(args.out, '--out')
      let first = true, stopped = false, timer, wake
      const stop = () => { stopped = true; clearTimeout(timer); wake?.() }
      if (follow) process.once('SIGINT', stop)
      try {
        do {
          const r = await control('GET', `/v1/audit/export?${q({ since_seq: since, limit: 5000 })}`)
          if (args.out) {
            if (first) {
              const result = await write(args.out, r.rows.map((v) => JSON.stringify(v)).join('\n') + (r.rows.length ? '\n' : ''), force)
              if (result.replaced) console.error(`replaced ${args.out}`)
            } else for (const row of r.rows) append(args.out, JSON.stringify(row))
          } else if (!isJson()) for (const row of r.rows) console.log(JSON.stringify(row))
          if (isJson()) output(r)
          first = false
          const previous = since
          since = r.next_seq
          if (r.rows.length >= 5000 && since > previous) continue
          if (!follow || stopped) break
          await new Promise((resolve) => { wake = resolve; timer = setTimeout(resolve, 2000); if (stopped) stop() })
        } while (!stopped)
      } finally { process.removeListener('SIGINT', stop); clearTimeout(timer) }
    },
    async 'audit:witness'(args) {
      const path = args.out === undefined ? join(stateDir(), 'witness.jsonl') : textFlag(args.out, '--out')
      if (args.out === undefined) mkdirSync(stateDir(), { recursive: true, mode: 0o700 })
      const r = await control('GET', '/v1/audit/checkpoint')
      append(path, JSON.stringify(r))
      output(r, `${C.green('witnessed')} record ${r.seq}, head ${r.head.slice(0, 16)}…`)
    },
    async 'audit:verify'(args) {
      const chain = await control('GET', '/v1/audit/verify')
      let witness
      if (args.witness !== undefined) {
        let checkpoints
        try { checkpoints = readFileSync(textFlag(args.witness, '--witness'), 'utf8').split(/\r?\n/).filter((s) => s.trim()).map((s) => JSON.parse(s)) } catch (e) { usage(`cannot read --witness: ${e.code || 'not JSONL'}`) }
        witness = await control('POST', '/v1/audit/verify-witness', { checkpoints })
      }
      const ok = chain.ok === true && (!witness || witness.ok === true)
      const result = witness ? { ...chain, ok, witness } : chain
      // A broken chain or witness is a failure envelope, never data inside a
      // success one: a caller reading only --json must not see ok:true.
      if (chain.ok !== true) {
        fail(cleanText(chain.brokenAt ? `chain broken at record ${chain.brokenAt}: ${chain.reason}` : `the audit log cannot be trusted: ${chain.reason}`), EXIT.FAILURE, { problem: result })
      }
      if (witness && witness.ok !== true) {
        fail(cleanText(`the audit log does not match the witness: ${(witness.ahead || []).length} ahead of the log (records were removed) · ${(witness.mismatched || []).length} mismatched · ${(witness.forged || []).length} forged · ${(witness.other_vault || []).length} other vault`), EXIT.FAILURE, { problem: result })
      }
      output(result, `chain intact ${chain.count} records, head ${chain.head?.slice(0, 16)}...` + (witness ? `\nwitness ok ${witness.checked} checkpoints` : ''))
    },
    async preflight(args) {
      const cred = textFlag(args.cred, '--cred'), method = textFlag(args.method, '--method').toUpperCase(), path = textFlag(args.path, '--path')
      if (!/^[a-z0-9][a-z0-9._-]*$/i.test(cred) || !path.startsWith('/')) usage('--cred must be a slug and --path must begin with /')
      const headers = (args.header || []).map((v) => {
        const m = /^([^:\s]+):[ \t]*(.*)$/.exec(textFlag(v, '--header'))
        if (!m || /[\r\n]/.test(v)) usage('--header must be K: V without line breaks')
        return [m[1], m[2]]
      })
      const st = loadState()
      if (!st.token) throw Object.assign(new Error('no session selected'), { exit: EXIT.SESSION, next: 'agent-vault session create --cred <slug>' })
      // The documented form names no placeholder: judge it as the agent's
      // request would be, with one at the credential's site (as
      // vault_preflight does). A placeholder the caller does send is checked.
      const input = { method, path: `/p/${cred}${path}`, headers, assume_placeholder: true,
        ...(args.query !== undefined ? { query: textFlag(args.query, '--query') } : {}),
        ...(args['body-file'] !== undefined ? { body_base64: readFileSync(textFlag(args['body-file'], '--body-file')).toString('base64') } : {}),
      }
      const r = await gatewayPreflight(gatewayPortOf(st), st.token, input)
      output(r, `${r.would === 'allow' ? C.green('would allow') : r.would === 'hold' ? C.yellow('would hold for approval') : C.red('would refuse')}\n` + r.checks.map((v) => `${v.ok === true ? 'ok  ' : 'warn'} ${v.stage.padEnd(26)} ${v.code || ''} ${v.rule || ''}`).join('\n') + `\n${r.advisory}`)
      process.exitCode = r.would === 'allow' ? 0 : r.would === 'hold' ? EXIT.APPROVAL : EXIT.POLICY_DENIED
    },
  }
}

function gatewayPreflight(port, token, body) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path: '/v1/preflight', method: 'POST', headers: { 'content-type': 'application/json', 'av-session': token } }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('error', reject)
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(Buffer.concat(chunks).toString()) } catch { return reject(new Error('invalid preflight response')) }
        if (res.statusCode >= 400) reject(Object.assign(new Error(parsed.detail || 'preflight refused'), { problem: parsed, exit: CODES[parsed.code]?.exit ?? EXIT.FAILURE }))
        else resolve(parsed)
      })
    })
    req.on('error', (e) => reject(Object.assign(e, { exit: EXIT.DAEMON_UNREACHABLE })))
    req.end(JSON.stringify(body))
  })
}

function sessionSummary(r, markdown) {
  const lines = [], field = (k, v) => lines.push(markdown ? `- **${k}**: ${show(v)}` : `  ${k.padEnd(15)}${show(v)}`)
  lines.push(markdown ? `# Session ${r.session.id}` : `session ${r.session.id}`)
  for (const [k, v] of Object.entries(r.session)) field(k, v)
  for (const g of r.grants) {
    lines.push(`\n${markdown ? '##' : 'grant'} ${g.cred} ${g.grant_id}`)
    for (const [k, v] of Object.entries(g.effective || {})) field(k, v)
    for (const k of ['state', 'budget', 'limits', 'counters']) field(k, g[k])
    field('expires', g.expires_at || 'session lifetime')
    if (g.spend) {
      const s = g.spend, count = (n) => n == null ? 'unlimited' : n.toLocaleString('en-US')
      const usd = (n) => n == null ? 'unlimited' : `$${(n / 1e6).toFixed(2)}`
      field('spend', `${count(s.tokens_used)} / ${count(s.limit_tokens)} tokens · ${usd(s.usd_micros_used)} / ${usd(s.limit_usd_micros)} (estimate, prices ${s.prices_version || PRICES_VERSION})`)
      field('reserved', { tokens: s.reserved_tokens, usd_micros: s.reserved_usd_micros })
    }
    field('placeholders', g.placeholders)
  }
  const a = r.activity || {}
  lines.push(`\n${markdown ? '##' : ''} Activity`)
  field('requests', a.requests); field('approvals', a.approvals)
  for (const p of a.paths || []) lines.push(`  ${p.count}  ${p.method} ${p.path}`)
  for (const d of a.denials || []) lines.push(`  ${d.count}  ${d.code}  ${d.rule}`)
  field('tripwires', a.tripwires)
  if (a.complete === false) field('note', a.note || 'history is incomplete')
  return lines.join('\n')
}
function reportSummary(r, markdown) {
  const lines = [markdown ? '# Access review' : 'access review', `since ${r.since} · generated ${r.generated_at}`]
  const table = (title, rows, columns) => {
    lines.push(`\n${markdown ? '## ' : ''}${title}`)
    lines.push(columns.join(markdown ? ' | ' : '  '))
    if (markdown) lines.push(columns.map(() => '---').join(' | '))
    for (const row of rows) lines.push(columns.map((key) => cleanText(show(row[key])).replaceAll('|', '\\|').replaceAll('\n', ' ')).join(markdown ? ' | ' : '  '))
  }
  table('Credentials', r.credentials, ['slug', 'sessions_active', 'sessions_total', 'requests', 'denials', 'last_used_at', 'expiry_warning', 'health_status', 'quarantined'])
  table('Sessions', r.sessions, ['id', 'label', 'state', 'creds', 'requests', 'denials', 'last_seen_at', 'elevated', 'unused_methods'])
  if (r.complete === false) lines.push('note: history is incomplete')
  return lines.join('\n')
}
