// The Sessions page's rules, ported from src/ui/the old page as pure functions so
// the tests can hold them to the old page's behaviour. Nothing here touches the
// DOM or the network: the components read their inputs, call these, and send
// exactly what comes back.

import { canonicalJson } from '../../lib/presence.js'
import { policyValue, until } from '../../lib/format.js'
import { cleanLine } from '../../lib/text.js'

// ---- constants, as the old page named them -------------------------------------

export const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS']
export const APPROVAL_ORDER = ['auto', 'first-use', 'on-write', 'each']
export const MODEL_KINDS = ['anthropic', 'openai', 'google-genai']
export const ROUTE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']
export const MAX_ROUTE_ROWS = 16
export const MAX_SESSION_CREDS = 16
/** The env-var names the CLI's `env --map` accepts (src/cli/files.js ENV_NAME). */
export const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/
/** `env` maps at most this many names (src/cli/index.js MAX_MAPPINGS). */
export const MAX_MAPPINGS = 64

export const APPROVAL_OPTIONS = [
  { value: 'on-write', label: 'ask me before writes (on-write)' },
  { value: 'each', label: 'ask me every time' },
  { value: 'first-use', label: 'ask me the first time' },
  { value: 'auto', label: 'never ask (auto)' },
]
export const LIFETIME_OPTIONS = [
  { value: '1', label: '1 hour' },
  { value: '8', label: '8 hours' },
  { value: '24', label: '24 hours' },
  { value: 'never', label: 'No expiry' },
]

export const AUTO_WARNING = 'No approval prompts for writes, or only for the first request. Your authenticator is asked every time you create one.'
export const NEVER_WARNING = 'This session never expires. It lasts until you revoke it, and your authenticator is asked every time you create one.'

// ---- the session list ------------------------------------------------------

/**
 * Auto or first-use with any method that writes: after at most one request
 * the session never asks you again (C26), so it is elevated.
 */
export const autoWrites = (approval, methods) =>
  (approval === 'auto' || approval === 'first-use')
  && (methods || ['GET', 'HEAD']).some((m) => !SAFE_METHODS.includes(String(m).toUpperCase()))

/**
 * The session's strictest mode. When it lets writes through unasked, its
 * laxest mode instead (auto, or first-use), shown as a warning. Null when it
 * has no credentials to read a mode from (the old page's approvalBadge).
 */
export function approvalMode(s) {
  const modes = (s?.creds || []).map((c) => c?.approval ?? 'auto')
  if (!modes.length) return null
  const rank = (m) => (APPROVAL_ORDER.includes(m) ? APPROVAL_ORDER.indexOf(m) : APPROVAL_ORDER.length)
  const elevated = (s.elevated || []).includes('approval_auto_writes')
  const mode = modes.reduce((a, b) => ((elevated ? rank(b) < rank(a) : rank(b) > rank(a)) ? b : a))
  return { mode, elevated }
}

/** "never expires" for an infinite session, the time left otherwise. */
export const sessionExpiry = (s) => (s?.infinite ? 'never expires' : until(s?.expires_at))

/** The three one-click narrowings on a live session (F15). Each only takes away. */
export const NARROWINGS = {
  'drop-writes': {
    label: 'Drop write access', hint: 'Only GET and HEAD from now on', title: 'Write access dropped',
    body: (sid) => ({ sid, narrow: { methods: ['GET', 'HEAD'] } }),
  },
  'approve-each': {
    label: 'Require approval for everything', hint: 'Every request waits for you', title: 'Every request now needs your approval',
    body: (sid) => ({ sid, narrow: { approval: 'each' } }),
  },
  'end-1h': {
    label: 'End in 1 hour', hint: 'It ends within the hour, whatever lifetime it had', title: 'Ends within the hour',
    body: (sid) => ({ sid, narrow: {}, session_ttl_minutes: 60 }),
  },
}

/**
 * What a narrow changed, grant by grant (F15): `{ ends, grants: [{ cred,
 * changes: [{ key, before, after }], expires_at }] }`.
 */
export function narrowSummary(r) {
  const grants = Array.isArray(r?.grants) ? r.grants : []
  const ends = r?.infinite === true ? 'never expires' : r?.expires_at ? `expires ${r.expires_at}` : ''
  return {
    sessionId: r?.session_id ?? '',
    ends,
    grants: grants.map((g) => {
      const keys = [...new Set([...Object.keys(g?.before || {}), ...Object.keys(g?.after || {})])]
      const changed = keys.filter((k) => canonicalJson(g.before?.[k]) !== canonicalJson(g.after?.[k]))
      return {
        cred: g?.cred ?? '',
        changes: changed.map((k) => ({ key: k, before: policyValue(g.before?.[k]), after: policyValue(g.after?.[k]) })),
        expires_at: g?.expires_at ?? null,
      }
    }),
  }
}

// ---- the new-session form ------------------------------------------------------

/**
 * GrantSpec fields from the advanced inputs (the old page advancedFields). Rate
 * and quota go as typed, for the daemon to parse; numbers go as numbers; the
 * payload is parsed here, before anything is signed. Empty means absent.
 */
export function advancedFields(raw) {
  const out = {}
  const num = (k, v) => {
    if (v === undefined || v === null || String(v).trim() === '') return true
    const n = Number(v)
    if (!Number.isFinite(n)) return false
    out[k] = n
    return true
  }
  if (raw.rate?.trim()) out.rate = raw.rate.trim()
  if (raw.quota?.trim()) out.quota = raw.quota.trim()
  for (const [k, v] of [['max_concurrent', raw.concurrency], ['redirects', raw.redirects],
    ['grant_ttl_minutes', raw.grantTtl], ['spend_tokens', raw.spendTokens], ['spend_usd', raw.spendUsd]]) {
    if (!num(k, v)) return { error: `${k} must be a number` }
  }
  let payload = null
  if (raw.payload?.trim()) {
    try { payload = JSON.parse(raw.payload) } catch (e) { return { error: `The payload rules are not JSON: ${e.message}` } }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return { error: 'The payload rules must be a JSON object.' }
  }
  if (raw.graphqlQueriesOnly === true) {
    payload = { ...(payload || {}), graphql: { ...(payload?.graphql || {}), operations: ['query'] } }
  }
  if (payload) out.payload = payload
  const rows = (raw.routes || []).filter((r) => (r.methods || []).length || String(r.paths || '').trim())
  if (rows.length > MAX_ROUTE_ROWS) return { error: `At most ${MAX_ROUTE_ROWS} routes.` }
  for (const r of rows) {
    const paths = String(r.paths || '').split(',').map((p) => p.trim()).filter(Boolean)
    if (!(r.methods || []).length || !paths.length) return { error: 'Each route needs at least one method and one path.' }
  }
  if (rows.length) {
    out.routes = rows.map((r) => ({ methods: r.methods.slice(), paths: String(r.paths).split(',').map((p) => p.trim()).filter(Boolean) }))
  }
  return { fields: out }
}

/** Whether any picked credential is a model provider's (spend limits apply). */
export const picksModel = (picked, kinds) => picked.some((slug) => MODEL_KINDS.includes(kinds.get(slug)))

/**
 * What the free-form New session form would create (the old page
 * readSessionForm), or `{ error }`. `form` holds the inputs' values as typed.
 */
export function buildSessionBody(form, kinds = new Map()) {
  const picked = form.picked || []
  if (!picked.length) return { error: 'Pick at least one credential' }
  if (picked.length > MAX_SESSION_CREDS) return { error: 'A session holds at most 16 credentials' }
  const models = picksModel(picked, kinds)
  const adv = advancedFields({
    rate: form.rate ?? '', concurrency: form.concurrency ?? '', quota: form.quota ?? '',
    redirects: form.redirects ?? '', grantTtl: form.grantTtl ?? '',
    // Spend only means something for a model provider; hidden is absent.
    spendTokens: models ? form.spendTokens ?? '' : '', spendUsd: models ? form.spendUsd ?? '' : '',
    payload: form.payload ?? '', graphqlQueriesOnly: form.graphql === true,
    routes: form.routes || [],
  })
  if (adv.error) return { error: adv.error }
  // The same limits for every credential picked, one grant each.
  const shared = {
    methods: String(form.methods ?? '').split(',').map((m) => m.trim().toUpperCase()).filter(Boolean),
    paths: String(form.paths ?? '').split(',').map((p) => p.trim()).filter(Boolean),
    budget: Number(form.budget ?? ''),
    approval: form.approval,
    ...adv.fields,
  }
  const lifetime = form.lifetime
  return {
    body: {
      label: String(form.label ?? '').trim() || 'ui session',
      grants: picked.map((cred) => ({ cred, ...shared })),
      // No expiry is no lifetime at all, never a long one.
      ...(lifetime === 'never' ? { infinite: true } : { ttl_hours: Number(lifetime) }),
    },
    picked,
  }
}

/** The form's starting values (the old page freeForm's defaults). */
export function freshForm(creds = []) {
  return {
    picked: creds.length ? [creds[0].slug] : [],
    label: '', methods: 'GET,HEAD', paths: '/**', budget: '500', approval: 'on-write', lifetime: '8', grantTtl: '',
    rate: '', concurrency: '', quota: '', redirects: '', spendTokens: '', spendUsd: '', payload: '', graphql: false,
    routes: [],
  }
}

// ---- templates (F17) -------------------------------------------------------------

/** What a template allows, per field, over all of its grants. */
export function templateLimits(spec) {
  const grants = Array.isArray(spec?.grants) ? spec.grants : [spec || {}]
  const nums = (k) => grants.map((g) => Number(g[k])).filter((n) => Number.isFinite(n) && n >= 0)
  const budgets = nums('budget')
  const ttls = nums('grant_ttl_minutes')
  const rank = (m) => { const i = APPROVAL_ORDER.indexOf(m ?? 'on-write'); return i < 0 ? APPROVAL_ORDER.length : i }
  return {
    creds: grants.map((g) => g.cred).filter(Boolean),
    methods: [...new Set(grants.flatMap((g) => (Array.isArray(g.methods) ? g.methods : ['GET', 'HEAD'])).map((m) => String(m).toUpperCase()))],
    // Overrides apply per grant, so the laxest grant is what any choice
    // can still narrow; a choice laxer than that narrows nothing.
    approvalFloor: Math.min(...grants.map((g) => rank(g.approval))),
    budget: budgets.length === grants.length ? Math.max(...budgets) : null,
    grantTtl: ttls.length === grants.length ? Math.max(...ttls) : null,
    infinite: spec?.infinite === true,
    ttlHours: spec?.infinite === true ? null : Number.isFinite(Number(spec?.ttl_hours)) && spec?.ttl_hours != null ? Number(spec.ttl_hours) : 8,
  }
}

/**
 * The overrides a form sends on top of a template: only what the human
 * changed, and only ever narrower. `{ error }` when a value would widen.
 */
export function templateOverrides(limits, chosen) {
  const out = {}
  if (chosen.label) out.label = chosen.label
  const methods = (chosen.methods || []).filter((m) => limits.methods.includes(m))
  if (!methods.length) return { error: 'Pick at least one method the template allows.' }
  if (methods.length < limits.methods.length) out.methods = methods
  if (chosen.approval) {
    if (!APPROVAL_ORDER.includes(chosen.approval) || APPROVAL_ORDER.indexOf(chosen.approval) < limits.approvalFloor) {
      return { error: 'That approval mode is laxer than the template; a template can only be narrowed.' }
    }
    out.approval = chosen.approval
  }
  if (chosen.budget !== undefined && chosen.budget !== '') {
    const n = Number(chosen.budget)
    if (!Number.isFinite(n) || n < 1 || (limits.budget !== null && n > limits.budget)) {
      return { error: `The budget can only go down${limits.budget !== null ? ` from ${limits.budget}` : ''}.` }
    }
    out.budget = n
  }
  if (chosen.lifetime && chosen.lifetime !== 'template') {
    const h = Number(chosen.lifetime)
    if (chosen.lifetime === 'never' || !Number.isFinite(h)) {
      if (!limits.infinite) return { error: 'This template has a lifetime; it cannot be made endless.' }
    } else {
      if (!limits.infinite && h > limits.ttlHours) return { error: `The lifetime can only go down from ${limits.ttlHours} hours.` }
      out.ttl_hours = h
    }
  }
  if (chosen.grantTtl !== undefined && chosen.grantTtl !== '') {
    const n = Number(chosen.grantTtl)
    if (!Number.isFinite(n) || n < 1 || (limits.grantTtl !== null && n > limits.grantTtl)) {
      return { error: 'A grant lifetime can only go down.' }
    }
    out.grant_ttl_minutes = n
  }
  return { overrides: out }
}

/** The body for creating from a template: its hash pins the one on screen. */
export function templateSessionBody(t, chosen) {
  const { overrides, error } = templateOverrides(t.limits, chosen)
  if (error) return { error }
  // The hash is the one fetched with the template on screen, so an edit
  // made after you looked is refused by the daemon (template_changed).
  return { body: { template: t.name, template_hash: t.hash, ...overrides }, picked: t.limits.creds }
}

// ---- the hand-off card -------------------------------------------------------------

/** The name a tool most likely reads a credential from. */
export const suggestedName = (g) => g?.env?.key || `${String(g?.cred).toUpperCase().replace(/[^A-Z0-9]/g, '_')}_TOKEN`

/**
 * A curl line that puts the placeholder where this credential declares it
 * goes. Anywhere else and the daemon refuses with AV_BAD_LOCATION, so a
 * generic example would be an example of the error.
 */
export function exampleCall(s) {
  const site = (s.sites || [])[0] || ''
  const [kind, name, scheme] = site.split(':')
  // The token goes in AV-Session. For a Bearer-site credential the
  // placeholder goes in Authorization, and of two Authorization headers a
  // server keeps the first.
  const auth = `  -H "AV-Session: ${s.token}"`
  if (kind === 'header') {
    const header = `${name}: ${scheme ? `${scheme} ` : ''}${s.placeholder}`
    return `curl "${s.base_url}${s.probe || '/'}" \\\n${auth} \\\n  -H "${header}"`
  }
  return `curl "${s.base_url}${s.probe || '/'}" \\\n${auth}\n\n# then put the placeholder at: ${site}`
}

/** One env mapping row per grant, named as a tool would look for it. */
export const defaultMappings = (grants) => grants.map((g) => ({ name: suggestedName(g), cred: g.cred, what: 'placeholder' }))

/** Why a set of mappings would be refused by `env`, per row; null when fine. */
export function mappingProblems(rows) {
  const seen = new Map()
  for (const r of rows) seen.set(r.name, (seen.get(r.name) || 0) + 1)
  return rows.map((r) => {
    if (!ENV_NAME.test(r.name || '')) return 'Letters, digits and _ only, not starting with a digit'
    if (seen.get(r.name) > 1) return `${r.name} is mapped twice`
    return null
  })
}

/**
 * `<cli> env --session <sid> --out .env --map NAME=<cred>[:base_url]…`. The
 * command writes placeholders and loopback URLs only; the session token is
 * not in it.
 */
export function envCommand({ cli, sessionId, mappings }) {
  const maps = mappings.map((m) => `--map ${m.name}=${m.cred}${m.what === 'base_url' ? ':base_url' : ''}`)
  return `${cli} env --session ${sessionId} --out .env ${maps.join(' ')}`.trimEnd()
}

/**
 * The hand-off from a create answer. Only the fields the card shows are kept,
 * so nothing else the answer carried lingers in state. The first grant's own
 * injection site comes from the credential, as the old page read it.
 */
export function handoffFrom(created, { cli, creds = [], picked = [] }) {
  const first = created?.grants?.[0]?.cred ?? picked[0]
  const cred = creds.find((c) => c.slug === first)
  const grants = (Array.isArray(created?.grants) && created.grants.length ? created.grants : [created]).map((g) => ({
    cred: g?.cred ?? first ?? '',
    base_url: g?.base_url ?? '',
    placeholder: g?.placeholder ?? '',
    usage: Array.isArray(g?.usage) ? g.usage.slice() : [],
    lint: Array.isArray(g?.lint) ? g.lint.map((p) => String(p?.message ?? p)) : [],
    env: g?.env?.key ? { key: g.env.key } : undefined,
  }))
  return {
    session_id: created?.session_id ?? '',
    token: created?.token ?? '',
    expires_at: created?.expires_at ?? null,
    infinite: created?.infinite === true,
    cli: cli || 'agent-vault',
    sites: (cred?.fields?.[0]?.sites || created?.grants?.[0]?.sites || created?.sites || []).slice(),
    probe: cred?.probe_path || created?.grants?.[0]?.probe || created?.probe || '',
    grants,
  }
}

// ---- session detail ----------------------------------------------------------------

/**
 * An effective policy in the Described shape (F20) as rows of [label,
 * words]; the payload rules come back apart, to be shown as agent text.
 */
export function describedRows(e) {
  if (!e || typeof e !== 'object') return { rows: [], payload: null }
  const rows = [
    ['hosts', e.hosts], ['methods', e.methods], ['paths', e.paths], ['denied paths', e.deny_paths],
    ['approval', e.approval], ['routes', (e.routes || []).map((set) => (set || []).map((r) => `${(r.methods || []).join(',')} ${(r.paths || []).join(' ')}`).join(' | '))],
    ['budget', e.budget?.invalid ? 'invalid: every request is refused' : e.budget?.limit],
    ['spend', e.spend], ['rate', e.rate ? `${e.rate.count}/${e.rate.per}` : null],
    ['concurrency', e.max_concurrent], ['quota', e.quota ? `${e.quota.count}/${e.quota.window}` : null],
    ['redirects', e.redirects?.max ?? 0],
  ].map(([k, v]) => [k, policyValue(v)])
  const payload = Array.isArray(e.payload) && e.payload.length ? JSON.stringify(e.payload, null, 2) : null
  return { rows, payload }
}

/** budget / rate now / in flight / quota used, for one grant. */
export function grantUsageRows(g) {
  const lim = g?.limits || {}
  return [
    ['budget', g?.budget ? `${policyValue(g.budget.used)} used of ${policyValue(g.budget.limit)}` : 'none'],
    ...(lim.rate ? [['rate now', `${policyValue(lim.rate.tokens_now)} of ${lim.rate.count} per ${lim.rate.per}`]] : []),
    ...(lim.max_concurrent ? [['in flight', `${policyValue(lim.max_concurrent.in_flight)} of ${policyValue(lim.max_concurrent.limit)}`]] : []),
    ...(lim.quota ? [['quota used', `${policyValue(lim.quota.estimate)} of ${lim.quota.count} per ${lim.quota.window}`]] : []),
  ]
}

/** The spend lines and their bars: `[{ text, used, reserved, limit }]`. */
export function spendLines(sp) {
  if (!sp) return []
  const out = []
  if (Number.isFinite(sp.limit_tokens)) {
    out.push({ text: `tokens: ${sp.tokens_used} used, ${sp.reserved_tokens} reserved, of ${sp.limit_tokens}`, used: sp.tokens_used, reserved: sp.reserved_tokens, limit: sp.limit_tokens })
  }
  if (Number.isFinite(sp.limit_usd_micros)) {
    const usd = (n) => (n / 1e6).toFixed(2)
    out.push({
      text: `spend: $${usd(sp.usd_micros_used)} used, $${usd(sp.reserved_usd_micros)} reserved, of $${usd(sp.limit_usd_micros)} (estimate, prices ${sp.prices_version})`,
      used: sp.usd_micros_used, reserved: sp.reserved_usd_micros, limit: sp.limit_usd_micros,
    })
  }
  return out
}

/**
 * Used against limit as a width step out of 20 (5% each), so the bar is drawn
 * with Tailwind classes and needs no inline style (CSP, U2).
 */
export function barSteps(used, reserved, limit) {
  if (!Number.isFinite(limit) || limit <= 0) return null
  const step = (n) => Math.max(0, Math.min(20, Math.round(((Number(n) || 0) / limit) * 20)))
  return { used: step(used), reserved: step((Number(used) || 0) + (Number(reserved) || 0)) }
}

/** One placeholder of a grant, in words. */
export const placeholderText = (p) =>
  `${p.field} · ${p.uses}/${p.max_uses ?? '∞'} · ${p.state}${p.dead_reason ? ` (${p.dead_reason})` : ''} · ${p.expires_at ? until(p.expires_at) : 'no expiry of its own'}`

/** The session's facts, as the detail card listed them. */
export function sessionFacts(s = {}) {
  return [
    ['label', cleanLine(s.label ?? '')], ['state', s.state], ['created', s.created_at],
    ['expires', s.infinite === true ? 'never' : s.expires_at], ['last seen', s.last_seen_at || 'never'],
    ['remote', s.remote === true ? 'yes' : 'no'], ['template', s.template || 'none'],
    ['elevated', (s.elevated || []).join(', ') || 'no'],
  ].map(([k, v]) => [k, v === undefined || v === null ? '' : String(v)])
}

/** The activity counts line. */
export function activityLine(a = {}) {
  const req = a.requests || {}
  const appr = a.approvals || {}
  return `${req.allowed ?? 0} allowed · ${req.denied ?? 0} refused · ${req.held ?? 0} held · approvals: ${appr.requested ?? 0} asked, ${appr.granted ?? 0} granted, ${appr.denied ?? 0} denied`
}

/** The same sections as a Markdown summary, for pasting into a review. */
export function detailMarkdown(d) {
  const s = d?.session || {}
  const a = d?.activity || {}
  const tick = (v) => `\`${String(v ?? '').replace(/`/g, "'")}\``
  const lines = [
    `## Session ${tick(s.id)}${s.label ? ` (${cleanLine(s.label)})` : ''}`,
    '',
    `- state: ${s.state ?? 'unknown'}`,
    `- expires: ${s.infinite === true ? 'never' : s.expires_at ?? 'unknown'}`,
    `- elevated: ${(s.elevated || []).join(', ') || 'no'}`,
  ]
  if (a.complete === false) lines.push(`- **history incomplete:** ${a.note || 'the audit log does not cover the whole session'}`)
  for (const g of Array.isArray(d?.grants) ? d.grants : []) {
    lines.push('', `### ${tick(g.cred)} (${g.state ?? 'unknown'})`, '')
    const e = g.effective || {}
    for (const k of ['hosts', 'methods', 'paths', 'deny_paths', 'approval', 'rate', 'max_concurrent', 'quota', 'spend']) {
      if (e[k] !== null && e[k] !== undefined) lines.push(`- ${k}: ${tick(policyValue(e[k]))}`)
    }
    if (e.budget) lines.push(`- budget: ${g.budget?.used ?? 0} used of ${e.budget.limit ?? 'unlimited'}`)
    if (g.expires_at) lines.push(`- grant expires: ${g.expires_at}`)
  }
  const req = a.requests || {}
  lines.push('', '### Activity', '', `- ${req.allowed ?? 0} allowed, ${req.denied ?? 0} refused, ${req.held ?? 0} held`)
  // The method and path are what the agent sent: one clean line each.
  for (const p of a.paths || []) lines.push(`- ${p.count} × ${tick(`${cleanLine(p.method)} ${cleanLine(p.path)}`)}`)
  for (const x of a.denials || []) lines.push(`- refused ${x.count} × ${tick(`${x.code} ${x.rule || ''}`.trim())}`)
  return lines.join('\n')
}

// ---- routes inside the page ------------------------------------------------------

/** `#sessions/<rest>`: which tab, which session, which template. */
export function sessionsRoute(rest = '') {
  const r = String(rest || '')
  if (r.startsWith('detail:')) return { tab: 'list', detail: r.slice('detail:'.length) }
  if (r === 'new') return { tab: 'new' }
  if (r.startsWith('new:')) return { tab: 'new', template: r.slice('new:'.length) }
  if (r === 'review') return { tab: 'review' }
  return { tab: 'list' }
}
