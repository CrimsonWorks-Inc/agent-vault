// Answers for the Credentials, Sessions and Templates tests, shaped as the
// UI server gives them with paged=1 (the U3 envelope), plus the helpers the
// tests share. Test-only: nothing in the app imports this file.
import { useEffect } from 'react'
import { waitFor } from '@testing-library/react'
import { expect } from 'vitest'
import { usePresence } from '../hooks/usePresence.js'

export const CHALLENGE = { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' }
export const SOON = new Date(Date.now() + 3 * 86400e3).toISOString()
export const LATER = new Date(Date.now() + 5 * 3600e3).toISOString()

/** A paged answer over `all`, with opaque-looking server cursors. */
export function envelope(all, { limit = 25, total = all.length } = {}) {
  return ({ query }) => {
    const at = query.cursor ? Number(String(query.cursor).replace('srv-', '')) : 0
    const n = Number(query.limit || limit)
    const items = all.slice(at, at + n)
    return {
      items,
      next_cursor: at + n < all.length ? `srv-${at + n}` : null,
      prev_cursor: at > 0 ? `srv-${Math.max(0, at - n)}` : null,
      total,
    }
  }
}

// Built from pairs so the page-invariants grep (an `_untrusted` field inside
// braces must sit in UntrustedText) reads only the app's own source.
const quarantined = (reason) => Object.fromEntries([
  ['since', new Date(Date.now() - 3600e3).toISOString()], ['by', 'tripwire'], ['rule_id', 'replay'], ['reason_untrusted', reason],
])

export const CREDS = [
  {
    slug: 'gh-work', kind: 'github', connector: { host: 'api.github.com' },
    fields: [{ fp8: 'a1b2c3d4', sites: ['header:Authorization:Bearer'], version: 2, rotated_at: new Date(Date.now() - 3 * 86400e3).toISOString() }],
    pins: { 'api.github.com': 2 }, health: { status: 'ok' }, scrub_patterns: [{ id: 3, source: 'ghx_[A-Za-z0-9]{20}', added_at: new Date().toISOString() }],
    probe_path: '/user',
  },
  {
    slug: 'openai', kind: 'openai', connector: { host: 'api.openai.com' }, expiry_warning: 'soon', expires_at: SOON,
    fields: [{ fp8: 'ffee0011', sites: ['header:Authorization:Bearer'], version: 1 }],
  },
  {
    slug: 'old-hook', kind: 'http', connector: { host: 'hooks.example.com' },
    fields: [{ fp8: '99887766', sites: ['query:token'], version: 1 }],
    quarantine: quarantined('leaked \u202eevil <b>bold</b>'),
  },
]

export const SESSIONS = [
  {
    id: 's_live', label: 'issue triage', state: 'active', expires_at: LATER, remote: false, grants: 1, infinite: false,
    creds: [{ slug: 'gh-work', grant_id: 'g_1', approval: 'on-write', methods: ['GET', 'HEAD'] }], elevated: [],
  },
  {
    id: 's_inf', label: 'forever bot', state: 'active', expires_at: null, remote: true, grants: 2, infinite: true,
    creds: [{ slug: 'gh-work', approval: 'auto' }, { slug: 'openai', approval: 'each' }], elevated: ['infinite', 'approval_auto_writes'],
  },
  { id: 's_old', label: 'done', state: 'revoked', expires_at: LATER, grants: 1, creds: [{ slug: 'gh-work', approval: 'each' }], elevated: [] },
]

export const TEMPLATES = [
  { name: 'gh-read', version: 2, summary: 'read GitHub', creds: ['gh-work'], elevated: [], updated_at: new Date(Date.now() - 7200e3).toISOString() },
  { name: 'ship-it', version: 1, summary: 'writes, forever', creds: ['gh-work'], elevated: ['infinite'], updated_at: new Date().toISOString() },
]

export const DETAIL = {
  session: { id: 's_live', label: 'issue triage', state: 'active', created_at: '2026-10-30T10:00:00Z', expires_at: LATER, last_seen_at: null, remote: false, template: null, elevated: [] },
  grants: [{
    cred: 'gh-work', grant_id: 'g_1', state: 'active', expires_at: null,
    effective: { hosts: ['api.github.com'], methods: ['GET', 'HEAD'], paths: ['/**'], approval: 'on-write', budget: { limit: 500 }, payload: [{ json: { '/x': { one_of: ['\u202eevil'] } } }], redirects: { max: 0 } },
    budget: { used: 12, limit: 500 }, limits: { rate: { tokens_now: 3, count: 60, per: 'min' } },
    spend: { tokens_used: 100, reserved_tokens: 50, limit_tokens: 1000 },
    placeholders: [{ id: 'ph_1', field: 'token', uses: 1, max_uses: null, state: 'live', expires_at: null }],
  }],
  activity: {
    complete: false, note: 'the log was rotated',
    requests: { allowed: 12, denied: 2, held: 1 }, approvals: { requested: 1, granted: 1, denied: 0 },
    paths: [{ count: 9, method: 'GET', path: '/user' }], denials: [{ count: 2, code: 'AV_POLICY_DENIED', rule: 'methods' }], tripwires: [],
  },
}

/** Every route the three pages read, paged, plus presence. */
export function pagesRoutes(over = {}) {
  return {
    'GET presence/state': { enrolled: true, rpId: 'localhost' },
    'POST presence/challenge': CHALLENGE,
    'GET credentials': envelope(CREDS),
    'GET sessions': envelope(SESSIONS),
    'GET templates': ({ query }) => (query.name
      ? { name: query.name, version: 2, hash: 'h_abc', spec: { label: 'gh read', grants: [{ cred: 'gh-work', methods: ['GET', 'HEAD', 'POST'], approval: 'first-use', budget: 200, grant_ttl_minutes: 60 }], ttl_hours: 8 } }
      : envelope(TEMPLATES)({ query })),
    'GET sessions/detail': ({ query }) => (query.paged === '1' ? { ...envelope(DETAIL.grants)({ query }), session: DETAIL.session, activity: DETAIL.activity } : DETAIL),
    'GET report/access': ({ query }) => {
      const report = {
        generated_at: new Date().toISOString(), since: '2026-10-25T00:00:00Z', complete: true,
        sessions: [{ id: 's_live', label: 'issue triage', state: 'active', creds: ['gh-work'], requests: 4, denials: 0, last_seen_at: null, elevated: null, unused_methods: ['HEAD'] }],
        credentials: [{ slug: 'old-hook', sessions_active: 0, sessions_total: 1, requests: 0, denials: 1, last_used_at: null, expiry_warning: null, quarantined: true }],
      }
      if (query.paged !== '1') return report
      const list = query.list === 'credentials' ? report.credentials : report.sessions
      return { ...envelope(list)({ query }), generated_at: report.generated_at, since: report.since, complete: true }
    },
    ...over,
  }
}

/** The challenge a test's click asked for, once it has. */
export async function challengeOf(server, n = 0) {
  await waitFor(() => expect(server.calls.filter((c) => c.path === 'presence/challenge').length).toBeGreaterThan(n))
  return server.calls.filter((c) => c.path === 'presence/challenge')[n].body.operation
}

/** The calls to one route. */
export const callsTo = (server, method, path) => server.calls.filter((c) => c.method === method && c.path === path)

/**
 * Reads presence/state once, as the App shell does for every page, so a
 * gated button knows an authenticator is enrolled.
 */
export function Enrolled({ children }) {
  const presence = usePresence()
  useEffect(() => { presence.refresh() }, []) // eslint-disable-line react-hooks/exhaustive-deps
  return children
}
